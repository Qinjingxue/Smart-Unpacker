import json
import sys
from pathlib import Path

import pytest

from benchmarks.cli import main
from benchmarks.harness import (
    AdaptivePressureGate,
    BenchmarkReport,
    BenchmarkWorkspace,
    PhaseReporter,
    ProcessSampler,
    measure,
    render_report,
)
from benchmarks.scenarios.extraction_format_matrix import _cached_corpus, _phase_aggregates


def test_measure_validates_dimensions_and_returns_common_clock_fields():
    with pytest.raises(ValueError):
        measure(lambda: None, runs=0)

    rows = measure(lambda: "ok", runs=2, warmups=1)

    assert [row.iteration for row in rows] == [0, 1]
    assert all(row.wall_ms >= 0 and row.cpu_ms >= 0 for row in rows)
    assert [row.value for row in rows] == ["ok", "ok"]


def test_report_uses_versioned_common_envelope():
    payload = json.loads(render_report(BenchmarkReport(
        scenario="reader.example",
        parameters={"runs": 2},
        samples=[{"wall_ms": 1.0}],
        summary={"median_wall_ms": 1.0},
    )))

    assert payload["schema_version"] == 1
    assert payload["scenario"] == "reader.example"
    assert payload["environment"]["python"]


def test_process_sampler_takes_current_process_snapshot():
    sampler = ProcessSampler(interval_seconds=0.01)

    sample = sampler.take()

    assert sample.rss_mib > 0
    assert sample.children_rss_mib >= 0
    assert sample.child_count >= 0


def test_benchmark_cli_dispatches_registered_module(monkeypatch):
    captured = {}

    def fake_run_module(module, run_name):
        captured.update(module=module, run_name=run_name, argv=list(sys.argv))

    monkeypatch.setattr("benchmarks.cli.runpy.run_module", fake_run_module)

    assert main(["reader", "embedded-scan", "--rounds", "1"]) == 0
    assert captured == {
        "module": "benchmarks.scenarios.reader_embedded_scan",
        "run_name": "__main__",
        "argv": ["benchmarks.scenarios.reader_embedded_scan", "--rounds", "1"],
    }


def test_benchmark_workspace_keeps_results_and_removes_temporary_corpus(tmp_path):
    results_root = tmp_path / "results"
    temp_root = tmp_path / "temporary"

    with BenchmarkWorkspace("extraction.real", results_root=results_root, temp_root=temp_root) as workspace:
        temporary_root = workspace.root
        result_dir = workspace.result_dir
        (workspace.corpus / "sample.zip").write_bytes(b"archive")
        workspace.write_result_json("report.json", {"ok": True})

    assert not temporary_root.exists()
    assert json.loads((result_dir / "report.json").read_text(encoding="utf-8")) == {"ok": True}
    manifest = json.loads((result_dir / "manifest.json").read_text(encoding="utf-8"))
    assert manifest["status"] == "completed"
    assert manifest["temporary_workdir"] is None
    assert manifest["temporary_workdir_retained"] is False


def test_benchmark_workspace_can_explicitly_keep_workdir(tmp_path):
    with BenchmarkWorkspace(
        "reader.real",
        results_root=tmp_path / "results",
        temp_root=tmp_path / "temporary",
        keep_workdir=True,
    ) as workspace:
        temporary_root = workspace.root
        result_dir = workspace.result_dir

    assert temporary_root.is_dir()
    manifest = json.loads((result_dir / "manifest.json").read_text(encoding="utf-8"))
    assert manifest["temporary_workdir"] == str(temporary_root)
    assert manifest["temporary_workdir_retained"] is True


def test_adaptive_pressure_gate_waits_until_host_is_healthy(monkeypatch):
    cpu = iter([95.0, 20.0])
    memory = type("Memory", (), {"available": 80, "total": 100})()
    monkeypatch.setattr("benchmarks.harness.pressure.psutil.cpu_percent", lambda interval: next(cpu))
    monkeypatch.setattr("benchmarks.harness.pressure.psutil.virtual_memory", lambda: memory)

    gate = AdaptivePressureGate(max_cpu_percent=80, sample_seconds=0.01, max_wait_seconds=1)
    result = gate.wait()

    assert result.samples == 2
    assert result.reason == "ready"
    assert gate.summary()["launches"] == 1


def test_phase_aggregates_report_slowest_phases_by_format():
    rows = [{
        "format": "zip",
        "phase_profile": {"timing_medians_seconds": {"extract_total": 2.0, "output_scan": 0.5}},
    }]

    aggregate = _phase_aggregates(rows)

    assert aggregate["zip"]["top_phases"][0] == {"phase": "extract_total", "median_seconds": 2.0}


def test_phase_reporter_times_phases_and_emits_timestamped_lines():
    import io

    stream = io.StringIO()
    reporter = PhaseReporter(stream=stream)

    with reporter.phase("first"):
        pass
    with reporter.phase("second"):
        pass
    reporter.record("second", 0.25)

    totals = reporter.totals()
    assert set(totals) == {"first", "second"}
    assert totals["first"] > 0
    assert totals["second"] > 0.25
    summary = reporter.render_summary()
    assert "first" in summary and "second" in summary

    output = stream.getvalue()
    assert "first: done in" in output
    assert "second: done in" in output
    import re

    assert re.search(r"^\[\d{2}:\d{2}:\d{2}\] first: done in", output, re.MULTILINE)


def test_phase_reporter_disabled_emits_nothing():
    import io

    stream = io.StringIO()
    reporter = PhaseReporter(enabled=False, stream=stream)

    with reporter.phase("first"):
        pass
    reporter.note("ignored")

    assert stream.getvalue() == ""
    assert reporter.totals() == {}


def test_format_matrix_corpus_cache_reuses_generated_archives(tmp_path, monkeypatch):
    calls = []

    def fake_create(root, extra, small_files, large_files, large_file_mib):
        calls.append(root)
        archive = root / "inputs" / "many_small-zip" / "many_small.zip"
        archive.parent.mkdir(parents=True)
        archive.write_bytes(b"cached archive")
        return ({"many_small:zip": {
            "workload": "many_small", "format": "zip", "path": archive, "expected_payload_bytes": 14,
        }}, {})

    monkeypatch.setattr("benchmarks.scenarios.extraction_format_matrix.create_corpus", fake_create)
    first, _, first_info = _cached_corpus(
        tmp_path / "run-1" / "corpus", cache_root=tmp_path / "cache",
        small_files=1, large_files=1, large_file_mib=1, rebuild=False,
    )
    second, _, second_info = _cached_corpus(
        tmp_path / "run-2" / "corpus", cache_root=tmp_path / "cache",
        small_files=1, large_files=1, large_file_mib=1, rebuild=False,
    )

    assert len(calls) == 1
    assert first_info["hit"] is False and second_info["hit"] is True
    assert Path(first["many_small:zip"]["path"]).read_bytes() == b"cached archive"
    assert Path(second["many_small:zip"]["path"]).read_bytes() == b"cached archive"
