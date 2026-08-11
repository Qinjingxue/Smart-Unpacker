import json
import sys

import pytest

from benchmarks.cli import main
from benchmarks.harness import BenchmarkReport, BenchmarkWorkspace, ProcessSampler, measure, render_report


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
