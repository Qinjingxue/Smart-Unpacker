from pathlib import Path
from types import SimpleNamespace

import pytest

from benchmarks.scenarios.extraction_large_archive import (
    RequestRuntimeProfiler,
    _derived_timing,
    _cleanup_generated_output,
    _generated_output_path,
    _run_profile_once,
)


def test_request_profiler_hooks_current_per_request_runtime_factory(monkeypatch):
    runtime = object()
    runner = SimpleNamespace(_request_runtime_factory=lambda: runtime)
    profiler = RequestRuntimeProfiler()
    instrumented = []
    monkeypatch.setattr(
        profiler,
        "_instrument_runtime",
        lambda current, timings: instrumented.append((current, timings)),
    )

    profiler.install(runner)
    profiler.enabled = True
    try:
        assert runner._request_runtime_factory() is runtime
        assert instrumented[0][0] is runtime
        assert len(profiler.request_timings) == 1
    finally:
        profiler.restore()


def test_cleanup_generated_output_removes_only_profile_tree(tmp_path: Path):
    output_base = tmp_path / "profile"
    output = _generated_output_path(output_base, "run", 3)
    output.mkdir()
    (output / "payload.bin").write_bytes(b"payload")

    _cleanup_generated_output(output, output_base)

    assert not output.exists()
    with pytest.raises(ValueError, match="non-generated output"):
        _cleanup_generated_output(tmp_path / "unrelated", output_base)


def test_profile_run_cleans_output_when_pipeline_fails(tmp_path: Path):
    output_base = tmp_path / "profile"
    output = _generated_output_path(output_base, "run", 0)
    config = {"output": {"root": str(output_base)}}

    class FailedFuture:
        def result(self):
            output.mkdir(parents=True)
            (output / "partial.bin").write_bytes(b"partial")
            raise RuntimeError("pipeline failed")

    runner = SimpleNamespace(submit=lambda *_args, **_kwargs: FailedFuture())

    with pytest.raises(RuntimeError, match="pipeline failed"):
        _run_profile_once(
            runner,
            str(tmp_path / "archive.rar"),
            output,
            output_base,
            config,
            keep_output=False,
        )

    assert not output.exists()


def test_worker_wait_residual_excludes_protocol_processing():
    derived = _derived_timing({
        "worker_read_protocol": [1.0],
        "worker_protocol_json_decode": [0.1],
        "worker_protocol_drain_stderr": [0.02],
        "worker_protocol_emit_progress": [0.03],
    })

    assert derived["worker_wait_residual"] == pytest.approx(0.85)
