from pathlib import Path

import pytest

from sunpack.config.schema import normalize_config
from sunpack.contracts.extraction import ExtractionResult
from sunpack.coordinator.engine import PipelineEngine
from sunpack.filesystem.watcher.scheduler import WatchScheduler
from tests.helpers.detection_config import with_detection_pipeline
from tests.helpers.fs_builder import make_zip


def _config(**pipeline):
    return normalize_config(with_detection_pipeline({
        "recursive_extract": "1",
        "cli": {"quiet": True},
        "pipeline": {"batch_window_seconds": 0.1, **pipeline},
        "post_extract": {"archive_cleanup_mode": "k", "flatten_single_directory": False},
        "thresholds": {"archive_score_threshold": 5, "maybe_archive_threshold": 3},
    }, scoring=[
        {"name": "extension", "enabled": True, "extension_score_groups": [{"score": 5, "extensions": [".zip"]}]},
    ]))


def test_engine_micro_batches_independent_submissions_and_keeps_results_isolated(tmp_path, monkeypatch):
    first = tmp_path / "first.zip"
    second = tmp_path / "second.zip"
    first.write_bytes(make_zip({"first.txt": "first"}))
    second.write_bytes(make_zip({"second.txt": "second"}))
    engine = PipelineEngine(_config())
    batch_sizes = []
    execute_batch = engine._runtime.execute

    def measured_execute(submissions, **kwargs):
        batch_sizes.append(len(submissions))
        return execute_batch(submissions, **kwargs)

    monkeypatch.setattr(engine._runtime, "execute", measured_execute)
    monkeypatch.setattr(engine.extractor, "inspect", lambda *_args, **_kwargs: type("Preflight", (), {"skip_result": None})())
    monkeypatch.setattr(engine.batch_runner.resource_inspector, "inspect", lambda task: task)

    def fake_extract(task, out_dir, runtime_scheduler=None, **_kwargs):
        Path(out_dir).mkdir(parents=True, exist_ok=True)
        return ExtractionResult(success=True, archive=task.main_path, out_dir=out_dir, all_parts=task.all_parts)

    monkeypatch.setattr(engine.extractor, "extract", fake_extract)
    engine.start()
    first_handle = engine.submit([str(first)])
    second_handle = engine.submit([str(second)])
    first_response = first_handle.result(timeout=10)
    second_response = second_handle.result(timeout=10)
    engine.close()

    assert batch_sizes == [2]
    assert first_response.summary.success_count == 1
    assert second_response.summary.success_count == 1
    assert [item.input_path for item in first_response.summary.target_results] == [str(first)]
    assert [item.input_path for item in second_response.summary.target_results] == [str(second)]


def test_engine_only_closes_resident_extractor_when_engine_closes(tmp_path, monkeypatch):
    engine = PipelineEngine(_config(batch_window_seconds=0))
    executor_pool = engine._runtime.executor_pool
    analysis_pool = engine._runtime.analysis_executor_pool
    close_calls = []
    monkeypatch.setattr(engine.extractor, "close", lambda: close_calls.append(True))
    engine.start()
    engine.submit([str(tmp_path)]).result(timeout=10)
    engine.submit([str(tmp_path)]).result(timeout=10)

    assert close_calls == []
    assert engine.batch_runner.executor_pool is executor_pool
    assert executor_pool._shutdown is False
    assert analysis_pool._shutdown is False

    engine.close()
    assert close_calls == [True]
    assert executor_pool._shutdown is True
    assert analysis_pool._shutdown is True
    with pytest.raises(RuntimeError, match="started"):
        engine.submit([str(tmp_path)])


def test_watch_submits_all_quiet_files_to_one_engine_micro_batch(tmp_path, monkeypatch):
    watch_root = tmp_path / "watch"
    watch_root.mkdir()
    first = watch_root / "first.zip"
    second = watch_root / "second.zip"
    first.write_bytes(make_zip({"first.txt": "first"}))
    second.write_bytes(make_zip({"second.txt": "second"}))
    config = _config()
    config["watch"] = {"clipboard_monitor_enabled": False}
    engine = PipelineEngine(config)
    batch_sizes = []
    execute_batch = engine._runtime.execute

    def measured_execute(submissions, **kwargs):
        batch_sizes.append(len(submissions))
        return execute_batch(submissions, **kwargs)

    monkeypatch.setattr(engine._runtime, "execute", measured_execute)
    monkeypatch.setattr(engine.extractor, "inspect", lambda *_args, **_kwargs: type("Preflight", (), {"skip_result": None})())
    monkeypatch.setattr(engine.batch_runner.resource_inspector, "inspect", lambda task: task)

    def fake_extract(task, out_dir, runtime_scheduler=None, **_kwargs):
        Path(out_dir).mkdir(parents=True, exist_ok=True)
        (Path(out_dir) / "payload.txt").write_text(task.logical_name, encoding="utf-8")
        return ExtractionResult(success=True, archive=task.main_path, out_dir=out_dir, all_parts=task.all_parts)

    monkeypatch.setattr(engine.extractor, "extract", fake_extract)
    engine.start()
    watcher = WatchScheduler(
        config,
        [str(watch_root)],
        out_dir=str(tmp_path / "out"),
        state_path=str(tmp_path / "watch-state.json"),
        quiet_seconds=0,
        initial_scan=False,
        pipeline_engine=engine,
    )
    watcher.enqueue(str(first))
    watcher.enqueue(str(second))
    result = watcher.run_once()
    engine.close()

    assert batch_sizes == [2]
    assert result.succeeded == 2
    assert len(list((tmp_path / "out").rglob("payload.txt"))) == 2
