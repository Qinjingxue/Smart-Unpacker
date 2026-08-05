from pathlib import Path
import queue
import threading
import time

import pytest

import sunpack.coordinator.engine as engine_module
from sunpack.config.schema import normalize_config
from sunpack.contracts.extraction import ExtractionResult
from sunpack.contracts.pipeline import PipelineArtifacts, PipelineResponse
from sunpack.contracts.results import RunSummary
from sunpack.coordinator.engine import PipelineEngine
from sunpack.filesystem.watcher.scheduler import WatchScheduler
from tests.helpers.detection_config import with_detection_pipeline
from tests.helpers.fs_builder import make_zip


def _config(**pipeline):
    return normalize_config(with_detection_pipeline({
        "recursive_extract": "1",
        "cli": {"quiet": True},
        "pipeline": {"batch_window_seconds": 0.1, **pipeline},
        "repair": {"enabled": False},
        "verification": {"enabled": False, "methods": []},
        "post_extract": {"archive_cleanup_mode": "k", "flatten_single_directory": False},
        "thresholds": {"archive_score_threshold": 5, "maybe_archive_threshold": 3},
    }))


def test_engine_idle_state_includes_active_and_queued_requests():
    engine = object.__new__(PipelineEngine)
    engine._pressure_lock = threading.Lock()
    engine._active_request_count = 0
    engine._queue = queue.Queue()

    assert engine.is_idle()
    engine._queue.put(object())
    assert not engine.is_idle()
    engine._queue.get_nowait()
    engine._active_request_count = 1
    assert not engine.is_idle()


def test_finalize_remaps_nested_cleanup_and_flatten_paths_with_promoted_parent(tmp_path, monkeypatch):
    probe_outer = tmp_path / "probe" / "outer"
    final_outer = tmp_path / "downloads" / "outer"
    captured = {}
    call_order = []

    class FakePostProcessActions:
        def __init__(self, _config):
            pass

        def apply(self, **kwargs):
            call_order.append("postprocess")
            captured.update(kwargs)

    monkeypatch.setattr(engine_module, "PostProcessActions", FakePostProcessActions)
    monkeypatch.setattr(
        engine_module,
        "notify_shell_directories_updated",
        lambda paths: call_order.append("notify") or captured.update(shell_refresh_paths=list(paths)),
    )
    runtime = object.__new__(engine_module._PipelineRuntime)
    runtime.config = {}
    response = PipelineResponse(
        request_id="request",
        summary=RunSummary(success_count=1, failed_tasks=[], processed_keys=[]),
        artifacts=PipelineArtifacts(
            archives_to_clean=((str(probe_outer / "inner.7z"),),),
            flatten_targets=(str(probe_outer / "inner"),),
            shell_refresh_paths=(str(probe_outer / "inner.7z"), str(probe_outer / "inner")),
        ),
    )

    runtime.finalize(response, output_path_map={str(probe_outer): str(final_outer)})

    assert captured["archives_to_clean"] == [[str(final_outer / "inner.7z")]]
    assert captured["flatten_targets"] == [str(final_outer / "inner")]
    assert captured["shell_refresh_paths"] == [str(final_outer / "inner.7z"), str(final_outer / "inner")]
    assert call_order == ["postprocess", "notify"]


def test_engine_micro_batches_independent_submissions_and_keeps_results_isolated(tmp_path, monkeypatch):
    first = tmp_path / "first.zip"
    second = tmp_path / "second.zip"
    first.write_bytes(make_zip({"first.txt": "first"}))
    second.write_bytes(make_zip({"second.txt": "second"}))
    engine = PipelineEngine(_config())
    batch_sizes = []
    shell_refresh_calls = []
    execute_batch = engine._runtime.execute

    def measured_execute(submissions, **kwargs):
        batch_sizes.append(len(submissions))
        return execute_batch(submissions, **kwargs)

    monkeypatch.setattr(engine._runtime, "execute", measured_execute)
    monkeypatch.setattr(
        engine_module,
        "notify_shell_directories_updated",
        lambda paths: shell_refresh_calls.append(list(paths)) or [],
    )
    monkeypatch.setattr(engine.extractor, "inspect", lambda *_args, **_kwargs: type("Preflight", (), {"skip_result": None})())
    monkeypatch.setattr(engine.batch_runner.resource_inspector, "inspect", lambda task: task)

    def fake_extract(task, out_dir, runtime_scheduler=None, **_kwargs):
        Path(out_dir).mkdir(parents=True, exist_ok=True)
        (Path(out_dir) / "payload.txt").write_text(task.logical_name, encoding="utf-8")
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
    assert len(shell_refresh_calls) == 2
    assert any(str(first) in paths and any(Path(path).name == "first" for path in paths) for paths in shell_refresh_calls)
    assert any(str(second) in paths and any(Path(path).name == "second" for path in paths) for paths in shell_refresh_calls)


def test_engine_only_closes_resident_extractor_when_engine_closes(tmp_path, monkeypatch):
    engine = PipelineEngine(_config(batch_window_seconds=0))
    executor_pool = engine._runtime.executor_pool
    planning_pool = engine._runtime.input_planning_executor_pool
    close_calls = []
    monkeypatch.setattr(engine.extractor, "close", lambda: close_calls.append(True))
    engine.start()
    engine.submit([str(tmp_path)]).result(timeout=10)
    engine.submit([str(tmp_path)]).result(timeout=10)

    assert close_calls == []
    assert engine.batch_runner.executor_pool is executor_pool
    assert executor_pool._shutdown is False
    assert planning_pool._shutdown is False
    assert engine.resource_scheduler.is_running is True

    engine.close()
    assert close_calls == [True]
    assert executor_pool._shutdown is True
    assert planning_pool._shutdown is True
    assert engine.resource_scheduler.is_running is False
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
    deadline = time.monotonic() + 10
    while not result.processed and time.monotonic() < deadline:
        time.sleep(0.01)
        result = watcher.run_once()
    engine.close()

    assert batch_sizes == [2]
    assert result.succeeded == 2
    assert len(list((tmp_path / "out").rglob("payload.txt"))) == 2


def test_engine_scheduler_keeps_feedback_across_separate_micro_batches(tmp_path, monkeypatch):
    engine = PipelineEngine(_config(batch_window_seconds=0))
    scheduler = engine.resource_scheduler

    def record_batch(submissions, **_kwargs):
        for submission in submissions:
            scheduler.record_task_feedback(
                demand={"cpu": 1, "io": 1, "memory": 1},
                duration_seconds=1.0,
                estimated_bytes=1024,
                active_workers_at_start=1,
                success=True,
                profile_key="zip:test",
            )
            submission.future.set_result(None)

    monkeypatch.setattr(engine._runtime, "execute", record_batch)
    engine.start()
    engine.submit([str(tmp_path / "first.zip")]).result(timeout=5)
    engine.submit([str(tmp_path / "second.zip")]).result(timeout=5)

    assert engine.resource_scheduler is scheduler
    assert scheduler.is_running is True
    assert len(scheduler.feedback.feedback_window) == 2
    assert len(scheduler.feedback.profile_feedback_windows["zip:test"]) == 2
    engine.close()


def test_engine_queue_and_active_batch_feed_pipeline_pressure(tmp_path, monkeypatch):
    engine = PipelineEngine(_config(batch_window_seconds=0))
    entered = threading.Event()
    release = threading.Event()

    def blocked_batch(submissions, **_kwargs):
        entered.set()
        assert release.wait(timeout=5)
        for submission in submissions:
            submission.future.set_result(None)

    monkeypatch.setattr(engine._runtime, "execute", blocked_batch)
    engine.start()
    first = engine.submit([str(tmp_path / "first.zip")])
    assert entered.wait(timeout=5)
    second = engine.submit([str(tmp_path / "second.zip")])

    assert engine.resource_scheduler.pressure_snapshot()["pipeline_requests"] >= 2
    release.set()
    first.result(timeout=5)
    second.result(timeout=5)
    engine.close()


def test_engine_releases_request_scoped_password_contexts(tmp_path, monkeypatch):
    engine = PipelineEngine(_config(batch_window_seconds=0))
    archive_session_clear_calls = []
    monkeypatch.setattr(engine_module, "clear_archive_sessions", lambda: archive_session_clear_calls.append(True))

    def complete_batch(submissions, **_kwargs):
        engine.batch_runner.directory_password_contexts._contexts[str(tmp_path)] = ["secret"]
        engine._runtime.input_planning_stage._report_cache[("source", "archive")] = object()
        for submission in submissions:
            submission.future.set_result(None)

    monkeypatch.setattr(engine._runtime, "execute", complete_batch)
    engine.start()
    engine.submit([str(tmp_path / "archive.zip")]).result(timeout=5)

    assert engine.batch_runner.directory_password_contexts._contexts == {}
    assert engine.batch_runner.progress_reporter is None
    assert engine._runtime.input_planning_stage._report_cache == {}
    assert archive_session_clear_calls == [True]
    engine.close()
