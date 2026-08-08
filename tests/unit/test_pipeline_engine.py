import queue
import threading
import time

import pytest

import sunpack.coordinator.engine as engine_module
from sunpack.config.schema import normalize_config
from sunpack.contracts.pipeline import PipelineArtifacts, PipelineResponse
from sunpack.contracts.results import RunSummary
from sunpack.coordinator.engine import PipelineEngine
from tests.helpers.detection_config import with_detection_pipeline


def _config(**pipeline):
    return normalize_config(with_detection_pipeline({
        "recursive_extract": "1",
        "cli": {"quiet": True},
        "pipeline": {"batch_window_seconds": 0.1, **pipeline},
        "repair": {"enabled": False},
        "verification": {"enabled": False, "methods": []},
        "post_extract": {"archive_cleanup_mode": "k", "flatten_single_directory": False},
    }))


def _response(submission, *, passwords=()):
    return PipelineResponse(
        request_id=submission.request_id,
        summary=RunSummary(success_count=0, failed_tasks=[], processed_keys=[]),
        artifacts=PipelineArtifacts(),
        recent_passwords=tuple(passwords),
    )


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
    response = PipelineResponse(
        request_id="request",
        summary=RunSummary(success_count=1, failed_tasks=[], processed_keys=[]),
        artifacts=PipelineArtifacts(
            archives_to_clean=((str(probe_outer / "inner.7z"),),),
            flatten_targets=(str(probe_outer / "inner"),),
            shell_refresh_paths=(str(probe_outer / "inner.7z"), str(probe_outer / "inner")),
        ),
    )

    engine_module._finalize_response({}, response, output_path_map={str(probe_outer): str(final_outer)})

    assert captured["archives_to_clean"] == [[str(final_outer / "inner.7z")]]
    assert captured["flatten_targets"] == [str(final_outer / "inner")]
    assert captured["shell_refresh_paths"] == [str(final_outer / "inner.7z"), str(final_outer / "inner")]
    assert call_order == ["postprocess", "notify"]


def test_independent_submission_completes_while_another_request_is_blocked(tmp_path):
    engine = PipelineEngine(_config(max_active_pipeline_requests=2))
    first_entered = threading.Event()
    release_first = threading.Event()

    class Runtime:
        def __init__(self, _services, submission, *_args):
            self.submission = submission

        def execute(self):
            if self.submission.targets[0].path.endswith("first.zip"):
                first_entered.set()
                assert release_first.wait(timeout=5)
            return _response(self.submission)

    engine._request_runtime_factory = Runtime
    engine.start()
    first = engine.submit([str(tmp_path / "first.zip")])
    assert first_entered.wait(timeout=5)
    second = engine.submit([str(tmp_path / "second.zip")])

    assert second.result(timeout=2).request_id == second.request_id
    assert not first.done()
    release_first.set()
    first.result(timeout=5)
    engine.close()


def test_same_input_path_is_serialized_by_engine_lease(tmp_path):
    engine = PipelineEngine(_config(max_active_pipeline_requests=2))
    entered = []
    first_release = threading.Event()

    class Runtime:
        def __init__(self, _services, submission, *_args):
            self.submission = submission

        def execute(self):
            entered.append(self.submission.request_id)
            if len(entered) == 1:
                assert first_release.wait(timeout=5)
            return _response(self.submission)

    engine._request_runtime_factory = Runtime
    engine.start()
    path = str(tmp_path / "same.zip")
    first = engine.submit([path])
    deadline = time.monotonic() + 5
    while not entered and time.monotonic() < deadline:
        time.sleep(0.01)
    second = engine.submit([path])
    time.sleep(0.1)
    assert len(entered) == 1
    first_release.set()
    first.result(timeout=5)
    second.result(timeout=5)
    assert len(entered) == 2
    engine.close()


def test_split_member_lease_expansion_is_serialized_without_deadlock(tmp_path):
    engine = PipelineEngine(_config(max_active_pipeline_requests=2))
    first_part = str(tmp_path / "archive.part1.rar")
    second_part = str(tmp_path / "archive.part2.rar")
    active = 0
    maximum_active = 0
    lock = threading.Lock()

    class Runtime:
        def __init__(self, _services, submission, _options, path_leases):
            self.submission = submission
            self.path_leases = path_leases

        def execute(self):
            nonlocal active, maximum_active
            self.path_leases.replace(self.submission.request_id, [first_part, second_part])
            with lock:
                active += 1
                maximum_active = max(maximum_active, active)
            time.sleep(0.05)
            with lock:
                active -= 1
            return _response(self.submission)

    engine._request_runtime_factory = Runtime
    engine.start()
    first = engine.submit([first_part])
    second = engine.submit([second_part])
    first.result(timeout=5)
    second.result(timeout=5)
    assert maximum_active == 1
    engine.close()


def test_reconfigure_only_changes_future_request_snapshots(tmp_path):
    config = _config(max_active_pipeline_requests=2)
    config["cli"]["quiet"] = True
    engine = PipelineEngine(config)
    observed = {}
    first_entered = threading.Event()
    release_first = threading.Event()

    class Runtime:
        def __init__(self, _services, submission, *_args):
            self.submission = submission

        def execute(self):
            observed[self.submission.targets[0].path] = self.submission.config["cli"]["quiet"]
            if self.submission.targets[0].path.endswith("first.zip"):
                first_entered.set()
                assert release_first.wait(timeout=5)
            return _response(self.submission)

    engine._request_runtime_factory = Runtime
    engine.start()
    first_path = str(tmp_path / "first.zip")
    second_path = str(tmp_path / "second.zip")
    first = engine.submit([first_path])
    assert first_entered.wait(timeout=5)
    updated = _config(max_active_pipeline_requests=2)
    updated["cli"]["quiet"] = False
    engine.reconfigure_request(updated)
    second = engine.submit([second_path])
    second.result(timeout=5)
    release_first.set()
    first.result(timeout=5)

    assert observed == {first_path: True, second_path: False}
    engine.close()


def test_engine_aggregates_recent_passwords_per_completed_request(tmp_path):
    engine = PipelineEngine(_config(max_active_pipeline_requests=2))

    class Runtime:
        def __init__(self, _services, submission, *_args):
            self.submission = submission

        def execute(self):
            password = "first" if self.submission.targets[0].path.endswith("first.zip") else "second"
            return _response(self.submission, passwords=[password])

    engine._request_runtime_factory = Runtime
    engine.start()
    engine.submit([str(tmp_path / "first.zip")]).result(timeout=5)
    engine.submit([str(tmp_path / "second.zip")]).result(timeout=5)
    assert engine.recent_passwords == ["second", "first"]
    engine.close()


def test_engine_pressure_counts_active_and_waiting_requests(tmp_path):
    engine = PipelineEngine(_config(max_active_pipeline_requests=1))
    entered = threading.Event()
    release = threading.Event()

    class Runtime:
        def __init__(self, _services, submission, *_args):
            self.submission = submission

        def execute(self):
            entered.set()
            assert release.wait(timeout=5)
            return _response(self.submission)

    engine._request_runtime_factory = Runtime
    engine.start()
    first = engine.submit([str(tmp_path / "first.zip")])
    assert entered.wait(timeout=5)
    second = engine.submit([str(tmp_path / "second.zip")])
    assert engine.resource_scheduler.pressure_snapshot()["pipeline_requests"] >= 2
    release.set()
    first.result(timeout=5)
    second.result(timeout=5)
    engine.close()


def test_archive_sessions_are_cleared_only_when_engine_closes(tmp_path, monkeypatch):
    engine = PipelineEngine(_config(max_active_pipeline_requests=2))
    clear_calls = []
    monkeypatch.setattr(engine_module, "clear_archive_sessions", lambda: clear_calls.append(True))

    class Runtime:
        def __init__(self, _services, submission, *_args):
            self.submission = submission

        def execute(self):
            return _response(self.submission)

    engine._request_runtime_factory = Runtime
    engine.start()
    engine.submit([str(tmp_path / "archive.zip")]).result(timeout=5)
    assert clear_calls == []
    engine.close()
    assert clear_calls == [True]


def test_non_graceful_close_cancels_requests_that_have_not_started(tmp_path):
    engine = PipelineEngine(_config(max_active_pipeline_requests=1))
    entered = threading.Event()
    release = threading.Event()

    class Runtime:
        def __init__(self, _services, submission, *_args):
            self.submission = submission

        def execute(self):
            entered.set()
            release.wait(timeout=5)
            return _response(self.submission)

    engine._request_runtime_factory = Runtime
    engine.start()
    first = engine.submit([str(tmp_path / "first.zip")])
    assert entered.wait(timeout=5)
    second = engine.submit([str(tmp_path / "second.zip")])
    closer = threading.Thread(target=lambda: engine.close(graceful=False))
    closer.start()
    deadline = time.monotonic() + 2
    while not second._submission.future.cancelled() and time.monotonic() < deadline:
        time.sleep(0.01)
    assert second._submission.future.cancelled()
    release.set()
    first.result(timeout=5)
    closer.join(timeout=5)
    assert not closer.is_alive()
    with pytest.raises(RuntimeError, match="started"):
        engine.submit([str(tmp_path / "third.zip")])
