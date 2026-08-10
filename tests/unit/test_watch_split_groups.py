from __future__ import annotations

from types import SimpleNamespace

import pytest

from sunpack.contracts.failures import FailureInfo, FailureKind
from sunpack.coordinator.watch_group_coordinator import WatchGroupCoordinator
from tests.helpers.fake_pipeline_engine import FakePipelineEngine
from sunpack.filesystem.watcher.scheduler import WatchScheduler


def _summary(*failures: FailureInfo):
    return SimpleNamespace(
        success_count=0 if failures else 1,
        failed_tasks=[failure.message for failure in failures],
        failures=list(failures),
    )


def _partial_summary(*failures: FailureInfo):
    return SimpleNamespace(
        success_count=0,
        partial_success_count=1,
        failed_tasks=[],
        failures=list(failures),
        target_results=[],
    )


def _watcher(tmp_path, runner_factory) -> WatchScheduler:
    root = tmp_path / "in"
    root.mkdir(exist_ok=True)
    return WatchScheduler(
        {"watch": {"clipboard_monitor_enabled": False, "password_retry_debounce_seconds": 0}},
        [str(root)],
        out_dir=str(tmp_path / "out"),
        state_path=str(tmp_path / "state.json"),
        quiet_seconds=0,
        initial_scan=False,
        pipeline_engine=FakePipelineEngine(runner_factory),
        group_coordinator=WatchGroupCoordinator({}),
    )


def test_watch_holds_orphan_non_head_until_first_volume_arrives(tmp_path):
    attempts: list[str] = []

    class Runner:
        def __init__(self, config):
            pass

        def run_targets(self, paths):
            attempts.extend(paths)
            return _summary()

    watcher = _watcher(tmp_path, Runner)
    root = tmp_path / "in"
    second = root / "sample.7z.002"
    second.write_bytes(b"part-2")
    watcher.enqueue(str(second))

    first = watcher.run_once()
    head = root / "sample.7z.001"
    head.write_bytes(b"part-1")
    watcher.enqueue(str(head))
    second_result = watcher.run_once()

    assert first.processed == 0
    assert second_result.succeeded == 1
    assert attempts == [str(head.resolve())]


def test_watch_conservatively_holds_old_rar_orphan_until_head_arrives(tmp_path):
    attempts: list[str] = []

    class Runner:
        def __init__(self, config):
            pass

        def run_targets(self, paths):
            attempts.extend(paths)
            return _summary()

    watcher = _watcher(tmp_path, Runner)
    root = tmp_path / "in"
    for name in ("old-style.r00",):
        path = root / name
        path.write_bytes(name.encode())
        watcher.enqueue(str(path))
    assert watcher.run_once().processed == 0

    head = root / "old-style.rar"
    head.write_bytes(b"head")
    watcher.enqueue(str(head))

    assert watcher.run_once().succeeded == 1
    assert attempts == [str(head.resolve())]


def test_watch_does_not_hold_plain_numeric_files_as_missing_volumes(tmp_path):
    attempts: list[str] = []

    class Runner:
        def __init__(self, config):
            pass

        def run_targets(self, paths):
            attempts.extend(paths)
            return _summary()

    watcher = _watcher(tmp_path, Runner)
    root = tmp_path / "in"
    for name in ("plain.002", "plain.003"):
        path = root / name
        path.write_bytes(name.encode())
        watcher.enqueue(str(path))

    result = watcher.run_once()

    assert result.processed == 1
    assert len(attempts) == 1


def test_watch_holds_strong_middle_gap_until_missing_volume_arrives(tmp_path):
    attempts: list[str] = []

    class Runner:
        def __init__(self, config):
            pass

        def run_targets(self, paths):
            attempts.extend(paths)
            return _summary()

    watcher = _watcher(tmp_path, Runner)
    root = tmp_path / "in"
    head = root / "gap.7z.001"
    third = root / "gap.7z.003"
    head.write_bytes(b"7z\xbc\xaf\x27\x1c-head")
    third.write_bytes(b"tail")
    watcher.enqueue(str(head))

    first_result = watcher.run_once()

    assert first_result.processed == 0
    assert attempts == []
    state = watcher.state.group_state(next(iter(watcher.state.groups)))
    assert state is not None
    assert "missing_volume" not in state.blockers
    assert state.failure_payload["details"]["completeness_status"] == "middle_gap"
    assert state.failure_payload["details"]["completeness_confidence"] == "strong"

    second = root / "gap.7z.002"
    second.write_bytes(b"middle")
    watcher.enqueue(str(second))

    second_result = watcher.run_once()
    assert second_result.succeeded == 1
    assert attempts == [str(head.resolve())]


def test_watch_dispatches_weak_camouflaged_gap_for_backend_classification(tmp_path):
    attempts: list[str] = []

    class Runner:
        def __init__(self, config):
            pass

        def run_targets(self, paths):
            attempts.extend(paths)
            return _summary()

    watcher = _watcher(tmp_path, Runner)
    root = tmp_path / "in"
    head = root / "gap.part1.123"
    third = root / "gap.part3.789"
    head.write_bytes(b"ordinary data")
    third.write_bytes(b"ordinary data")
    watcher.enqueue(str(head))

    result = watcher.run_once()

    assert result.succeeded == 1
    assert attempts == [str(head.resolve())]


def test_watch_holds_content_confirmed_camouflaged_middle_gap(tmp_path):
    attempts: list[str] = []

    class Runner:
        def __init__(self, config):
            pass

        def run_targets(self, paths):
            attempts.extend(paths)
            return _summary()

    watcher = _watcher(tmp_path, Runner)
    root = tmp_path / "in"
    head = root / "gap.part1.123"
    third = root / "gap.part3.789"
    head.write_bytes(b"7z\xbc\xaf\x27\x1c-head")
    third.write_bytes(b"tail")
    watcher.enqueue(str(head))

    result = watcher.run_once()

    assert result.processed == 0
    assert attempts == []
    state = watcher.state.group_state(next(iter(watcher.state.groups)))
    assert state is not None
    assert state.failure_payload["details"]["completeness_status"] == "middle_gap"
    assert state.failure_payload["details"]["completeness_confidence"] == "strong"
    assert "archive_head_confirmed" in state.failure_payload["details"]["completeness_basis"]


def test_watch_does_not_infer_missing_tail_from_equal_volume_sizes(tmp_path):
    attempts: list[str] = []

    class Runner:
        def __init__(self, config):
            pass

        def run_targets(self, paths):
            attempts.extend(paths)
            return _summary()

    watcher = _watcher(tmp_path, Runner)
    root = tmp_path / "in"
    head = root / "exact-boundary.7z.001"
    second = root / "exact-boundary.7z.002"
    head.write_bytes(b"x" * 4096)
    second.write_bytes(b"y" * 4096)
    watcher.enqueue(str(head))

    result = watcher.run_once()

    assert result.succeeded == 1
    assert attempts == [str(head.resolve())]


def test_watch_holds_classic_zip_until_required_terminal_arrives(tmp_path):
    attempts: list[str] = []

    class Runner:
        def __init__(self, config):
            pass

        def run_targets(self, paths):
            attempts.extend(paths)
            return _summary()

    watcher = _watcher(tmp_path, Runner)
    root = tmp_path / "in"
    first = root / "classic.z01"
    second = root / "classic.z02"
    first.write_bytes(b"segment-1")
    second.write_bytes(b"segment-2")
    watcher.enqueue(str(first))

    assert watcher.run_once().processed == 0
    assert attempts == []

    terminal = root / "classic.zip"
    terminal.write_bytes(b"terminal")
    watcher.enqueue(str(terminal))

    assert watcher.run_once().succeeded == 1
    assert attempts == [str(first.resolve())]


def test_watch_runtime_missing_volume_retries_only_after_group_changes(tmp_path):
    attempts: list[str] = []

    class Runner:
        def __init__(self, config):
            pass

        def run_targets(self, paths):
            attempts.extend(paths)
            if len(attempts) == 1:
                return _summary(FailureInfo(FailureKind.MISSING_VOLUME, "extraction", "missing volume"))
            return _summary()

    watcher = _watcher(tmp_path, Runner)
    root = tmp_path / "in"
    head = root / "sample.7z.001"
    second = root / "sample.7z.002"
    head.write_bytes(b"part-1")
    second.write_bytes(b"part-2")
    watcher.enqueue(str(head))
    watcher.enqueue(str(second))
    assert watcher.run_once().failed == 1

    watcher.enqueue(str(head), force=True)
    assert watcher.run_once().processed == 0
    third = root / "sample.7z.003"
    third.write_bytes(b"part-3")
    watcher.enqueue(str(third))

    assert watcher.run_once().succeeded == 1
    assert attempts == [str(head.resolve()), str(head.resolve())]


def test_watch_treats_possible_missing_partial_recovery_as_suspended(tmp_path):
    attempts: list[str] = []
    possible_missing = FailureInfo(
        FailureKind.MISSING_VOLUME,
        "extraction_report",
        "one or more split volumes may be missing",
        details={"missing_volume_confirmed": False, "partial_recovery": True},
    )

    class Runner:
        def __init__(self, config):
            pass

        def run_targets(self, paths):
            attempts.extend(paths)
            return _partial_summary(possible_missing) if len(attempts) == 1 else _summary()

    watcher = _watcher(tmp_path, Runner)
    root = tmp_path / "in"
    head = root / "sample.zip.001"
    second = root / "sample.zip.002"
    head.write_bytes(b"part-1")
    second.write_bytes(b"part-2")
    watcher.enqueue(str(head))
    watcher.enqueue(str(second))

    assert watcher.run_once().failed == 1
    group_state = watcher.state.group_state(next(iter(watcher.state.groups)))
    assert group_state is not None
    assert group_state.status == "suspended"
    assert group_state.has_blocker("missing_volume")

    watcher.enqueue(str(head), force=True)
    assert watcher.run_once().processed == 0
    third = root / "sample.zip.003"
    third.write_bytes(b"part-3")
    watcher.enqueue(str(third))

    assert watcher.run_once().succeeded == 1
    assert attempts == [str(head.resolve()), str(head.resolve())]


def test_watch_combined_missing_volume_and_password_requires_both_changes(tmp_path):
    attempts: list[str] = []
    combined = FailureInfo(
        FailureKind.MISSING_VOLUME,
        "extraction",
        "missing volume and password",
        causes=(FailureInfo(FailureKind.WRONG_PASSWORD, "password_resolution", "wrong password"),),
    )

    class Runner:
        def __init__(self, config):
            pass

        def run_targets(self, paths):
            attempts.extend(paths)
            return _summary(combined) if len(attempts) == 1 else _summary()

    watcher = _watcher(tmp_path, Runner)
    root = tmp_path / "in"
    head = root / "sample.7z.001"
    second = root / "sample.7z.002"
    head.write_bytes(b"part-1")
    second.write_bytes(b"part-2")
    watcher.enqueue(str(head))
    watcher.enqueue(str(second))
    assert watcher.run_once().failed == 1

    watcher.notify_password_source_changed("test")
    assert watcher.run_once().processed == 0
    third = root / "sample.7z.003"
    third.write_bytes(b"part-3")
    watcher.enqueue(str(third))

    assert watcher.run_once().succeeded == 1
    assert len(attempts) == 2


def test_watch_replaces_missing_blocker_with_password_blocker_after_retry(tmp_path):
    attempts: list[str] = []

    class Runner:
        def __init__(self, config):
            pass

        def run_targets(self, paths):
            attempts.extend(paths)
            if len(attempts) == 1:
                return _summary(FailureInfo(FailureKind.MISSING_VOLUME, "extraction", "missing volume"))
            if len(attempts) == 2:
                return _summary(FailureInfo(FailureKind.WRONG_PASSWORD, "password_resolution", "wrong password"))
            return _summary()

    watcher = _watcher(tmp_path, Runner)
    root = tmp_path / "in"
    head = root / "sample.7z.001"
    second = root / "sample.7z.002"
    head.write_bytes(b"part-1")
    second.write_bytes(b"part-2")
    watcher.enqueue(str(head))
    watcher.enqueue(str(second))
    assert watcher.run_once().failed == 1

    third = root / "sample.7z.003"
    third.write_bytes(b"part-3")
    watcher.enqueue(str(third))
    assert watcher.run_once().failed == 1
    watcher.notify_password_source_changed("test")

    assert watcher.run_once().succeeded == 1
    assert len(attempts) == 3


def test_watch_single_archive_combined_failure_waits_for_first_detected_part(tmp_path):
    attempts: list[str] = []
    combined = FailureInfo(
        FailureKind.MISSING_VOLUME,
        "extraction",
        "missing split ZIP volume",
        causes=(FailureInfo(FailureKind.WRONG_PASSWORD, "password_resolution", "wrong password"),),
    )

    class Runner:
        def __init__(self, config):
            pass

        def run_targets(self, paths):
            attempts.extend(paths)
            return _summary(combined) if len(attempts) == 1 else _summary()

    watcher = _watcher(tmp_path, Runner)
    root = tmp_path / "in"
    terminal = root / "sample.zip"
    terminal.write_bytes(b"PK\x05\x06")
    watcher.enqueue(str(terminal))
    assert watcher.run_once().failed == 1

    watcher.notify_password_source_changed("test")
    assert watcher.run_once().processed == 0
    first_part = root / "sample.z01"
    first_part.write_bytes(b"split payload")
    watcher.enqueue(str(first_part))

    assert watcher.run_once().succeeded == 1
    assert attempts == [str(terminal.resolve()), str(first_part.resolve())]


def test_watch_split_suspension_survives_restart(tmp_path):
    attempts: list[str] = []

    class Runner:
        def __init__(self, config):
            pass

        def run_targets(self, paths):
            attempts.extend(paths)
            if len(attempts) == 1:
                return _summary(FailureInfo(FailureKind.MISSING_VOLUME, "extraction", "missing volume"))
            return _summary()

    first_watcher = _watcher(tmp_path, Runner)
    root = tmp_path / "in"
    head = root / "restart.7z.001"
    second = root / "restart.7z.002"
    head.write_bytes(b"part-1")
    second.write_bytes(b"part-2")
    first_watcher.enqueue(str(head))
    first_watcher.enqueue(str(second))
    assert first_watcher.run_once().failed == 1

    restarted = _watcher(tmp_path, Runner)
    restarted.enqueue(str(head), force=True)
    assert restarted.run_once().processed == 0
    third = root / "restart.7z.003"
    third.write_bytes(b"part-3")
    restarted.enqueue(str(third))

    assert restarted.run_once().succeeded == 1
    assert len(attempts) == 2
