from __future__ import annotations

import threading
import time
from pathlib import Path
from types import SimpleNamespace

import pytest

from sunpack.filesystem.watcher.toast import WatchToastCoordinator
from sunpack.platform.windows.toast_protocol import (
    ToastActionKind,
    ToastProgressMode,
    ToastSnapshotKind,
)


class _Host:
    def __init__(self):
        self.snapshots = []
        self.clear_count = 0
        self._condition = threading.Condition()

    def publish(self, snapshot):
        with self._condition:
            self.snapshots.append(snapshot)
            self._condition.notify_all()

    def clear(self):
        with self._condition:
            self.clear_count += 1
            self._condition.notify_all()

    def wait_for_terminal_snapshots(self, timeout=1.0):
        with self._condition:
            ready = self._condition.wait_for(
                lambda: any(
                    snapshot.kind != ToastSnapshotKind.PROGRESS
                    for snapshot in self.snapshots
                ),
                timeout=timeout,
            )
            assert ready, "timed out waiting for a terminal toast snapshot"
            return [
                snapshot
                for snapshot in self.snapshots
                if snapshot.kind != ToastSnapshotKind.PROGRESS
            ]


def _config(*, language="en", debounce_ms=20):
    return {
        "cli": {"language": language},
        "watch": {
            "toast_completion_debounce_ms": debounce_ms,
            "toast_success_ttl_seconds": 10,
            "toast_failure_ttl_seconds": 60,
            "toast_report_retention_days": 30,
            "toast_report_max_files": 32,
            "toast_report_max_bytes": 1024 * 1024,
        },
    }


def _task(path):
    return SimpleNamespace(main_path=str(path))


def _ready(coordinator, request_id, task):
    coordinator.progress(
        request_id,
        task,
        {
            "type": "semantic",
            "event": "extract_ready",
            "completed_bytes": 0,
            "total_bytes": 0,
        },
    )


def _terminal_snapshots(host):
    return [snapshot for snapshot in host.snapshots if snapshot.kind != ToastSnapshotKind.PROGRESS]


def test_aggregate_progress_regresses_when_a_new_archive_joins(tmp_path):
    host = _Host()
    coordinator = WatchToastCoordinator(host, _config(), str(tmp_path / "state"))
    first = _task(tmp_path / "first.zip")
    second = _task(tmp_path / "second.zip")
    coordinator.submitted("first", str(first.main_path))
    coordinator.submitted("second", str(second.main_path))

    _ready(coordinator, "first", first)
    coordinator.progress("first", first, {"type": "progress", "completed_bytes": 40, "total_bytes": 100})
    before_join = host.snapshots[-1]
    assert before_join.progress_mode == ToastProgressMode.DETERMINATE
    assert before_join.progress_value == pytest.approx(0.4)

    _ready(coordinator, "second", second)
    coordinator.progress("second", second, {"type": "progress", "completed_bytes": 0, "total_bytes": 300})
    after_join = host.snapshots[-1]
    assert after_join.progress_value == pytest.approx(0.1)
    assert "2" in after_join.progress_title

    coordinator.progress("second", second, {"type": "progress", "completed_bytes": 150, "total_bytes": 300})
    assert host.snapshots[-1].progress_value == pytest.approx(190 / 400)
    coordinator.stop()


def test_concurrent_requests_emit_one_unified_success_after_debounce(tmp_path):
    host = _Host()
    coordinator = WatchToastCoordinator(host, _config(debounce_ms=30), str(tmp_path / "state"))
    output_root = tmp_path / "out"
    first_output = output_root / "first"
    second_output = output_root / "second"
    first_output.mkdir(parents=True)
    second_output.mkdir()
    first = _task(tmp_path / "first.zip")
    second = _task(tmp_path / "second.zip")
    coordinator.submitted("first", str(first.main_path))
    coordinator.submitted("second", str(second.main_path))
    _ready(coordinator, "first", first)
    _ready(coordinator, "second", second)
    coordinator.progress("first", first, {"type": "progress", "completed_bytes": 100, "total_bytes": 100})
    coordinator.progress("second", second, {"type": "progress", "completed_bytes": 50, "total_bytes": 100})

    coordinator.succeeded("first", [str(first_output)])
    time.sleep(0.04)
    assert _terminal_snapshots(host) == []
    coordinator.succeeded("second", [str(second_output)])
    time.sleep(0.06)

    terminal = _terminal_snapshots(host)
    assert len(terminal) == 1
    assert terminal[0].kind == ToastSnapshotKind.SUCCESS
    assert terminal[0].ttl_ms == 10_000
    assert terminal[0].actions[0].kind == ToastActionKind.OPEN_DIRECTORY
    assert terminal[0].actions[0].target == str(output_root)
    coordinator.stop()


def test_new_ready_request_cancels_pending_finalization(tmp_path):
    host = _Host()
    coordinator = WatchToastCoordinator(host, _config(debounce_ms=60), str(tmp_path / "state"))
    first = _task(tmp_path / "first.zip")
    second = _task(tmp_path / "second.zip")
    coordinator.submitted("first", str(first.main_path))
    _ready(coordinator, "first", first)
    coordinator.succeeded("first", [])

    time.sleep(0.02)
    coordinator.submitted("second", str(second.main_path))
    _ready(coordinator, "second", second)
    time.sleep(0.07)
    assert _terminal_snapshots(host) == []

    coordinator.succeeded("second", [])
    time.sleep(0.08)
    terminal = _terminal_snapshots(host)
    assert len(terminal) == 1
    assert "2" in terminal[0].body
    coordinator.stop()


def test_mixed_batch_exposes_output_and_aggregate_failure_report(tmp_path):
    host = _Host()
    coordinator = WatchToastCoordinator(host, _config(), str(tmp_path / "state"))
    output = tmp_path / "out" / "good"
    output.mkdir(parents=True)
    good = _task(tmp_path / "good.zip")
    broken = _task(tmp_path / "broken.zip")
    coordinator.submitted("good", str(good.main_path))
    coordinator.submitted("broken", str(broken.main_path))
    _ready(coordinator, "good", good)
    _ready(coordinator, "broken", broken)

    coordinator.succeeded("good", [str(output)])
    coordinator.failed("broken", ["CRC mismatch"], [{"kind": "corrupt_archive"}])
    terminal = host.wait_for_terminal_snapshots(timeout=1.0)
    assert len(terminal) == 1
    assert terminal[0].kind == ToastSnapshotKind.MIXED
    assert [action.kind for action in terminal[0].actions] == [
        ToastActionKind.OPEN_DIRECTORY,
        ToastActionKind.OPEN_LOG,
    ]
    assert terminal[0].actions[0].target == str(output)
    assert Path(terminal[0].actions[1].target).is_file()
    coordinator.stop()


def test_password_or_missing_volume_suppression_never_creates_a_final_toast(tmp_path):
    host = _Host()
    coordinator = WatchToastCoordinator(host, _config(), str(tmp_path / "state"))
    coordinator.submitted("password", str(tmp_path / "locked.rar"))
    coordinator.suppressed("password")
    time.sleep(0.04)
    assert host.snapshots == []
    assert host.clear_count == 0

    task = _task(tmp_path / "late-missing.7z")
    coordinator.submitted("missing", str(task.main_path))
    _ready(coordinator, "missing", task)
    coordinator.suppressed("missing")
    time.sleep(0.04)
    assert _terminal_snapshots(host) == []
    assert host.clear_count == 1
    coordinator.stop()


@pytest.mark.parametrize(
    ("reason", "expected"),
    [
        ("password", "内层归档需要密码"),
        ("missing_volume", "内层归档缺少分卷"),
    ],
)
def test_visible_nested_failure_emits_reason_toast_and_report(tmp_path, reason, expected):
    host = _Host()
    coordinator = WatchToastCoordinator(host, _config(language="zh", debounce_ms=0), str(tmp_path / "state"))
    task = _task(tmp_path / "nested-inner.zip")
    coordinator.submitted("nested", str(tmp_path / "outer.zip"))
    _ready(coordinator, "nested", task)
    coordinator.failed(
        "nested",
        [f"嵌套压缩包内层失败：{task.main_path}"],
        [{
            "kind": "wrong_password" if reason == "password" else "missing_volume",
            "message": "nested failure",
            "details": {"scope": "nested_archive", "reason": reason},
        }],
    )
    terminal = host.wait_for_terminal_snapshots()
    assert len(terminal) == 1
    assert expected in terminal[0].body
    report_path = terminal[0].actions[-1].target
    report = Path(report_path).read_text(encoding="utf-8")
    assert expected in report
    assert "nested-inner.zip" in report
    coordinator.stop()


def test_invisible_nested_failure_does_not_create_a_final_toast(tmp_path):
    host = _Host()
    coordinator = WatchToastCoordinator(host, _config(debounce_ms=0), str(tmp_path / "state"))
    coordinator.submitted("nested", str(tmp_path / "outer.zip"))
    coordinator.failed(
        "nested",
        ["nested failure"],
        [{
            "kind": "wrong_password",
            "details": {"scope": "nested_archive", "reason": "password"},
        }],
    )
    time.sleep(0.04)

    assert _terminal_snapshots(host) == []
    coordinator.stop()


def test_nested_toast_reuses_failure_kind_when_reason_detail_is_missing(tmp_path):
    host = _Host()
    coordinator = WatchToastCoordinator(host, _config(language="zh", debounce_ms=0), str(tmp_path / "state"))
    task = _task(tmp_path / "nested-inner.7z.001")
    coordinator.submitted("nested", str(tmp_path / "outer.zip"))
    _ready(coordinator, "nested", task)
    coordinator.failed(
        "nested",
        ["nested failure"],
        [{
            "kind": "missing_volume",
            "message": "missing split volume",
            "details": {"scope": "nested_archive"},
        }],
    )
    time.sleep(0.04)

    terminal = _terminal_snapshots(host)
    assert len(terminal) == 1
    assert "内层归档缺少分卷" in terminal[0].body
    coordinator.stop()


def test_failure_toast_links_to_unique_localized_aggregate_report(tmp_path):
    host = _Host()
    coordinator = WatchToastCoordinator(host, _config(language="zh"), str(tmp_path / "state"))
    task = _task(tmp_path / "broken.zip")
    coordinator.submitted("broken", str(task.main_path))
    _ready(coordinator, "broken", task)
    coordinator.failed(
        "broken",
        ["CRC mismatch"],
        [{"kind": "corrupt_archive", "message": "CRC mismatch"}],
    )
    terminal = host.wait_for_terminal_snapshots(timeout=1.0)
    assert len(terminal) == 1
    assert terminal[0].kind == ToastSnapshotKind.FAILURE
    assert terminal[0].title == "解压失败"
    assert terminal[0].actions[-1].kind == ToastActionKind.OPEN_LOG
    report_path = terminal[0].actions[-1].target
    report = Path(report_path)
    text = report.read_text(encoding="utf-8")
    assert "SunPack watch 失败报告" in text
    assert "broken.zip" in text
    assert "CRC mismatch" in text
    assert report.parent.name == "failures"
    coordinator.stop()
