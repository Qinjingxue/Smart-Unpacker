from __future__ import annotations

import zipfile
from pathlib import Path
from types import SimpleNamespace

import sunpack.filesystem.watcher.scheduler as scheduler_module
from sunpack.contracts.failures import FailureInfo, FailureKind
from sunpack.filesystem.watcher.scheduler import WatchScheduler


class FakeObserver:
    started_count = 0
    stopped_count = 0
    join_timeouts = []

    def __init__(self):
        self.scheduled = []
        self.started = False
        self.stopped = False

    def schedule(self, handler, path, recursive=True):
        self.scheduled.append((handler, path, recursive))

    def start(self):
        self.started = True
        type(self).started_count += 1

    def stop(self):
        self.stopped = True
        type(self).stopped_count += 1

    def join(self, timeout=None):
        type(self).join_timeouts.append(timeout)
        return None


class FakeSummary:
    success_count = 1
    failed_tasks = []
    failures = []


def _write_zip(path: Path):
    with zipfile.ZipFile(path, "w") as archive:
        archive.writestr("inside.txt", "ok")


def test_watch_scheduler_uses_watchdog_observer_and_initial_scan(tmp_path, monkeypatch):
    FakeObserver.started_count = 0
    FakeObserver.stopped_count = 0
    FakeObserver.join_timeouts = []
    monkeypatch.setattr(scheduler_module, "Observer", FakeObserver)

    watch_root = tmp_path / "in"
    watch_root.mkdir()
    _write_zip(watch_root / "sample.zip")
    state_path = tmp_path / "state.json"

    watcher = WatchScheduler(
        {},
        [str(watch_root)],
        out_dir=str(tmp_path / "out"),
        state_path=str(state_path),
        stable_seconds=0,
        initial_scan=True,
    )

    watcher.start()

    assert watcher.pending_count == 1
    assert FakeObserver.started_count == 1

    watcher.stop()
    assert FakeObserver.stopped_count == 1


def test_watch_scheduler_uses_directory_scan_mode_for_non_recursive_watch(tmp_path, monkeypatch):
    FakeObserver.started_count = 0
    monkeypatch.setattr(scheduler_module, "Observer", FakeObserver)

    watch_root = tmp_path / "in"
    nested = watch_root / "nested"
    nested.mkdir(parents=True)
    _write_zip(watch_root / "root.zip")
    _write_zip(nested / "nested.zip")

    watcher = WatchScheduler(
        {"filesystem": {"directory_scan_mode": "-", "scan_filters": []}},
        [str(watch_root)],
        out_dir=str(tmp_path / "out"),
        state_path=str(tmp_path / "state.json"),
        stable_seconds=0,
        initial_scan=True,
    )

    watcher.start()

    assert watcher._observer.scheduled[0][1:] == (str(watch_root.resolve()), False)
    pending_names = {Path(path).name for path in watcher._pending}
    assert pending_names == {"root.zip"}


def test_watch_scheduler_uses_directory_scan_mode_for_recursive_watch(tmp_path, monkeypatch):
    monkeypatch.setattr(scheduler_module, "Observer", FakeObserver)

    watch_root = tmp_path / "in"
    nested = watch_root / "nested"
    nested.mkdir(parents=True)
    _write_zip(watch_root / "root.zip")
    _write_zip(nested / "nested.zip")

    watcher = WatchScheduler(
        {"filesystem": {"directory_scan_mode": "*", "scan_filters": []}},
        [str(watch_root)],
        out_dir=str(tmp_path / "out"),
        state_path=str(tmp_path / "state.json"),
        stable_seconds=0,
        initial_scan=True,
    )

    watcher.start()

    assert watcher._observer.scheduled[0][1:] == (str(watch_root.resolve()), True)
    pending_names = {Path(path).name for path in watcher._pending}
    assert pending_names == {"root.zip", "nested.zip"}


def test_watch_scheduler_uses_stop_timeout_without_suffix_prefilter(tmp_path, monkeypatch):
    FakeObserver.started_count = 0
    FakeObserver.stopped_count = 0
    FakeObserver.join_timeouts = []
    monkeypatch.setattr(scheduler_module, "Observer", FakeObserver)

    watch_root = tmp_path / "in"
    watch_root.mkdir()
    (watch_root / "sample.rar").write_bytes(b"Rar!\x1a\x07\x00payload")
    _write_zip(watch_root / "sample.zip")

    watcher = WatchScheduler(
        {},
        [str(watch_root)],
        out_dir=str(tmp_path / "out"),
        state_path=str(tmp_path / "state.json"),
        stable_seconds=0,
        initial_scan=False,
        observer_stop_timeout_seconds=1.25,
    )

    watcher.start()
    watcher.enqueue(str(watch_root / "sample.rar"))
    watcher.enqueue(str(watch_root / "sample.zip"))

    pending_paths = set(watcher._pending)
    assert any(path.endswith("sample.rar") for path in pending_paths)
    assert any(path.endswith("sample.zip") for path in pending_paths)

    watcher.stop()
    assert FakeObserver.join_timeouts == [1.25]


def test_watch_scheduler_uses_filesystem_filters_for_candidates(tmp_path, monkeypatch):
    FakeObserver.started_count = 0
    FakeObserver.stopped_count = 0
    FakeObserver.join_timeouts = []
    monkeypatch.setattr(scheduler_module, "Observer", FakeObserver)

    watch_root = tmp_path / "in"
    watch_root.mkdir()
    keep = watch_root / "keep.weird"
    blocked = watch_root / "blocked.zip"
    keep.write_bytes(b"PK\x03\x04payload")
    blocked.write_bytes(b"PK\x03\x04payload")

    watcher = WatchScheduler(
        {
            "filesystem": {
                "scan_filters": [
                    {"name": "blacklist", "enabled": True, "blocked_files": ["blocked.zip"]},
                    {"name": "size_range", "enabled": True, "range": "r >= 1 B"},
                ],
            }
        },
        [str(watch_root)],
        out_dir=str(tmp_path / "out"),
        state_path=str(tmp_path / "state.json"),
        stable_seconds=0,
        initial_scan=False,
    )

    watcher.enqueue(str(keep))
    watcher.enqueue(str(blocked))

    pending_paths = set(watcher._pending)
    assert any(path.endswith("keep.weird") for path in pending_paths)
    assert not any(path.endswith("blocked.zip") for path in pending_paths)


def test_watch_scheduler_rechecks_filesystem_filters_before_processing(tmp_path, monkeypatch):
    monkeypatch.setattr(scheduler_module, "Observer", FakeObserver)

    watch_root = tmp_path / "in"
    watch_root.mkdir()
    archive = watch_root / "sample.zip"
    archive.write_bytes(b"PK\x03\x04payload")

    watcher = WatchScheduler(
        {"filesystem": {"scan_filters": []}},
        [str(watch_root)],
        out_dir=str(tmp_path / "out"),
        state_path=str(tmp_path / "state.json"),
        stable_seconds=0,
        initial_scan=False,
    )
    watcher.enqueue(str(archive))
    assert watcher.pending_count == 1

    watcher.filters = scheduler_module.build_filters({
        "filesystem": {
            "scan_filters": [
                {"name": "blacklist", "enabled": True, "blocked_files": ["sample.zip"]},
            ],
        }
    })

    result = watcher.run_once()

    assert result.processed == 0
    assert watcher.pending_count == 0


def test_watch_scheduler_processes_stable_candidate_with_watch_root_common_root(tmp_path, monkeypatch):
    monkeypatch.setattr(scheduler_module, "Observer", FakeObserver)
    captured = {}

    class FakePipelineRunner:
        def __init__(self, config):
            captured["config"] = config

        def run_targets(self, paths):
            captured["paths"] = paths
            return FakeSummary()

    watch_root = tmp_path / "in"
    nested = watch_root / "nested"
    nested.mkdir(parents=True)
    archive_path = nested / "sample.zip"
    _write_zip(archive_path)

    watcher = WatchScheduler(
        {},
        [str(watch_root)],
        out_dir=str(tmp_path / "out"),
        state_path=str(tmp_path / "state.json"),
        stable_seconds=0,
        initial_scan=False,
        runner_factory=FakePipelineRunner,
    )
    watcher.enqueue(str(archive_path))

    result = watcher.run_once()

    assert result.processed == 1
    assert result.succeeded == 1
    assert captured["paths"] == [str(archive_path.resolve())]
    assert captured["config"]["output"]["root"] == str((tmp_path / "out").resolve())
    assert captured["config"]["output"]["common_root"] == str(watch_root.resolve())


def test_watch_scheduler_sends_stable_nonstandard_extension_to_main_pipeline(tmp_path, monkeypatch):
    monkeypatch.setattr(scheduler_module, "Observer", FakeObserver)
    captured = {}

    class FakePipelineRunner:
        def __init__(self, config):
            captured["config"] = config

        def run_targets(self, paths):
            captured["paths"] = paths
            return FakeSummary()

    watch_root = tmp_path / "in"
    watch_root.mkdir()
    target = watch_root / "payload.weird"
    target.write_bytes(b"PK\x03\x04payload")

    watcher = WatchScheduler(
        {"filesystem": {"scan_filters": []}},
        [str(watch_root)],
        out_dir=str(tmp_path / "out"),
        state_path=str(tmp_path / "state.json"),
        stable_seconds=0,
        initial_scan=False,
        runner_factory=FakePipelineRunner,
    )
    watcher.enqueue(str(target))

    result = watcher.run_once()

    assert result.processed == 1
    assert result.succeeded == 1
    assert captured["paths"] == [str(target.resolve())]


def test_watch_scheduler_ignores_output_root_events(tmp_path, monkeypatch):
    monkeypatch.setattr(scheduler_module, "Observer", FakeObserver)

    watch_root = tmp_path
    out_root = tmp_path / "out"
    out_root.mkdir()
    archive_path = out_root / "sample.zip"
    _write_zip(archive_path)

    watcher = WatchScheduler(
        {},
        [str(watch_root)],
        out_dir=str(out_root),
        state_path=str(tmp_path / "state.json"),
        stable_seconds=0,
        initial_scan=False,
    )
    watcher.enqueue(str(archive_path))

    assert watcher.pending_count == 0


def test_watch_scheduler_marks_terminal_failure_and_skips_retry(tmp_path, monkeypatch):
    monkeypatch.setattr(scheduler_module, "Observer", FakeObserver)

    class FailingRunner:
        def __init__(self, config):
            pass

        def run_targets(self, paths):
            return SimpleNamespace(
                success_count=0,
                failed_tasks=["damaged"],
                failures=[FailureInfo(FailureKind.DAMAGED, "extraction", "damaged")],
            )

    watch_root = tmp_path / "in"
    watch_root.mkdir()
    archive_path = watch_root / "sample.zip"
    archive_path.write_bytes(b"PK\x03\x04payload")

    watcher = WatchScheduler(
        {"watch": {"clipboard_monitor_enabled": False}},
        [str(watch_root)],
        out_dir=str(tmp_path / "out"),
        state_path=str(tmp_path / "state.json"),
        stable_seconds=0,
        initial_scan=False,
        runner_factory=FailingRunner,
    )
    watcher.enqueue(str(archive_path))

    result = watcher.run_once()
    watcher.enqueue(str(archive_path))

    assert result.failed == 1
    assert watcher.pending_count == 0
    entry = next(iter(watcher.state.entries.values()))
    assert entry.status == "failed_terminal"
    assert entry.failure_kind == "damaged"


def test_watch_scheduler_retries_password_failure_after_password_source_change(tmp_path, monkeypatch):
    monkeypatch.setattr(scheduler_module, "Observer", FakeObserver)
    attempts = {"count": 0}

    class PasswordThenSuccessRunner:
        def __init__(self, config):
            pass

        def run_targets(self, paths):
            attempts["count"] += 1
            if attempts["count"] == 1:
                return SimpleNamespace(
                    success_count=0,
                    failed_tasks=["wrong password"],
                    failures=[FailureInfo(FailureKind.WRONG_PASSWORD, "password_resolution", "wrong password")],
                )
            return SimpleNamespace(success_count=1, failed_tasks=[], failures=[])

    watch_root = tmp_path / "in"
    watch_root.mkdir()
    archive_path = watch_root / "sample.zip"
    archive_path.write_bytes(b"PK\x03\x04payload")

    watcher = WatchScheduler(
        {
            "watch": {
                "clipboard_monitor_enabled": False,
                "password_retry_debounce_seconds": 0,
            }
        },
        [str(watch_root)],
        out_dir=str(tmp_path / "out"),
        state_path=str(tmp_path / "state.json"),
        stable_seconds=0,
        initial_scan=False,
        runner_factory=PasswordThenSuccessRunner,
    )
    watcher.enqueue(str(archive_path))
    first = watcher.run_once()
    watcher.enqueue(str(archive_path))
    assert watcher.pending_count == 0

    watcher.notify_password_source_changed("test")
    second = watcher.run_once()

    assert first.failed == 1
    assert second.succeeded == 1
    assert attempts["count"] == 2
    entry = next(iter(watcher.state.entries.values()))
    assert entry.status == "done"


def test_watch_scheduler_password_table_event_retries_password_failure(tmp_path, monkeypatch):
    monkeypatch.setattr(scheduler_module, "Observer", FakeObserver)
    attempts = {"count": 0}

    class PasswordThenSuccessRunner:
        def __init__(self, config):
            pass

        def run_targets(self, paths):
            attempts["count"] += 1
            if attempts["count"] == 1:
                return SimpleNamespace(
                    success_count=0,
                    failed_tasks=["password required"],
                    failures=[FailureInfo(FailureKind.PASSWORD_REQUIRED, "password_resolution", "password required")],
                )
            return SimpleNamespace(success_count=1, failed_tasks=[], failures=[])

    watch_root = tmp_path / "in"
    watch_root.mkdir()
    archive_path = watch_root / "sample.zip"
    password_table = watch_root / "passwords.txt"
    archive_path.write_bytes(b"PK\x03\x04payload")
    password_table.write_text("secret\n", encoding="utf-8")

    watcher = WatchScheduler(
        {
            "watch": {
                "clipboard_monitor_enabled": False,
                "password_retry_debounce_seconds": 0,
            }
        },
        [str(watch_root)],
        out_dir=str(tmp_path / "out"),
        state_path=str(tmp_path / "state.json"),
        stable_seconds=0,
        initial_scan=False,
        runner_factory=PasswordThenSuccessRunner,
    )
    watcher.enqueue(str(archive_path))
    watcher.run_once()

    handler = scheduler_module._WatchEventHandler(watcher)
    handler._handle_path(str(password_table))
    result = watcher.run_once()

    assert result.succeeded == 1
    assert attempts["count"] == 2
    assert not any(path.endswith("passwords.txt") for path in watcher._pending)


def test_watch_scheduler_writes_jsonl_log_for_failures(tmp_path, monkeypatch):
    monkeypatch.setattr(scheduler_module, "Observer", FakeObserver)

    class FailingRunner:
        def __init__(self, config):
            pass

        def run_targets(self, paths):
            return SimpleNamespace(
                success_count=0,
                failed_tasks=["wrong password"],
                failures=[FailureInfo(FailureKind.WRONG_PASSWORD, "password_resolution", "wrong password")],
            )

    watch_root = tmp_path / "in"
    watch_root.mkdir()
    archive_path = watch_root / "sample.zip"
    archive_path.write_bytes(b"PK\x03\x04payload")

    watcher = WatchScheduler(
        {"watch": {"clipboard_monitor_enabled": False}},
        [str(watch_root)],
        out_dir=str(tmp_path / "out"),
        state_path=str(tmp_path / ".sunpack_watch" / "state.json"),
        stable_seconds=0,
        initial_scan=False,
        runner_factory=FailingRunner,
    )
    watcher.enqueue(str(archive_path))
    watcher.run_once()

    log_path = tmp_path / ".sunpack_watch" / "events.jsonl"
    text = log_path.read_text(encoding="utf-8")
    assert '"event":"failed_password"' in text
    assert "wrong password" in text


def test_watch_scheduler_silently_ignores_metadata_events(tmp_path, monkeypatch):
    monkeypatch.setattr(scheduler_module, "Observer", FakeObserver)

    watch_root = tmp_path
    metadata_dir = tmp_path / ".sunpack_watch"
    metadata_dir.mkdir()
    log_path = metadata_dir / "events.jsonl"
    log_path.write_text("", encoding="utf-8")

    watcher = WatchScheduler(
        {},
        [str(watch_root)],
        out_dir=str(tmp_path / "out"),
        state_path=str(metadata_dir / "state.json"),
        stable_seconds=0,
        initial_scan=False,
    )

    handler = scheduler_module._WatchEventHandler(watcher)
    handler._handle_path(str(log_path))
    watcher.enqueue(str(log_path))

    assert watcher.pending_count == 0
    assert log_path.read_text(encoding="utf-8") == ""
