from __future__ import annotations

import zipfile
from pathlib import Path
from types import SimpleNamespace

import sunpack.filesystem.watcher.scheduler as scheduler_module
import sunpack.passwords.internal.builtin as builtin_module
import sunpack.passwords.internal.clipboard_monitor as clipboard_monitor_module
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
    assert (watch_root / ".sunpack-passwords.txt").read_text(encoding="utf-8") == ""

    watcher.stop()
    assert FakeObserver.stopped_count == 1


def test_watch_scheduler_observes_builtin_password_file_directory(tmp_path, monkeypatch):
    monkeypatch.setattr(scheduler_module, "Observer", FakeObserver)
    builtin_path = tmp_path / "resources" / "builtin_passwords.txt"
    monkeypatch.setattr(builtin_module, "builtin_password_path", lambda: builtin_path)
    watch_root = tmp_path / "in"
    watch_root.mkdir()
    watcher = WatchScheduler(
        {"watch": {"clipboard_monitor_enabled": False}},
        [str(watch_root)],
        out_dir=str(tmp_path / "out"),
        state_path=str(tmp_path / "state.json"),
        initial_scan=False,
    )

    watcher.start()

    scheduled = {(Path(path), recursive) for _handler, path, recursive in watcher._observer.scheduled}
    assert (watch_root.resolve(), True) in scheduled
    assert (builtin_path.parent.resolve(), False) in scheduled


def test_watch_scheduler_preserves_existing_directory_password_file(tmp_path, monkeypatch):
    monkeypatch.setattr(scheduler_module, "Observer", FakeObserver)
    watch_root = tmp_path / "in"
    watch_root.mkdir()
    password_file = watch_root / ".sunpack-passwords.txt"
    password_file.write_text("existing-secret\n", encoding="utf-8")

    watcher = WatchScheduler(
        {},
        [str(watch_root)],
        out_dir=str(tmp_path / "out"),
        state_path=str(tmp_path / "state.json"),
        initial_scan=True,
    )

    watcher.start()

    assert password_file.read_text(encoding="utf-8") == "existing-secret\n"
    assert watcher.pending_count == 0


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


def test_watch_scheduler_processes_moved_file_after_fast_stable_window(tmp_path, monkeypatch):
    monkeypatch.setattr(scheduler_module, "Observer", FakeObserver)
    now = [2000000000.0]
    monkeypatch.setattr(scheduler_module.time, "time", lambda: now[0])

    class FakePipelineRunner:
        def __init__(self, config):
            self.context = SimpleNamespace(flatten_candidates=set(), recovered_outputs=[])

        def run_targets(self, paths):
            return FakeSummary()

    watch_root = tmp_path / "in"
    watch_root.mkdir()
    archive_path = watch_root / "sample.zip"
    _write_zip(archive_path)

    watcher = WatchScheduler(
        {"watch": {"clipboard_monitor_enabled": False, "fast_stable_seconds": 0.5}},
        [str(watch_root)],
        out_dir=str(tmp_path / "out"),
        state_path=str(tmp_path / ".sunpack_watch" / "state.json"),
        stable_seconds=10,
        initial_scan=False,
        runner_factory=FakePipelineRunner,
    )
    watcher.enqueue(str(archive_path), event_type="moved", src_path=str(tmp_path / "sample.zip"))

    now[0] = 2000000000.4
    assert watcher.run_once().processed == 0
    now[0] = 2000000000.6
    assert watcher.run_once().processed == 1


def test_watch_scheduler_processes_explorer_copy_after_final_mtime_update(tmp_path, monkeypatch):
    monkeypatch.setattr(scheduler_module, "Observer", FakeObserver)
    now = [2000001000.0]
    monkeypatch.setattr(scheduler_module.time, "time", lambda: now[0])

    class FakePipelineRunner:
        def __init__(self, config):
            self.context = SimpleNamespace(flatten_candidates=set(), recovered_outputs=[])

        def run_targets(self, paths):
            return FakeSummary()

    watch_root = tmp_path / "in"
    watch_root.mkdir()
    archive_path = watch_root / "sample.zip"
    archive_path.write_bytes(b"PK\x03\x04" + b"x" * 1024)
    os_time = 2000001000.0
    import os
    os.utime(archive_path, (os_time, os_time))

    watcher = WatchScheduler(
        {"watch": {"clipboard_monitor_enabled": False, "copy_final_stable_seconds": 0.75}},
        [str(watch_root)],
        out_dir=str(tmp_path / "out"),
        state_path=str(tmp_path / ".sunpack_watch" / "state.json"),
        stable_seconds=10,
        initial_scan=False,
        runner_factory=FakePipelineRunner,
    )
    watcher.enqueue(str(archive_path), event_type="created")

    now[0] = 2000001000.1
    archive_path.write_bytes(b"PK\x03\x04" + b"x" * 4096)
    os.utime(archive_path, (2000001000.1, 2000001000.1))
    watcher.enqueue(str(archive_path), event_type="modified")

    now[0] = 2000001000.2
    os.utime(archive_path, (2000000000.0, 2000000000.0))
    watcher.enqueue(str(archive_path), event_type="modified")

    now[0] = 2000001000.8
    assert watcher.run_once().processed == 0
    now[0] = 2000001001.0
    assert watcher.run_once().processed == 1


def test_watch_scheduler_uses_conservative_delay_for_direct_final_name_growth(tmp_path, monkeypatch):
    monkeypatch.setattr(scheduler_module, "Observer", FakeObserver)
    now = [2000002000.0]
    monkeypatch.setattr(scheduler_module.time, "time", lambda: now[0])

    class FakePipelineRunner:
        def __init__(self, config):
            self.context = SimpleNamespace(flatten_candidates=set(), recovered_outputs=[])

        def run_targets(self, paths):
            return FakeSummary()

    watch_root = tmp_path / "in"
    watch_root.mkdir()
    archive_path = watch_root / "slow.zip"
    archive_path.write_bytes(b"PK\x03\x04" + b"x" * 1024)
    import os
    os.utime(archive_path, (2000002000.0, 2000002000.0))

    watcher = WatchScheduler(
        {"watch": {"clipboard_monitor_enabled": False}},
        [str(watch_root)],
        out_dir=str(tmp_path / "out"),
        state_path=str(tmp_path / ".sunpack_watch" / "state.json"),
        stable_seconds=10,
        initial_scan=False,
        runner_factory=FakePipelineRunner,
    )
    watcher.enqueue(str(archive_path), event_type="created")

    now[0] = 2000002000.2
    archive_path.write_bytes(b"PK\x03\x04" + b"x" * 4096)
    os.utime(archive_path, (2000002000.2, 2000002000.2))
    watcher.enqueue(str(archive_path), event_type="modified")

    now[0] = 2000002002.0
    assert watcher.run_once().processed == 0
    now[0] = 2000002010.3
    assert watcher.run_once().processed == 1


def test_watch_scheduler_does_not_log_duplicate_pending_candidate(tmp_path, monkeypatch):
    monkeypatch.setattr(scheduler_module, "Observer", FakeObserver)

    watch_root = tmp_path / "in"
    watch_root.mkdir()
    archive_path = watch_root / "sample.zip"
    _write_zip(archive_path)

    watcher = WatchScheduler(
        {"watch": {"clipboard_monitor_enabled": False}},
        [str(watch_root)],
        out_dir=str(tmp_path / "out"),
        state_path=str(tmp_path / ".sunpack_watch" / "state.json"),
        stable_seconds=0,
        initial_scan=False,
    )
    watcher.enqueue(str(archive_path))
    watcher.enqueue(str(archive_path))

    assert watcher.pending_count == 1
    log_text = (tmp_path / ".sunpack_watch" / "events.jsonl").read_text(encoding="utf-8")
    assert log_text.count('"event":"candidate_queued"') == 1


def test_watch_scheduler_logs_no_tasks_found_without_done_for_empty_summary(tmp_path, monkeypatch):
    monkeypatch.setattr(scheduler_module, "Observer", FakeObserver)

    class NoTasksRunner:
        def __init__(self, config):
            self.context = SimpleNamespace(flatten_candidates=set(), recovered_outputs=[])

        def run_targets(self, paths):
            return SimpleNamespace(success_count=0, failed_tasks=[], processed_keys=[], recovered_outputs=[], failures=[])

    watch_root = tmp_path / "in"
    watch_root.mkdir()
    target = watch_root / "paper.pdf"
    target.write_bytes(b"%PDF-" + b"x" * 1024)

    watcher = WatchScheduler(
        {"watch": {"clipboard_monitor_enabled": False, "output_suppression_seconds": 0}},
        [str(watch_root)],
        out_dir=str(tmp_path / "out"),
        state_path=str(tmp_path / ".sunpack_watch" / "state.json"),
        stable_seconds=0,
        initial_scan=False,
        runner_factory=NoTasksRunner,
    )
    watcher.enqueue(str(target))

    result = watcher.run_once()
    watcher.enqueue(str(target))

    assert result.processed == 1
    assert result.succeeded == 0
    assert watcher.pending_count == 0
    entry = next(iter(watcher.state.entries.values()))
    assert entry.status == "ignored_no_tasks"
    log_text = (tmp_path / ".sunpack_watch" / "events.jsonl").read_text(encoding="utf-8")
    assert '"event":"no_tasks_found"' in log_text
    assert '"event":"done"' not in log_text


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


def test_watch_scheduler_processes_archive_when_output_root_matches_watch_root(tmp_path, monkeypatch):
    monkeypatch.setattr(scheduler_module, "Observer", FakeObserver)
    captured = {}

    class FakePipelineRunner:
        def __init__(self, config):
            captured["config"] = config
            self.context = SimpleNamespace(flatten_candidates={str(tmp_path / "sample")}, recovered_outputs=[])

        def run_targets(self, paths):
            captured["paths"] = paths
            return FakeSummary()

    archive_path = tmp_path / "sample.zip"
    _write_zip(archive_path)

    watcher = WatchScheduler(
        {"watch": {"clipboard_monitor_enabled": False}},
        [str(tmp_path)],
        out_dir=str(tmp_path),
        state_path=str(tmp_path / ".sunpack_watch" / "state.json"),
        stable_seconds=0,
        initial_scan=False,
        runner_factory=FakePipelineRunner,
    )
    watcher.enqueue(str(archive_path))

    result = watcher.run_once()

    assert result.processed == 1
    assert result.succeeded == 1
    assert captured["paths"] == [str(archive_path.resolve())]
    entry = next(iter(watcher.state.entries.values()))
    assert entry.output_dir == str((tmp_path / "sample").resolve())
    assert entry.generated_output_dirs == [str((tmp_path / "sample").resolve())]


def test_watch_scheduler_suppresses_recursive_output_events_during_same_root_extract(tmp_path, monkeypatch):
    monkeypatch.setattr(scheduler_module, "Observer", FakeObserver)
    watcher = None

    class FakePipelineRunner:
        def __init__(self, config):
            self.context = SimpleNamespace(flatten_candidates={str(tmp_path / "outer")}, recovered_outputs=[])

        def run_targets(self, paths):
            output_dir = tmp_path / "outer"
            output_dir.mkdir()
            nested = output_dir / "inner.zip"
            _write_zip(nested)
            watcher.enqueue(str(nested))
            return FakeSummary()

    archive_path = tmp_path / "outer.zip"
    _write_zip(archive_path)

    watcher = WatchScheduler(
        {"watch": {"clipboard_monitor_enabled": False}},
        [str(tmp_path)],
        out_dir=str(tmp_path),
        state_path=str(tmp_path / ".sunpack_watch" / "state.json"),
        stable_seconds=0,
        initial_scan=False,
        runner_factory=FakePipelineRunner,
    )
    watcher.enqueue(str(archive_path))

    result = watcher.run_once()

    assert result.processed == 1
    assert watcher.pending_count == 0


def test_watch_scheduler_initial_scan_skips_known_outputs_when_output_root_matches_watch_root(tmp_path, monkeypatch):
    monkeypatch.setattr(scheduler_module, "Observer", FakeObserver)

    old_archive = tmp_path / "old.zip"
    output_dir = tmp_path / "old"
    output_dir.mkdir()
    nested = output_dir / "nested.zip"
    fresh = tmp_path / "fresh.zip"
    _write_zip(old_archive)
    _write_zip(nested)
    _write_zip(fresh)

    state_path = tmp_path / ".sunpack_watch" / "state.json"
    first = WatchScheduler(
        {"watch": {"clipboard_monitor_enabled": False}},
        [str(tmp_path)],
        out_dir=str(tmp_path),
        state_path=str(state_path),
        stable_seconds=0,
        initial_scan=False,
    )
    stat = old_archive.stat()
    first.state.mark(
        str(old_archive),
        old_archive.stat().st_size,
        stat.st_mtime,
        status="done",
        output_dir=str(output_dir),
        generated_output_dirs=[str(output_dir)],
    )

    watcher = WatchScheduler(
        {"watch": {"clipboard_monitor_enabled": False}},
        [str(tmp_path)],
        out_dir=str(tmp_path),
        state_path=str(state_path),
        stable_seconds=0,
        initial_scan=True,
    )
    watcher.start()

    pending_names = {Path(path).name for path in watcher._pending}
    assert pending_names == {"fresh.zip"}

    watcher.stop()


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


def test_watch_scheduler_defaults_to_user_and_builtin_password_sources(tmp_path, monkeypatch):
    monkeypatch.setattr(scheduler_module, "Observer", FakeObserver)
    monkeypatch.setattr(scheduler_module, "get_builtin_passwords", lambda: ["builtin-secret"])
    captured = []

    class CapturingRunner:
        recent_passwords = []

        def __init__(self, config):
            captured.append(config)

        def run_targets(self, paths):
            return SimpleNamespace(success_count=1, failed_tasks=[], failures=[])

    watch_root = tmp_path / "in"
    watch_root.mkdir()
    archive_path = watch_root / "sample.zip"
    archive_path.write_bytes(b"PK\x03\x04payload")
    state_path = tmp_path / "state.json"
    watcher = WatchScheduler(
        {"user_passwords": ["user-secret"], "watch": {"clipboard_monitor_enabled": False}},
        [str(watch_root)],
        out_dir=str(tmp_path / "out"),
        state_path=str(state_path),
        stable_seconds=0,
        initial_scan=False,
        runner_factory=CapturingRunner,
    )

    watcher.enqueue(str(archive_path))
    watcher.run_once()

    assert captured[0]["user_passwords"] == ["user-secret"]
    assert captured[0]["builtin_passwords"] == ["builtin-secret"]
    state_text = state_path.read_text(encoding="utf-8")
    assert "user-secret" not in state_text
    assert "builtin-secret" not in state_text


def test_watch_scheduler_clipboard_persistence_refreshes_candidates_and_retries(tmp_path, monkeypatch):
    monkeypatch.setattr(scheduler_module, "Observer", FakeObserver)
    builtin_path = tmp_path / "builtin_passwords.txt"
    monkeypatch.setattr(builtin_module, "builtin_password_path", lambda: builtin_path)
    monkeypatch.setattr(clipboard_monitor_module, "read_clipboard_passwords", lambda: ["clipboard-secret"])
    attempts = []

    class ConfigAwareRunner:
        recent_passwords = []

        def __init__(self, config):
            self.config = config

        def run_targets(self, paths):
            candidates = list(self.config.get("builtin_passwords") or [])
            attempts.append(candidates)
            if "clipboard-secret" in candidates:
                return SimpleNamespace(success_count=1, failed_tasks=[], failures=[])
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
        {"watch": {"clipboard_monitor_enabled": True, "password_retry_debounce_seconds": 0}},
        [str(watch_root)],
        out_dir=str(tmp_path / "out"),
        state_path=str(tmp_path / "state.json"),
        stable_seconds=0,
        initial_scan=False,
        runner_factory=ConfigAwareRunner,
    )
    watcher.enqueue(str(archive_path))
    first = watcher.run_once()

    watcher._clipboard_monitor._handle_clipboard_update()
    generation = watcher.state.password_generation
    scheduler_module._WatchEventHandler(watcher)._handle_path(str(builtin_path), event_type="modified")
    second = watcher.run_once()

    assert first.failed == 1
    assert second.succeeded == 1
    assert "clipboard-secret" not in attempts[0]
    assert "clipboard-secret" in attempts[1]
    assert "clipboard-secret" in builtin_path.read_text(encoding="utf-8")
    assert watcher.state.password_generation == generation


def test_watch_scheduler_retries_on_builtin_password_file_watchdog_event(tmp_path, monkeypatch):
    monkeypatch.setattr(scheduler_module, "Observer", FakeObserver)
    builtin_path = tmp_path / "resources" / "builtin_passwords.txt"
    builtin_path.parent.mkdir()
    builtin_path.write_text("wrong\n", encoding="utf-8")
    monkeypatch.setattr(builtin_module, "builtin_password_path", lambda: builtin_path)
    builtin_passwords = ["wrong"]
    monkeypatch.setattr(scheduler_module, "get_builtin_passwords", lambda: list(builtin_passwords))
    attempts = []

    class ConfigAwareRunner:
        recent_passwords = []

        def __init__(self, config):
            self.config = config

        def run_targets(self, paths):
            attempts.append(list(self.config.get("builtin_passwords") or []))
            if "new-secret" in self.config.get("builtin_passwords", []):
                return SimpleNamespace(success_count=1, failed_tasks=[], failures=[])
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
        {"watch": {"clipboard_monitor_enabled": False, "password_retry_debounce_seconds": 0}},
        [str(watch_root)],
        out_dir=str(tmp_path / "out"),
        state_path=str(tmp_path / "state.json"),
        stable_seconds=0,
        initial_scan=False,
        runner_factory=ConfigAwareRunner,
    )
    watcher.enqueue(str(archive_path))
    watcher.run_once()

    builtin_passwords.append("new-secret")
    assert watcher.run_once().processed == 0
    handler = scheduler_module._WatchEventHandler(watcher)
    handler.on_moved(
        SimpleNamespace(
            src_path=str(builtin_path.with_name(".builtin_passwords.txt.tmp")),
            dest_path=str(builtin_path),
            is_directory=False,
        )
    )
    result = watcher.run_once()

    assert result.succeeded == 1
    assert attempts == [["wrong"], ["wrong", "new-secret"]]


def test_watch_scheduler_retries_persisted_password_failure_when_config_passwords_change(tmp_path, monkeypatch):
    monkeypatch.setattr(scheduler_module, "Observer", FakeObserver)
    monkeypatch.setattr(scheduler_module, "get_builtin_passwords", lambda: [])
    attempts = []

    class ConfigAwareRunner:
        recent_passwords = []

        def __init__(self, config):
            self.config = config

        def run_targets(self, paths):
            attempts.append(list(self.config.get("user_passwords") or []))
            if "new-secret" in self.config.get("user_passwords", []):
                return SimpleNamespace(success_count=1, failed_tasks=[], failures=[])
            return SimpleNamespace(
                success_count=0,
                failed_tasks=["wrong password"],
                failures=[FailureInfo(FailureKind.WRONG_PASSWORD, "password_resolution", "wrong password")],
            )

    watch_root = tmp_path / "in"
    watch_root.mkdir()
    archive_path = watch_root / "sample.zip"
    archive_path.write_bytes(b"PK\x03\x04payload")
    state_path = tmp_path / "state.json"
    first_watcher = WatchScheduler(
        {"user_passwords": ["wrong"], "watch": {"clipboard_monitor_enabled": False, "password_retry_debounce_seconds": 0}},
        [str(watch_root)],
        out_dir=str(tmp_path / "out"),
        state_path=str(state_path),
        stable_seconds=0,
        initial_scan=False,
        runner_factory=ConfigAwareRunner,
    )
    first_watcher.enqueue(str(archive_path))
    first_watcher.run_once()

    second_watcher = WatchScheduler(
        {"user_passwords": ["new-secret"], "watch": {"clipboard_monitor_enabled": False, "password_retry_debounce_seconds": 0}},
        [str(watch_root)],
        out_dir=str(tmp_path / "out"),
        state_path=str(state_path),
        stable_seconds=0,
        initial_scan=False,
        runner_factory=ConfigAwareRunner,
    )
    result = second_watcher.run_once()

    assert result.succeeded == 1
    assert attempts == [["wrong"], ["new-secret"]]


def test_watch_scheduler_promotes_recent_success_password_and_retries_other_failures(tmp_path, monkeypatch):
    monkeypatch.setattr(scheduler_module, "Observer", FakeObserver)
    monkeypatch.setattr(scheduler_module, "get_builtin_passwords", lambda: [])
    attempts = []

    class LearningRunner:
        def __init__(self, config):
            self.config = config
            self.recent_passwords = []

        def run_targets(self, paths):
            archive_name = Path(paths[0]).name
            candidates = list(self.config.get("user_passwords") or [])
            attempts.append((archive_name, candidates))
            if archive_name == "teacher.zip":
                self.recent_passwords = ["learned-secret"]
                return SimpleNamespace(success_count=1, failed_tasks=[], failures=[])
            if "learned-secret" in candidates:
                return SimpleNamespace(success_count=1, failed_tasks=[], failures=[])
            return SimpleNamespace(
                success_count=0,
                failed_tasks=["wrong password"],
                failures=[FailureInfo(FailureKind.WRONG_PASSWORD, "password_resolution", "wrong password")],
            )

    watch_root = tmp_path / "in"
    watch_root.mkdir()
    failed_archive = watch_root / "failed.zip"
    teacher_archive = watch_root / "teacher.zip"
    failed_archive.write_bytes(b"PK\x03\x04failed")
    teacher_archive.write_bytes(b"PK\x03\x04teacher")
    watcher = WatchScheduler(
        {"watch": {"clipboard_monitor_enabled": False, "password_retry_debounce_seconds": 0}},
        [str(watch_root)],
        out_dir=str(tmp_path / "out"),
        state_path=str(tmp_path / "state.json"),
        stable_seconds=0,
        initial_scan=False,
        runner_factory=LearningRunner,
    )
    watcher.enqueue(str(failed_archive))
    watcher.run_once()
    watcher.enqueue(str(teacher_archive))
    learned = watcher.run_once()
    retried = watcher.run_once()

    assert learned.succeeded == 1
    assert retried.succeeded == 1
    assert attempts == [
        ("failed.zip", []),
        ("teacher.zip", []),
        ("failed.zip", ["learned-secret"]),
    ]


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
    password_table = watch_root / ".sunpack-passwords.txt"
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
    assert not any(path.endswith(".sunpack-passwords.txt") for path in watcher._pending)


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
