from __future__ import annotations

import json
import os
import zipfile
from pathlib import Path
from types import SimpleNamespace

import sunpack.filesystem.watcher.scheduler as scheduler_module
import sunpack.passwords.internal.builtin as builtin_module
import sunpack.passwords.internal.clipboard_monitor as clipboard_monitor_module
from sunpack.contracts.failures import FailureInfo, FailureKind
from sunpack.contracts.results import OutcomeKind, TargetRunResult
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


def _watch_summary(path: str, kind: OutcomeKind, verification: dict):
    return SimpleNamespace(
        success_count=1 if kind == OutcomeKind.COMPLETE_SUCCESS else 0,
        partial_success_count=1 if kind == OutcomeKind.PARTIAL_SUCCESS else 0,
        failed_tasks=[],
        failures=[],
        processed_keys=[path],
        target_results=[TargetRunResult(path, kind, verification=verification)],
    )


def test_partial_result_does_not_self_retry_but_modified_epoch_does(tmp_path, monkeypatch):
    monkeypatch.setattr(scheduler_module, "Observer", FakeObserver)
    archive = tmp_path / "sample.zip"
    _write_zip(archive)
    calls = []
    postprocess_maps = []
    outcomes = [OutcomeKind.PARTIAL_SUCCESS, OutcomeKind.COMPLETE_SUCCESS]

    class SequenceRunner:
        recent_passwords = []

        def __init__(self, config):
            self.output_dir = Path(config["output"]["root"]) / "sample"
            self.context = SimpleNamespace(flatten_candidates=set(), recovered_outputs=[])

        def run_targets(self, paths):
            kind = outcomes[len(calls)]
            calls.append(kind)
            self.output_dir.mkdir(parents=True)
            (self.output_dir / "payload.bin").write_bytes(b"payload")
            if kind == OutcomeKind.PARTIAL_SUCCESS:
                self.context.recovered_outputs = [{"out_dir": str(self.output_dir)}]
                verification = {"decision_hint": "accept_partial", "archive_coverage": {"complete_files": 1}}
            else:
                self.context.flatten_candidates = {str(self.output_dir)}
                verification = {"decision_hint": "accept"}
            return _watch_summary(paths[0], kind, verification)

        def apply_deferred_postprocess(self, output_path_map):
            assert all(Path(target).exists() for target in output_path_map.values())
            postprocess_maps.append(dict(output_path_map))

    watcher = WatchScheduler(
        {"watch": {"clipboard_monitor_enabled": False}},
        [str(tmp_path)],
        out_dir=str(tmp_path / "out"),
        state_path=str(tmp_path / "state.json"),
        quiet_seconds=0,
        initial_scan=False,
        runner_factory=SequenceRunner,
    )
    watcher.enqueue(str(archive))
    assert watcher.run_once().processed == 1
    probe_root = tmp_path / ".sunpack_watch_probes"
    assert probe_root.is_dir()
    assert list(probe_root.iterdir()) == []
    assert watcher.run_once().processed == 0
    watcher.enqueue(str(archive), event_type="modified")
    final = watcher.run_once()

    assert final.succeeded == 1
    assert (tmp_path / "out" / "sample" / "payload.bin").is_file()
    assert len(postprocess_maps) == 1
    assert probe_root.is_dir()
    assert list(probe_root.iterdir()) == []


def test_content_event_during_processing_starts_a_new_active_epoch(tmp_path, monkeypatch):
    monkeypatch.setattr(scheduler_module, "Observer", FakeObserver)
    archive = tmp_path / "sample.zip"
    _write_zip(archive)
    attempts = 0
    watcher = None

    class MutatingRunner:
        recent_passwords = []

        def __init__(self, config):
            self.context = SimpleNamespace(flatten_candidates=set(), recovered_outputs=[])

        def run_targets(self, paths):
            nonlocal attempts
            attempts += 1
            if attempts == 1:
                archive.write_bytes(archive.read_bytes() + b"new-data")
                watcher.enqueue(str(archive), event_type="modified")
            return _watch_summary(paths[0], OutcomeKind.PARTIAL_SUCCESS, {"decision_hint": "accept_partial"})

    watcher = WatchScheduler(
        {"watch": {"clipboard_monitor_enabled": False}},
        [str(tmp_path)],
        out_dir=str(tmp_path / "out"),
        state_path=str(tmp_path / "state.json"),
        quiet_seconds=0,
        initial_scan=False,
        runner_factory=MutatingRunner,
    )
    watcher.enqueue(str(archive))

    assert watcher.run_once().processed == 1
    assert watcher.pending_count == 1
    assert len(watcher.state.pending_snapshots()) == 1
    assert watcher.run_once().processed == 1
    assert attempts == 2


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
        quiet_seconds=0,
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


def test_watch_scheduler_start_cleans_probe_contents_but_keeps_probe_root(tmp_path, monkeypatch):
    monkeypatch.setattr(scheduler_module, "Observer", FakeObserver)
    probe_root = tmp_path / ".sunpack_watch_probes"
    stale_workspace = probe_root / "stale-owner" / "work"
    stale_workspace.mkdir(parents=True)
    (stale_workspace / "partial.bin").write_bytes(b"partial")
    watcher = WatchScheduler(
        {"watch": {"clipboard_monitor_enabled": False}},
        [str(tmp_path)],
        out_dir=str(tmp_path / "out"),
        state_path=str(tmp_path / "state.json"),
        initial_scan=False,
    )

    watcher.start()

    assert probe_root.is_dir()
    assert list(probe_root.iterdir()) == []
    watcher.stop()


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
        quiet_seconds=0,
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
        quiet_seconds=0,
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
        quiet_seconds=0,
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
        quiet_seconds=0,
        initial_scan=False,
    )

    watcher.enqueue(str(keep))
    watcher.enqueue(str(blocked))

    pending_paths = set(watcher._pending)
    assert any(path.endswith("keep.weird") for path in pending_paths)
    assert not any(path.endswith("blocked.zip") for path in pending_paths)


def test_watch_scheduler_reuses_filter_result_for_unchanged_pending_candidate(tmp_path, monkeypatch):
    monkeypatch.setattr(scheduler_module, "Observer", FakeObserver)

    watch_root = tmp_path / "in"
    watch_root.mkdir()
    archive = watch_root / "sample.zip"
    archive.write_bytes(b"PK\x03\x04payload")

    watcher = WatchScheduler(
        {
            "filesystem": {
                "scan_filters": [
                    {"name": "size_range", "enabled": True, "range": "r >= 1 B"},
                ],
            },
            "watch": {"clipboard_monitor_enabled": False},
        },
        [str(watch_root)],
        out_dir=str(tmp_path / "out"),
        state_path=str(tmp_path / "state.json"),
        quiet_seconds=30,
        initial_scan=False,
    )
    original_passes = watcher._passes_filesystem_filters
    filter_calls = []

    def counted_passes(candidate):
        filter_calls.append((candidate.size, candidate.mtime))
        return original_passes(candidate)

    monkeypatch.setattr(watcher, "_passes_filesystem_filters", counted_passes)

    watcher.enqueue(str(archive))
    watcher.enqueue(str(archive), event_type="modified")
    watcher.run_once()
    watcher.run_once()

    assert len(filter_calls) == 1
    assert watcher.pending_count == 1
    archive.write_bytes(b"PK\x03\x04payload-more")
    watcher.enqueue(str(archive), event_type="modified")

    assert len(filter_calls) == 1
    assert watcher.pending_count == 1


def test_event_burst_reads_file_identity_once_at_quiet_transition(tmp_path, monkeypatch):
    monkeypatch.setattr(scheduler_module, "Observer", FakeObserver)
    archive = tmp_path / "sample.zip"
    _write_zip(archive)
    identity_calls = 0
    original_identity = scheduler_module._candidate_with_file_identity

    def counted_identity(candidate):
        nonlocal identity_calls
        identity_calls += 1
        return original_identity(candidate)

    monkeypatch.setattr(scheduler_module, "_candidate_with_file_identity", counted_identity)
    watcher = WatchScheduler(
        {"watch": {"clipboard_monitor_enabled": False}},
        [str(tmp_path)],
        out_dir=str(tmp_path / "out"),
        state_path=str(tmp_path / "state.json"),
        quiet_seconds=0,
        initial_scan=False,
        runner_factory=lambda _config: SimpleNamespace(
            context=SimpleNamespace(flatten_candidates=set(), recovered_outputs=[]),
            run_targets=lambda paths: _watch_summary(paths[0], OutcomeKind.PARTIAL_SUCCESS, {}),
            recent_passwords=[],
        ),
    )

    for _ in range(100):
        watcher.enqueue(str(archive), event_type="modified")

    assert identity_calls == 0
    assert watcher.pending_count == 1
    assert watcher.run_once().processed == 1
    assert identity_calls == 1


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
        quiet_seconds=0,
        initial_scan=False,
    )
    original_passes = watcher._passes_filesystem_filters
    filter_calls = []

    def counted_passes(candidate):
        filter_calls.append((candidate.size, candidate.mtime))
        return original_passes(candidate)

    monkeypatch.setattr(watcher, "_passes_filesystem_filters", counted_passes)
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
    assert len(filter_calls) == 2


def test_watch_scheduler_processes_quiet_candidate_with_watch_root_common_root(tmp_path, monkeypatch):
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
        quiet_seconds=0,
        initial_scan=False,
        runner_factory=FakePipelineRunner,
    )
    watcher.enqueue(str(archive_path))

    result = watcher.run_once()

    assert result.processed == 1
    assert result.succeeded == 1
    assert captured["paths"] == [str(archive_path.resolve())]
    assert Path(captured["config"]["output"]["root"]).parent.parent.name == ".sunpack_watch_probes"
    assert Path(captured["config"]["output"]["root"]).is_relative_to(watch_root)
    assert captured["config"]["output"]["common_root"] == str(watch_root.resolve())


def test_watch_scheduler_sends_quiet_nonstandard_extension_to_main_pipeline(tmp_path, monkeypatch):
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
        quiet_seconds=0,
        initial_scan=False,
        runner_factory=FakePipelineRunner,
    )
    watcher.enqueue(str(target))

    result = watcher.run_once()

    assert result.processed == 1
    assert result.succeeded == 1
    assert captured["paths"] == [str(target.resolve())]


def test_watch_scheduler_moved_file_uses_common_quiet_window(tmp_path, monkeypatch):
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
        {"watch": {"clipboard_monitor_enabled": False}},
        [str(watch_root)],
        out_dir=str(tmp_path / "out"),
        state_path=str(tmp_path / ".sunpack_watch" / "state.json"),
        quiet_seconds=10,
        initial_scan=False,
        runner_factory=FakePipelineRunner,
    )
    watcher.enqueue(str(archive_path), event_type="moved", src_path=str(tmp_path / "sample.zip"))

    now[0] = 2000000009.9
    assert watcher.run_once().processed == 0
    now[0] = 2000000010.1
    assert watcher.run_once().processed == 1


def test_watch_scheduler_copy_events_reset_common_quiet_window(tmp_path, monkeypatch):
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
        {"watch": {"clipboard_monitor_enabled": False}},
        [str(watch_root)],
        out_dir=str(tmp_path / "out"),
        state_path=str(tmp_path / ".sunpack_watch" / "state.json"),
        quiet_seconds=10,
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

    now[0] = 2000001010.1
    assert watcher.run_once().processed == 0
    now[0] = 2000001010.3
    assert watcher.run_once().processed == 1


def test_watch_scheduler_growth_resets_the_common_quiet_window(tmp_path, monkeypatch):
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
        quiet_seconds=10,
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
        quiet_seconds=0,
        initial_scan=False,
    )
    watcher.enqueue(str(archive_path))
    watcher.enqueue(str(archive_path))

    assert watcher.pending_count == 1
    log_text = (tmp_path / ".sunpack_watch" / "events.jsonl").read_text(encoding="utf-8")
    assert log_text.count('"event":"candidate_active"') == 1


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
        quiet_seconds=0,
        initial_scan=False,
        runner_factory=NoTasksRunner,
    )
    watcher.enqueue(str(target))

    result = watcher.run_once()
    watcher.enqueue(str(target))
    unchanged = watcher.run_once()

    assert result.processed == 1
    assert result.succeeded == 0
    assert unchanged.processed == 0
    assert watcher.pending_count == 0
    assert not watcher.state.entries
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
        quiet_seconds=0,
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
            self.output_dir = Path(config["output"]["root"]) / "sample"
            self.context = SimpleNamespace(flatten_candidates={str(self.output_dir)}, recovered_outputs=[])

        def run_targets(self, paths):
            captured["paths"] = paths
            self.output_dir.mkdir(parents=True)
            return FakeSummary()

    archive_path = tmp_path / "sample.zip"
    _write_zip(archive_path)

    watcher = WatchScheduler(
        {"watch": {"clipboard_monitor_enabled": False}},
        [str(tmp_path)],
        out_dir=str(tmp_path),
        state_path=str(tmp_path / ".sunpack_watch" / "state.json"),
        quiet_seconds=0,
        initial_scan=False,
        runner_factory=FakePipelineRunner,
    )
    watcher.enqueue(str(archive_path))

    result = watcher.run_once()

    assert result.processed == 1
    assert result.succeeded == 1
    assert captured["paths"] == [str(archive_path.resolve())]
    assert not watcher.state.entries
    assert watcher.state.snapshot_matches(
        str(archive_path),
        archive_path.stat().st_size,
        archive_path.stat().st_mtime,
        f"{archive_path.stat().st_dev}:{archive_path.stat().st_ino}",
    )
    assert str((tmp_path / "sample").resolve()) in watcher.state.generated_output_roots()


def test_watch_scheduler_does_not_reprocess_unchanged_input_when_output_is_deleted(tmp_path, monkeypatch):
    monkeypatch.setattr(scheduler_module, "Observer", FakeObserver)
    archive_path = tmp_path / "sample.zip"
    output_dir = tmp_path / "sample"
    _write_zip(archive_path)
    runs = []

    class FakePipelineRunner:
        def __init__(self, config):
            self.context = SimpleNamespace(flatten_candidates={str(output_dir)}, recovered_outputs=[])

        def run_targets(self, paths):
            runs.append(list(paths))
            output_dir.mkdir(exist_ok=True)
            return FakeSummary()

    watcher = WatchScheduler(
        {"watch": {"clipboard_monitor_enabled": False}},
        [str(tmp_path)],
        out_dir=".",
        state_path=str(tmp_path / ".sunpack_watch" / "state.json"),
        quiet_seconds=0,
        initial_scan=False,
        runner_factory=FakePipelineRunner,
    )

    watcher.enqueue(str(archive_path))
    assert watcher.run_once().succeeded == 1
    assert len(runs) == 1

    watcher.enqueue(str(archive_path))
    assert watcher.run_once().processed == 0

    output_dir.rmdir()
    watcher.enqueue(str(archive_path))

    assert watcher.run_once().processed == 0
    assert len(runs) == 1


def test_watch_scheduler_reprocesses_identical_archive_after_it_moves_out_and_back(tmp_path, monkeypatch):
    monkeypatch.setattr(scheduler_module, "Observer", FakeObserver)
    watch_root = tmp_path / "watched"
    outside_root = tmp_path / "outside"
    watch_root.mkdir()
    outside_root.mkdir()
    archive_path = watch_root / "sample.zip"
    outside_path = outside_root / archive_path.name
    output_dir = watch_root / "sample"
    _write_zip(archive_path)
    runs = []

    class FakePipelineRunner:
        def __init__(self, config):
            self.context = SimpleNamespace(flatten_candidates={str(output_dir)}, recovered_outputs=[])

        def run_targets(self, paths):
            runs.append(list(paths))
            output_dir.mkdir(exist_ok=True)
            return FakeSummary()

    watcher = WatchScheduler(
        {"watch": {"clipboard_monitor_enabled": False}},
        [str(watch_root)],
        out_dir=".",
        state_path=str(tmp_path / ".sunpack_watch" / "state.json"),
        quiet_seconds=0,
        initial_scan=False,
        runner_factory=FakePipelineRunner,
    )
    handler = scheduler_module._WatchEventHandler(watcher)
    watcher.enqueue(str(archive_path))
    assert watcher.run_once().succeeded == 1

    archive_path.replace(outside_path)
    handler.on_moved(SimpleNamespace(src_path=str(archive_path), dest_path=str(outside_path), is_directory=False))
    outside_path.replace(archive_path)
    handler.on_moved(SimpleNamespace(src_path=str(outside_path), dest_path=str(archive_path), is_directory=False))

    assert watcher.pending_count == 1
    assert watcher.run_once().succeeded == 1
    assert len(runs) == 2


def test_watch_scheduler_processes_same_path_again_after_input_changes(tmp_path, monkeypatch):
    monkeypatch.setattr(scheduler_module, "Observer", FakeObserver)
    archive_path = tmp_path / "sample.zip"
    _write_zip(archive_path)
    runs = []

    class FakePipelineRunner:
        def __init__(self, config):
            self.context = SimpleNamespace(flatten_candidates=set(), recovered_outputs=[])

        def run_targets(self, paths):
            runs.append(list(paths))
            return FakeSummary()

    watcher = WatchScheduler(
        {"watch": {"clipboard_monitor_enabled": False}},
        [str(tmp_path)],
        out_dir=".",
        state_path=str(tmp_path / ".sunpack_watch" / "state.json"),
        quiet_seconds=0,
        initial_scan=False,
        runner_factory=FakePipelineRunner,
    )
    watcher.enqueue(str(archive_path))
    assert watcher.run_once().succeeded == 1

    archive_path.write_bytes(archive_path.read_bytes() + b"changed")
    watcher.enqueue(str(archive_path), event_type="modified")

    assert watcher.run_once().succeeded == 1
    assert len(runs) == 2


def test_watch_scheduler_recovers_persisted_pending_input_after_restart(tmp_path, monkeypatch):
    monkeypatch.setattr(scheduler_module, "Observer", FakeObserver)
    archive_path = tmp_path / "sample.zip"
    _write_zip(archive_path)
    state_path = tmp_path / ".sunpack_watch" / "state.json"
    first = WatchScheduler(
        {"watch": {"clipboard_monitor_enabled": False}},
        [str(tmp_path)],
        out_dir=".",
        state_path=str(state_path),
        quiet_seconds=0,
        initial_scan=False,
    )
    stat = archive_path.stat()
    first.state.queue_active(
        SimpleNamespace(path=str(archive_path), size=stat.st_size, mtime=stat.st_mtime),
    )
    runs = []

    class FakePipelineRunner:
        def __init__(self, config):
            self.context = SimpleNamespace(flatten_candidates=set(), recovered_outputs=[])

        def run_targets(self, paths):
            runs.append(list(paths))
            return FakeSummary()

    restarted = WatchScheduler(
        {"watch": {"clipboard_monitor_enabled": False}},
        [str(tmp_path)],
        out_dir=".",
        state_path=str(state_path),
        quiet_seconds=0,
        initial_scan=False,
        runner_factory=FakePipelineRunner,
    )
    restarted.start()

    assert restarted.run_once().succeeded == 1
    assert len(runs) == 1
    assert not restarted.state.pending_snapshots()
    restarted.stop()


def test_relative_output_directory_is_resolved_per_matching_watch_root(tmp_path, monkeypatch):
    monkeypatch.setattr(scheduler_module, "Observer", FakeObserver)
    first_root = tmp_path / "first"
    second_root = tmp_path / "second"
    first_root.mkdir()
    second_root.mkdir()
    archive_path = second_root / "sample.zip"
    _write_zip(archive_path)
    captured = {}

    class FakePipelineRunner:
        def __init__(self, config):
            captured["output"] = config["output"]
            self.output_dir = Path(config["output"]["root"]) / "sample"
            self.context = SimpleNamespace(flatten_candidates={str(self.output_dir)}, recovered_outputs=[])

        def run_targets(self, paths):
            self.output_dir.mkdir(parents=True)
            return FakeSummary()

    watcher = WatchScheduler(
        {"watch": {"clipboard_monitor_enabled": False}},
        [str(first_root), str(second_root)],
        out_dir=".",
        state_path=str(first_root / ".sunpack_watch" / "state.json"),
        quiet_seconds=0,
        initial_scan=False,
        runner_factory=FakePipelineRunner,
    )
    watcher.enqueue(str(archive_path))

    result = watcher.run_once()

    assert result.succeeded == 1
    assert Path(captured["output"]["root"]).is_relative_to(second_root)
    assert ".sunpack_watch_probes" in Path(captured["output"]["root"]).parts
    assert captured["output"]["common_root"] == str(second_root.resolve())


def test_watch_scheduler_suppresses_recursive_output_events_during_same_root_extract(tmp_path, monkeypatch):
    monkeypatch.setattr(scheduler_module, "Observer", FakeObserver)
    watcher = None

    class FakePipelineRunner:
        def __init__(self, config):
            self.output_dir = Path(config["output"]["root"]) / "outer"
            self.context = SimpleNamespace(flatten_candidates={str(self.output_dir)}, recovered_outputs=[])

        def run_targets(self, paths):
            self.output_dir.mkdir(parents=True)
            nested = self.output_dir / "inner.zip"
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
        quiet_seconds=0,
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
        quiet_seconds=0,
        initial_scan=False,
    )
    stat = old_archive.stat()
    first.state.record_attempt(
        str(old_archive),
        old_archive.stat().st_size,
        stat.st_mtime,
        f"{stat.st_dev}:{stat.st_ino}",
    )
    first.state.complete_work([str(old_archive)])
    first.state.remember_output_roots([str(output_dir)])

    watcher = WatchScheduler(
        {"watch": {"clipboard_monitor_enabled": False}},
        [str(tmp_path)],
        out_dir=str(tmp_path),
        state_path=str(state_path),
        quiet_seconds=0,
        initial_scan=True,
    )
    watcher.start()

    ready_names = {Path(candidate.path).name for candidate in watcher._pop_ready(float("inf"))}
    assert ready_names == {"fresh.zip"}

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
        quiet_seconds=0,
        initial_scan=False,
        runner_factory=FailingRunner,
    )
    watcher.enqueue(str(archive_path))

    result = watcher.run_once()
    watcher.enqueue(str(archive_path))
    unchanged = watcher.run_once()

    assert result.failed == 1
    assert unchanged.processed == 0
    assert watcher.pending_count == 0
    assert not watcher.state.entries


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
        quiet_seconds=0,
        initial_scan=False,
        runner_factory=PasswordThenSuccessRunner,
    )
    watcher.enqueue(str(archive_path))
    first = watcher.run_once()
    watcher.enqueue(str(archive_path))

    watcher.notify_password_source_changed("test")
    second = watcher.run_once()

    assert first.failed == 1
    assert second.succeeded == 1
    assert attempts["count"] == 2
    assert not watcher.state.entries


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
        quiet_seconds=0,
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
        quiet_seconds=0,
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
        quiet_seconds=0,
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
        quiet_seconds=0,
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
        quiet_seconds=0,
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
        quiet_seconds=0,
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
        quiet_seconds=0,
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
        quiet_seconds=0,
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
        quiet_seconds=0,
        initial_scan=False,
    )

    handler = scheduler_module._WatchEventHandler(watcher)
    handler._handle_path(str(log_path))
    watcher.enqueue(str(log_path))

    assert watcher.pending_count == 0
    assert log_path.read_text(encoding="utf-8") == ""


def test_watch_scheduler_does_not_special_case_downloader_suffixes(tmp_path, monkeypatch):
    monkeypatch.setattr(scheduler_module, "Observer", FakeObserver)
    watch_root = tmp_path / "in"
    watch_root.mkdir()
    temporary = watch_root / "sample.zip.baiduyun.p.downloading"
    temporary.write_bytes(b"PK\x03\x04payload")

    watcher = WatchScheduler(
        {"watch": {"clipboard_monitor_enabled": False}},
        [str(watch_root)],
        out_dir=str(tmp_path / "out"),
        state_path=str(tmp_path / "state.json"),
        quiet_seconds=0,
        initial_scan=False,
    )
    watcher.enqueue(str(temporary), event_type="created")
    watcher.enqueue(str(temporary), event_type="modified")

    assert watcher.pending_count == 1


def test_watch_scheduler_same_stat_modified_event_resets_quiet_window(tmp_path, monkeypatch):
    monkeypatch.setattr(scheduler_module, "Observer", FakeObserver)
    now = [2000010000.0]
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
        {"watch": {"clipboard_monitor_enabled": False}},
        [str(watch_root)],
        out_dir=str(tmp_path / "out"),
        state_path=str(tmp_path / "state.json"),
        quiet_seconds=10,
        initial_scan=False,
        runner_factory=FakePipelineRunner,
    )
    watcher.enqueue(str(archive_path), event_type="created")
    now[0] += 0.8
    watcher.enqueue(str(archive_path), event_type="modified")

    now[0] += 0.3
    assert watcher.run_once().processed == 0
    now[0] += 9.8
    assert watcher.run_once().processed == 1


def test_modified_epoch_triggers_even_when_size_mtime_and_file_id_are_unchanged(tmp_path, monkeypatch):
    monkeypatch.setattr(scheduler_module, "Observer", FakeObserver)
    now = [2000020000.0]
    monkeypatch.setattr(scheduler_module.time, "time", lambda: now[0])

    class FakePipelineRunner:
        def __init__(self, config):
            self.context = SimpleNamespace(flatten_candidates=set(), recovered_outputs=[])

        def run_targets(self, paths):
            return FakeSummary()

    watch_root = tmp_path / "in"
    watch_root.mkdir()
    archive_path = watch_root / "sample.zip"
    archive_path.write_bytes(b"A" * (512 * 1024))
    original_mtime = archive_path.stat().st_mtime
    watcher = WatchScheduler(
        {"watch": {"clipboard_monitor_enabled": False}},
        [str(watch_root)],
        out_dir=str(tmp_path / "out"),
        state_path=str(tmp_path / "state.json"),
        quiet_seconds=10,
        initial_scan=False,
        runner_factory=FakePipelineRunner,
    )
    watcher.enqueue(str(archive_path), event_type="created")
    with archive_path.open("r+b") as handle:
        handle.seek(0)
        handle.write(b"B" * 32 * 1024)
    os.utime(archive_path, (original_mtime, original_mtime))
    watcher.enqueue(str(archive_path), event_type="modified")

    now[0] += 9.9
    assert watcher.run_once().processed == 0
    now[0] += 0.2
    assert watcher.run_once().processed == 1


def test_watch_scheduler_adapts_quiet_window_to_fast_content_writes(tmp_path, monkeypatch):
    monkeypatch.setattr(scheduler_module, "Observer", FakeObserver)
    now = [2000030000.0]
    monkeypatch.setattr(scheduler_module.time, "time", lambda: now[0])
    archive_path = tmp_path / "sample.zip"
    archive_path.write_bytes(b"0")
    os.utime(archive_path, (now[0], now[0]))
    watcher = WatchScheduler(
        {"watch": {"clipboard_monitor_enabled": False}},
        [str(tmp_path)],
        out_dir=str(tmp_path / "out"),
        state_path=str(tmp_path / "state.json"),
        initial_scan=False,
        runner_factory=lambda _config: SimpleNamespace(
            context=SimpleNamespace(flatten_candidates=set(), recovered_outputs=[]),
            recent_passwords=[],
            run_targets=lambda paths: FakeSummary(),
        ),
    )
    watcher.enqueue(str(archive_path), event_type="created")
    for index in range(20):
        now[0] += 0.5
        archive_path.write_bytes(bytes([index % 256]) * (index + 2))
        os.utime(archive_path, (now[0], now[0]))
        watcher.enqueue(str(archive_path), event_type="modified")

    state = watcher._active_states[str(archive_path)]
    assert 3.5 <= state.quiet_seconds <= 4.5
    now[0] += state.quiet_seconds - 0.01
    assert watcher.run_once().processed == 0
    now[0] += 0.02
    assert watcher.run_once().processed == 1


def test_watch_scheduler_default_cold_start_is_one_second(tmp_path, monkeypatch):
    monkeypatch.setattr(scheduler_module, "Observer", FakeObserver)
    now = [2000035000.0]
    monkeypatch.setattr(scheduler_module.time, "time", lambda: now[0])
    archive_path = tmp_path / "sample.zip"
    _write_zip(archive_path)
    watcher = WatchScheduler(
        {"watch": {"clipboard_monitor_enabled": False}},
        [str(tmp_path)],
        out_dir=str(tmp_path / "out"),
        state_path=str(tmp_path / "state.json"),
        initial_scan=False,
        runner_factory=lambda _config: SimpleNamespace(
            context=SimpleNamespace(flatten_candidates=set(), recovered_outputs=[]),
            recent_passwords=[],
            run_targets=lambda paths: FakeSummary(),
        ),
    )
    watcher.enqueue(str(archive_path), event_type="created")

    assert watcher._active_states[str(archive_path)].quiet_seconds == 1.0
    now[0] += 0.99
    assert watcher.run_once().processed == 0
    now[0] += 0.02
    assert watcher.run_once().processed == 1


def test_watch_scheduler_retains_slow_interval_learning_across_active_epochs(tmp_path, monkeypatch):
    monkeypatch.setattr(scheduler_module, "Observer", FakeObserver)
    now = [2000040000.0]
    monkeypatch.setattr(scheduler_module.time, "time", lambda: now[0])
    archive_path = tmp_path / "sample.zip"
    archive_path.write_bytes(b"first")
    os.utime(archive_path, (now[0], now[0]))
    watcher = WatchScheduler(
        {"watch": {"clipboard_monitor_enabled": False}},
        [str(tmp_path)],
        out_dir=str(tmp_path / "out"),
        state_path=str(tmp_path / "state.json"),
        initial_scan=False,
        runner_factory=lambda _config: SimpleNamespace(
            context=SimpleNamespace(flatten_candidates=set(), recovered_outputs=[]),
            recent_passwords=[],
            run_targets=lambda paths: FakeSummary(),
        ),
    )
    watcher.enqueue(str(archive_path), event_type="created")

    now[0] += 10.01
    assert watcher.run_once().processed == 1
    now[0] += 9.99
    archive_path.write_bytes(b"second")
    os.utime(archive_path, (now[0], now[0]))
    watcher.enqueue(str(archive_path), event_type="modified")

    state = watcher._active_states[str(archive_path)]
    assert state.quiet_seconds > 20.0
    now[0] += 20.0
    assert watcher.run_once().processed == 0


def test_modified_event_retries_same_metadata_identity(tmp_path, monkeypatch):
    monkeypatch.setattr(scheduler_module, "Observer", FakeObserver)
    attempts = []

    class FakePipelineRunner:
        def __init__(self, config):
            self.context = SimpleNamespace(flatten_candidates=set(), recovered_outputs=[])

        def run_targets(self, paths):
            attempts.append(list(paths))
            return FakeSummary()

    watch_root = tmp_path / "in"
    watch_root.mkdir()
    archive_path = watch_root / "sample.zip"
    archive_path.write_bytes(b"A" * (256 * 1024))
    original_mtime = archive_path.stat().st_mtime
    watcher = WatchScheduler(
        {"watch": {"clipboard_monitor_enabled": False}},
        [str(watch_root)],
        out_dir=str(tmp_path / "out"),
        state_path=str(tmp_path / "state.json"),
        quiet_seconds=0,
        initial_scan=False,
        runner_factory=FakePipelineRunner,
    )
    watcher.enqueue(str(archive_path), event_type="modified")
    assert watcher.run_once().processed == 1

    archive_path.write_bytes(b"B" * (256 * 1024))
    os.utime(archive_path, (original_mtime, original_mtime))
    watcher.enqueue(str(archive_path), event_type="modified")
    assert watcher.run_once().processed == 1
    assert len(attempts) == 2
