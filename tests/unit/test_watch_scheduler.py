from __future__ import annotations

import zipfile
from pathlib import Path

import packrelic.watch.scheduler as scheduler_module
from packrelic.watch.scheduler import WatchScheduler


class FakeObserver:
    started_count = 0
    stopped_count = 0

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
        return None


class FakeSummary:
    success_count = 1
    failed_tasks = []


def _write_zip(path: Path):
    with zipfile.ZipFile(path, "w") as archive:
        archive.writestr("inside.txt", "ok")


def test_watch_scheduler_uses_watchdog_observer_and_initial_scan(tmp_path, monkeypatch):
    FakeObserver.started_count = 0
    FakeObserver.stopped_count = 0
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
