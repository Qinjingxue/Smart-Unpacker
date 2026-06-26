from __future__ import annotations

import threading
import time
from types import SimpleNamespace

import sunpack.filesystem.watcher.service as service_module
from sunpack.filesystem.watcher.service import CONTROL_RELOAD, CONTROL_STOP, WatchService
from sunpack.app.commands.watch import _watch_running


class FakeRunner:
    pass


def test_watch_service_releases_named_mutex_after_exit(tmp_path, monkeypatch):
    state_dir = tmp_path / ".sunpack_watch"
    roots_path = tmp_path / "sunpack_watch_roots.txt"
    monkeypatch.setattr(service_module, "watch_roots_path", lambda: roots_path)
    monkeypatch.setattr(
        service_module,
        "load_config",
        lambda: {"watch": {"state_dir": str(state_dir), "roots": [], "tray_enabled": False}},
    )

    service = WatchService(runner_factory=FakeRunner)

    assert service.run(once=True) == 0
    assert not _watch_running({"watch": {"state_dir": str(state_dir)}})
    assert not (state_dir / "watch.lock").exists()


def test_watch_service_keeps_active_named_mutex(tmp_path, monkeypatch):
    state_dir = tmp_path / ".sunpack_watch"
    roots_path = tmp_path / "sunpack_watch_roots.txt"
    monkeypatch.setattr(service_module, "watch_roots_path", lambda: roots_path)
    monkeypatch.setattr(
        service_module,
        "load_config",
        lambda: {"watch": {"state_dir": str(state_dir), "roots": [], "tray_enabled": False}},
    )

    first = WatchService(runner_factory=FakeRunner)
    second = WatchService(runner_factory=FakeRunner)

    assert first._acquire_lock()
    try:
        result = []
        thread = threading.Thread(target=lambda: result.append(second.run(once=True)))
        thread.start()
        thread.join(timeout=2.0)

        assert result == [2]
        assert not (state_dir / "watch.lock").exists()
    finally:
        first._release_lock()


def test_watch_running_reflects_named_mutex_owner(tmp_path, monkeypatch):
    state_dir = tmp_path / ".sunpack_watch"
    roots_path = tmp_path / "sunpack_watch_roots.txt"
    monkeypatch.setattr(service_module, "watch_roots_path", lambda: roots_path)

    service = WatchService(runner_factory=FakeRunner)

    assert not _watch_running({"watch": {"state_dir": str(state_dir)}})
    assert service._acquire_lock()
    try:
        result = []
        thread = threading.Thread(target=lambda: result.append(_watch_running({"watch": {"state_dir": str(state_dir)}})))
        thread.start()
        thread.join(timeout=2.0)

        assert result == [True]
    finally:
        service._release_lock()
    assert not _watch_running({"watch": {"state_dir": str(state_dir)}})


def test_signal_stop_sets_named_event(tmp_path, monkeypatch):
    roots_path = tmp_path / "sunpack_watch_roots.txt"
    monkeypatch.setattr(service_module, "watch_roots_path", lambda: roots_path)
    signaled = []
    monkeypatch.setattr(service_module, "_set_named_event", lambda name: signaled.append(name) or True)

    result = service_module.signal_stop({"watch": {"state_dir": str(tmp_path / ".sunpack_watch")}})

    assert result == service_module.watch_control_event_names()[CONTROL_STOP]
    assert signaled == [result]


def test_signal_reload_sets_named_event(tmp_path, monkeypatch):
    roots_path = tmp_path / "sunpack_watch_roots.txt"
    monkeypatch.setattr(service_module, "watch_roots_path", lambda: roots_path)
    signaled = []
    monkeypatch.setattr(service_module, "_set_named_event", lambda name: signaled.append(name) or True)

    result = service_module.signal_reload({"watch": {"state_dir": str(tmp_path / ".sunpack_watch")}})

    assert result == service_module.watch_control_event_names()[CONTROL_RELOAD]
    assert signaled == [result]


def test_watch_roots_are_stored_in_program_txt(tmp_path, monkeypatch):
    roots_path = tmp_path / "sunpack_watch_roots.txt"
    first = tmp_path / "first"
    second = tmp_path / "second"
    first.mkdir()
    second.mkdir()
    monkeypatch.setattr(service_module, "watch_roots_path", lambda: roots_path)

    path, added = service_module.add_watch_roots([str(first), str(second), str(first)])
    listed_path, roots = service_module.list_watch_roots()
    _, removed = service_module.remove_watch_roots([str(first)])

    assert path == roots_path
    assert listed_path == roots_path
    assert added == [str(first.resolve()), str(second.resolve())]
    assert roots == [str(first.resolve()), str(second.resolve())]
    assert removed == [str(first.resolve())]
    assert roots_path.read_text(encoding="utf-8").splitlines() == [str(second.resolve())]


def test_watch_roots_add_is_serialized_across_concurrent_callers(tmp_path, monkeypatch):
    roots_path = tmp_path / "sunpack_watch_roots.txt"
    first = tmp_path / "first"
    second = tmp_path / "second"
    first.mkdir()
    second.mkdir()
    monkeypatch.setattr(service_module, "watch_roots_path", lambda: roots_path)
    original_write = service_module._write_watch_roots_unlocked

    def slow_write(roots, path):
        time.sleep(0.05)
        return original_write(roots, path)

    monkeypatch.setattr(service_module, "_write_watch_roots_unlocked", slow_write)
    threads = [
        threading.Thread(target=service_module.add_watch_roots, args=([str(first)],)),
        threading.Thread(target=service_module.add_watch_roots, args=([str(second)],)),
    ]

    for thread in threads:
        thread.start()
    for thread in threads:
        thread.join(timeout=2.0)

    assert not any(thread.is_alive() for thread in threads)
    assert set(roots_path.read_text(encoding="utf-8").splitlines()) == {str(first.resolve()), str(second.resolve())}


def test_watch_service_reads_roots_from_txt_not_config(tmp_path, monkeypatch):
    roots_path = tmp_path / "sunpack_watch_roots.txt"
    txt_root = tmp_path / "txt-root"
    config_root = tmp_path / "config-root"
    txt_root.mkdir()
    config_root.mkdir()
    roots_path.write_text(str(txt_root), encoding="utf-8")
    monkeypatch.setattr(service_module, "watch_roots_path", lambda: roots_path)
    monkeypatch.setattr(
        service_module,
        "load_config",
        lambda: {
            "watch": {
                "state_dir": str(tmp_path / ".sunpack_watch"),
                "roots": [str(config_root)],
                "tray_enabled": False,
            }
        },
    )

    service = WatchService(runner_factory=FakeRunner)

    assert service.roots == [str(txt_root.resolve())]


def test_watch_service_waits_on_control_event_until_scheduler_is_due(tmp_path, monkeypatch):
    state_dir = tmp_path / ".sunpack_watch"
    state_dir.mkdir()
    monkeypatch.setattr(
        service_module,
        "load_config",
        lambda: {
            "watch": {
                "state_dir": str(state_dir),
                "roots": [],
                "reload_poll_seconds": 1.0,
                "tray_enabled": False,
            }
        },
    )
    service = WatchService(runner_factory=FakeRunner)
    scheduler_runs = []
    waits = []

    class FakeScheduler:
        interval_seconds = 5.0

        def run_once(self):
            scheduler_runs.append(len(scheduler_runs))
            return SimpleNamespace(processed=0, succeeded=0, failed=0, pending=0, errors=[])

    class FakeControlEvents:
        def start(self):
            pass

        def wait(self, timeout_seconds):
            waits.append(timeout_seconds)
            return CONTROL_STOP if len(waits) == 2 else None

        def close(self):
            pass

    monkeypatch.setattr(service, "_acquire_lock", lambda: True)
    monkeypatch.setattr(service, "_release_lock", lambda: None)
    monkeypatch.setattr(service, "_start_scheduler", lambda: setattr(service, "scheduler", FakeScheduler()))
    monkeypatch.setattr(service, "_stop_scheduler", lambda: setattr(service, "scheduler", None))
    monkeypatch.setattr(service, "_start_tray", lambda: None)
    monkeypatch.setattr(service, "_stop_tray", lambda: None)
    service.control_events = FakeControlEvents()
    times = iter([0.0, 5.0])
    monkeypatch.setattr(service_module.time, "monotonic", lambda: next(times))

    assert service.run() == 0
    assert len(scheduler_runs) == 2
    assert waits == [5.0, 5.0]
