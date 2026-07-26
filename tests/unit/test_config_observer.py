from __future__ import annotations

import threading

from watchdog.events import FileCreatedEvent, FileDeletedEvent, FileModifiedEvent, FileMovedEvent

from sunpack.filesystem.watcher.config_observer import ConfigFileObserver


class FakeObserver:
    def __init__(self):
        self.handler = None
        self.path = None
        self.recursive = None
        self.started = False
        self.stopped = False
        self.join_timeout = None

    def schedule(self, handler, path, *, recursive):
        self.handler = handler
        self.path = path
        self.recursive = recursive

    def start(self):
        self.started = True

    def stop(self):
        self.stopped = True

    def join(self, timeout):
        self.join_timeout = timeout


def test_config_observer_watches_program_directory_non_recursively(tmp_path):
    observer = ConfigFileObserver(
        tmp_path,
        ("sunpack_config.json",),
        lambda: None,
        observer_factory=FakeObserver,
    )

    observer.start()
    observer.stop(timeout_seconds=1.25)

    assert observer._observer.path == str(tmp_path.resolve())
    assert observer._observer.recursive is False
    assert observer._observer.started is True
    assert observer._observer.stopped is True
    assert observer._observer.join_timeout == 1.25


def test_config_observer_filters_files_and_debounces_event_burst(tmp_path):
    emitted = threading.Event()
    calls = []
    observer = ConfigFileObserver(
        tmp_path,
        ("sunpack_config.json", "sunpack_advanced_config.json", "sunpack_watch_roots.txt"),
        lambda: (calls.append("reload"), emitted.set()),
        debounce_seconds=0.02,
        observer_factory=FakeObserver,
    )
    observer.start()
    handler = observer._observer.handler

    handler.on_modified(FileModifiedEvent(str(tmp_path / "unrelated.txt")))
    handler.on_created(FileCreatedEvent(str(tmp_path / "SUNPACK_CONFIG.JSON")))
    handler.on_modified(FileModifiedEvent(str(tmp_path / "sunpack_advanced_config.json")))
    handler.on_deleted(FileDeletedEvent(str(tmp_path / "sunpack_watch_roots.txt")))

    assert emitted.wait(timeout=1.0)
    assert calls == ["reload"]
    observer.stop()


def test_config_observer_handles_atomic_replace_destination(tmp_path):
    emitted = threading.Event()
    observer = ConfigFileObserver(
        tmp_path,
        ("sunpack_config.json",),
        emitted.set,
        debounce_seconds=0.0,
        observer_factory=FakeObserver,
    )
    observer.start()

    observer._observer.handler.on_moved(
        FileMovedEvent(
            str(tmp_path / ".sunpack_config.json.tmp"),
            str(tmp_path / "sunpack_config.json"),
        )
    )

    assert emitted.wait(timeout=1.0)
    observer.stop()


def test_config_observer_cancels_pending_reload_when_stopped(tmp_path):
    emitted = threading.Event()
    observer = ConfigFileObserver(
        tmp_path,
        ("sunpack_config.json",),
        emitted.set,
        debounce_seconds=0.1,
        observer_factory=FakeObserver,
    )
    observer.start()
    observer.notify_path_changed(str(tmp_path / "sunpack_config.json"))

    observer.stop()

    assert not emitted.wait(timeout=0.2)


def test_real_watchdog_observer_detects_config_change(tmp_path):
    emitted = threading.Event()
    observer = ConfigFileObserver(
        tmp_path,
        ("sunpack_config.json",),
        emitted.set,
        debounce_seconds=0.02,
    )
    observer.start()
    try:
        (tmp_path / "sunpack_config.json").write_text("{}", encoding="utf-8")
        assert emitted.wait(timeout=3.0)
    finally:
        observer.stop()
