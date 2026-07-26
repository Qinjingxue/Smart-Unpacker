from __future__ import annotations

import threading
import time
from types import SimpleNamespace

import sunpack.filesystem.watcher.service as service_module
import sunpack.coordinator.watch_runtime as watch_runtime
import sunpack.cli.commands.watch as watch_command
from sunpack.filesystem.watcher.service import (
    CONTROL_RELOAD,
    CONTROL_SCHEDULER_WAKEUP,
    CONTROL_STOP,
    WatchService,
)
from sunpack.cli.commands.watch import _watch_running
from tests.helpers.fake_pipeline_engine import FakePipelineEngine


class FakeRunner:
    pass


def test_watch_runtime_uses_neutral_cwd_and_restores_caller_cwd(tmp_path, monkeypatch):
    caller = tmp_path / "caller"
    neutral = tmp_path / "neutral"
    caller.mkdir()
    neutral.mkdir()
    observed = {}
    monkeypatch.chdir(caller)
    monkeypatch.setattr(watch_runtime, "runtime_working_directory", lambda: str(neutral))

    class FakeService:
        def __init__(self, **_kwargs):
            observed["constructed"] = __import__("os").getcwd()

        def run(self, *, once=False):
            observed["run"] = (__import__("os").getcwd(), once)
            return 7

    monkeypatch.setattr(watch_runtime, "WatchService", FakeService)

    assert watch_runtime.run_watch_service(tray_enabled=False, once=True) == 7
    assert observed == {"constructed": str(neutral), "run": (str(neutral), True)}
    assert __import__("os").getcwd() == str(caller)


def test_watch_background_starts_in_neutral_working_directory(tmp_path, monkeypatch):
    captured = {}
    monkeypatch.setattr(watch_command, "runtime_working_directory", lambda: str(tmp_path))
    monkeypatch.setattr(watch_command, "_watch_start_argv", lambda: ["sunpack", "watch", "start"])
    monkeypatch.setattr(watch_command.subprocess, "Popen", lambda *args, **kwargs: captured.update(kwargs))

    assert watch_command._start_watch_background()
    assert captured["cwd"] == str(tmp_path)


def test_watch_cli_start_exits_after_elevated_relaunch(monkeypatch):
    monkeypatch.setattr(watch_command, "_request_watch_elevation", lambda _args: True)
    args = SimpleNamespace(once=False, no_tray=False)
    ctx = SimpleNamespace(t=lambda key, **_kwargs: key)

    code, result = watch_command._handle_start(args, ctx)

    assert code == 0
    assert result.summary == {"elevated_relaunch": True}


def test_watch_cli_elevation_argv_preserves_runtime_flags(monkeypatch):
    monkeypatch.setattr(watch_command.sys, "frozen", True, raising=False)
    monkeypatch.setattr(watch_command.sys, "executable", r"C:\SunPack\sunpack.exe")

    argv = watch_command._watch_cli_start_argv(SimpleNamespace(once=True, no_tray=True))

    assert argv[1:] == ["watch", "start", "--once", "--no-tray"]


def test_watch_service_releases_named_mutex_after_exit(tmp_path, monkeypatch):
    state_dir = tmp_path / ".sunpack_watch"
    roots_path = tmp_path / "sunpack_watch_roots.txt"
    monkeypatch.setattr(service_module, "watch_roots_path", lambda: roots_path)
    monkeypatch.setattr(
        service_module,
        "load_config",
        lambda: {
            "watch": {
                "state_dir": str(state_dir),
                "roots": [],
                "tray_enabled": False,
                "clipboard_monitor_enabled": False,
            }
        },
    )

    service = WatchService(engine_factory=lambda _config: FakePipelineEngine(FakeRunner))

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

    first = WatchService(engine_factory=lambda _config: FakePipelineEngine(FakeRunner))
    second = WatchService(engine_factory=lambda _config: FakePipelineEngine(FakeRunner))

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


def test_request_stop_wakes_service_blocked_without_scheduler(tmp_path, monkeypatch):
    state_dir = tmp_path / ".sunpack_watch"
    monkeypatch.setattr(
        service_module,
        "load_config",
        lambda: {
            "watch": {
                "state_dir": str(state_dir),
                "roots": [],
                "tray_enabled": False,
            }
        },
    )
    service = WatchService(engine_factory=lambda _config: FakePipelineEngine(FakeRunner))
    waiting = threading.Event()
    wake = threading.Event()

    class BlockingControlEvents:
        def start(self):
            pass

        def wait(self, timeout_seconds):
            assert timeout_seconds is None
            waiting.set()
            assert wake.wait(timeout=1.0)
            return CONTROL_STOP

        def wake_stop(self):
            wake.set()
            return True

        def close(self):
            pass

    monkeypatch.setattr(service, "_acquire_lock", lambda: True)
    monkeypatch.setattr(service, "_release_lock", lambda: None)
    monkeypatch.setattr(service, "_start_scheduler", lambda: setattr(service, "scheduler", None))
    monkeypatch.setattr(service, "_stop_scheduler", lambda: setattr(service, "scheduler", None))
    monkeypatch.setattr(service, "_start_tray", lambda: None)
    monkeypatch.setattr(service, "_stop_tray", lambda: None)
    service.control_events = BlockingControlEvents()
    results = []
    thread = threading.Thread(target=lambda: results.append(service.run()))
    thread.start()
    assert waiting.wait(timeout=1.0)

    service.request_stop()
    thread.join(timeout=1.0)

    assert not thread.is_alive()
    assert results == [0]


def test_watch_service_config_observer_targets_program_files(tmp_path, monkeypatch):
    roots_path = tmp_path / "sunpack_watch_roots.txt"
    state_dir = tmp_path / ".sunpack_watch"
    captured = {}

    class FakeConfigObserver:
        def __init__(self, directory, filenames, callback, *, debounce_seconds):
            captured.update(
                directory=directory,
                filenames=set(filenames),
                callback=callback,
                debounce_seconds=debounce_seconds,
            )

        def start(self):
            captured["started"] = True

        def stop(self):
            captured["stopped"] = True

    monkeypatch.setattr(service_module, "watch_roots_path", lambda: roots_path)
    monkeypatch.setattr(service_module, "ConfigFileObserver", FakeConfigObserver)
    monkeypatch.setattr(
        service_module,
        "load_config",
        lambda: {"watch": {"state_dir": str(state_dir), "tray_enabled": False}},
    )
    service = WatchService(engine_factory=lambda _config: FakePipelineEngine(FakeRunner))
    wakeups = []
    service.control_events.wake_reload = lambda: wakeups.append("reload")

    service._start_config_observer()
    captured["callback"]()
    service._stop_config_observer()

    assert captured["directory"] == tmp_path.resolve()
    assert captured["filenames"] == {
        "sunpack_config.json",
        "sunpack_advanced_config.json",
        "sunpack_watch_roots.txt",
    }
    assert captured["debounce_seconds"] == 0.5
    assert captured["started"] is True
    assert captured["stopped"] is True
    assert wakeups == ["reload"]


def test_watch_service_invalid_config_reload_preserves_running_service(tmp_path, monkeypatch):
    state_dir = tmp_path / ".sunpack_watch"
    initial_config = {"watch": {"state_dir": str(state_dir), "tray_enabled": False}}
    monkeypatch.setattr(service_module, "load_config", lambda: initial_config)
    service = WatchService(engine_factory=lambda _config: FakePipelineEngine(FakeRunner))
    original_config = service.config
    original_service_config = service.service_config
    original_log = service.log
    scheduler_restarts = []
    written = []
    service.log.write = lambda event, **payload: written.append((event, payload))
    monkeypatch.setattr(service_module, "load_config", lambda: (_ for _ in ()).throw(ValueError("invalid json")))
    monkeypatch.setattr(service, "_start_scheduler", lambda: scheduler_restarts.append(True))

    service._reload_config()

    assert service.config is original_config
    assert service.service_config is original_service_config
    assert service.log is original_log
    assert scheduler_restarts == []
    assert written == [
        (
            "config_reload_failed",
            {"error": "invalid json", "error_type": "ValueError", "phase": "load"},
        )
    ]


def test_watch_service_reload_applies_new_roots_and_restarts_runtime(tmp_path, monkeypatch):
    roots_path = tmp_path / "sunpack_watch_roots.txt"
    first_root = tmp_path / "first"
    second_root = tmp_path / "second"
    first_root.mkdir()
    second_root.mkdir()
    roots_path.write_text(str(first_root), encoding="utf-8")
    state_dir = tmp_path / ".sunpack_watch"
    configs = iter(
        [
            {"watch": {"state_dir": str(state_dir), "tray_enabled": False}, "revision": 1},
            {"watch": {"state_dir": str(state_dir), "tray_enabled": False}, "revision": 2},
        ]
    )
    monkeypatch.setattr(service_module, "watch_roots_path", lambda: roots_path)
    monkeypatch.setattr(service_module, "load_config", lambda: next(configs))
    service = WatchService(engine_factory=lambda _config: FakePipelineEngine(FakeRunner))
    starts = []
    tray_events = []
    monkeypatch.setattr(service, "_start_scheduler", lambda: starts.append((service.config["revision"], service.roots)))
    monkeypatch.setattr(service, "_stop_tray", lambda: tray_events.append("stop"))
    monkeypatch.setattr(service, "_start_tray", lambda: tray_events.append("start"))
    roots_path.write_text(str(second_root), encoding="utf-8")

    service._reload_config()

    assert service.config["revision"] == 2
    assert service.roots == [str(second_root.resolve())]
    assert starts == [(2, [str(second_root.resolve())])]
    assert tray_events == ["stop", "start"]


def test_watch_service_apply_failure_rolls_back_previous_config(tmp_path, monkeypatch):
    roots_path = tmp_path / "sunpack_watch_roots.txt"
    watch_root = tmp_path / "watched"
    watch_root.mkdir()
    roots_path.write_text(str(watch_root), encoding="utf-8")
    state_dir = tmp_path / ".sunpack_watch"
    configs = iter(
        [
            {"watch": {"state_dir": str(state_dir), "tray_enabled": False}, "revision": 1},
            {"watch": {"state_dir": str(state_dir), "tray_enabled": False}, "revision": 2},
        ]
    )
    monkeypatch.setattr(service_module, "watch_roots_path", lambda: roots_path)
    monkeypatch.setattr(service_module, "load_config", lambda: next(configs))
    service = WatchService(engine_factory=lambda _config: FakePipelineEngine(FakeRunner))
    starts = []

    def start_scheduler():
        starts.append(service.config["revision"])
        if service.config["revision"] == 2:
            raise RuntimeError("new runtime failed")

    monkeypatch.setattr(service, "_start_scheduler", start_scheduler)

    service._reload_config()

    assert service.config["revision"] == 1
    assert starts == [2, 1]


def test_watch_running_reflects_named_mutex_owner(tmp_path, monkeypatch):
    state_dir = tmp_path / ".sunpack_watch"
    roots_path = tmp_path / "sunpack_watch_roots.txt"
    monkeypatch.setattr(service_module, "watch_roots_path", lambda: roots_path)

    service = WatchService(engine_factory=lambda _config: FakePipelineEngine(FakeRunner))

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


def test_relative_watch_state_path_uses_program_directory_not_process_working_directory(tmp_path, monkeypatch):
    program_dir = tmp_path / "program"
    working_dir = tmp_path / "windows-system-directory"
    roots_path = program_dir / "sunpack_watch_roots.txt"
    program_dir.mkdir()
    working_dir.mkdir()
    watch_root = tmp_path / "watched"
    watch_root.mkdir()
    roots_path.write_text(str(watch_root), encoding="utf-8")
    monkeypatch.chdir(working_dir)
    monkeypatch.setattr(service_module, "watch_roots_path", lambda: roots_path)

    config = {"watch": {"out_dir": ".", "state_dir": "runtime/state"}}

    assert service_module.service_state_dir(config) == str((program_dir / "runtime" / "state").resolve())


def test_default_watch_state_uses_program_directory_and_output_stays_relative(tmp_path, monkeypatch):
    program_dir = tmp_path / "program"
    working_dir = tmp_path / "windows-system-directory"
    watch_root = tmp_path / "watched"
    roots_path = program_dir / "sunpack_watch_roots.txt"
    program_dir.mkdir()
    working_dir.mkdir()
    watch_root.mkdir()
    roots_path.write_text(str(watch_root), encoding="utf-8")
    monkeypatch.chdir(working_dir)
    monkeypatch.setattr(service_module, "watch_roots_path", lambda: roots_path)
    monkeypatch.setattr(
        service_module,
        "load_config",
        lambda: {"watch": {"out_dir": ".", "state_dir": "", "tray_enabled": False}},
    )
    captured = {}

    class FakeScheduler:
        def __init__(self, config, roots, **kwargs):
            captured["out_dir"] = kwargs["out_dir"]
            captured["state_path"] = kwargs["state_path"]

        def start(self):
            pass

        def stop(self):
            pass

    monkeypatch.setattr(service_module, "WatchScheduler", FakeScheduler)

    service = WatchService(engine_factory=lambda _config: FakePipelineEngine(FakeRunner))
    service._start_scheduler()

    assert service.state_dir == str((program_dir / ".sunpack_watch").resolve())
    assert captured["out_dir"] == "."
    assert captured["state_path"] == str((program_dir / ".sunpack_watch" / "state.json").resolve())


def test_watch_state_falls_back_to_program_directory_without_existing_roots(tmp_path, monkeypatch):
    program_dir = tmp_path / "program"
    roots_path = program_dir / "sunpack_watch_roots.txt"
    program_dir.mkdir()
    monkeypatch.setattr(service_module, "watch_roots_path", lambda: roots_path)

    assert service_module.service_state_dir({"watch": {"out_dir": ".", "state_dir": ""}}) == str(
        (program_dir / ".sunpack_watch").resolve()
    )


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

    service = WatchService(engine_factory=lambda _config: FakePipelineEngine(FakeRunner))

    assert service.roots == [str(txt_root.resolve())]


def test_watch_service_scheduler_uses_directory_scan_mode_not_watch_recursive(tmp_path, monkeypatch):
    roots_path = tmp_path / "sunpack_watch_roots.txt"
    watch_root = tmp_path / "watch-root"
    watch_root.mkdir()
    roots_path.write_text(str(watch_root), encoding="utf-8")
    state_dir = tmp_path / ".sunpack_watch"
    captured = {}
    original_scheduler = service_module.WatchScheduler

    class FakeScheduler:
        def __init__(self, config, roots, **kwargs):
            captured["config"] = config
            captured["roots"] = roots
            captured["kwargs"] = kwargs
            self.recursive = original_scheduler(config, roots, **kwargs).recursive

        def start(self):
            captured["started"] = True

        def stop(self):
            pass

    monkeypatch.setattr(service_module, "watch_roots_path", lambda: roots_path)
    monkeypatch.setattr(service_module, "WatchScheduler", FakeScheduler)
    monkeypatch.setattr(
        service_module,
        "load_config",
        lambda: {
            "filesystem": {"directory_scan_mode": "current_dir_only", "scan_filters": []},
            "watch": {
                "state_dir": str(state_dir),
                "recursive": True,
                "tray_enabled": False,
            },
        },
    )

    service = WatchService(engine_factory=lambda _config: FakePipelineEngine(FakeRunner))
    service._start_scheduler()

    assert captured["roots"] == [str(watch_root.resolve())]
    assert "recursive" not in captured["kwargs"]
    assert captured["kwargs"]["quiet_seconds"] == 1.0
    assert service.scheduler.recursive is False
    assert captured["started"] is True


def test_watch_service_waits_indefinitely_when_scheduler_is_idle(tmp_path, monkeypatch):
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
    service = WatchService(engine_factory=lambda _config: FakePipelineEngine(FakeRunner))
    scheduler_runs = []
    waits = []

    class FakeScheduler:
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
    assert len(scheduler_runs) == 1
    assert waits == [None, None]


def test_watch_service_recalculates_deadline_after_scheduler_wakeup(tmp_path, monkeypatch):
    state_dir = tmp_path / ".sunpack_watch"
    state_dir.mkdir()
    monkeypatch.setattr(
        service_module,
        "load_config",
        lambda: {"watch": {"state_dir": str(state_dir), "roots": [], "tray_enabled": False}},
    )
    service = WatchService(engine_factory=lambda _config: FakePipelineEngine(FakeRunner))
    scheduler_runs = []
    waits = []

    class FakeScheduler:
        def __init__(self):
            self.delay = 120.0

        def run_once(self):
            scheduler_runs.append(len(scheduler_runs))
            if len(scheduler_runs) == 2:
                self.delay = 5.0
            return SimpleNamespace(processed=0, succeeded=0, failed=0, pending=1, errors=[])

        def next_delay_seconds(self):
            return self.delay

    scheduler = FakeScheduler()

    class FakeControlEvents:
        def start(self):
            pass

        def wait(self, timeout_seconds):
            waits.append(timeout_seconds)
            if len(waits) == 1:
                scheduler.delay = 1.0
                return CONTROL_SCHEDULER_WAKEUP
            return CONTROL_STOP

        def close(self):
            pass

    monkeypatch.setattr(service, "_acquire_lock", lambda: True)
    monkeypatch.setattr(service, "_release_lock", lambda: None)
    monkeypatch.setattr(service, "_start_scheduler", lambda: setattr(service, "scheduler", scheduler))
    monkeypatch.setattr(service, "_stop_scheduler", lambda: setattr(service, "scheduler", None))
    monkeypatch.setattr(service, "_start_tray", lambda: None)
    monkeypatch.setattr(service, "_stop_tray", lambda: None)
    service.control_events = FakeControlEvents()
    times = iter([0.0, 0.0, 1.0])
    monkeypatch.setattr(service_module.time, "monotonic", lambda: next(times))

    assert service.run() == 0
    assert len(scheduler_runs) == 2
    assert waits == [120.0, 5.0]


def test_watch_service_deduplicates_unchanged_pending_ticks(tmp_path, monkeypatch):
    state_dir = tmp_path / ".sunpack_watch"
    state_dir.mkdir()
    monkeypatch.setattr(
        service_module,
        "load_config",
        lambda: {"watch": {"state_dir": str(state_dir), "roots": [], "tray_enabled": False}},
    )
    service = WatchService(engine_factory=lambda _config: FakePipelineEngine(FakeRunner))
    written = []

    class FakeLog:
        def write(self, event, **payload):
            written.append((event, payload))

    class FakeScheduler:
        def __init__(self):
            self.results = iter([
                SimpleNamespace(processed=0, succeeded=0, failed=0, pending=1, errors=[]),
                SimpleNamespace(processed=0, succeeded=0, failed=0, pending=1, errors=[]),
                SimpleNamespace(processed=1, succeeded=1, failed=0, pending=0, errors=[]),
                SimpleNamespace(processed=0, succeeded=0, failed=0, pending=1, errors=[]),
            ])

        def run_once(self):
            return next(self.results)

        def next_delay_seconds(self):
            return 5.0

    class FakeControlEvents:
        def __init__(self):
            self.count = 0

        def start(self):
            pass

        def wait(self, timeout_seconds):
            self.count += 1
            return CONTROL_STOP if self.count == 4 else None

        def close(self):
            pass

    monkeypatch.setattr(service, "_acquire_lock", lambda: True)
    monkeypatch.setattr(service, "_release_lock", lambda: None)
    monkeypatch.setattr(service, "_start_scheduler", lambda: setattr(service, "scheduler", FakeScheduler()))
    monkeypatch.setattr(service, "_stop_scheduler", lambda: setattr(service, "scheduler", None))
    monkeypatch.setattr(service, "_start_tray", lambda: None)
    monkeypatch.setattr(service, "_stop_tray", lambda: None)
    service.control_events = FakeControlEvents()
    service.log = FakeLog()
    times = iter([0.0, 5.0, 10.0, 15.0])
    monkeypatch.setattr(service_module.time, "monotonic", lambda: next(times))

    assert service.run() == 0

    tick_payloads = [payload for event, payload in written if event == "scheduler_tick"]
    assert tick_payloads == [
        {"processed": 0, "succeeded": 0, "failed": 0, "pending": 1, "errors": []},
        {"processed": 1, "succeeded": 1, "failed": 0, "pending": 0, "errors": []},
        {"processed": 0, "succeeded": 0, "failed": 0, "pending": 1, "errors": []},
    ]
