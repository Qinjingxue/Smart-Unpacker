import os
import secrets
import threading

from sunpack.platform.windows import toast_host as toast_host_module
from sunpack.platform.windows.toast_host import ToastHostManager
from sunpack.platform.windows.toast_protocol import ToastSnapshot, ToastSnapshotKind


def _terminal_snapshot(*, ttl_ms: int = 5_000) -> ToastSnapshot:
    return ToastSnapshot(
        kind=ToastSnapshotKind.SUCCESS,
        batch_id="batch",
        title="complete",
        ttl_ms=ttl_ms,
    )


def test_terminal_retention_starts_only_after_snapshot_is_sent(monkeypatch):
    manager = ToastHostManager()
    snapshot = _terminal_snapshot()

    manager.publish(snapshot)

    assert manager._snapshot_expires_at == 0.0
    revision = manager._revision
    monkeypatch.setattr(toast_host_module.time, "monotonic", lambda: 100.0)
    manager._retain_terminal_after_send(snapshot, revision)
    assert manager._snapshot_expires_at == 105.0


def test_expired_terminal_is_forgotten_without_sending_clear(monkeypatch):
    manager = ToastHostManager()
    snapshot = _terminal_snapshot()
    manager.publish(snapshot)
    revision = manager._revision
    monkeypatch.setattr(toast_host_module.time, "monotonic", lambda: 100.0)
    manager._retain_terminal_after_send(snapshot, revision)

    with manager._condition:
        manager._forget_expired_snapshot_locked(105.0)

    assert manager._snapshot is None
    assert manager._snapshot_expires_at == 0.0
    assert manager._revision == revision


def test_native_host_receives_diagnostic_log_path(tmp_path, monkeypatch):
    host_path = tmp_path / "sunpack_toast_host.exe"
    host_path.write_bytes(b"")
    diagnostic_log_path = tmp_path / "state" / "toast_host_events.jsonl"
    launched = {}

    class _Process:
        pid = 42

    def launcher(arguments, *, cwd):
        launched["arguments"] = arguments
        launched["cwd"] = cwd
        return _Process()

    manager = ToastHostManager(
        host_path=str(host_path),
        diagnostic_log_path=str(diagnostic_log_path),
        launcher=launcher,
    )
    manager._stop_handle = 456
    monkeypatch.setattr(toast_host_module, "_create_event", lambda *_args, **_kwargs: 123)
    monkeypatch.setattr(toast_host_module, "_wait_for_host_ready", lambda *_args, **_kwargs: None)
    monkeypatch.setattr(toast_host_module, "_open_pipe", lambda _name, _timeout: 123)
    monkeypatch.setattr(manager, "_start_process_waiter", lambda _process, _generation: None)
    monkeypatch.setattr(manager, "_write", lambda _frame: None)

    class _Kernel32:
        @staticmethod
        def CloseHandle(_handle):
            return True

    monkeypatch.setattr(toast_host_module, "_kernel32", lambda: _Kernel32())

    manager._start_and_connect()

    assert launched["arguments"][-2:] == ["--diagnostic-log", str(diagnostic_log_path)]
    ready_index = launched["arguments"].index("--ready-event")
    assert launched["arguments"][ready_index + 1].startswith("Local\\SunPackToastReady-")
    assert launched["cwd"] == str(tmp_path)


def test_process_exit_waiter_notifies_the_matching_generation():
    manager = ToastHostManager()
    released = threading.Event()

    class _Process:
        @staticmethod
        def wait(timeout=None):
            assert timeout is None
            released.wait()
            return 37

    process = _Process()
    with manager._condition:
        manager._process = process
        manager._process_generation = 4
    manager._start_process_waiter(process, 4)

    released.set()
    with manager._condition:
        assert manager._condition.wait_for(
            lambda: manager._process_exit_generation == 4,
            timeout=1.0,
        )
        assert manager._process_exit_code == 37


def test_idle_supervisor_has_no_periodic_wakeup(monkeypatch):
    manager = ToastHostManager()
    observed_timeouts = []

    def start_and_connect():
        manager._pipe_handle = 123

    def wait_for(predicate, timeout=None):
        observed_timeouts.append(timeout)
        manager._stopping = True
        return predicate()

    class _Kernel32:
        @staticmethod
        def CloseHandle(_handle):
            return True

    monkeypatch.setattr(manager, "_start_and_connect", start_and_connect)
    monkeypatch.setattr(manager, "_send", lambda _message_type: None)
    monkeypatch.setattr(manager._condition, "wait_for", wait_for)
    monkeypatch.setattr(toast_host_module, "_kernel32", lambda: _Kernel32())

    manager._supervise()

    assert observed_timeouts == [None]


def test_cross_integrity_ready_event_security_descriptor_is_valid():
    handle = toast_host_module._create_event(
        f"Local\\SunPackToastReady-test-{os.getpid()}-{secrets.token_hex(4)}",
        cross_integrity=True,
    )
    try:
        assert handle
    finally:
        toast_host_module._kernel32().CloseHandle(handle)
