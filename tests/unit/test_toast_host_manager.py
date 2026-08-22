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

        @staticmethod
        def poll():
            return None

    def launcher(arguments, *, cwd):
        launched["arguments"] = arguments
        launched["cwd"] = cwd
        return _Process()

    manager = ToastHostManager(
        host_path=str(host_path),
        diagnostic_log_path=str(diagnostic_log_path),
        launcher=launcher,
    )
    monkeypatch.setattr(toast_host_module, "_open_pipe", lambda _name, _timeout: 123)
    monkeypatch.setattr(manager, "_write", lambda _frame: None)

    manager._start_and_connect()

    assert launched["arguments"][-2:] == ["--diagnostic-log", str(diagnostic_log_path)]
    assert launched["cwd"] == str(tmp_path)
