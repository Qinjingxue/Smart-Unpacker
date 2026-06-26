from __future__ import annotations

import sunpack.passwords.internal.builtin as builtin_module
import sunpack.passwords.internal.clipboard_monitor as clipboard_monitor_module
from sunpack.passwords.internal.clipboard_monitor import ClipboardPasswordMonitor


def test_clipboard_monitor_persists_clipboard_passwords_and_notifies(tmp_path, monkeypatch):
    builtin_path = tmp_path / "builtin_passwords.txt"
    builtin_path.write_text("existing\n", encoding="utf-8")
    monkeypatch.setattr(builtin_module, "builtin_password_path", lambda: builtin_path)
    monkeypatch.setattr(clipboard_monitor_module, "read_clipboard_passwords", lambda: [f"clip-{index}" for index in range(35)])
    notifications = []

    monitor = ClipboardPasswordMonitor(
        on_passwords_changed=notifications.append,
        max_entries=30,
        enabled=True,
    )

    monitor._handle_clipboard_update()

    passwords = builtin_module.get_builtin_passwords()
    assert notifications == ["clipboard"]
    assert "existing" in passwords
    assert "clip-0" not in passwords
    assert "clip-5" in passwords
    assert "clip-34" in passwords
