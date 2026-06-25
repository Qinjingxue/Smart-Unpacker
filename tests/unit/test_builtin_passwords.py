from __future__ import annotations

import sunpack.passwords.internal.builtin as builtin_module


def test_watch_clipboard_passwords_are_persisted_in_managed_builtin_block(tmp_path, monkeypatch):
    builtin_path = tmp_path / "builtin_passwords.txt"
    builtin_path.write_text("user-secret\n# comment\n", encoding="utf-8")
    monkeypatch.setattr(builtin_module, "builtin_password_path", lambda: builtin_path)

    changed = builtin_module.merge_watch_clipboard_passwords(["clip-a", "clip-b"], max_entries=10)

    text = builtin_path.read_text(encoding="utf-8")
    assert changed is True
    assert "user-secret" in text
    assert builtin_module.WATCH_CLIPBOARD_BLOCK_BEGIN in text
    assert "clip-a" in text
    assert "clip-b" in text
    assert builtin_module.get_builtin_passwords() == ["user-secret", "clip-a", "clip-b"]


def test_watch_clipboard_password_block_keeps_most_recent_entries(tmp_path, monkeypatch):
    builtin_path = tmp_path / "builtin_passwords.txt"
    builtin_path.write_text("user-secret\n", encoding="utf-8")
    monkeypatch.setattr(builtin_module, "builtin_password_path", lambda: builtin_path)

    builtin_module.merge_watch_clipboard_passwords(["a", "b"], max_entries=2)
    changed = builtin_module.merge_watch_clipboard_passwords(["c"], max_entries=2)

    text = builtin_path.read_text(encoding="utf-8")
    assert changed is True
    assert "\na\n" not in text
    assert "\nb\n" in text
    assert "\nc\n" in text
