from types import SimpleNamespace
from unittest.mock import patch

from smart_unpacker.extraction.internal.password_manager import PasswordManager


def test_password_order_matches_user_recent_builtin():
    manager = PasswordManager(cli_passwords=["user", "dup"], builtin_passwords=["builtin", "dup"])
    manager.add_recent_password("recent")

    assert manager.get_passwords_to_try() == ["user", "dup", "recent", "builtin"]


def test_successful_non_empty_password_moves_to_recent_front():
    manager = PasswordManager(cli_passwords=["first", "second"], builtin_passwords=[])
    failed = SimpleNamespace(returncode=2, stdout="", stderr="wrong password")
    succeeded = SimpleNamespace(returncode=0, stdout="", stderr="")

    with patch("smart_unpacker.extraction.internal.password_manager.subprocess.run", side_effect=[failed, succeeded]):
        password, _, error = manager.find_working_password("archive.7z")

    assert password == "second"
    assert error == ""
    assert manager.recent_passwords == ["second"]


def test_password_search_stops_on_archive_damage_signal():
    manager = PasswordManager(cli_passwords=["wrong", "never-used"], builtin_passwords=[])
    damaged = SimpleNamespace(returncode=2, stdout="", stderr="Unexpected end of archive")

    with patch("smart_unpacker.extraction.internal.password_manager.subprocess.run", return_value=damaged) as run:
        password, result, error = manager.find_working_password("archive.7z")

    assert password == "wrong"
    assert result is damaged
    assert "unexpected end of archive" in error
    assert run.call_count == 1
