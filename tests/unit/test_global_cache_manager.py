from types import SimpleNamespace

from sunpack.support.global_cache_manager import cached_readonly_command, clear_cache_namespace


def test_cached_readonly_command_reuses_result_for_unchanged_file(tmp_path):
    clear_cache_namespace("external_command")
    target = tmp_path / "archive.zip"
    target.write_bytes(b"zip")
    calls = []

    def runner(cmd, **kwargs):
        calls.append(cmd)
        return SimpleNamespace(args=cmd, returncode=0, stdout="ok", stderr="")

    first = cached_readonly_command(["7z", "t", str(target)], str(target), runner)
    second = cached_readonly_command(["7z", "t", str(target)], str(target), runner)

    assert first.returncode == 0
    assert second.stdout == "ok"
    assert len(calls) == 1


def test_cached_readonly_command_invalidates_when_file_changes(tmp_path):
    clear_cache_namespace("external_command")
    target = tmp_path / "archive.zip"
    target.write_bytes(b"one")
    calls = []

    def runner(cmd, **kwargs):
        calls.append(cmd)
        return SimpleNamespace(args=cmd, returncode=0, stdout=str(len(calls)), stderr="")

    first = cached_readonly_command(["7z", "t", str(target)], str(target), runner)
    target.write_bytes(b"two-two")
    second = cached_readonly_command(["7z", "t", str(target)], str(target), runner)

    assert first.stdout == "1"
    assert second.stdout == "2"
    assert len(calls) == 2


def test_cached_readonly_command_keeps_distinct_commands_separate(tmp_path):
    clear_cache_namespace("external_command")
    target = tmp_path / "archive.zip"
    target.write_bytes(b"zip")
    calls = []

    def runner(cmd, **kwargs):
        calls.append(cmd)
        return SimpleNamespace(args=cmd, returncode=0, stdout=cmd[1], stderr="")

    test_result = cached_readonly_command(["7z", "t", str(target)], str(target), runner)
    list_result = cached_readonly_command(["7z", "l", str(target)], str(target), runner)

    assert test_result.stdout == "t"
    assert list_result.stdout == "l"
    assert len(calls) == 2
