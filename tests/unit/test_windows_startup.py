import sunpack.platform.windows.startup as startup_module


def test_startup_command_launches_packaged_executable_in_hidden_window(tmp_path, monkeypatch):
    executable = tmp_path / "SunPack Folder" / "sunpack-watch.exe"
    monkeypatch.setattr(startup_module, "watch_launch_argv", lambda **_kwargs: [str(executable)])

    command = startup_module.startup_command()

    assert command == f'"{executable}"'
