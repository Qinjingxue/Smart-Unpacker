import sunpack.platform.windows.startup as startup_module


def test_startup_command_launches_packaged_executable_in_hidden_window(tmp_path, monkeypatch):
    executable = tmp_path / "SunPack Folder" / "sunpack-runtime.exe"
    monkeypatch.setattr(
        startup_module,
        "watch_launch_argv",
        lambda **_kwargs: [str(executable), "--_sunpack-mode=watch"],
    )

    command = startup_module.startup_command()

    assert command == f'"{executable}" --_sunpack-mode=watch'
