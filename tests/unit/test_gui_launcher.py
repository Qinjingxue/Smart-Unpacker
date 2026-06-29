import sunpack.gui.launcher as launcher_module


def test_packaged_watch_launcher_uses_sibling_gui_executable(tmp_path, monkeypatch):
    cli_executable = tmp_path / "sunpack.exe"
    watch_executable = tmp_path / launcher_module.WATCH_EXECUTABLE_NAME
    watch_executable.write_bytes(b"")
    monkeypatch.setattr(launcher_module.sys, "executable", str(cli_executable))

    assert launcher_module.watch_launch_argv() == [str(watch_executable.resolve())]


def test_source_watch_launcher_uses_gui_module(tmp_path, monkeypatch):
    python = tmp_path / "python.exe"
    monkeypatch.setattr(launcher_module.sys, "executable", str(python))
    monkeypatch.setattr(launcher_module, "packaged_watch_executable", lambda *_args, **_kwargs: None)

    assert launcher_module.watch_launch_argv() == [str(python.resolve()), "-m", "sunpack.gui"]


def test_source_startup_prefers_pythonw(tmp_path, monkeypatch):
    python = tmp_path / "python.exe"
    pythonw = tmp_path / "pythonw.exe"
    pythonw.write_bytes(b"")
    monkeypatch.setattr(launcher_module.sys, "executable", str(python))
    monkeypatch.setattr(launcher_module, "packaged_watch_executable", lambda *_args, **_kwargs: None)

    assert launcher_module.watch_launch_argv(prefer_windowed_python=True) == [
        str(pythonw.resolve()),
        "-m",
        "sunpack.gui",
    ]
