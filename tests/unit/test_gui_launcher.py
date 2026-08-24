import sunpack.gui.launcher as launcher_module
from sunpack.support import runtime_identity


def test_packaged_watch_launcher_uses_shared_runtime_with_watch_mode(tmp_path, monkeypatch):
    cli_executable = tmp_path / "sunpack.exe"
    runtime_executable = tmp_path / launcher_module.RUNTIME_EXECUTABLE_NAME
    runtime_executable.write_bytes(b"")
    monkeypatch.setattr(launcher_module.sys, "executable", str(cli_executable))

    assert launcher_module.watch_launch_argv(once=True, no_tray=True) == [
        str(runtime_executable.resolve()),
        "--_sunpack-mode=watch",
        "--once",
        "--no-tray",
    ]


def test_source_watch_launcher_uses_gui_module(tmp_path, monkeypatch):
    python = tmp_path / "python.exe"
    monkeypatch.setattr(launcher_module.sys, "executable", str(python))
    monkeypatch.setattr(launcher_module, "packaged_runtime_executable", lambda *_args, **_kwargs: None)

    assert launcher_module.watch_launch_argv(once=True) == [
        str(python.resolve()),
        "-m",
        "sunpack.gui",
        "--once",
    ]


def test_source_startup_prefers_pythonw(tmp_path, monkeypatch):
    python = tmp_path / "python.exe"
    pythonw = tmp_path / "pythonw.exe"
    pythonw.write_bytes(b"")
    monkeypatch.setattr(launcher_module.sys, "executable", str(python))
    monkeypatch.setattr(launcher_module, "packaged_runtime_executable", lambda *_args, **_kwargs: None)

    assert launcher_module.watch_launch_argv(prefer_windowed_python=True) == [
        str(pythonw.resolve()),
        "-m",
        "sunpack.gui",
    ]


def test_watch_launcher_forwards_runtime_identity(monkeypatch):
    monkeypatch.setattr(runtime_identity, "_runtime_id", "v2-0123456789abcdef")
    monkeypatch.setattr(launcher_module, "packaged_runtime_executable", lambda *_args, **_kwargs: None)
    monkeypatch.setattr(launcher_module.sys, "executable", r"C:\Python310\python.exe")

    assert launcher_module.watch_launch_argv(once=True) == [
        r"C:\Python310\python.exe",
        "-m",
        "sunpack.gui",
        "--_sunpack-runtime-id=v2-0123456789abcdef",
        "--once",
    ]


def test_watch_launcher_forwards_initial_scan(monkeypatch):
    monkeypatch.setattr(runtime_identity, "_runtime_id", None)
    monkeypatch.setattr(launcher_module, "packaged_runtime_executable", lambda *_args, **_kwargs: None)
    monkeypatch.setattr(launcher_module.sys, "executable", r"C:\Python310\python.exe")

    assert launcher_module.watch_launch_argv(initial_scan=True) == [
        r"C:\Python310\python.exe",
        "-m",
        "sunpack.gui",
        "--initial-scan",
    ]
