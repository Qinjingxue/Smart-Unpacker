from __future__ import annotations

import sunpack.gui.main as gui_main
import sunpack.platform.windows.process_qos as process_qos


def test_watch_gui_main_applies_background_mode_and_forwards_options(monkeypatch, tmp_path):
    captured = {}
    monkeypatch.setattr(gui_main, "_request_watch_elevation", lambda _args: False)
    monkeypatch.setattr(gui_main, "runtime_working_directory", lambda: str(tmp_path))
    monkeypatch.setattr(gui_main.os, "chdir", lambda path: captured.setdefault("cwd", path))
    monkeypatch.setattr(process_qos, "enter_background_processing", lambda: captured.setdefault("qos", "background"))
    monkeypatch.setattr(
        gui_main,
        "_run_watch_service",
        lambda *, once, no_tray, initial_scan: captured.update(
            once=once,
            no_tray=no_tray,
            initial_scan=initial_scan,
        ) or 7,
    )

    assert gui_main.main(["--once", "--no-tray"]) == 7
    assert captured == {
        "cwd": str(tmp_path),
        "qos": "background",
        "once": True,
        "no_tray": True,
        "initial_scan": False,
    }


def test_watch_gui_main_stops_after_elevation_request(monkeypatch):
    monkeypatch.setattr(gui_main, "_request_watch_elevation", lambda _args: True)
    monkeypatch.setattr(gui_main, "_run_watch_service", lambda **_kwargs: (_ for _ in ()).throw(AssertionError()))

    assert gui_main.main([]) == 0


def test_watch_gui_elevation_relaunch_preserves_launch_options(monkeypatch, tmp_path):
    captured = {}
    import sunpack.gui.launcher as launcher
    import sunpack.platform.windows.elevation as elevation

    def build_argv(**kwargs):
        captured["launch_kwargs"] = kwargs
        return ["sunpack-watch.exe", "--once", "--no-tray"]

    monkeypatch.setattr(gui_main, "runtime_working_directory", lambda: str(tmp_path))
    monkeypatch.setattr(
        launcher,
        "watch_launch_argv",
        build_argv,
    )
    monkeypatch.setattr(
        elevation,
        "relaunch_elevated",
        lambda argv, *, cwd: captured.update(argv=argv, cwd=cwd) or True,
    )

    assert gui_main._request_watch_elevation(gui_main._parse_args(["--once", "--no-tray"]))
    assert captured == {
        "launch_kwargs": {
            "once": True,
            "no_tray": True,
            "initial_scan": False,
            "prefer_windowed_python": True,
        },
        "argv": ["sunpack-watch.exe", "--once", "--no-tray"],
        "cwd": str(tmp_path),
    }
