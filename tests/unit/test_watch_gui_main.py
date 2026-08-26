from __future__ import annotations

import sunpack.gui.main as gui_main
import sunpack.platform.windows.process_qos as process_qos


def test_watch_gui_main_applies_background_mode_and_forwards_options(monkeypatch, tmp_path):
    captured = {}
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
