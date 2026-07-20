import json

import sunpack.gui.main as gui_main


def test_gui_main_runs_shared_watch_service(monkeypatch):
    calls = []
    monkeypatch.setattr(gui_main, "_request_watch_elevation", lambda: False)
    monkeypatch.setattr(gui_main, "_run_watch_service", lambda: calls.append("run") or 0)

    assert gui_main.main() == 0
    assert calls == ["run"]


def test_gui_main_logs_bootstrap_failure(tmp_path, monkeypatch):
    def fail():
        raise RuntimeError("startup failed")

    monkeypatch.setattr(gui_main, "_request_watch_elevation", lambda: False)
    monkeypatch.setattr(gui_main, "_run_watch_service", fail)
    monkeypatch.setattr(gui_main, "get_resource_path", lambda _name: tmp_path / ".sunpack_watch")

    assert gui_main.main() == 1
    record = json.loads((tmp_path / ".sunpack_watch" / "events.jsonl").read_text(encoding="utf-8"))
    assert record["event"] == "gui_bootstrap_error"
    assert record["error_type"] == "RuntimeError"
    assert record["error"] == "startup failed"


def test_gui_main_exits_after_elevated_relaunch(monkeypatch):
    calls = []
    monkeypatch.setattr(gui_main, "_request_watch_elevation", lambda: True)
    monkeypatch.setattr(gui_main, "_run_watch_service", lambda: calls.append("run") or 0)

    assert gui_main.main() == 0
    assert calls == []
