from __future__ import annotations

import sunpack.platform.windows.elevation as elevation


def test_elevated_relaunch_quotes_arguments_and_reports_success(monkeypatch):
    captured = {}
    monkeypatch.setattr(elevation.sys, "platform", "win32")
    monkeypatch.setattr(elevation, "is_process_elevated", lambda: False)
    monkeypatch.setattr(
        elevation,
        "_shell_execute_runas",
        lambda executable, parameters, cwd: captured.update(
            executable=executable,
            parameters=parameters,
            cwd=cwd,
        )
        or 42,
    )

    assert elevation.relaunch_elevated(
        [r"C:\Program Files\SunPack\sunpack-watch.exe", "--value", "two words"],
        cwd=r"C:\Program Files\SunPack",
    )
    assert captured == {
        "executable": r"C:\Program Files\SunPack\sunpack-watch.exe",
        "parameters": '--value "two words"',
        "cwd": r"C:\Program Files\SunPack",
    }


def test_rejected_uac_prompt_falls_back_to_current_process(monkeypatch):
    monkeypatch.setattr(elevation.sys, "platform", "win32")
    monkeypatch.setattr(elevation, "is_process_elevated", lambda: False)
    monkeypatch.setattr(elevation, "_shell_execute_runas", lambda *_args: 5)

    assert not elevation.relaunch_elevated(["sunpack-watch.exe"])


def test_already_elevated_process_does_not_relaunch(monkeypatch):
    calls = []
    monkeypatch.setattr(elevation.sys, "platform", "win32")
    monkeypatch.setattr(elevation, "is_process_elevated", lambda: True)
    monkeypatch.setattr(elevation, "_shell_execute_runas", lambda *_args: calls.append(True) or 42)

    assert not elevation.relaunch_elevated(["sunpack-watch.exe"])
    assert calls == []
