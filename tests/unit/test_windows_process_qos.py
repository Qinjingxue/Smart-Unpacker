from __future__ import annotations

import sunpack.platform.windows.process_qos as process_qos


class _FakeFunction:
    def __init__(self, callback):
        self.callback = callback
        self.argtypes = None
        self.restype = None

    def __call__(self, *args):
        return self.callback(*args)


def test_background_mode_is_preferred_on_windows(monkeypatch):
    calls = []
    kernel32 = type(
        "Kernel32",
        (),
        {
            "GetCurrentProcess": _FakeFunction(lambda: 123),
            "SetPriorityClass": _FakeFunction(lambda process, priority: calls.append((process, priority)) or True),
        },
    )()
    monkeypatch.setattr(process_qos.sys, "platform", "win32")
    monkeypatch.setattr(process_qos.ctypes, "WinDLL", lambda *_args, **_kwargs: kernel32, raising=False)

    assert process_qos.enter_background_processing() == "background"
    assert calls == [(123, process_qos.PROCESS_MODE_BACKGROUND_BEGIN)]


def test_background_mode_falls_back_to_below_normal(monkeypatch):
    calls = []
    kernel32 = type(
        "Kernel32",
        (),
        {
            "GetCurrentProcess": _FakeFunction(lambda: 123),
            "SetPriorityClass": _FakeFunction(
                lambda process, priority: calls.append((process, priority)) or priority == process_qos.BELOW_NORMAL_PRIORITY_CLASS
            ),
        },
    )()
    monkeypatch.setattr(process_qos.sys, "platform", "win32")
    monkeypatch.setattr(process_qos.ctypes, "WinDLL", lambda *_args, **_kwargs: kernel32, raising=False)

    assert process_qos.enter_background_processing() == "below_normal"
    assert calls == [
        (123, process_qos.PROCESS_MODE_BACKGROUND_BEGIN),
        (123, process_qos.BELOW_NORMAL_PRIORITY_CLASS),
    ]


def test_background_mode_is_noop_off_windows(monkeypatch):
    monkeypatch.setattr(process_qos.sys, "platform", "linux")

    assert process_qos.enter_background_processing() == "unsupported"
