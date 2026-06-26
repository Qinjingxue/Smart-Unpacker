from __future__ import annotations

from types import SimpleNamespace

import sunpack.filesystem.watcher.service as service_module
import sunpack.platform.windows.tray as tray_module
from sunpack.platform.windows.tray import WindowsTrayIcon, _tray_language_from_service


def test_tray_open_watch_roots_file_creates_and_opens_txt(tmp_path, monkeypatch):
    roots_path = tmp_path / "sunpack_watch_roots.txt"
    opened = []
    tray = object.__new__(WindowsTrayIcon)
    tray._open_path = opened.append
    monkeypatch.setattr(service_module, "watch_roots_path", lambda: roots_path)
    monkeypatch.setattr(tray_module, "watch_roots_path", lambda: roots_path)

    tray._open_watch_roots_file()

    assert roots_path.exists()
    assert opened == [str(roots_path)]


def test_tray_uses_chinese_text_when_cli_language_is_zh():
    service = SimpleNamespace(config={"cli": {"language": "zh"}})

    assert _tray_language_from_service(service) == "zh"

    tray = object.__new__(WindowsTrayIcon)
    tray.language = "zh"

    assert tray._text("open_config") == "打开配置文件"
    assert tray._text("open_watch_roots") == "打开监控目录列表"
    assert tray._text("exit") == "退出"


def test_tray_defaults_to_english_text():
    service = SimpleNamespace(config={"cli": {"language": "en"}})

    assert _tray_language_from_service(service) == "en"

    tray = object.__new__(WindowsTrayIcon)
    tray.language = "en"

    assert tray._text("open_config") == "Open config"
    assert tray._text("open_watch_roots") == "Open watch folders file"
    assert tray._text("exit") == "Exit"
