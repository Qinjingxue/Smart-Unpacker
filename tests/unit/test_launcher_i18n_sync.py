import re
from pathlib import Path

from sunpack.i18n.catalog import CATALOG


REPO_ROOT = Path(__file__).resolve().parents[2]
LAUNCHER_SOURCE = REPO_ROOT / "native" / "sevenzip_bridge" / "src" / "launcher.cpp"

# Localized strings printed directly by the C++ launcher. The constant names
# must match the declarations in launcher.cpp; the catalog keys must match the
# comment next to those declarations.
LAUNCHER_LITERALS = {
    "cli.press_enter": ("kPressEnterEn", "kPressEnterZh"),
    "cli.persistent_start_timeout": ("kPersistentTimeoutEn", "kPersistentTimeoutZh"),
}


def _launcher_literal(source: str, name: str) -> str:
    match = re.search(rf'\b{name}\b\s*\[\]\s*=\s*L"([^"]*)"', source)
    assert match is not None, f"launcher.cpp is missing localized literal {name}"
    return match.group(1)


def test_launcher_localized_strings_match_i18n_catalog():
    source = LAUNCHER_SOURCE.read_text(encoding="utf-8")
    for key, (english_name, chinese_name) in LAUNCHER_LITERALS.items():
        assert key in CATALOG["en"], f"catalog is missing English key {key}"
        assert key in CATALOG["zh"], f"catalog is missing Chinese key {key}"
        assert _launcher_literal(source, english_name) == CATALOG["en"][key]
        assert _launcher_literal(source, chinese_name) == CATALOG["zh"][key]


def test_launcher_no_longer_prints_hardcoded_messages():
    source = LAUNCHER_SOURCE.read_text(encoding="utf-8")
    assert 'write_stream(STD_OUTPUT_HANDLE, "Press Enter to continue...")' not in source
    assert 'write_stream(STD_ERROR_HANDLE, "SunPack persistent process did not start in time.\\n")' not in source
