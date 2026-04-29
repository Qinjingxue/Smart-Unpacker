import json
import os
from pathlib import Path


def _repo_root() -> Path:
    return Path(__file__).resolve().parents[2]


def _config_path() -> Path:
    return Path(__file__).resolve().parents[1] / "test_tools.json"


def _resolve_tool(value: str | None, repo_root: Path) -> Path | None:
    if not value:
        return None
    expanded = os.path.expandvars(value)
    path = Path(expanded)
    if not path.is_absolute():
        path = repo_root / path
    return path.resolve()


def get_test_tools() -> dict[str, Path | None]:
    repo_root = _repo_root()
    config = {}
    path = _config_path()
    if path.exists():
        config = json.loads(path.read_text(encoding="utf-8"))

    seven_zip = os.environ.get("packrelic_TEST_7Z") or config.get("seven_zip") or "tools/7z.exe"
    seven_zip_sfx = os.environ.get("packrelic_TEST_7Z_SFX") or config.get("seven_zip_sfx") or "tools/7zCon.sfx"
    zstd_exe = os.environ.get("packrelic_TEST_ZSTD") or config.get("zstd_exe") or "tools/zstd.exe"
    rar_exe = os.environ.get("packrelic_TEST_RAR") or config.get("rar_exe")

    return {
        "seven_zip": _resolve_tool(seven_zip, repo_root),
        "seven_zip_sfx": _resolve_tool(seven_zip_sfx, repo_root),
        "zstd_exe": _resolve_tool(zstd_exe, repo_root),
        "rar_exe": _resolve_tool(rar_exe, repo_root),
    }


def require_7z() -> Path:
    seven_zip = get_test_tools()["seven_zip"]
    if not seven_zip or not seven_zip.is_file():
        raise FileNotFoundError("7z.exe is required for this test. Configure tests/test_tools.json or packrelic_TEST_7Z.")
    return seven_zip


def require_zstd() -> Path:
    zstd_exe = get_test_tools()["zstd_exe"]
    if not zstd_exe or not zstd_exe.is_file():
        raise FileNotFoundError("zstd.exe is required for this test. Configure tests/test_tools.json or packrelic_TEST_ZSTD.")
    return zstd_exe


def get_optional_rar() -> Path | None:
    rar = get_test_tools()["rar_exe"]
    return rar if rar and rar.is_file() else None
