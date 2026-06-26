from __future__ import annotations

import json
import os
from pathlib import Path
import subprocess
import tempfile
import threading
import time


_CACHE_VERSION = 1
_CACHE_MAX_AGE_SECONDS = 30 * 24 * 60 * 60
_CACHE_LOCK = threading.Lock()
_MEMORY_CACHE: dict[str, bool] = {}


def detect_max_workers() -> int:
    cpu_count = os.cpu_count() or 4
    return max(2, cpu_count) if _cached_is_ssd() else 2


def resolve_max_workers() -> int:
    return max(1, detect_max_workers())


def _cached_is_ssd() -> bool:
    cache_path = _cache_path()
    key = str(cache_path)
    with _CACHE_LOCK:
        if key in _MEMORY_CACHE:
            return _MEMORY_CACHE[key]
        cached = _read_cache(cache_path)
        if cached is None:
            cached = _probe_is_ssd()
            _write_cache(cache_path, cached)
        _MEMORY_CACHE[key] = cached
        return cached


def _cache_path() -> Path:
    override = os.environ.get("SUNPACK_MACHINE_PROBE_CACHE")
    if override:
        return Path(override)
    root = os.environ.get("LOCALAPPDATA") or tempfile.gettempdir()
    return Path(root) / "SunPack" / "cache" / "machine_probe.json"


def _read_cache(path: Path) -> bool | None:
    try:
        payload = json.loads(path.read_text(encoding="utf-8"))
        age = time.time() - float(payload.get("detected_at", 0))
        if int(payload.get("version", 0)) != _CACHE_VERSION or age < 0 or age > _CACHE_MAX_AGE_SECONDS:
            return None
        return bool(payload["is_ssd"])
    except (OSError, ValueError, TypeError, KeyError, json.JSONDecodeError):
        return None


def _probe_is_ssd() -> bool:
    try:
        result = subprocess.run(
            [
                "powershell",
                "-NoLogo",
                "-NoProfile",
                "-NonInteractive",
                "-Command",
                "Get-PhysicalDisk | Select-Object -ExpandProperty MediaType",
            ],
            capture_output=True,
            text=True,
            stdin=subprocess.DEVNULL,
            timeout=5,
            creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0),
        )
        return result.returncode == 0 and "SSD" in result.stdout.upper()
    except (OSError, subprocess.SubprocessError):
        return False


def _write_cache(path: Path, is_ssd: bool) -> None:
    try:
        path.parent.mkdir(parents=True, exist_ok=True)
        temporary = path.with_suffix(path.suffix + f".{os.getpid()}.tmp")
        temporary.write_text(
            json.dumps({
                "version": _CACHE_VERSION,
                "detected_at": time.time(),
                "is_ssd": bool(is_ssd),
            }, ensure_ascii=False, separators=(",", ":")),
            encoding="utf-8",
        )
        os.replace(temporary, path)
    except OSError:
        pass
