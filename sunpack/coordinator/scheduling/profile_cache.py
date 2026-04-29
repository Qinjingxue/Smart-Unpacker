import json
import os
import time
from pathlib import Path


PROFILE_CACHE_VERSION = 3


def resolve_profile_calibration_cache_path(configured_path) -> Path:
    if configured_path:
        return Path(configured_path)
    project_root = Path(__file__).resolve().parents[3]
    return project_root / ".sunpack_cache" / "profile_calibration.json"


def load_profile_adjustments(cache_path: Path, max_delta: int, enabled: bool = True) -> dict[str, dict[str, int]]:
    if not enabled:
        return {}
    try:
        payload = json.loads(cache_path.read_text(encoding="utf-8"))
    except Exception:
        return {}
    if not isinstance(payload, dict) or payload.get("version") != PROFILE_CACHE_VERSION:
        return {}
    profiles = payload.get("profiles", {})
    if not isinstance(profiles, dict):
        return {}
    loaded: dict[str, dict[str, int]] = {}
    for profile_key, adjustment in profiles.items():
        if not isinstance(profile_key, str) or not isinstance(adjustment, dict):
            continue
        try:
            loaded[profile_key] = clean_profile_adjustment(adjustment, max_delta)
        except Exception:
            continue
    return loaded


def save_profile_adjustments(cache_path: Path, profiles: dict[str, dict[str, int]]) -> None:
    payload = {
        "version": PROFILE_CACHE_VERSION,
        "updated_at": int(time.time()),
        "profiles": profiles,
    }
    cache_path.parent.mkdir(parents=True, exist_ok=True)
    temporary_path = cache_path.with_suffix(cache_path.suffix + ".tmp")
    temporary_path.write_text(json.dumps(payload, ensure_ascii=False, indent=2, sort_keys=True), encoding="utf-8")
    os.replace(temporary_path, cache_path)


def clean_profile_adjustment(adjustment: dict[str, int], max_delta: int) -> dict[str, int]:
    return {
        "cpu": max(-1, min(max_delta, int(adjustment.get("cpu", 0)))),
        "io": max(-1, min(max_delta, int(adjustment.get("io", 0)))),
        "memory": max(0, min(max_delta, int(adjustment.get("memory", 0)))),
    }
