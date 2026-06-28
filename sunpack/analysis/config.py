from typing import Any

DEFAULT_ANALYSIS_CONFIG = {
    "enabled": True,
    "parallel": True,
    "max_workers": 3,
    "max_concurrent_reads": 1,
    "shared_cache_mb": 64,
    "max_read_mb_per_archive": 256,
    "prepass": {
        "enabled": True,
        "head_bytes": 1024 * 1024,
        "tail_bytes": 1024 * 1024,
        # Full-file signature discovery is a second-stage fallback only.  It
        # is enabled explicitly by callers (notably detection rescue), so the
        # normal archive path remains bounded to head/tail reads.
        "full_scan_max_bytes": 0,
        "deep_scan": False,
        "full_scan_chunk_bytes": 4 * 1024 * 1024,
        "full_scan_max_hits": 256,
    },
    "fuzzy": {
        "enabled": True,
        "modules": [
            {
                "name": "binary_profile",
                "enabled": True,
                "window_bytes": 64 * 1024,
                "max_windows": 8,
                "max_sample_bytes": 1024 * 1024,
                "entropy_high_threshold": 6.8,
                "entropy_low_threshold": 3.5,
                "entropy_jump_threshold": 1.25,
                "ngram_top_k": 8,
                "max_ngram_sample_bytes": 256 * 1024,
            },
        ],
    },
    "thresholds": {
        "extractable_confidence": 0.85,
        "repair_confidence": 0.35,
    },
    "modules": [
        {"name": "zip", "enabled": True},
        {"name": "rar", "enabled": True},
        {"name": "seven_zip", "enabled": True},
        {"name": "tar", "enabled": True},
        {"name": "gzip", "enabled": True},
        {"name": "bzip2", "enabled": True},
        {"name": "xz", "enabled": True},
        {"name": "zstd", "enabled": True},
        {"name": "tar_gz", "enabled": True},
        {"name": "tar_bz2", "enabled": True},
        {"name": "tar_xz", "enabled": True},
        {"name": "tar_zst", "enabled": True},
    ],
}


def analysis_config(config: dict[str, Any] | None) -> dict[str, Any]:
    payload = dict((config or {}).get("analysis") or {})
    return _merge(DEFAULT_ANALYSIS_CONFIG, payload)


def enabled_fuzzy_module_configs(config: dict[str, Any]) -> dict[str, dict[str, Any]]:
    fuzzy = config.get("fuzzy") if isinstance(config.get("fuzzy"), dict) else {}
    modules = fuzzy.get("modules")
    if not isinstance(modules, list):
        return {}
    result = {}
    for item in modules:
        if not isinstance(item, dict) or not item.get("enabled", False):
            continue
        name = item.get("name")
        if isinstance(name, str) and name.strip():
            result[name.strip()] = {key: value for key, value in item.items() if key not in {"name", "enabled"}}
    return result


def _merge(base: dict, override: dict) -> dict:
    result = dict(base)
    for key, value in override.items():
        if isinstance(value, dict) and isinstance(result.get(key), dict):
            result[key] = _merge(result[key], value)
        else:
            result[key] = value
    return result
