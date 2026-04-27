from typing import Any


DEFAULT_REPAIR_CONFIG = {
    "enabled": True,
    "workspace": ".smart_unpacker_repair",
    "keep_candidates": False,
    "max_modules_per_job": 4,
    "trigger_on_medium_confidence": True,
    "trigger_on_extraction_failure": True,
    "thresholds": {
        "medium_confidence_min": 0.35,
        "extractable_confidence": 0.85,
    },
    "stages": {
        "targeted": True,
        "safe_repair": True,
        "deep": False,
    },
    "modules": [
        {"name": "zip_eocd_repair", "enabled": True},
        {"name": "zip_comment_length_fix", "enabled": True},
        {"name": "zip_central_directory_count_fix", "enabled": True},
        {"name": "zip_central_directory_offset_fix", "enabled": True},
        {"name": "zip_trailing_junk_trim", "enabled": True},
        {"name": "zip_central_directory_rebuild", "enabled": True},
        {"name": "zip_data_descriptor_recovery", "enabled": True},
        {"name": "zip_partial_recovery", "enabled": True},
        {"name": "tar_header_checksum_fix", "enabled": True},
        {"name": "tar_trailing_junk_trim", "enabled": True},
        {"name": "tar_trailing_zero_block_repair", "enabled": True},
        {"name": "gzip_trailing_junk_trim", "enabled": True},
        {"name": "gzip_footer_fix", "enabled": True},
        {"name": "bzip2_trailing_junk_trim", "enabled": True},
        {"name": "xz_trailing_junk_trim", "enabled": True},
        {"name": "zstd_trailing_junk_trim", "enabled": True},
        {"name": "seven_zip_start_header_crc_fix", "enabled": True},
        {"name": "seven_zip_boundary_trim", "enabled": True},
        {"name": "rar_trailing_junk_trim", "enabled": True},
        {"name": "zip_boundary", "enabled": True},
        {"name": "zip_directory", "enabled": True},
        {"name": "seven_zip_boundary", "enabled": True},
        {"name": "rar_boundary", "enabled": True},
        {"name": "tar_boundary", "enabled": True},
        {"name": "gzip_boundary", "enabled": True},
        {"name": "bzip2_boundary", "enabled": True},
        {"name": "xz_boundary", "enabled": True},
        {"name": "zstd_boundary", "enabled": True},
    ],
}


def repair_config(config: dict[str, Any] | None) -> dict[str, Any]:
    payload = dict((config or {}).get("repair") or {})
    return _merge(DEFAULT_REPAIR_CONFIG, payload)


def enabled_module_configs(config: dict[str, Any]) -> dict[str, dict[str, Any]]:
    modules = config.get("modules")
    if not isinstance(modules, list):
        return {}
    result = {}
    for item in modules:
        if not isinstance(item, dict) or not item.get("enabled", False):
            continue
        name = item.get("name")
        if isinstance(name, str) and name.strip():
            result[name.strip()] = {
                key: value
                for key, value in item.items()
                if key not in {"name", "enabled"}
            }
    return result


def _merge(base: dict, override: dict) -> dict:
    result = dict(base)
    for key, value in override.items():
        if isinstance(value, dict) and isinstance(result.get(key), dict):
            result[key] = _merge(result[key], value)
        else:
            result[key] = value
    return result
