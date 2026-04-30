from copy import deepcopy
from typing import Any


DEFAULT_REPAIR_CONFIG = {
    "enabled": True,
    "workspace": ".sunpack_repair",
    "keep_candidates": False,
    "max_modules_per_job": 4,
    "max_attempts_per_task": 3,
    "max_repair_rounds_per_task": 3,
    "max_repair_seconds_per_task": 120.0,
    "max_repair_generated_files_per_task": 16,
    "max_repair_generated_mb_per_task": 2048.0,
    "stages": {
        "targeted": True,
        "safe_repair": True,
        "deep": False,
    },
    "safety": {
        "allow_unsafe": False,
        "allow_partial": True,
        "allow_lossy": False,
    },
    "deep": {
        "max_candidates_per_module": 3,
        "max_entries": 20000,
        "max_seconds_per_module": 30.0,
        "max_input_size_mb": 512,
        "max_output_size_mb": 2048,
        "max_entry_uncompressed_mb": 512,
        "verify_candidates": True,
    },
    "auto_deep": {
        "enabled": True,
        "require_verification_repair": True,
        "max_modules": 2,
        "max_candidates_per_module": 1,
        "max_input_size_mb": 128,
    },
    "beam": {
        "enabled": True,
        "beam_width": 4,
        "max_candidates_per_state": 4,
        "max_analyze_candidates": 8,
        "max_assess_candidates": 4,
        "max_rounds": 3,
        "min_improvement": 0.01,
    },
    "telemetry": {
        "enabled": False,
    },
    "modules": [
        {"name": "zip_eocd_repair", "enabled": True},
        {"name": "zip_comment_length_fix", "enabled": True},
        {"name": "zip_central_directory_count_fix", "enabled": True},
        {"name": "zip_central_directory_offset_fix", "enabled": True},
        {"name": "zip64_field_repair", "enabled": True},
        {"name": "zip_local_header_field_repair", "enabled": True},
        {"name": "zip_trailing_junk_trim", "enabled": True},
        {"name": "zip_central_directory_rebuild", "enabled": True},
        {"name": "zip_data_descriptor_recovery", "enabled": True},
        {"name": "zip_entry_quarantine_rebuild", "enabled": True},
        {"name": "zip_partial_recovery", "enabled": True},
        {"name": "zip_deep_partial_recovery", "enabled": True},
        {"name": "zip_missing_volume_partial_salvage", "enabled": True},
        {"name": "zip_conflict_resolver_rebuild", "enabled": True},
        {"name": "tar_header_checksum_fix", "enabled": True},
        {"name": "tar_truncated_partial_recovery", "enabled": True},
        {"name": "tar_metadata_downgrade_recovery", "enabled": True},
        {"name": "tar_sparse_pax_longname_repair", "enabled": True},
        {"name": "tar_trailing_junk_trim", "enabled": True},
        {"name": "tar_trailing_zero_block_repair", "enabled": True},
        {"name": "gzip_trailing_junk_trim", "enabled": True},
        {"name": "gzip_footer_fix", "enabled": True},
        {"name": "gzip_deflate_member_resync", "enabled": True},
        {"name": "gzip_deflate_prefix_salvage", "enabled": True},
        {"name": "gzip_truncated_partial_recovery", "enabled": True},
        {"name": "tar_gzip_truncated_partial_recovery", "enabled": True},
        {"name": "bzip2_trailing_junk_trim", "enabled": True},
        {"name": "bzip2_block_salvage", "enabled": True},
        {"name": "bzip2_truncated_partial_recovery", "enabled": True},
        {"name": "tar_bzip2_truncated_partial_recovery", "enabled": True},
        {"name": "xz_trailing_junk_trim", "enabled": True},
        {"name": "xz_block_salvage", "enabled": True},
        {"name": "xz_truncated_partial_recovery", "enabled": True},
        {"name": "tar_xz_truncated_partial_recovery", "enabled": True},
        {"name": "zstd_trailing_junk_trim", "enabled": True},
        {"name": "zstd_frame_salvage", "enabled": True},
        {"name": "zstd_truncated_partial_recovery", "enabled": True},
        {"name": "tar_zstd_truncated_partial_recovery", "enabled": True},
        {"name": "archive_carrier_crop_deep_recovery", "enabled": True},
        {"name": "archive_nested_payload_salvage", "enabled": True},
        {"name": "seven_zip_start_header_crc_fix", "enabled": True},
        {"name": "seven_zip_next_header_field_repair", "enabled": True},
        {"name": "seven_zip_boundary_trim", "enabled": True},
        {"name": "seven_zip_precise_boundary_repair", "enabled": True},
        {"name": "seven_zip_crc_field_repair", "enabled": True},
        {"name": "seven_zip_solid_block_partial_salvage", "enabled": True},
        {"name": "seven_zip_non_solid_partial_salvage", "enabled": True},
        {"name": "rar_trailing_junk_trim", "enabled": True},
        {"name": "rar_carrier_crop_deep_recovery", "enabled": True},
        {"name": "rar_block_chain_trim", "enabled": True},
        {"name": "rar_end_block_repair", "enabled": True},
        {"name": "rar_file_quarantine_rebuild", "enabled": True},
        {"name": "rar4_file_quarantine_rebuild", "enabled": True},
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
    return normalize_repair_config(payload)


def normalize_repair_config(value: Any) -> dict[str, Any]:
    if value is None:
        value = {}
    if not isinstance(value, dict):
        raise ValueError("repair must be an object")
    if "trigger_on_medium_confidence" in value:
        raise ValueError("repair.trigger_on_medium_confidence was removed; repair now runs after extraction verification")
    if "thresholds" in value:
        raise ValueError("repair.thresholds was removed; analysis confidence no longer triggers repair directly")
    if "trigger_on_extraction_failure" in value:
        raise ValueError("repair.trigger_on_extraction_failure was removed; repair now runs from verification decisions")
    config = _merge(DEFAULT_REPAIR_CONFIG, value)
    config["enabled"] = _bool_value(config.get("enabled", True), "repair.enabled")
    config["workspace"] = str(config.get("workspace") or ".sunpack_repair")
    config["keep_candidates"] = _bool_value(config.get("keep_candidates", False), "repair.keep_candidates")
    config["max_modules_per_job"] = _int_at_least(config, "max_modules_per_job", 1)
    config["max_attempts_per_task"] = _int_at_least(config, "max_attempts_per_task", 0)
    config["max_repair_rounds_per_task"] = _int_at_least(config, "max_repair_rounds_per_task", 0)
    config["max_repair_seconds_per_task"] = _float_at_least(config, "max_repair_seconds_per_task", 0.0)
    config["max_repair_generated_files_per_task"] = _int_at_least(config, "max_repair_generated_files_per_task", 0)
    config["max_repair_generated_mb_per_task"] = _float_at_least(config, "max_repair_generated_mb_per_task", 0.0)
    config["stages"] = _normalize_bool_map(config.get("stages"), "repair.stages")
    config["safety"] = _normalize_safety(config.get("safety"))
    config["deep"] = _normalize_deep(config.get("deep"))
    config["auto_deep"] = _normalize_auto_deep(config.get("auto_deep"))
    config["beam"] = _normalize_beam(config.get("beam"))
    config["telemetry"] = _normalize_telemetry(config.get("telemetry"))
    config["modules"] = _normalize_modules(config.get("modules"))
    return config


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
    result = deepcopy(base)
    for key, value in override.items():
        if isinstance(value, dict) and isinstance(result.get(key), dict):
            result[key] = _merge(result[key], value)
        else:
            result[key] = deepcopy(value)
    return result


def _normalize_bool_map(value: Any, path: str) -> dict[str, bool]:
    if not isinstance(value, dict):
        raise ValueError(f"{path} must be an object")
    return {str(key): _bool_value(item, f"{path}.{key}") for key, item in value.items()}


def _normalize_safety(value: Any) -> dict[str, bool]:
    if not isinstance(value, dict):
        raise ValueError("repair.safety must be an object")
    allow_unsafe = value.get("allow_unsafe", value.get("allow_unsafe_modules", False))
    allow_partial = value.get("allow_partial", value.get("allow_partial_results", True))
    allow_lossy = value.get("allow_lossy", value.get("allow_lossy_repair", False))
    return {
        **value,
        "allow_unsafe": _bool_value(allow_unsafe, "repair.safety.allow_unsafe"),
        "allow_partial": _bool_value(allow_partial, "repair.safety.allow_partial"),
        "allow_lossy": _bool_value(allow_lossy, "repair.safety.allow_lossy"),
    }


def _normalize_deep(value: Any) -> dict[str, Any]:
    if not isinstance(value, dict):
        raise ValueError("repair.deep must be an object")
    return {
        **value,
        "max_candidates_per_module": _int_at_least(value, "max_candidates_per_module", 1),
        "max_entries": _int_at_least(value, "max_entries", 1),
        "max_seconds_per_module": _float_at_least(value, "max_seconds_per_module", 0.0),
        "max_input_size_mb": _float_at_least(value, "max_input_size_mb", 0.0),
        "max_output_size_mb": _float_at_least(value, "max_output_size_mb", 0.0),
        "max_entry_uncompressed_mb": _float_at_least(value, "max_entry_uncompressed_mb", 0.0),
        "verify_candidates": _bool_value(value.get("verify_candidates", True), "repair.deep.verify_candidates"),
    }


def _normalize_auto_deep(value: Any) -> dict[str, Any]:
    if not isinstance(value, dict):
        raise ValueError("repair.auto_deep must be an object")
    return {
        **value,
        "enabled": _bool_value(value.get("enabled", True), "repair.auto_deep.enabled"),
        "require_verification_repair": _bool_value(
            value.get("require_verification_repair", True),
            "repair.auto_deep.require_verification_repair",
        ),
        "max_modules": _int_at_least(value, "max_modules", 1),
        "max_candidates_per_module": _int_at_least(value, "max_candidates_per_module", 1),
        "max_input_size_mb": _float_at_least(value, "max_input_size_mb", 0.0),
    }


def _normalize_beam(value: Any) -> dict[str, Any]:
    if not isinstance(value, dict):
        raise ValueError("repair.beam must be an object")
    return {
        **value,
        "enabled": _bool_value(value.get("enabled", True), "repair.beam.enabled"),
        "beam_width": _int_at_least(value, "beam_width", 1),
        "max_candidates_per_state": _int_at_least(value, "max_candidates_per_state", 1),
        "max_analyze_candidates": _int_at_least(value, "max_analyze_candidates", 1),
        "max_assess_candidates": _int_at_least(value, "max_assess_candidates", 1),
        "max_rounds": _int_at_least(value, "max_rounds", 0),
        "min_improvement": _float_at_least(value, "min_improvement", 0.0),
    }


def _normalize_telemetry(value: Any) -> dict[str, bool]:
    if not isinstance(value, dict):
        raise ValueError("repair.telemetry must be an object")
    return {
        "enabled": _bool_value(value.get("enabled", False), "repair.telemetry.enabled"),
    }


def _normalize_modules(value: Any) -> list[dict[str, Any]]:
    if value is None:
        return []
    if not isinstance(value, list):
        raise ValueError("repair.modules must be a list")
    result = []
    for index, item in enumerate(value):
        if not isinstance(item, dict):
            raise ValueError(f"repair.modules[{index}] must be an object")
        name = str(item.get("name") or "").strip()
        if not name:
            raise ValueError(f"repair.modules[{index}].name must not be empty")
        normalized = dict(item)
        normalized["name"] = name
        normalized["enabled"] = _bool_value(item.get("enabled", False), f"repair.modules[{index}].enabled")
        result.append(normalized)
    return result


def _int_at_least(config: dict[str, Any], name: str, minimum: int) -> int:
    try:
        value = int(config.get(name))
    except (TypeError, ValueError) as exc:
        raise ValueError(f"repair.{name} must be an integer") from exc
    if value < minimum:
        raise ValueError(f"repair.{name} must be >= {minimum}")
    return value


def _float_at_least(config: dict[str, Any], name: str, minimum: float) -> float:
    try:
        value = float(config.get(name))
    except (TypeError, ValueError) as exc:
        raise ValueError(f"repair.{name} must be a number") from exc
    if value < minimum:
        raise ValueError(f"repair.{name} must be >= {minimum:g}")
    return value


def _bool_value(value: Any, path: str) -> bool:
    if isinstance(value, bool):
        return value
    if isinstance(value, int) and value in {0, 1}:
        return bool(value)
    if isinstance(value, str):
        text = value.strip().lower()
        if text in {"1", "true", "yes", "y", "on"}:
            return True
        if text in {"0", "false", "no", "n", "off"}:
            return False
    raise ValueError(f"{path} must be a boolean")
