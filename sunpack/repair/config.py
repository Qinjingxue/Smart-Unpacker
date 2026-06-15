from copy import deepcopy
from typing import Any


DEFAULT_REPAIR_CONFIG = {
    "enabled": True,
    "workspace": ".sunpack_repair",
    "keep_candidates": False,
    "max_attempts_per_task": 3,
    "max_repair_rounds_per_task": 100,
    "max_repair_seconds_per_task": 200.0,
    "max_repair_generated_files_per_task": 16,
    "max_repair_generated_mb_per_task": 2048.0,
    "stagnation_patience_rounds": 3,
    "min_recovery_improvement": 0.01,
    "continue_after_partial": True,
    "runtime_cache": {
        "enabled": True,
        "max_entries": 512,
    },
    "safety": {
        "allow_unsafe": False,
        "allow_partial": True,
        "allow_lossy": False,
    },
    "module_limits": {
        "max_candidates_per_module": 3,
        "max_entries": 20000,
        "max_seconds_per_module": 30.0,
        "max_input_size_mb": 512,
        "max_output_size_mb": 2048,
        "max_entry_uncompressed_mb": 512,
        "verify_candidates": True,
        "max_stream_trim_probe_attempts": 32,
        "max_stream_trim_decode_mb": 64,
        "max_gzip_footer_fix_decode_mb": 32,
        "max_next_header_scan_bytes": 1024 * 1024,
    },
    "beam": {
        "enabled": True,
        "beam_width": 6,
        "max_candidates_per_state": 8,
        "max_analyze_candidates": 24,
        "max_assess_candidates": 12,
        "max_rounds": 6,
        "min_improvement": 0.01,
        "patience_rounds": 3,
        "return_best_partial": True,
    },
    "policy": {
        "enabled": True,
        "strict_model_errors": False,
        "graph_stop_stale_patience": 100,
        "min_best_recovery_improvement": 0.01,
    },
    "telemetry": {
        "enabled": False,
    },
    "modules": [
        {"name": "zip_trim_trailing_junk", "enabled": True},
        {"name": "zip_fix_eocd_comment_length", "enabled": True},
        {"name": "zip_fix_eocd_record", "enabled": True},
        {"name": "zip_fix_cd_offset", "enabled": True},
        {"name": "zip_fix_cd_entry_count", "enabled": True},
        {"name": "zip_fix_local_header_fields", "enabled": True},
        {"name": "zip_fix_extra_field_length", "enabled": True},
        {"name": "zip_fix_zip64_locator", "enabled": True},
        {"name": "zip_fix_zip64_eocd", "enabled": True},
        {"name": "zip_fix_zip64_extra_size", "enabled": True},
        {"name": "zip_rebuild_cd_from_local_headers", "enabled": True},
        {"name": "zip_rebuild_cd_preserve_raw_names", "enabled": True},
        {"name": "zip_rebuild_cd_from_data_descriptors", "enabled": True},
        {"name": "zip_remove_spurious_data_descriptor", "enabled": True},
        {"name": "zip_normalize_data_descriptor_flags", "enabled": True},
        {"name": "zip_reconcile_cd_entry_names_from_local_headers", "enabled": True},
        {"name": "zip_reconcile_cd_local_headers", "enabled": True},
        {"name": "zip_quarantine_failed_entries", "enabled": True},
        {"name": "zip_salvage_verified_entries", "enabled": True},
        {"name": "zip_partial_salvage_missing_volume", "enabled": True},
        {"name": "zip_local_header_partial_scan", "enabled": True},
        {"name": "zip_resolve_duplicate_entries", "enabled": True},
        {"name": "zip_resolve_overlapping_entries", "enabled": True},
        {"name": "zip_reconcile_cd_data_descriptor_conflict", "enabled": True},
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
        {"name": "seven_zip_trim_trailing_junk", "enabled": True},
        {"name": "seven_zip_crop_carrier_prefix", "enabled": True},
        {"name": "seven_zip_fix_start_header_crc", "enabled": True},
        {"name": "seven_zip_fix_signature_header_version", "enabled": True},
        {"name": "seven_zip_fix_next_header_crc", "enabled": True},
        {"name": "seven_zip_fix_next_header_offset", "enabled": True},
        {"name": "seven_zip_fix_next_header_size", "enabled": True},
        {"name": "seven_zip_repoint_next_header", "enabled": True},
        {"name": "seven_zip_decode_encoded_header", "enabled": True},
        {"name": "seven_zip_fix_pack_stream_offset", "enabled": True},
        {"name": "seven_zip_fix_pack_stream_size", "enabled": True},
        {"name": "seven_zip_fix_stream_crc", "enabled": True},
        {"name": "seven_zip_quarantine_bad_folder", "enabled": True},
        {"name": "seven_zip_fix_empty_stream_flags", "enabled": True},
        {"name": "seven_zip_fix_encoded_header_stream_crc", "enabled": True},
        {"name": "seven_zip_fix_header_end_marker", "enabled": True},
        {"name": "seven_zip_repair_encoded_header_coder_properties", "enabled": True},
        {"name": "seven_zip_fix_unpack_size", "enabled": True},
        {"name": "seven_zip_repair_folder_bind_pairs", "enabled": True},
        {"name": "seven_zip_repair_folder_stream_counts", "enabled": True},
        {"name": "seven_zip_fix_file_count_metadata", "enabled": True},
        {"name": "seven_zip_reconcile_file_names_utf16", "enabled": True},
        {"name": "seven_zip_drop_unreferenced_folder", "enabled": True},
        {"name": "seven_zip_drop_unreferenced_file_record", "enabled": True},
        {"name": "seven_zip_clear_invalid_stream_crc_defined_flag", "enabled": True},
        {"name": "seven_zip_salvage_non_solid_entries", "enabled": True},
        {"name": "seven_zip_salvage_solid_prefix", "enabled": True},
        {"name": "rar_trailing_junk_trim", "enabled": True},
        {"name": "rar_carrier_crop_deep_recovery", "enabled": True},
        {"name": "rar_block_chain_trim", "enabled": True},
        {"name": "rar_end_block_repair", "enabled": True},
        {"name": "rar_file_quarantine_rebuild", "enabled": True},
        {"name": "rar4_file_quarantine_rebuild", "enabled": True},
        {"name": "zip_boundary", "enabled": True},
        {"name": "zip_directory", "enabled": True},
        {"name": "rar_boundary", "enabled": True},
        {"name": "tar_boundary", "enabled": True},
        {"name": "gzip_boundary", "enabled": True},
        {"name": "bzip2_boundary", "enabled": True},
        {"name": "xz_boundary", "enabled": True},
        {"name": "zstd_boundary", "enabled": True},
    ],
}

REMOVED_ZIP_COARSE_MODULES = {
    "zip_fix_boundary": "zip_trim_trailing_junk / zip_fix_eocd_comment_length",
    "zip_fix_pointers": "zip_fix_eocd_record / zip_fix_cd_offset / zip_fix_cd_entry_count / zip_fix_local_header_fields",
    "zip_fix_zip64": "zip_fix_zip64_locator / zip_fix_zip64_eocd / zip_fix_zip64_extra_size",
    "zip_rebuild": "zip_rebuild_cd_from_local_headers / zip_rebuild_cd_from_data_descriptors",
    "zip_salvage": "zip_reconcile_cd_local_headers / zip_quarantine_failed_entries / zip_salvage_verified_entries / zip_partial_salvage_missing_volume / zip_local_header_partial_scan",
    "zip_resolve_conflicts": "zip_resolve_duplicate_entries / zip_resolve_overlapping_entries / zip_reconcile_cd_data_descriptor_conflict",
    "zip_central_directory_rebuild": "zip_rebuild_cd_from_local_headers",
    "zip_data_descriptor_recovery": "zip_rebuild_cd_from_data_descriptors",
    "zip_partial_recovery": "zip_local_header_partial_scan",
    "zip_eocd_repair": "zip_fix_eocd_record",
    "zip_central_directory_offset_fix": "zip_fix_cd_offset",
    "zip_central_directory_count_fix": "zip_fix_cd_entry_count",
    "zip_trailing_junk_trim": "zip_trim_trailing_junk",
    "zip_comment_length_fix": "zip_fix_eocd_comment_length",
    "zip_deep_partial_recovery": "zip_local_header_partial_scan",
    "zip_conflict_resolver_rebuild": "zip_resolve_duplicate_entries / zip_resolve_overlapping_entries",
    "zip_entry_quarantine_rebuild": "zip_quarantine_failed_entries",
    "zip_missing_volume_partial_salvage": "zip_partial_salvage_missing_volume",
    "zip64_field_repair": "zip_fix_zip64_locator / zip_fix_zip64_eocd / zip_fix_zip64_extra_size",
    "zip_local_header_field_repair": "zip_fix_local_header_fields",
}

MODULE_NAME_ALIASES = {}


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
    removed = sorted({"stages", "deep", "auto_deep", "max_modules_per_job"} & set(value))
    if removed:
        joined = ", ".join(f"repair.{name}" for name in removed)
        raise ValueError(f"{joined} was removed; repair now always uses maximum module exploration. Move resource budgets to repair.module_limits or per-module module_limits.")
    config = _merge(DEFAULT_REPAIR_CONFIG, value)
    config["enabled"] = _bool_value(config.get("enabled", True), "repair.enabled")
    config["workspace"] = str(config.get("workspace") or ".sunpack_repair")
    config["keep_candidates"] = _bool_value(config.get("keep_candidates", False), "repair.keep_candidates")
    config["max_attempts_per_task"] = _int_at_least(config, "max_attempts_per_task", 0)
    config["max_repair_rounds_per_task"] = _int_at_least(config, "max_repair_rounds_per_task", 0)
    config["max_repair_seconds_per_task"] = _float_at_least(config, "max_repair_seconds_per_task", 0.0)
    config["max_repair_generated_files_per_task"] = _int_at_least(config, "max_repair_generated_files_per_task", 0)
    config["max_repair_generated_mb_per_task"] = _float_at_least(config, "max_repair_generated_mb_per_task", 0.0)
    config["stagnation_patience_rounds"] = _int_at_least(config, "stagnation_patience_rounds", 0)
    config["min_recovery_improvement"] = _float_at_least(config, "min_recovery_improvement", 0.0)
    config["continue_after_partial"] = _bool_value(config.get("continue_after_partial", True), "repair.continue_after_partial")
    config["safety"] = _normalize_safety(config.get("safety"))
    config["module_limits"] = _normalize_module_limits(config.get("module_limits"))
    config["beam"] = _normalize_beam(config.get("beam"))
    config["policy"] = _normalize_policy(config.get("policy"))
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


def _normalize_module_limits(value: Any) -> dict[str, Any]:
    if not isinstance(value, dict):
        raise ValueError("repair.module_limits must be an object")
    return {
        **value,
        "max_candidates_per_module": _int_at_least(value, "max_candidates_per_module", 1),
        "max_entries": _int_at_least(value, "max_entries", 1),
        "max_seconds_per_module": _float_at_least(value, "max_seconds_per_module", 0.0),
        "max_input_size_mb": _float_at_least(value, "max_input_size_mb", 0.0),
        "max_output_size_mb": _float_at_least(value, "max_output_size_mb", 0.0),
        "max_entry_uncompressed_mb": _float_at_least(value, "max_entry_uncompressed_mb", 0.0),
        "max_stream_trim_probe_attempts": _int_at_least(value, "max_stream_trim_probe_attempts", 1),
        "max_stream_trim_decode_mb": _float_at_least(value, "max_stream_trim_decode_mb", 0.0),
        "max_gzip_footer_fix_decode_mb": _float_at_least(value, "max_gzip_footer_fix_decode_mb", 0.0),
        "max_next_header_scan_bytes": _int_at_least(value, "max_next_header_scan_bytes", 1),
        "verify_candidates": _bool_value(value.get("verify_candidates", True), "repair.module_limits.verify_candidates"),
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
        "patience_rounds": _int_at_least(value, "patience_rounds", 0),
        "return_best_partial": _bool_value(value.get("return_best_partial", True), "repair.beam.return_best_partial"),
    }


def _normalize_telemetry(value: Any) -> dict[str, bool]:
    if not isinstance(value, dict):
        raise ValueError("repair.telemetry must be an object")
    return {
        "enabled": _bool_value(value.get("enabled", False), "repair.telemetry.enabled"),
    }


def _normalize_policy(value: Any) -> dict[str, Any]:
    if not isinstance(value, dict):
        raise ValueError("repair.policy must be an object")
    removed = sorted({"fallback_to_selector", "disable_beam_when_model_active", "step_mode"} & set(value))
    if removed:
        joined = ", ".join(f"repair.policy.{name}" for name in removed)
        raise ValueError(f"{joined} was removed; repair policy now always uses graph step mode without selector/beam fallback")
    if "provider_package" in value:
        raise ValueError("repair.policy.provider_package was removed; RepairModelRuntime loads bundled models directly")
    return {
        "enabled": _bool_value(value.get("enabled", True), "repair.policy.enabled"),
        "strict_model_errors": _bool_value(value.get("strict_model_errors", False), "repair.policy.strict_model_errors"),
        "graph_stop_stale_patience": _int_at_least(value, "graph_stop_stale_patience", 0) if "graph_stop_stale_patience" in value else 100,
        "min_best_recovery_improvement": _float_at_least(value, "min_best_recovery_improvement", 0.0) if "min_best_recovery_improvement" in value else 0.01,
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
        if name in REMOVED_ZIP_COARSE_MODULES:
            raise ValueError(
                f"repair.modules[{index}].name={name!r} was removed; use atomic ZIP repair modules: "
                f"{REMOVED_ZIP_COARSE_MODULES[name]}"
            )
        normalized = dict(item)
        normalized["name"] = MODULE_NAME_ALIASES.get(name, name)
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
