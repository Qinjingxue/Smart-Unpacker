from copy import deepcopy
from typing import Any

from sunpack.config.advanced_defaults import advanced_config_value
from sunpack.config.edition import is_lite_edition

DEFAULT_REPAIR_CONFIG = advanced_config_value(("repair",))


def repair_config(config: dict[str, Any] | None) -> dict[str, Any]:
    payload = dict((config or {}).get("repair") or {})
    return normalize_repair_config(payload)


def repair_system_mode() -> str:
    return "lite" if is_lite_edition() else "full"


def normalize_repair_config(value: Any) -> dict[str, Any]:
    if value is None:
        value = {}
    if not isinstance(value, dict):
        raise ValueError("repair must be an object")
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
    config.pop("continue_after_partial", None)
    config["safety"] = _normalize_safety(config.get("safety"))
    config["module_limits"] = _normalize_module_limits(config.get("module_limits"))
    config["beam"] = _normalize_beam(config.get("beam"))
    config["policy"] = _normalize_policy(config.get("policy"))
    config["telemetry"] = _normalize_telemetry(config.get("telemetry"))
    config["modules"] = _normalize_modules(config.get("modules"))
    if repair_system_mode() == "lite":
        config["enabled"] = False
        config["max_attempts_per_task"] = 0
        config["max_repair_rounds_per_task"] = 0
        config["policy"]["enabled"] = False
    return config


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
    allow_lossy = value.get("allow_lossy", value.get("allow_lossy_repair", False))
    normalized = {
        key: item
        for key, item in value.items()
        if key not in {"allow_partial", "allow_partial_results"}
    }
    return {
        **normalized,
        "allow_unsafe": _bool_value(allow_unsafe, "repair.safety.allow_unsafe"),
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
    normalized = {key: item for key, item in value.items() if key != "return_best_partial"}
    return {
        **normalized,
        "enabled": _bool_value(value.get("enabled", True), "repair.beam.enabled"),
        "beam_width": _int_at_least(value, "beam_width", 1),
        "max_candidates_per_state": _int_at_least(value, "max_candidates_per_state", 1),
        "max_analyze_candidates": _int_at_least(value, "max_analyze_candidates", 1),
        "max_assess_candidates": _int_at_least(value, "max_assess_candidates", 1),
        "max_rounds": _int_at_least(value, "max_rounds", 0),
        "min_improvement": _float_at_least(value, "min_improvement", 0.0),
        "patience_rounds": _int_at_least(value, "patience_rounds", 0),
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
    allowed = {"enabled", "strict_model_errors", "graph_stop_stale_patience", "min_best_recovery_improvement"}
    unknown = sorted(set(value) - allowed)
    if unknown:
        raise ValueError(f"unknown repair.policy fields: {', '.join(unknown)}")
    return {
        "enabled": _bool_value(value["enabled"], "repair.policy.enabled"),
        "strict_model_errors": _bool_value(value["strict_model_errors"], "repair.policy.strict_model_errors"),
        "graph_stop_stale_patience": _int_at_least(value, "graph_stop_stale_patience", 0),
        "min_best_recovery_improvement": _float_at_least(value, "min_best_recovery_improvement", 0.0),
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
