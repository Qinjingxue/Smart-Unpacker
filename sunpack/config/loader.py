from pathlib import Path
from typing import Any

from sunpack.config.detection_view import DIRECTORY_SCAN_MODES, directory_scan_mode, rule_pipeline_config, scan_filters_config
from sunpack.config.schema import ConfigSchemaError, normalize_config, validate_external_config
from sunpack.support.json_format import load_json_file
from sunpack.support.resources import candidate_resource_paths, dedupe_paths, first_existing_path


class ConfigError(RuntimeError):
    pass


SIMPLE_CONFIG_FILENAME = "sunpack_config.json"
ADVANCED_CONFIG_FILENAME = "sunpack_advanced_config.json"


def _load_json(path: Path) -> dict[str, Any]:
    payload = load_json_file(path)
    if not isinstance(payload, dict):
        raise ConfigError(f"Config file must contain a JSON object: {path}")
    return payload


def _candidate_config_paths(filename: str) -> list[Path]:
    project_root = Path(__file__).resolve().parents[2]
    return dedupe_paths(candidate_resource_paths(filename) + [project_root / filename, Path.cwd() / filename])


def _first_existing_config(filename: str) -> Path | None:
    return first_existing_path(_candidate_config_paths(filename))


_NAMED_MODULE_LIST_PATHS = {
    ("detection", "fact_collectors"),
    ("detection", "processors"),
    ("detection", "rule_pipeline", "precheck"),
    ("detection", "rule_pipeline", "scoring"),
    ("detection", "rule_pipeline", "confirmation"),
}


def _deep_merge_config(base: dict[str, Any], override: dict[str, Any], path: tuple[str, ...] = ()) -> dict[str, Any]:
    merged = dict(base)
    for key, value in override.items():
        item_path = path + (key,)
        base_value = merged.get(key)
        if isinstance(base_value, dict) and isinstance(value, dict):
            merged[key] = _deep_merge_config(base_value, value, item_path)
        elif item_path in _NAMED_MODULE_LIST_PATHS and isinstance(base_value, list) and isinstance(value, list):
            merged[key] = _merge_named_module_list(base_value, value)
        else:
            merged[key] = value
    return merged


def _merge_named_module_list(base: list[Any], override: list[Any]) -> list[Any]:
    merged = list(base)
    indexes = {
        item.get("name"): index
        for index, item in enumerate(merged)
        if isinstance(item, dict) and isinstance(item.get("name"), str)
    }
    for item in override:
        if not isinstance(item, dict) or not isinstance(item.get("name"), str):
            merged.append(item)
            continue
        existing_index = indexes.get(item["name"])
        if existing_index is None or not isinstance(merged[existing_index], dict):
            indexes[item["name"]] = len(merged)
            merged.append(item)
            continue
        merged[existing_index] = _deep_merge_config(merged[existing_index], item)
    return merged


def _load_layered_config() -> tuple[Path, dict[str, Any]]:
    simple_path = _first_existing_config(SIMPLE_CONFIG_FILENAME)
    advanced_path = _first_existing_config(ADVANCED_CONFIG_FILENAME)
    if simple_path is None and advanced_path is None:
        searched = [
            *[str(path) for path in _candidate_config_paths(SIMPLE_CONFIG_FILENAME)],
            *[str(path) for path in _candidate_config_paths(ADVANCED_CONFIG_FILENAME)],
        ]
        raise ConfigError(f"Missing required {SIMPLE_CONFIG_FILENAME} or {ADVANCED_CONFIG_FILENAME}. Searched: {', '.join(searched)}")

    advanced = _load_json(advanced_path) if advanced_path is not None else {}
    if simple_path is None:
        return advanced_path, advanced
    simple = _load_json(simple_path)
    return simple_path, _deep_merge_config(advanced, simple)


def _validate_pipeline(config: dict[str, Any]):
    shortcut_errors = validate_external_config(config)
    if shortcut_errors:
        raise ConfigError("; ".join(shortcut_errors))

    filesystem = config.get("filesystem")
    if not isinstance(filesystem, dict):
        raise ConfigError("Missing required config object: filesystem")
    try:
        scan_mode = directory_scan_mode(config)
    except ValueError as exc:
        raise ConfigError(str(exc)) from exc
    if scan_mode not in DIRECTORY_SCAN_MODES:
        allowed = ", ".join(sorted(DIRECTORY_SCAN_MODES))
        raise ConfigError(f"filesystem.directory_scan_mode must be one of: {allowed}")
    filters = scan_filters_config(config)
    if not isinstance(filters, list):
        raise ConfigError("Missing required filesystem.scan_filters list")
    for index, scan_filter in enumerate(filters):
        if not isinstance(scan_filter, dict):
            raise ConfigError(f"filesystem.scan_filters[{index}] must be an object")
        if not isinstance(scan_filter.get("name"), str) or not scan_filter["name"].strip():
            raise ConfigError(f"filesystem.scan_filters[{index}] must declare a filter name")

    detection = config.get("detection")
    if not isinstance(detection, dict):
        raise ConfigError("Missing required config object: detection")
    pipeline = rule_pipeline_config(config)
    if not isinstance(pipeline, dict):
        raise ConfigError("Missing required config object: detection.rule_pipeline")
    for layer in ("precheck", "scoring"):
        rules = pipeline.get(layer)
        if not isinstance(rules, list):
            raise ConfigError(f"Missing required detection.rule_pipeline list: {layer}")
        for index, rule in enumerate(rules):
            if not isinstance(rule, dict):
                raise ConfigError(f"detection.rule_pipeline.{layer}[{index}] must be an object")
            if not isinstance(rule.get("name"), str) or not rule["name"].strip():
                raise ConfigError(f"detection.rule_pipeline.{layer}[{index}] must declare a rule name")


def load_config() -> dict[str, Any]:
    """Read the external configuration required to run the pipeline."""
    _, config = _load_layered_config()
    _validate_pipeline(config)
    try:
        return normalize_config(config)
    except ConfigSchemaError as exc:
        raise ConfigError(str(exc)) from exc


def load_effective_config_payload() -> tuple[Path, dict[str, Any]]:
    config_path, config = _load_layered_config()
    _validate_pipeline(config)
    return config_path, config
