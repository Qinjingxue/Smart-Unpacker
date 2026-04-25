from pathlib import Path
from typing import Any

from smart_unpacker.config.detection_view import DIRECTORY_SCAN_MODES, directory_scan_mode, rule_pipeline_config, scan_filters_config
from smart_unpacker.support.json_format import load_json_file
from smart_unpacker.support.resources import candidate_resource_paths, dedupe_paths, first_existing_path


class ConfigError(RuntimeError):
    pass


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


def _validate_pipeline(config: dict[str, Any]):
    filesystem = config.get("filesystem")
    if not isinstance(filesystem, dict):
        raise ConfigError("Missing required config object: filesystem")
    if directory_scan_mode(config) not in DIRECTORY_SCAN_MODES:
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
    for layer in ("hard_stop", "scoring"):
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
    config_path = _first_existing_config("smart_unpacker_config.json")
    if config_path is None:
        searched = ", ".join(str(path) for path in _candidate_config_paths("smart_unpacker_config.json"))
        raise ConfigError(f"Missing required smart_unpacker_config.json. Searched: {searched}")

    config = _load_json(config_path)
    _validate_pipeline(config)
    return config
