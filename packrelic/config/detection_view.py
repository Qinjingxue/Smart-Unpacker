from typing import Any

from packrelic.config.schema import normalize_config_value
from packrelic.config.fields.filesystem import (
    DIRECTORY_SCAN_CURRENT_DIR_ONLY,
    DIRECTORY_SCAN_MODES,
    DIRECTORY_SCAN_RECURSIVE,
)


DIRECTORY_SCAN_MODE_PATH = ("filesystem", "directory_scan_mode")


def detection_config(config: dict[str, Any]) -> dict[str, Any]:
    value = config.get("detection")
    return value if isinstance(value, dict) else {}


def rule_pipeline_config(config: dict[str, Any]) -> dict[str, Any]:
    value = detection_config(config).get("rule_pipeline")
    return value if isinstance(value, dict) else {}


def module_config(config: dict[str, Any], section: str, name: str) -> dict[str, Any]:
    modules = detection_config(config).get(section)
    if not isinstance(modules, list):
        return {}
    for item in modules:
        if isinstance(item, dict) and item.get("name") == name:
            return item
    return {}


def filesystem_config(config: dict[str, Any]) -> dict[str, Any]:
    value = config.get("filesystem")
    return value if isinstance(value, dict) else {}


def directory_scan_mode(config: dict[str, Any]) -> str:
    value = filesystem_config(config).get("directory_scan_mode")
    if value in DIRECTORY_SCAN_MODES:
        return value
    return normalize_config_value(DIRECTORY_SCAN_MODE_PATH, value)


def scan_filters_config(config: dict[str, Any]) -> list[dict[str, Any]]:
    filters = filesystem_config(config).get("scan_filters")
    return filters if isinstance(filters, list) else []


def scan_filter_config(config: dict[str, Any], name: str) -> dict[str, Any]:
    for item in scan_filters_config(config):
        if isinstance(item, dict) and item.get("name") == name:
            return item
    return {}
