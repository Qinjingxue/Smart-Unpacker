from copy import deepcopy
from typing import Any

from tests.helpers.detection_config import with_detection_pipeline


CONFIGS: dict[str, dict[str, Any]] = {
    "minimal": with_detection_pipeline({
        "thresholds": {"archive_score_threshold": 5, "maybe_archive_threshold": 3},
    }, precheck=[
        {"name": "size_range", "enabled": True, "gte": 0},
    ]),
    "embedded_archive_loose": with_detection_pipeline({
        "thresholds": {"archive_score_threshold": 5, "maybe_archive_threshold": 3},
    }, precheck=[
        {"name": "size_range", "enabled": True, "gte": 0},
    ], scoring=[
        {
            "name": "embedded_payload_identity",
            "enabled": True,
            "carrier_exts": [],
            "ambiguous_resource_exts": [".bin"],
            "loose_scan_score": 5,
            "loose_scan_min_tail_bytes": 1,
        },
    ]),
    "embedded_archive_carrier_tail": with_detection_pipeline({
        "thresholds": {"archive_score_threshold": 5, "maybe_archive_threshold": 3},
    }, precheck=[
        {"name": "size_range", "enabled": True, "gte": 0},
    ], scoring=[
        {"name": "embedded_payload_identity", "enabled": True, "carrier_tail_score": 5},
    ]),
    "archive_scan_full": with_detection_pipeline({
        "thresholds": {"archive_score_threshold": 6, "maybe_archive_threshold": 3},
    }, precheck=[
        {"name": "size_range", "enabled": True, "gte": 0},
    ], scoring=[
        {"name": "extension", "enabled": True, "extension_score_groups": [{"score": 5, "extensions": [".zip", ".7z", ".rar", ".gz", ".bz2", ".xz", ".001"]}]},
        {"name": "embedded_payload_identity", "enabled": True},
        {"name": "seven_zip_structure_identity", "enabled": True, "magic_score": 5, "next_header_nid_score": 5},
        {"name": "rar_structure_identity", "enabled": True, "magic_score": 5, "block_walk_score": 5},
    ], confirmation=[
        {"name": "seven_zip_probe", "enabled": True, "reject_executable_container": False, "reject_clear_non_archive": True},
        {"name": "seven_zip_validation", "enabled": True, "reject_on_failed": False},
    ]),
    "archive_scan_deep_embedded": with_detection_pipeline({
        "thresholds": {"archive_score_threshold": 6, "maybe_archive_threshold": 3},
    }, precheck=[
        {"name": "size_range", "enabled": True, "gte": 0},
    ], scoring=[
        {"name": "extension", "enabled": True, "extension_score_groups": [{"score": 5, "extensions": [".zip", ".7z", ".rar", ".gz", ".bz2", ".xz", ".001"]}]},
        {"name": "embedded_payload_identity", "enabled": True, "embedded_payload_scan_level": "deep"},
        {"name": "seven_zip_structure_identity", "enabled": True, "magic_score": 5, "next_header_nid_score": 5},
        {"name": "rar_structure_identity", "enabled": True, "magic_score": 5, "block_walk_score": 5},
    ], confirmation=[
        {"name": "seven_zip_probe", "enabled": True, "reject_executable_container": False, "reject_clear_non_archive": True},
        {"name": "seven_zip_validation", "enabled": True, "reject_on_failed": False},
    ]),
}


def get_config(name: str = "minimal", overrides: dict[str, Any] | None = None) -> dict[str, Any]:
    config = deepcopy(CONFIGS[name])
    if overrides:
        deep_merge(config, overrides)
    return config


def deep_merge(target: dict[str, Any], source: dict[str, Any]):
    for key, value in source.items():
        if isinstance(value, dict) and isinstance(target.get(key), dict):
            deep_merge(target[key], value)
        else:
            target[key] = deepcopy(value)

