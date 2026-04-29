from copy import deepcopy
from typing import Any

from tests.helpers.scene_rules import RECOMMENDED_SCENE_RULES_PAYLOAD
from tests.helpers.detection_config import with_detection_pipeline


CONFIGS: dict[str, dict[str, Any]] = {
    "minimal": with_detection_pipeline({
        "thresholds": {"archive_score_threshold": 5, "maybe_archive_threshold": 3},
    }, precheck=[
        {"name": "size_minimum", "enabled": True, "min_inspection_size_bytes": 0},
    ]),
    "embedded_archive_loose": with_detection_pipeline({
        "thresholds": {"archive_score_threshold": 5, "maybe_archive_threshold": 3},
    }, precheck=[
        {"name": "size_minimum", "enabled": True, "min_inspection_size_bytes": 0},
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
        {"name": "size_minimum", "enabled": True, "min_inspection_size_bytes": 0},
    ], scoring=[
        {"name": "embedded_payload_identity", "enabled": True, "carrier_tail_score": 5},
    ]),
    "scene_protect_enabled": with_detection_pipeline({
        "thresholds": {"archive_score_threshold": 5, "maybe_archive_threshold": 3},
    }, precheck=[
        {
            "name": "scene_protect",
            "enabled": True,
            "scene_rules": RECOMMENDED_SCENE_RULES_PAYLOAD,
        },
    ]),
    "scene_penalty_runtime": with_detection_pipeline({
        "thresholds": {"archive_score_threshold": 5, "maybe_archive_threshold": 3},
    }, scoring=[
        {"name": "extension", "enabled": True, "extension_score_groups": [{"score": 5, "extensions": [".zip", ".7z", ".rar", ".001"]}]},
        {
            "name": "scene_penalty",
            "enabled": True,
            "scene_rules": RECOMMENDED_SCENE_RULES_PAYLOAD,
            "runtime_resource_archive_penalty": -99,
        },
    ]),
    "archive_scan_full": with_detection_pipeline({
        "thresholds": {"archive_score_threshold": 6, "maybe_archive_threshold": 3},
    }, precheck=[
        {"name": "size_minimum", "enabled": True, "min_inspection_size_bytes": 0},
        {"name": "scene_protect", "enabled": True},
    ], scoring=[
        {"name": "extension", "enabled": True, "extension_score_groups": [{"score": 5, "extensions": [".zip", ".7z", ".rar", ".gz", ".bz2", ".xz", ".001"]}]},
        {"name": "embedded_payload_identity", "enabled": True},
        {"name": "seven_zip_structure_identity", "enabled": True},
        {"name": "rar_structure_identity", "enabled": True},
        {"name": "scene_penalty", "enabled": True},
    ], confirmation=[
        {"name": "seven_zip_probe", "enabled": True},
        {"name": "seven_zip_validation", "enabled": True},
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

