from smart_unpacker.app.cli_runtime import (
    apply_runtime_config_overrides,
    build_effective_config,
)
from smart_unpacker.config.config_validator import validate_config_payload
from tests.helpers.detection_config import with_detection_pipeline


def _payload():
    return with_detection_pipeline(
        scoring=[{"name": "archive_identity", "enabled": True}],
    )


def test_config_validate_checks_rule_schema_types_even_when_disabled():
    payload = _payload()
    payload["detection"]["rule_pipeline"]["scoring"][0]["enabled"] = False
    payload["detection"]["rule_pipeline"]["scoring"][0]["carrier_exts"] = 123

    result = validate_config_payload(payload)

    assert not result["ok"]
    assert any("Invalid type" in error for error in result["errors"])


def test_scheduler_profile_override_expands_scheduler_config():
    class Args:
        scheduler_profile = "aggressive"
        min_inspection_size_bytes = None
        recursive_extract = None
        archive_cleanup_mode = None
        flatten_single_directory = None

    config = {}
    overrides = apply_runtime_config_overrides(config, Args())

    assert overrides["scheduler_profile"] == "aggressive"
    assert config["performance"] == {"scheduler_profile": "aggressive"}


def test_effective_config_includes_thresholds_scheduler_and_rule_pipeline():
    config = _payload()
    config["filesystem"] = {
        "directory_scan_mode": "current_dir_only",
        "scan_filters": [
            {"name": "size_minimum", "enabled": True, "min_inspection_size_bytes": 1048576}
        ]
    }
    config["thresholds"] = {"archive_score_threshold": 6, "maybe_archive_threshold": 3}
    config["performance"] = {"scheduler_profile": "auto"}

    effective = build_effective_config(config)

    assert effective["thresholds"]["archive_score_threshold"] == 6
    assert effective["min_inspection_size_bytes"] == 1048576
    assert effective["filesystem"]["directory_scan_mode"] == "current_dir_only"
    assert effective["scheduler"]["scheduler_profile"] == "auto"
    assert effective["scheduler"]["resolved_scheduler_profile"] in {"conservative", "aggressive"}
    assert effective["detection"]["rule_pipeline"]["scoring"][0]["name"] == "archive_identity"
