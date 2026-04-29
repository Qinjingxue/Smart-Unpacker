from packrelic.app.cli_runtime import (
    apply_runtime_config_overrides,
    build_effective_config,
)
from packrelic.config.config_validator import validate_config_payload
from tests.helpers.detection_config import with_detection_pipeline


def _payload():
    return with_detection_pipeline(
        scoring=[{"name": "embedded_payload_identity", "enabled": True}],
    )


def test_config_validate_checks_rule_schema_types_even_when_disabled():
    payload = _payload()
    payload["detection"]["rule_pipeline"]["scoring"][0]["enabled"] = False
    payload["detection"]["rule_pipeline"]["scoring"][0]["carrier_exts"] = 123

    result = validate_config_payload(payload)

    assert not result["ok"]
    assert any("Invalid type" in error for error in result["errors"])


def test_config_validate_rejects_normalized_config_values_in_external_shorthand_fields():
    payload = _payload()
    payload["recursive_extract"] = {"mode": "infinite", "max_rounds": 999}
    payload["post_extract"] = {"archive_cleanup_mode": "recycle"}
    payload["filesystem"] = {"directory_scan_mode": "recursive", "scan_filters": []}

    result = validate_config_payload(payload)

    assert not result["ok"]
    assert any("recursive_extract must" in error for error in result["errors"])
    assert any("archive_cleanup_mode must" in error for error in result["errors"])
    assert any("directory_scan_mode must" in error for error in result["errors"])


def test_config_validate_checks_verification_methods_are_registered():
    payload = _payload()
    payload["verification"] = {
        "methods": [
            {"name": "output_presence", "enabled": True},
            {"name": "missing_verification_method", "enabled": False},
        ],
    }

    result = validate_config_payload(payload)

    assert not result["ok"]
    assert "output_presence" in result["available_verification_methods"]
    assert any("Unknown verification method" in error for error in result["errors"])


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
        "directory_scan_mode": "-",
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
    assert effective["detection"]["rule_pipeline"]["scoring"][0]["name"] == "embedded_payload_identity"
