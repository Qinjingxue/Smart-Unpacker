import json

import pytest

from sunpack.config import loader
from sunpack.detection.scheduler import DetectionScheduler


def _write_json(path, payload):
    path.write_text(json.dumps(payload), encoding="utf-8")


def _verification_config():
    return {
        "enabled": True, "max_retries": 2, "cleanup_failed_output": True,
        "accept_partial_when_source_damaged": True, "partial_min_completeness": 0.2,
        "complete_accept_threshold": 0.999, "partial_accept_threshold": 0.2,
        "retry_on_verification_failure": True,
        "methods": [{"name": "extraction_exit_signal", "enabled": True}, {"name": "output_presence", "enabled": True}],
    }


def _layered_config_paths(simple, advanced):
    def candidate_paths(filename):
        return [simple if filename == loader.SIMPLE_CONFIG_FILENAME else advanced]
    return candidate_paths


def _prepared_scoring_config(config, name):
    scheduler = DetectionScheduler(config)
    for rule in scheduler.rule_manager._prepare_rules("scoring"):
        if rule.name == name:
            return rule.config
    return None


def _advanced_payload(scoring=None):
    return {
        "cli": {"language": "en"},
        "thresholds": {"archive_score_threshold": 6, "maybe_archive_threshold": 3},
        "recursive_extract": "*",
        "post_extract": {"archive_cleanup_mode": "r", "flatten_single_directory": True},
        "filesystem": {"directory_scan_mode": "*", "scan_filters_enabled": True, "scan_filters": []},
        "performance": {"scheduler_profile": "auto", "max_extract_task_seconds": 1800},
        "verification": _verification_config(),
        "detection": {
            "enabled": True,
            "fact_collectors": [{"name": "file_facts", "enabled": True}],
            "processors": [],
            "rule_pipeline": {"precheck": [], "scoring": scoring or [{"name": "extension", "enabled": True}], "confirmation": []},
        },
    }


def test_load_config_merges_simple_config_over_advanced_config(tmp_path, monkeypatch):
    simple = tmp_path / "sunpack_config.json"
    advanced = tmp_path / "sunpack_advanced_config.json"
    payload = _advanced_payload()
    payload["filesystem"]["scan_filters"] = [{"name": "size_range", "enabled": True, "range": "r >= 1 MB"}]
    _write_json(advanced, payload)
    _write_json(simple, {
        "cli": {"language": "zh"},
        "filesystem": {"scan_filters": [{"name": "size_range", "enabled": True, "range": "r >= 2 MB"}]},
        "performance": {"scheduler_profile": "conservative"},
    })
    monkeypatch.setattr(loader, "_candidate_config_paths", _layered_config_paths(simple, advanced))
    config = loader.load_config()
    assert config["cli"]["language"] == "zh"
    assert config["filesystem"]["directory_scan_mode"] == "recursive"
    assert config["filesystem"]["scan_filters"][0]["range"] == "r >= 2 MB"
    assert config["performance"]["max_extract_task_seconds"] == 1800


def test_load_config_requires_external_verification_config(tmp_path, monkeypatch):
    simple = tmp_path / "sunpack_config.json"
    advanced = tmp_path / "sunpack_advanced_config.json"
    payload = _advanced_payload()
    payload.pop("verification")
    _write_json(advanced, payload)
    _write_json(simple, {})
    monkeypatch.setattr(loader, "_candidate_config_paths", _layered_config_paths(simple, advanced))
    with pytest.raises(loader.ConfigError, match="verification"):
        loader.load_effective_config_payload()


def test_effective_config_payload_returns_merged_external_config(tmp_path, monkeypatch):
    simple = tmp_path / "sunpack_config.json"
    advanced = tmp_path / "sunpack_advanced_config.json"
    _write_json(advanced, _advanced_payload())
    _write_json(simple, {"recursive_extract": "2"})
    monkeypatch.setattr(loader, "_candidate_config_paths", _layered_config_paths(simple, advanced))
    path, payload = loader.load_effective_config_payload()
    assert path == simple
    assert payload["recursive_extract"] == "2"
    assert payload["filesystem"]["directory_scan_mode"] == "*"


def test_embedded_single_candidate_ratio_simple_config_overrides_advanced(tmp_path, monkeypatch):
    simple = tmp_path / "sunpack_config.json"
    advanced = tmp_path / "sunpack_advanced_config.json"
    _write_json(advanced, _advanced_payload([{
        "name": "embedded_payload_identity", "enabled": True,
        "deep_scan_single_candidate_ratio": 0.3,
    }]))
    _write_json(simple, {"detection": {"rule_pipeline": {"scoring": [{
        "name": "embedded_payload_identity", "deep_scan_single_candidate_ratio": 0.8,
    }]}}})
    monkeypatch.setattr(loader, "_candidate_config_paths", _layered_config_paths(simple, advanced))
    prepared = _prepared_scoring_config(loader.load_config(), "embedded_payload_identity")
    assert prepared["deep_scan_single_candidate_ratio"] == 0.8


def test_obsolete_embedded_scan_configuration_is_rejected():
    config = _advanced_payload([{
        "name": "embedded_payload_identity", "enabled": True,
        "embedded_payload_scan_level": "deep",
    }])
    with pytest.raises(ValueError, match="embedded_payload_scan_level"):
        _prepared_scoring_config(config, "embedded_payload_identity")
