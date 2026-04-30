import json

from sunpack.config import loader
from sunpack.detection.scheduler import DetectionScheduler


def _write_json(path, payload):
    path.write_text(json.dumps(payload), encoding="utf-8")


def _verification_config():
    return {
        "enabled": True,
        "max_retries": 2,
        "cleanup_failed_output": True,
        "accept_partial_when_source_damaged": True,
        "partial_min_completeness": 0.2,
        "complete_accept_threshold": 0.999,
        "partial_accept_threshold": 0.2,
        "retry_on_verification_failure": True,
        "methods": [
            {"name": "extraction_exit_signal", "enabled": True},
            {"name": "output_presence", "enabled": True},
        ],
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


def test_load_config_merges_simple_config_over_advanced_config(tmp_path, monkeypatch):
    simple = tmp_path / "sunpack_config.json"
    advanced = tmp_path / "sunpack_advanced_config.json"
    _write_json(advanced, {
        "cli": {"language": "en"},
        "thresholds": {"archive_score_threshold": 6, "maybe_archive_threshold": 3},
        "recursive_extract": "*",
        "post_extract": {"archive_cleanup_mode": "r", "flatten_single_directory": True},
        "filesystem": {
            "directory_scan_mode": "*",
            "scan_filters_enabled": True,
            "scan_filters": [{"name": "size_range", "enabled": True, "range": "r >= 1 MB"}],
        },
        "performance": {
            "scheduler_profile": "auto",
            "max_extract_task_seconds": 1800,
        },
        "verification": _verification_config(),
        "detection": {
            "enabled": True,
            "fact_collectors": [{"name": "file_facts", "enabled": True}],
            "processors": [],
            "rule_pipeline": {
                "precheck": [],
                "scoring": [{"name": "extension", "enabled": True}],
                "confirmation": [],
            },
        },
    })
    _write_json(simple, {
        "cli": {"language": "zh"},
        "filesystem": {
            "scan_filters": [{"name": "size_range", "enabled": True, "range": "r >= 2 MB"}],
        },
        "performance": {"scheduler_profile": "conservative"},
    })

    monkeypatch.setattr(loader, "_candidate_config_paths", _layered_config_paths(simple, advanced))

    config = loader.load_config()

    assert config["cli"]["language"] == "zh"
    assert config["filesystem"]["directory_scan_mode"] == "recursive"
    assert config["filesystem"]["scan_filters"] == [{"name": "size_range", "enabled": True, "range": "r >= 2 MB"}]
    assert config["performance"]["scheduler_profile"] == "conservative"
    assert config["performance"]["max_extract_task_seconds"] == 1800
    assert config["detection"]["enabled"] is True


def test_load_config_requires_external_verification_config(tmp_path, monkeypatch):
    simple = tmp_path / "sunpack_config.json"
    advanced = tmp_path / "sunpack_advanced_config.json"
    _write_json(advanced, {
        "thresholds": {"archive_score_threshold": 6, "maybe_archive_threshold": 3},
        "recursive_extract": "*",
        "post_extract": {"archive_cleanup_mode": "r", "flatten_single_directory": True},
        "filesystem": {"directory_scan_mode": "*", "scan_filters": []},
        "detection": {
            "enabled": True,
            "rule_pipeline": {
                "precheck": [],
                "scoring": [{"name": "extension", "enabled": True}],
                "confirmation": [],
            },
        },
    })
    _write_json(simple, {})
    monkeypatch.setattr(loader, "_candidate_config_paths", _layered_config_paths(simple, advanced))

    try:
        loader.load_effective_config_payload()
    except loader.ConfigError as exc:
        assert "verification" in str(exc)
    else:
        raise AssertionError("missing verification config should be rejected")


def test_effective_config_payload_returns_merged_external_config(tmp_path, monkeypatch):
    simple = tmp_path / "sunpack_config.json"
    advanced = tmp_path / "sunpack_advanced_config.json"
    _write_json(advanced, {
        "thresholds": {"archive_score_threshold": 6, "maybe_archive_threshold": 3},
        "recursive_extract": "*",
        "post_extract": {"archive_cleanup_mode": "r", "flatten_single_directory": True},
        "filesystem": {"directory_scan_mode": "*", "scan_filters": []},
        "verification": _verification_config(),
        "detection": {
            "enabled": True,
            "rule_pipeline": {
                "precheck": [],
                "scoring": [{"name": "extension", "enabled": True}],
                "confirmation": [],
            },
        },
    })
    _write_json(simple, {"recursive_extract": "2"})

    monkeypatch.setattr(loader, "_candidate_config_paths", _layered_config_paths(simple, advanced))

    path, payload = loader.load_effective_config_payload()

    assert path == simple
    assert payload["recursive_extract"] == "2"
    assert payload["filesystem"]["directory_scan_mode"] == "*"


def test_embedded_payload_scan_level_simple_config_overrides_advanced_details(tmp_path, monkeypatch):
    simple = tmp_path / "sunpack_config.json"
    advanced = tmp_path / "sunpack_advanced_config.json"
    _write_json(advanced, {
        "thresholds": {"archive_score_threshold": 6, "maybe_archive_threshold": 3},
        "recursive_extract": "*",
        "post_extract": {"archive_cleanup_mode": "r", "flatten_single_directory": True},
        "filesystem": {"directory_scan_mode": "*", "scan_filters": []},
        "verification": _verification_config(),
        "detection": {
            "enabled": True,
            "processors": [
                {
                    "name": "embedded_archive",
                    "enabled": True,
                    "carrier_scan_tail_window_bytes": 999,
                    "carrier_scan_prefix_window_bytes": 999,
                }
            ],
            "rule_pipeline": {
                "precheck": [],
                "scoring": [
                    {
                        "name": "embedded_payload_identity",
                        "enabled": True,
                        "embedded_payload_scan_level": "deep",
                        "loose_scan_full_scan_max_bytes": 999,
                        "carrier_scan_tail_window_bytes": 999,
                    }
                ],
                "confirmation": [],
            },
        },
    })
    _write_json(simple, {
        "detection": {
            "rule_pipeline": {
                "scoring": [
                    {"name": "embedded_payload_identity", "embedded_payload_scan_level": "light"}
                ]
            }
        }
    })
    monkeypatch.setattr(loader, "_candidate_config_paths", _layered_config_paths(simple, advanced))

    path, payload = loader.load_effective_config_payload()
    config = loader.load_config()

    assert path == simple
    processor = payload["detection"]["processors"][0]
    scoring = payload["detection"]["rule_pipeline"]["scoring"][0]
    assert scoring["embedded_payload_scan_level"] == "light"
    assert processor["carrier_scan_tail_window_bytes"] == 999
    assert processor["carrier_scan_prefix_window_bytes"] == 999
    assert scoring["loose_scan_full_scan_max_bytes"] == 999
    assert scoring["carrier_scan_tail_window_bytes"] == 999
    prepared = _prepared_scoring_config(config, "embedded_payload_identity")
    assert prepared["embedded_payload_scan_level"] == "light"
    assert prepared["loose_scan_full_scan_max_bytes"] == 8 * 1024 * 1024
    assert prepared["carrier_scan_tail_window_bytes"] == 1024 * 1024
    assert prepared["carrier_scan_prefix_window_bytes"] == 0


def test_embedded_payload_scan_level_manual_preserves_detailed_parameters(tmp_path, monkeypatch):
    simple = tmp_path / "sunpack_config.json"
    advanced = tmp_path / "sunpack_advanced_config.json"
    _write_json(advanced, {
        "thresholds": {"archive_score_threshold": 6, "maybe_archive_threshold": 3},
        "recursive_extract": "*",
        "post_extract": {"archive_cleanup_mode": "r", "flatten_single_directory": True},
        "filesystem": {"directory_scan_mode": "*", "scan_filters": []},
        "verification": _verification_config(),
        "detection": {
            "enabled": True,
            "processors": [
                {
                    "name": "embedded_archive",
                    "enabled": True,
                    "carrier_scan_tail_window_bytes": 123,
                    "carrier_scan_prefix_window_bytes": 456,
                }
            ],
            "rule_pipeline": {
                "precheck": [],
                "scoring": [
                    {
                        "name": "embedded_payload_identity",
                        "enabled": True,
                        "embedded_payload_scan_level": "manual",
                        "loose_scan_full_scan_max_bytes": 789,
                        "carrier_scan_tail_window_bytes": 321,
                    }
                ],
                "confirmation": [],
            },
        },
    })
    _write_json(simple, {})
    monkeypatch.setattr(loader, "_candidate_config_paths", _layered_config_paths(simple, advanced))

    _, payload = loader.load_effective_config_payload()
    config = loader.load_config()

    processor = payload["detection"]["processors"][0]
    scoring = payload["detection"]["rule_pipeline"]["scoring"][0]
    assert scoring["embedded_payload_scan_level"] == "manual"
    assert processor["carrier_scan_tail_window_bytes"] == 123
    assert processor["carrier_scan_prefix_window_bytes"] == 456
    assert scoring["loose_scan_full_scan_max_bytes"] == 789
    assert scoring["carrier_scan_tail_window_bytes"] == 321
    prepared = _prepared_scoring_config(config, "embedded_payload_identity")
    assert prepared["loose_scan_full_scan_max_bytes"] == 789
    assert prepared["carrier_scan_tail_window_bytes"] == 321


def test_embedded_payload_scan_level_does_not_apply_when_rule_is_disabled(tmp_path, monkeypatch):
    simple = tmp_path / "sunpack_config.json"
    advanced = tmp_path / "sunpack_advanced_config.json"
    _write_json(advanced, {
        "thresholds": {"archive_score_threshold": 6, "maybe_archive_threshold": 3},
        "recursive_extract": "*",
        "post_extract": {"archive_cleanup_mode": "r", "flatten_single_directory": True},
        "filesystem": {"directory_scan_mode": "*", "scan_filters": []},
        "verification": _verification_config(),
        "detection": {
            "enabled": True,
            "processors": [
                {
                    "name": "embedded_archive",
                    "enabled": True,
                    "carrier_scan_tail_window_bytes": 123,
                    "carrier_scan_prefix_window_bytes": 456,
                }
            ],
            "rule_pipeline": {
                "precheck": [],
                "scoring": [
                    {
                        "name": "embedded_payload_identity",
                        "enabled": False,
                        "embedded_payload_scan_level": "light",
                        "carrier_scan_tail_window_bytes": 321,
                    }
                ],
                "confirmation": [],
            },
        },
    })
    _write_json(simple, {})
    monkeypatch.setattr(loader, "_candidate_config_paths", _layered_config_paths(simple, advanced))

    _, payload = loader.load_effective_config_payload()

    processor = payload["detection"]["processors"][0]
    scoring = payload["detection"]["rule_pipeline"]["scoring"][0]
    assert processor["carrier_scan_tail_window_bytes"] == 123
    assert processor["carrier_scan_prefix_window_bytes"] == 456
    assert scoring["carrier_scan_tail_window_bytes"] == 321
