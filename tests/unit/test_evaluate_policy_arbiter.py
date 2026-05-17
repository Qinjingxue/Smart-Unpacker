import pytest

from repair_training.evaluate_policy_arbiter import (
    _decision_stats,
    _hard_cases,
    _scheduler_config,
    _summary,
    _validate_model_root,
)


def test_policy_arbiter_eval_model_root_requires_four_models(tmp_path):
    model_root = tmp_path / "models"
    (model_root / "graph_action").mkdir(parents=True)
    (model_root / "graph_state_value").mkdir()

    with pytest.raises(SystemExit) as exc:
        _validate_model_root(model_root)

    message = str(exc.value)
    assert "normal_structure" in message
    assert "damage_location" in message


def test_policy_arbiter_eval_accepts_complete_model_root(tmp_path):
    model_root = tmp_path / "models"
    for name in ("normal_structure", "damage_location", "graph_state_value", "graph_action"):
        (model_root / name).mkdir(parents=True)

    assert _validate_model_root(model_root) == model_root.resolve()


def test_policy_arbiter_scheduler_config_inherits_advanced_verification(monkeypatch, tmp_path):
    def fake_load_config():
        return {
            "verification": {
                "enabled": True,
                "methods": [
                    {"name": "extraction_exit_signal", "enabled": True},
                    {"name": "archive_test_crc", "enabled": True, "max_items": 123},
                    {"name": "sample_readability", "enabled": True},
                ],
            },
            "repair": {
                "workspace": "original",
                "policy": {"enabled": False, "strict_provider_errors": True},
            },
        }

    monkeypatch.setattr("repair_training.evaluate_policy_arbiter.load_config", fake_load_config)

    config = _scheduler_config(workspace=tmp_path / "workspace", model_root=tmp_path / "models", max_rounds=6)

    methods = [item["name"] for item in config["verification"]["methods"]]
    assert methods == ["extraction_exit_signal", "archive_test_crc", "sample_readability"]
    assert config["repair"]["verification"] == config["verification"]
    assert config["repair"]["workspace"] == str(tmp_path / "workspace")
    assert config["repair"]["max_repair_rounds_per_task"] == 6
    assert config["repair"]["policy"]["enabled"] is True
    assert config["repair"]["policy"]["strict_provider_errors"] is True
    assert config["repair"]["policy"]["policy_model_root"] == str(tmp_path / "models")


def test_policy_arbiter_decision_stats_reads_scheduler_history_shape():
    rounds = [
        {
            "graph_action": {"action": "checkout", "node_id": "node:0"},
            "stop_controller": {
                "selected_prior": {"action_type": "stop_signal", "prior_score": 0.92},
            },
            "graph_summary": {"frontier_count": 2},
        },
        {
            "graph_action": {"action": "finish", "reason": "plateau"},
            "graph_summary": {"frontier_count": 1},
        },
        {
            "graph_action": {"action": "exhaust"},
            "best_seen_recovery": {"score": 0.5},
        }
    ]

    stats = _decision_stats(rounds)

    assert stats["actions"] == {"checkout": 1, "finish": 1, "exhaust": 1}
    assert stats["checkout_count"] == 1
    assert stats["exhaust_count"] == 1
    assert stats["stop_signal_overridden"] == 1
    assert stats["frontier_available_at_finish"] == 1
    assert stats["exhaust_then_recovered"] == 1


def test_policy_arbiter_summary_includes_oracle_and_decision_quality():
    runs = [
            {
                "status": "repaired",
                "final_recovery": {"status": "complete"},
                "final_recovery_score": 1.0,
                "oracle_best_recovery": 1.0,
                "oracle_gap": 0.0,
                "decision_stats": {"actions": {"expand": 1}, "graph_expansions": 1},
            },
            {
                "status": "partial",
                "final_recovery": {"status": "partial"},
                "final_recovery_score": 0.5,
                "oracle_best_recovery": 0.75,
                "oracle_gap": 0.25,
                "decision_stats": {"actions": {"finish": 1}, "frontier_available_at_finish": 1},
            },
        ]

    summary = _summary(runs, elapsed=3.0)

    assert summary["samples"] == 2
    assert summary["final_recovery_mean"] == 0.75
    assert summary["repaired_rate"] == 0.5
    assert summary["scheduler_repaired_rate"] == 0.5
    assert summary["oracle_repaired_rate"] == 0.5
    assert summary["oracle_best_complete_rate"] == 0.5
    assert summary["oracle_best_recovery_mean"] == 0.875
    assert summary["policy_vs_oracle_complete_rate_gap"] == 0.0
    assert summary["final_recovery_status_counts"] == {"complete": 1, "partial": 1}
    assert summary["oracle_gap_mean"] == 0.125
    assert summary["oracle_gap_available_count"] == 2
    assert summary["oracle_gap_missing_count"] == 0
    assert summary["decision_quality"]["actions"] == {"expand": 1, "finish": 1}
    assert summary["decision_quality"]["graph_expansions"] == 1
    assert summary["decision_quality"]["frontier_available_at_finish"] == 1


def test_policy_arbiter_summary_does_not_report_zero_oracle_gap_when_missing():
    summary = _summary(
        [
            {
                "status": "partial",
                "final_recovery": {"status": "complete"},
                "final_recovery_score": 1.0,
                "oracle_best_recovery": None,
                "oracle_gap": None,
                "decision_stats": {},
            }
        ],
        elapsed=1.0,
    )

    assert summary["oracle_gap_available_count"] == 0
    assert summary["oracle_gap_missing_count"] == 1
    assert summary["oracle_gap_mean"] is None
    assert summary["oracle_gap_p90"] is None
    assert summary["scheduler_partial_but_final_complete_count"] == 1
    assert summary["repaired_rate"] == 0.0
    assert summary["policy_final_complete_rate"] == 1.0
    assert summary["oracle_repaired_rate"] is None
    assert summary["oracle_best_complete_rate"] is None


def test_policy_arbiter_hard_cases_include_low_and_zero_recovery_without_oracle_gap():
    cases = _hard_cases(
        [
            {"index": 1, "status": "partial", "final_recovery_score": 1.0, "oracle_gap": None, "decision_stats": {}},
            {"index": 2, "status": "partial", "final_recovery_score": 0.4, "oracle_gap": None, "decision_stats": {}},
            {"index": 3, "status": "partial", "final_recovery_score": 0.0, "oracle_gap": None, "decision_stats": {}},
        ]
    )

    assert [case["index"] for case in cases] == [3, 2]
    assert cases[0]["hard_case_reasons"] == ["zero_final_recovery"]
    assert cases[1]["hard_case_reasons"] == ["low_final_recovery_lt_0_5"]
