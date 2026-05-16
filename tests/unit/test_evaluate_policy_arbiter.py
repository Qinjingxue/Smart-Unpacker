import pytest

from repair_training.evaluate_policy_arbiter import (
    _decision_stats,
    _summary,
    _validate_model_root,
)


def test_policy_arbiter_eval_model_root_requires_four_models(tmp_path):
    model_root = tmp_path / "models"
    (model_root / "repair_action").mkdir(parents=True)
    (model_root / "state_value").mkdir()

    with pytest.raises(SystemExit) as exc:
        _validate_model_root(model_root)

    message = str(exc.value)
    assert "normal_structure" in message
    assert "damage_location" in message


def test_policy_arbiter_eval_accepts_complete_model_root(tmp_path):
    model_root = tmp_path / "models"
    for name in ("normal_structure", "damage_location", "state_value", "repair_action"):
        (model_root / name).mkdir(parents=True)

    assert _validate_model_root(model_root) == model_root.resolve()


def test_policy_arbiter_decision_stats_reads_scheduler_history_shape():
    rounds = [
        {
            "value_gap": 0.4,
            "candidate_state_values": {
                "a": {"reachable_recovery_value": 0.8},
                "b": {"metadata": {"decision_reason": "candidate_value_budget_fallback"}},
            },
            "action": {
                "action": "stop",
                "arbiter": {
                    "scores": [
                        {"action": "stop", "value_gap": 0.4, "hard_guard": "stop_blocked_high_value_gap"},
                        {"action": "apply_patch", "candidate_id": "a", "value_delta": 0.2},
                        {"action": "apply_patch", "candidate_id": "b", "value_delta": 0.0, "hard_guard": "repeated_digest"},
                    ],
                },
            },
        }
    ]

    stats = _decision_stats(rounds)

    assert stats["actions"] == {"stop": 1}
    assert stats["high_gap_stop_count"] == 1
    assert stats["premature_stop_count"] == 1
    assert stats["loop_prevented_count"] == 1
    assert stats["apply_zero_value_delta_count"] == 1
    assert stats["candidate_value_predictions"] == 1
    assert stats["candidate_value_count"] == 2


def test_policy_arbiter_summary_includes_oracle_and_decision_quality():
    runs = [
        {
            "status": "repaired",
            "final_recovery_score": 1.0,
            "oracle_gap": 0.0,
            "decision_stats": {"actions": {"apply_patch": 1}, "high_gap_stop_count": 0},
        },
        {
            "status": "partial",
            "final_recovery_score": 0.5,
            "oracle_gap": 0.25,
            "decision_stats": {"actions": {"stop": 1}, "high_gap_stop_count": 1},
        },
    ]

    summary = _summary(runs, elapsed=3.0)

    assert summary["samples"] == 2
    assert summary["final_recovery_mean"] == 0.75
    assert summary["repaired_rate"] == 0.5
    assert summary["oracle_gap_mean"] == 0.125
    assert summary["decision_quality"]["actions"] == {"apply_patch": 1, "stop": 1}
    assert summary["decision_quality"]["high_gap_stop_count"] == 1
