import json
import random
from pathlib import Path

import pytest

from sunpack.contracts.archive_input import ArchiveInputDescriptor
from sunpack.contracts.archive_state import ArchiveState, PatchOperation, PatchPlan
from sunpack.repair.candidate import RepairCandidate
from sunpack.repair.search.proposals import ModuleMaterializationResult, PolicyModuleProposal
from sunpack.repair.search.recovery import PolicyRecoverySnapshot
from repair_training.policy.graph_rows import build_policy_graph_rows
from repair_training.policy.q_labels import annotate_episode_future_best_q
from repair_training.policy import teacher as teacher_module
from sunpack.repair.model.policy.inference import RepairPolicyTransformerModel
from sunpack.repair.model.policy.model import build_repair_policy_transformer
from sunpack.repair.model.policy.schema import PolicyAction, PolicyGraphTrainingSample, transition_sample_from_dict, world_sample_from_dict, sample_from_dict
from repair_training.policy.teacher import build_policy_teacher_samples, label_teacher_sample
from sunpack.repair.model.policy.tensorize import tensorize_sample, tensorize_world_sample
from sunpack.repair.model.policy.tensorize import WORLD_TARGET_DIM
from repair_training.policy.world_rows import build_policy_world_samples
from repair_training.__main__ import train_main


pytest.importorskip("torch")


def test_policy_graph_log_row_builds_training_sample():
    rows = build_policy_graph_rows([_runtime_log_row()])

    assert len(rows) == 1
    sample = rows[0]
    assert sample.current_node_id == "node_root"
    assert {action.action_type for action in sample.actions} == {"module", "undo", "stop"}
    assert any(action.action_prior == 1.0 and action.module_name == "zip_eocd_rebuild" for action in sample.actions)


def test_policy_graph_rows_are_sanitized_for_training():
    raw = _runtime_log_row()
    loop = raw["repair"]["history"]["items"][0]["diagnosis"]["policy_loop"]
    node = loop["graph"]["nodes"]["node_root"]
    node["archive_state"] = {"source": {"path": "secret.zip"}, "patches": [{"bytes": "large"}]}
    node["state_value"] = {"reachable_recovery_value": 1.0}
    node["verification"] = {
        "summary": {"completeness": 0.2, "assessment_status": "partial", "giant_blob": {"x": "y"}},
        "file_observations": [{"path": "out/a.txt"}],
    }
    loop["graph"]["edges"]["e1"] = {
        "edge_id": "e1",
        "from_node_id": "node_root",
        "candidate_id": "m1",
        "module_name": "zip_eocd_rebuild",
        "action_score": {"score": 0.9, "debug": {"huge": True}},
    }
    loop["rounds"][0]["actions"][0]["repaired_state"] = {"must": "not leak"}
    loop["rounds"][0]["actions"][0]["archive_state"] = {"must": "not leak"}
    loop["rounds"][0]["diagnosis_hgt"]["diagnostics"] = {"archive_knowledge": {"must": "not leak"}}

    sample = build_policy_graph_rows([raw])[0].to_dict()
    serialized = json.dumps(sample, sort_keys=True)

    assert "archive_state" not in serialized
    assert "state_value" not in serialized
    assert "repaired_state" not in serialized
    assert "archive_knowledge" not in serialized
    assert "file_observations" not in serialized
    assert "giant_blob" not in serialized
    assert "action_score" not in sample["graph"]["edges"]["e1"]
    assert sample["graph"]["nodes"]["node_root"]["verification"] == {
        "summary": {"completeness": 0.2, "assessment_status": "partial"}
    }


def test_policy_transformer_tensorize_and_forward_shapes():
    sample = build_policy_graph_rows([_runtime_log_row()])[0]
    item = tensorize_sample(sample)
    model = build_repair_policy_transformer({"hidden_dim": 32, "heads": 4, "layers": 1})

    logits = model(item["node_x"], item["memory_x"], item["action_x"])
    promising = model.promising_logit(item["node_x"], item["memory_x"])
    outputs = model.forward_all(item["node_x"], item["memory_x"], item["action_x"], item["edge_x"])

    assert logits.shape[0] == len(sample.actions)
    assert promising.shape == (1,)
    assert outputs["continue_branch"].shape == (1,)
    assert outputs["action_continue"].shape[0] == len(sample.actions)


def test_policy_transformer_fuses_continuation_head_into_action_logits():
    sample = build_policy_graph_rows([_runtime_log_row()])[0]
    item = tensorize_sample(sample)
    base = build_repair_policy_transformer({"hidden_dim": 32, "heads": 4, "layers": 1, "continuation_score_fusion_weight": 0.0})
    fused = build_repair_policy_transformer({"hidden_dim": 32, "heads": 4, "layers": 1, "continuation_score_fusion_weight": 0.5})

    base_outputs = base.forward_all(item["node_x"], item["memory_x"], item["action_x"], item["edge_x"])
    fused_outputs = fused.forward_all(item["node_x"], item["memory_x"], item["action_x"], item["edge_x"])

    assert base_outputs["action_logits"].shape == fused_outputs["action_logits"].shape
    assert "base_action_logits" in fused_outputs
    assert (fused_outputs["action_logits"] - fused_outputs["base_action_logits"]).abs().sum().item() > 0.0


def test_policy_transformer_tensorize_exposes_exploration_signals():
    raw = _runtime_log_row()
    loop = raw["repair"]["history"]["items"][0]["diagnosis"]["policy_loop"]
    node = loop["graph"]["nodes"]["node_root"]
    node["exploration"] = {"fresh_action_count": 0, "exhaustion_ratio": 1.0, "expanded_action_count": 1, "outgoing_action_count": 1}
    loop["graph"]["edges"]["e1"] = {
        "edge_id": "e1",
        "from_node_id": "node_root",
        "candidate_id": "m1",
        "module_name": "zip_eocd_rebuild",
        "module_family": "eocd",
        "exploration": {"attempt_count": 1, "reopened_after_exhaustion": True, "undo_count_after_attempt": 1},
    }
    loop["rounds"][0]["actions"][0]["route_family"] = "eocd"
    sample = build_policy_graph_rows([raw])[0]

    item = tensorize_sample(sample)
    module_features = item["action_x"][0].tolist()

    assert module_features[16] == pytest.approx(1.0)
    assert module_features[17] > 0.0
    assert module_features[18] == pytest.approx(0.0)
    assert module_features[19] == pytest.approx(1.0)
    assert module_features[20] == pytest.approx(0.0)
    assert module_features[21] == pytest.approx(1.0)


def test_policy_transition_schema_roundtrip_and_world_rows():
    transition = transition_sample_from_dict(_transition_row())

    assert transition.chosen_action.module_name == "zip_fix_eocd_record"
    rows = build_policy_world_samples([transition])
    tasks = {row.task for row in rows}

    assert tasks == {"transition", "masked_graph", "ranking"}
    assert all(world_sample_from_dict(row.to_dict()).task == row.task for row in rows)


def test_transition_episode_future_best_q_labels_chosen_and_stop_actions():
    first = transition_sample_from_dict(_transition_row())
    second_row = _transition_row()
    second_row["sample_id"] = "transition_case_step2"
    second_row["step_index"] = 2
    second_row["graph_before"] = first.graph_after
    second_row["current_node_id"] = "node_patch"
    second_row["best_node_id"] = "node_patch"
    second_row["available_actions"] = [
        {"action_type": "module", "action_id": "fix2", "module_name": "zip_fix_more"},
        {"action_type": "stop", "action_id": "stop"},
    ]
    second_row["chosen_action"] = {"action_type": "module", "action_id": "fix2", "module_name": "zip_fix_more"}
    second_row["graph_after"] = _graph_with_best_score("node_patch2", parent_id="node_patch", score=0.95)
    second = transition_sample_from_dict(second_row)

    labelled = annotate_episode_future_best_q([first, second])
    first_actions = {action.action_type if action.action_type == "stop" else action.module_name: action for action in labelled[0].available_actions}
    second_actions = {action.action_type if action.action_type == "stop" else action.module_name: action for action in labelled[1].available_actions}

    assert labelled[0].chosen_action.action_q_value == pytest.approx(0.95)
    assert labelled[0].action_q_values["module:zip_fix_eocd_record"] == pytest.approx(0.95)
    assert first_actions["stop"].action_q_value == pytest.approx(0.2)
    assert first_actions["zip_fix_eocd_record"].best_action_set_member is True
    assert first_actions["stop"].action_regret == pytest.approx(0.75)
    assert labelled[1].chosen_action.action_q_value == pytest.approx(0.95)
    assert second_actions["stop"].action_q_value == pytest.approx(0.8)


def test_world_tensorize_and_model_forward_all_shapes():
    transition = transition_sample_from_dict(_transition_row())
    world = next(row for row in build_policy_world_samples([transition]) if row.task == "transition")
    item = tensorize_world_sample(world)
    model = build_repair_policy_transformer({"hidden_dim": 32, "heads": 4, "layers": 1})

    output = model.forward_all(item["node_x"], item["memory_x"], item["action_x"], item["edge_x"])

    assert output["action_logits"].shape[0] == len(item["actions"])
    assert output["transition"].shape == (len(item["actions"]), WORLD_TARGET_DIM)
    assert output["masked"].shape[0] == 4


def test_transition_target_contains_next_node_hgt_and_verification_state():
    transition = transition_sample_from_dict(_transition_row())
    world = next(row for row in build_policy_world_samples([transition]) if row.task == "transition")
    item = tensorize_world_sample(world)
    target = item["transition_target"].tolist()

    assert len(target) == WORLD_TARGET_DIM
    assert target[0] == pytest.approx(0.8)
    assert target[1] == pytest.approx(0.6)
    # root-case vector starts after the six base delta fields; eocd.cd_size is index 1.
    assert target[6 + 1] == pytest.approx(0.2)
    recovery_offset = 6 + 26
    assert target[recovery_offset] == pytest.approx(0.8)
    assert target[recovery_offset + 1] == pytest.approx(0.75)
    assert target[recovery_offset + 4] == pytest.approx(2 / 1024)
    assert target[recovery_offset + 10] == pytest.approx(0.0)


def test_teacher_stop_q_equals_current_best_and_marks_promising_future():
    sample = _teacher_sample(actions=[
        PolicyAction(action_type="module", action_id="m1", module_name="zip_fix", action_q_value=0.8),
        PolicyAction(action_type="undo", action_id="undo", action_q_value=0.4),
        PolicyAction(action_type="stop", action_id="stop"),
    ])

    labelled = label_teacher_sample(sample, action_outcomes={"module:zip_fix": 0.8, "undo:undo": 0.4})
    actions = {action.action_type if action.action_type != "module" else "module": action for action in labelled.actions}

    assert actions["stop"].action_q_value == pytest.approx(0.2)
    assert labelled.has_promising_future is True
    assert labelled.stop_regret == pytest.approx(0.6)
    assert actions["stop"].action_regret == pytest.approx(0.6)


def test_teacher_undo_q_can_beat_current_branch_module():
    sample = _teacher_sample(actions=[
        PolicyAction(action_type="module", action_id="m_bad", module_name="zip_bad"),
        PolicyAction(action_type="undo", action_id="undo"),
        PolicyAction(action_type="stop", action_id="stop"),
    ])

    labelled = label_teacher_sample(sample, action_outcomes={"module:zip_bad": 0.25, "undo:undo": 0.9})
    by_type = {action.action_type: action for action in labelled.actions if action.action_type != "module"}
    module = next(action for action in labelled.actions if action.action_type == "module")

    assert by_type["undo"].action_q_value > module.action_q_value
    assert by_type["undo"].action_regret == pytest.approx(0.0)


def test_teacher_consecutive_undo_rows_keep_undo_best():
    first = label_teacher_sample(_teacher_sample(sample_id="undo1"), action_outcomes={"undo:undo": 0.9, "module:zip_bad": 0.3})
    second = label_teacher_sample(_teacher_sample(sample_id="undo2", depth=1), action_outcomes={"undo:undo": 0.85, "module:zip_bad": 0.2})

    for sample in (first, second):
        best = max(sample.actions, key=lambda action: action.action_q_value)
        assert best.action_type == "undo"


def test_transition_labels_cap_undo_without_promising_frontier():
    row = _undo_transition_row(parent_fresh=0, current_visit_count=1)
    transition = transition_sample_from_dict(row)

    labelled = annotate_episode_future_best_q([transition])[0]
    actions = {action.action_type if action.action_type != "module" else action.module_name: action for action in labelled.available_actions}

    assert actions["undo"].action_q_value <= 0.220001
    assert actions["undo"].features["undo_without_frontier_cap"] == pytest.approx(0.22)
    assert actions["zip_alt"].action_q_value > actions["undo"].action_q_value


def test_transition_labels_prefer_module_after_undo_reopen():
    row = _undo_transition_row(parent_fresh=0, current_visit_count=2)
    row["graph_before"]["nodes"]["node_parent"]["exploration"]["fresh_action_count"] = 0
    row["graph_before"]["nodes"]["node_current"]["exploration"]["fresh_action_count"] = 3
    transition = transition_sample_from_dict(row)

    labelled = annotate_episode_future_best_q([transition])[0]
    actions = {action.action_type if action.action_type != "module" else action.module_name: action for action in labelled.available_actions}

    assert actions["zip_alt"].features["post_undo_continue_module_bonus"] == pytest.approx(0.12)
    assert actions["undo"].features["post_undo_repeat_undo_penalty"] == pytest.approx(0.30)
    assert actions["zip_alt"].action_q_value > actions["undo"].action_q_value


def test_transition_labels_continue_promising_branch_before_undo():
    row = _undo_transition_row(parent_fresh=4, current_visit_count=1)
    row["graph_before"]["nodes"]["node_current"]["recovery"] = {"score": 0.35}
    row["graph_before"]["nodes"]["node_current"]["patch_status"] = "applied"
    row["graph_before"]["nodes"]["node_current"]["exploration"]["fresh_action_count"] = 4
    row["graph_before"]["nodes"]["node_current"]["diagnosis_hgt"] = {"root_case": {"scores": {"eocd.cd_size": 0.95}}}
    row["graph_before"]["nodes"]["node_parent"]["diagnosis_hgt"] = {"root_case": {"scores": {"eocd.cd_size": 0.4}}}
    transition = transition_sample_from_dict(row)

    labelled = annotate_episode_future_best_q([transition])[0]
    actions = {action.action_type if action.action_type != "module" else action.module_name: action for action in labelled.available_actions}

    assert actions["zip_alt"].features["branch_continuation_bonus"] > 0.0
    assert actions["undo"].features["premature_undo_on_promising_branch_penalty"] > 0.0
    assert actions["zip_alt"].action_q_value > actions["undo"].action_q_value


def test_tensorize_exposes_continuation_targets():
    row = _undo_transition_row(parent_fresh=4, current_visit_count=1)
    row["graph_before"]["nodes"]["node_current"]["recovery"] = {"score": 0.35}
    row["graph_before"]["nodes"]["node_current"]["patch_status"] = "applied"
    row["graph_before"]["nodes"]["node_current"]["exploration"]["fresh_action_count"] = 4
    sample = build_policy_world_samples([transition_sample_from_dict(row)])[-1].ranking_sample

    item = tensorize_sample(sample)

    assert item["continue_branch"].item() == pytest.approx(1.0)
    actions = item["actions"]
    module_index = next(index for index, action in enumerate(actions) if action["action_type"] == "module")
    undo_index = next(index for index, action in enumerate(actions) if action["action_type"] == "undo")
    assert item["action_continue_target"][module_index].item() == pytest.approx(1.0)
    assert item["action_continue_target"][undo_index].item() == pytest.approx(0.0)
    assert item["action_continue_mask"][undo_index].item() == pytest.approx(1.0)


def test_build_policy_teacher_samples_writes_q_labels():
    row = {
        "sample_id": "teacher_case",
        "format": "zip",
        "teacher_decisions": [{
            "graph": _teacher_graph(),
            "current_node_id": "node_current",
            "best_node_id": "node_best",
            "best_recovery": {"score": 0.2},
            "actions": [
                {"action_type": "module", "action_id": "m1", "module_name": "zip_fix"},
                {"action_type": "undo", "action_id": "undo"},
                {"action_type": "stop", "action_id": "stop"},
            ],
            "action_outcomes": {"module:zip_fix": 0.75, "undo:undo": 0.4},
        }],
    }
    built = [
        sample.to_dict()
        for sample in build_policy_teacher_samples([row], runtime_rollout=False)
    ]

    assert built[0]["has_promising_future"] is True
    assert any(action["action_type"] == "stop" and action["action_q_value"] == 0.2 for action in built[0]["actions"])


def test_runtime_teacher_rollout_materializes_real_patch_and_writes_clean_graph(tmp_path: Path, monkeypatch):
    damaged = tmp_path / "damaged.zip"
    damaged.write_bytes(b"broken")
    plugin = _RuntimeTeacherPlugin()
    monkeypatch.setattr(teacher_module, "available_module_proposals", plugin.available_modules)
    monkeypatch.setattr(teacher_module, "materialize_module_proposal", plugin.materialize_module)
    monkeypatch.setattr(teacher_module, "RepairModelRuntime", _FakeTeacherModelRuntime)

    def fake_recovery(self, job, state, **kwargs):
        depth = state.patch_depth() if state is not None else 0
        return PolicyRecoverySnapshot(
            state_digest=state.effective_patch_digest() if state is not None else "",
            patch_depth=depth,
            score=0.2 + 0.5 * min(1, depth),
            status="partial",
            verification={"summary": {"completeness": 0.2 + 0.5 * min(1, depth)}},
        )

    monkeypatch.setattr("repair_training.policy.teacher.RecoveryEvaluator.evaluate_state", fake_recovery)
    rows = [
        sample.to_dict()
        for sample in build_policy_teacher_samples([{
        "sample_id": "damaged",
        "format": "zip",
        "damaged_input": {"kind": "file", "path": str(damaged), "format_hint": "zip"},
    }],
            workspace=tmp_path / "teacher",
            recovery_mode="policy_light",
            budget={"max_depth": 2, "rollout_depth": 1, "module_branch_k": 1},
        )
    ]
    serialized = json.dumps(rows, sort_keys=True)

    assert rows
    assert "archive_state" not in serialized
    assert "teacher_hgt" in serialized
    assert plugin.seen_diagnosis and plugin.seen_diagnosis[0]["root_case"]["scores"]["teacher_hgt"] == pytest.approx(0.97)
    assert any(
        isinstance(node, dict) and node.get("patch_depth") == 1 and node.get("patch_status") == "applied"
        for row in rows
        for node in row["graph"]["nodes"].values()
    )
    assert any(action["action_type"] == "module" and action["action_q_value"] > action["action_regret"] for action in rows[0]["actions"])
    assert any(action["action_type"] == "stop" and action["action_q_value"] == pytest.approx(0.2) for action in rows[0]["actions"])


def test_teacher_next_action_can_sample_bad_branch_for_realistic_exploration():
    labelled = label_teacher_sample(_teacher_sample(actions=[
        PolicyAction(action_type="module", action_id="good", module_name="zip_good"),
        PolicyAction(action_type="module", action_id="bad", module_name="zip_bad"),
        PolicyAction(action_type="stop", action_id="stop"),
    ]), action_outcomes={"module:zip_good": 0.9, "module:zip_bad": 0.25})

    chosen = teacher_module._teacher_next_action(labelled, random.Random(3), {"teacher_bad_branch_rate": 1.0, "teacher_exploration_rate": 0.0, "teacher_second_best_rate": 0.0})

    assert chosen is not None
    assert chosen.module_name == "zip_bad"


def test_teacher_next_action_prefers_undo_after_stale_branch():
    labelled = label_teacher_sample(_teacher_sample(actions=[
        PolicyAction(action_type="module", action_id="m1", module_name="zip_fix"),
        PolicyAction(action_type="undo", action_id="undo"),
        PolicyAction(action_type="stop", action_id="stop"),
    ]), action_outcomes={"module:zip_fix": 0.9, "undo:undo": 0.87})
    labelled.memory[-1]["branch_failed_streak"] = 3

    chosen = teacher_module._teacher_next_action(labelled, random.Random(7), {"teacher_force_undo_after_stale": 2, "teacher_undo_margin": 0.05, "teacher_bad_branch_rate": 0.0, "teacher_exploration_rate": 0.0, "teacher_second_best_rate": 0.0})

    assert chosen is not None
    assert chosen.action_type == "undo"


def test_policy_transformer_train_and_infer_smoke(tmp_path: Path):
    run_dir = tmp_path / "run"
    datasets = run_dir / "datasets"
    datasets.mkdir(parents=True)
    ranking_rows = [build_policy_graph_rows([_runtime_log_row(sample_id=f"s{i}")])[0].to_dict() for i in range(4)]
    transitions = [
        transition_sample_from_dict({
            **_undo_transition_row(parent_fresh=1, current_visit_count=1),
            "sample_id": f"s{i}",
        })
        for i in range(4)
    ]
    world_rows = [
        sample.to_dict()
        for sample in build_policy_world_samples(transitions)
    ]
    input_path = datasets / "policy_world_rows.jsonl"
    input_path.write_text("\n".join(json.dumps(row) for row in world_rows), encoding="utf-8")

    assert train_main([
        "--format", "zip",
        "--model", "repair_policy_transformer",
        "--run-dir", str(run_dir),
        "--device", "cpu",
        "--epochs", "1",
        "--hidden-dim", "32",
        "--layers", "1",
    ]) == 0

    model_dir = run_dir / "models" / "repair_policy_transformer"
    assert (model_dir / "model.pt").is_file()
    assert (model_dir / "model_card.json").is_file()
    model = RepairPolicyTransformerModel(model_dir=model_dir, device="cpu")
    prediction = model.predict_sample(sample_from_dict(ranking_rows[0]))

    assert prediction["action_scores"]
    assert prediction["action_predictions"]
    assert "predicted_next_state" in prediction["action_scores"][0]["metadata"]
    assert prediction["action_scores"][0]["action_type"] in {"module", "undo", "stop"}


def test_policy_transformer_rejects_old_model_card(tmp_path: Path):
    model_dir = tmp_path / "model"
    model_dir.mkdir()
    (model_dir / "model_card.json").write_text(json.dumps({"model_type": "step_action", "policy_semantics": "step_q_v1"}), encoding="utf-8")

    with pytest.raises(RuntimeError, match="unsupported repair policy semantics"):
        RepairPolicyTransformerModel(model_dir=model_dir, device="cpu")


def _runtime_log_row(sample_id: str = "sample") -> dict:
    graph = {
        "current_node_id": "node_root",
        "best_node_id": "node_root",
        "nodes": {
            "node_root": {
                "node_id": "node_root",
                "patch_digest": "root",
                "patch_depth": 0,
                "recovery": {"score": 0.2, "completeness": 0.2},
                "patch_status": "root",
                "created_step": 0,
            }
        },
        "edges": {},
    }
    return {
        "sample_id": sample_id,
        "format": "zip",
        "repair": {
            "history": {
                "items": [{
                    "diagnosis": {
                        "policy_loop": {
                            "graph": graph,
                            "current_node_id": "node_root",
                            "best_node_id": "node_root",
                            "rounds": [{
                                "round": 1,
                                "actions": [
                                    {"action_type": "module", "action_id": "m1", "module_name": "zip_eocd_rebuild", "confidence": 0.8},
                                    {"action_type": "undo", "action_id": "undo"},
                                    {"action_type": "stop", "action_id": "stop"},
                                ],
                                "graph_action": {"action_type": "module", "action_id": "m1", "module_name": "zip_eocd_rebuild"},
                                "diagnosis_hgt": {"root_case": {"scores": {"eocd.cd_size": 0.9}}},
                                "current_recovery": {"score": 0.2},
                                "best_seen_recovery": {"score": 0.2},
                            }],
                        }
                    }
                }]
            }
        },
    }


def _transition_row() -> dict:
    graph_before = {
        "current_node_id": "node_root",
        "best_node_id": "node_root",
        "nodes": {
            "node_root": {
                "node_id": "node_root",
                "patch_digest": "root",
                "patch_depth": 0,
                "recovery": {"score": 0.2},
                "patch_status": "root",
                "diagnosis_hgt": {"root_case": {"scores": {"eocd.cd_size": 0.8}, "selected": ["eocd.cd_size"]}},
            }
        },
        "edges": {},
    }
    graph_after = {
        "current_node_id": "node_patch",
        "best_node_id": "node_patch",
        "nodes": {
            **graph_before["nodes"],
            "node_patch": {
                "node_id": "node_patch",
                "parent_id": "node_root",
                "patch_digest": "patch",
                "patch_depth": 1,
                "recovery": {"score": 0.8, "completeness": 0.75, "failed_files": 2, "status": "partial", "decision_hint": "repair"},
                "verification": {"summary": {"completeness": 0.75, "failed_files": 2, "assessment_status": "partial", "decision_hint": "repair"}},
                "patch_status": "applied",
                "diagnosis_hgt": {"root_case": {"scores": {"eocd.cd_size": 0.2}, "selected": []}},
            },
        },
        "edges": {
            "edge_patch": {
                "edge_id": "edge_patch",
                "from_node_id": "node_root",
                "to_node_id": "node_patch",
                "module_name": "zip_fix_eocd_record",
                "status": "expanded",
                "recovery_delta": 0.6,
                "patch_status": "applied",
                "best_updated": True,
            }
        },
    }
    return {
        "sample_id": "transition_case",
        "format": "zip",
        "graph_before": graph_before,
        "current_node_id": "node_root",
        "best_node_id": "node_root",
        "available_actions": [
            {"action_type": "module", "action_id": "fix", "module_name": "zip_fix_eocd_record"},
            {"action_type": "stop", "action_id": "stop"},
        ],
        "chosen_action": {"action_type": "module", "action_id": "fix", "module_name": "zip_fix_eocd_record"},
        "graph_after": graph_after,
        "observed_delta": {
            "next_recovery_score": 0.8,
            "recovery_delta": 0.6,
            "patch_status": "applied",
            "best_updated": True,
            "branch_stale_delta": 0,
            "diagnosis_root_case_delta": 0.2,
        },
        "episode_id": "episode",
        "step_index": 1,
    }


def _undo_transition_row(*, parent_fresh: int, current_visit_count: int) -> dict:
    graph_before = {
        "current_node_id": "node_current",
        "best_node_id": "node_parent",
        "nodes": {
            "node_parent": {
                "node_id": "node_parent",
                "patch_digest": "parent",
                "patch_depth": 0,
                "recovery": {"score": 0.2},
                "patch_status": "root",
                "exploration": {
                    "visit_count": 1,
                    "fresh_action_count": parent_fresh,
                    "outgoing_action_count": parent_fresh + 1,
                    "expanded_action_count": 1,
                    "exhaustion_ratio": 0.0 if parent_fresh else 1.0,
                },
            },
            "node_current": {
                "node_id": "node_current",
                "parent_id": "node_parent",
                "patch_digest": "current",
                "patch_depth": 1,
                "recovery": {"score": 0.1},
                "patch_status": "empty_failed",
                "exploration": {
                    "visit_count": current_visit_count,
                    "fresh_action_count": 0,
                    "outgoing_action_count": 2,
                    "expanded_action_count": 2,
                    "exhaustion_ratio": 1.0,
                },
            },
        },
        "edges": {},
    }
    graph_after = json.loads(json.dumps(graph_before))
    graph_after["current_node_id"] = "node_parent"
    return {
        "sample_id": "undo_transition_case",
        "format": "zip",
        "graph_before": graph_before,
        "current_node_id": "node_current",
        "best_node_id": "node_parent",
        "available_actions": [
            {"action_type": "module", "action_id": "alt", "module_name": "zip_alt"},
            {"action_type": "undo", "action_id": "undo"},
            {"action_type": "stop", "action_id": "stop"},
        ],
        "chosen_action": {"action_type": "undo", "action_id": "undo"},
        "graph_after": graph_after,
        "action_q_values": {"module:zip_alt": 0.35, "undo:undo": 0.9, "stop:stop": 0.2},
        "observed_delta": {
            "next_recovery_score": 0.2,
            "recovery_delta": 0.1,
            "patch_status": "root",
            "best_updated": False,
            "branch_stale_delta": 0,
            "diagnosis_root_case_delta": 0.0,
        },
        "episode_id": "episode_undo",
        "step_index": 2,
    }


def _graph_with_best_score(node_id: str, *, parent_id: str, score: float) -> dict:
    return {
        "current_node_id": node_id,
        "best_node_id": node_id,
        "nodes": {
            "node_root": {
                "node_id": "node_root",
                "patch_digest": "root",
                "patch_depth": 0,
                "recovery": {"score": 0.2},
                "patch_status": "root",
                "diagnosis_hgt": {"root_case": {"scores": {"eocd.cd_size": 0.8}, "selected": ["eocd.cd_size"]}},
            },
            "node_patch": {
                "node_id": "node_patch",
                "parent_id": "node_root",
                "patch_digest": "patch",
                "patch_depth": 1,
                "recovery": {"score": 0.8},
                "patch_status": "applied",
                "diagnosis_hgt": {"root_case": {"scores": {"eocd.cd_size": 0.2}, "selected": []}},
            },
            node_id: {
                "node_id": node_id,
                "parent_id": parent_id,
                "patch_digest": node_id,
                "patch_depth": 2,
                "recovery": {"score": score},
                "patch_status": "applied",
                "diagnosis_hgt": {"root_case": {"scores": {"eocd.cd_size": 0.1}, "selected": []}},
            },
        },
        "edges": {},
    }


def _teacher_graph() -> dict:
    return {
        "current_node_id": "node_current",
        "best_node_id": "node_best",
        "nodes": {
            "node_best": {
                "node_id": "node_best",
                "patch_digest": "best",
                "patch_depth": 0,
                "recovery": {"score": 0.2},
                "patch_status": "root",
            },
            "node_current": {
                "node_id": "node_current",
                "parent_id": "node_best",
                "patch_digest": "current",
                "patch_depth": 1,
                "recovery": {"score": 0.1},
                "patch_status": "empty_failed",
            },
        },
        "edges": {},
    }


def _teacher_sample(sample_id: str = "teacher", depth: int = 2, actions: list[PolicyAction] | None = None) -> PolicyGraphTrainingSample:
    graph = _teacher_graph()
    graph["nodes"]["node_current"]["patch_depth"] = depth
    return PolicyGraphTrainingSample(
        sample_id=sample_id,
        format="zip",
        graph=graph,
        current_node_id="node_current",
        best_node_id="node_best",
        actions=actions or [
            PolicyAction(action_type="module", action_id="m_bad", module_name="zip_bad"),
            PolicyAction(action_type="undo", action_id="undo"),
            PolicyAction(action_type="stop", action_id="stop"),
        ],
        memory=[{"round": 1, "graph_action": {"action_type": "module", "module_name": "zip_bad"}, "current_recovery": {"score": 0.1}, "branch_failed_streak": 1}],
        diagnosis_hgt={"root_case": {"scores": {"eocd.cd_size": 0.9}}},
        current_recovery={"score": 0.1},
        best_recovery={"score": 0.2},
    )


class _RuntimeTeacherPlugin:
    def __init__(self):
        self.seen_diagnosis = []

    def available_modules(self, *, scheduler, job, diagnosis_hgt, graph):
        self.seen_diagnosis.append(diagnosis_hgt)
        return [PolicyModuleProposal(
            action_id="m_patch",
            module_name="zip_teacher_patch",
            payload={"action_id": "m_patch", "candidate_id": "m_patch", "module_name": "zip_teacher_patch", "score_hint": 0.9, "route_family": "teacher"},
            candidate=_runtime_patch_candidate(job.archive_state),
        )]

    def build_module_job(self, *, job, module_name, graph):
        return job

    def materialize_module(self, *, scheduler, proposal, job):
        return ModuleMaterializationResult(candidate=proposal.candidate)


class _FakeTeacherModelRuntime:
    def __init__(self, config=None):
        self.config = config or {}

    def diagnose_state(self, *, job, archive_state, graph, recovery=None, round_index=0):
        return {
            "root_case": {
                "scores": {"teacher_hgt": 0.97},
                "ranked": [{"root_case": "teacher_hgt", "score": 0.97}],
                "selected": ["teacher_hgt"],
            },
            "diagnostics": {"model_id": "fake_teacher_hgt", "round_index": round_index},
        }, {"decision_status": "diagnosed", "model_id": "fake_teacher_hgt"}


def _runtime_patch_candidate(base: ArchiveState) -> RepairCandidate:
    patch = PatchPlan(
        module="zip_teacher_patch",
        format="zip",
        operations=[
            PatchOperation(op="truncate", offset=0, size=Path(base.source.entry_path).stat().st_size),
            PatchOperation.append_bytes(b"fixed"),
        ],
        confidence=0.9,
    )
    state = base.push_patch(patch)
    return RepairCandidate(
        module_name="zip_teacher_patch",
        format="zip",
        repaired_input={"kind": "archive_state"},
        confidence=0.9,
        actions=["zip_teacher_patch"],
        plan={"archive_state": state.to_dict(), "patch_plan": patch.to_dict()},
    )
