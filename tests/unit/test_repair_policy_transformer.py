import json
from pathlib import Path

import pytest

from repair_training.build_policy_graph_rows import build_policy_graph_rows
from repair_training.core.repair_policy_transformer.inference import RepairPolicyTransformerModel
from repair_training.core.repair_policy_transformer.model import build_repair_policy_transformer
from repair_training.core.repair_policy_transformer.schema import sample_from_dict
from repair_training.core.repair_policy_transformer.tensorize import tensorize_sample
from repair_training.train import main as train_main


pytest.importorskip("torch")


def test_policy_graph_log_row_builds_training_sample():
    rows = build_policy_graph_rows([_runtime_log_row()])

    assert len(rows) == 1
    sample = rows[0]
    assert sample.current_node_id == "node_root"
    assert {action.action_type for action in sample.actions} == {"module", "undo", "stop"}
    assert any(action.action_prior == 1.0 and action.module_name == "zip_eocd_rebuild" for action in sample.actions)


def test_policy_transformer_tensorize_and_forward_shapes():
    sample = build_policy_graph_rows([_runtime_log_row()])[0]
    item = tensorize_sample(sample)
    model = build_repair_policy_transformer({"hidden_dim": 32, "heads": 4, "layers": 1})

    logits = model(item["node_x"], item["memory_x"], item["action_x"])

    assert logits.shape[0] == len(sample.actions)


def test_policy_transformer_train_and_infer_smoke(tmp_path: Path):
    run_dir = tmp_path / "run"
    datasets = run_dir / "datasets"
    datasets.mkdir(parents=True)
    rows = [build_policy_graph_rows([_runtime_log_row(sample_id=f"s{i}")])[0].to_dict() for i in range(4)]
    input_path = datasets / "policy_graph_rows.jsonl"
    input_path.write_text("\n".join(json.dumps(row) for row in rows), encoding="utf-8")

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
    prediction = model.predict_sample(sample_from_dict(rows[0]))

    assert prediction["action_scores"]
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
