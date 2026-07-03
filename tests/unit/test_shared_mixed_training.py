from __future__ import annotations

from pathlib import Path

import pytest

from repair_training import __main__ as training_main
from repair_training.data.collection import _balanced_mixed_records
from sunpack.repair.model.diagnosis.graph_dispatcher import build_diagnosis_graph_sample_for_format
from sunpack.repair.model.diagnosis.tensorize import FORMAT_FEATURE_DIM, tensorize_sample as tensorize_diagnosis
from sunpack.repair.model.policy.schema import PolicyAction, PolicyGraphTrainingSample
from sunpack.repair.model.policy.tensorize import tensorize_sample as tensorize_policy


def test_mixed_records_round_robin_formats_and_semantics() -> None:
    groups = {
        "rar": [
            {"sample_id": "r1", "damage_layer": "header", "expected_module": "rar_header_crc_repair"},
            {"sample_id": "r2", "damage_layer": "payload", "expected_module": "rar_payload_salvage"},
        ],
        "tar": [
            {"sample_id": "t1", "damage_layer": "header", "expected_module": "tar_checksum_repair"},
            {"sample_id": "t2", "damage_layer": "tail", "expected_module": "tar_tail_repair"},
        ],
    }

    rows = _balanced_mixed_records(groups)

    assert [row["sample_id"] for row in rows[:2]] == ["r1", "t1"]
    assert all(row["mixed_training_balance"]["format"] in groups for row in rows)


def test_shared_diagnosis_tensor_has_format_condition_and_private_label_mask() -> None:
    rar = build_diagnosis_graph_sample_for_format("rar", {
        "sample_id": "r", "format": "rar", "damage_flags": ["rar_main_header_crc_bad"],
    })
    labels = ["rar_main_header_crc_bad", "tar_checksum_bad"]
    mapping = {"rar_main_header_crc_bad": ["rar"], "tar_checksum_bad": ["tar"]}

    item = tensorize_diagnosis(rar, root_cases=labels, root_label_formats=mapping)

    assert item.root_case_mask.tolist() == [1.0, 0.0]
    assert item["observation"].x.shape[1] >= FORMAT_FEATURE_DIM
    assert item["observation"].x[0, -FORMAT_FEATURE_DIM:].sum().item() == pytest.approx(1.0)


def test_shared_policy_tensor_masks_cross_format_action() -> None:
    sample = PolicyGraphTrainingSample(
        sample_id="rar-policy", format="rar",
        graph={"nodes": {"root": {}}, "edges": {}, "current_node_id": "root", "best_node_id": "root"},
        current_node_id="root", best_node_id="root",
        actions=[
            PolicyAction(action_type="module", action_id="rar", module_name="rar_main_header_crc_repair"),
            PolicyAction(action_type="module", action_id="zip", module_name="zip_eocd_repair"),
            PolicyAction(action_type="stop", action_id="stop"),
        ],
    )

    item = tensorize_policy(sample)

    assert item["action_legal_mask"].tolist() == [1.0, 0.0, 1.0]
    assert item["format"] == "rar"


def test_shared_diagnosis_cli_is_accepted(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    called = {}
    monkeypatch.setattr(training_main, "train_diagnosis_gnn_model", lambda **kwargs: called.update(kwargs) or {})

    assert training_main.train_main([
        "--format", "all", "--model", "diagnosis_gnn", "--run-dir", str(tmp_path),
    ]) == 0
    assert called["format_name"] == "shared"
