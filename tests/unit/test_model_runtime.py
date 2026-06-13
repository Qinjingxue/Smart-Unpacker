from types import SimpleNamespace

from sunpack.model_runtime import ModelAssetRegistry
from sunpack_repair_models import DiagnosisHGTProvider, RepairPolicyTransformerProvider


def test_model_registry_resolves_zip_assets():
    registry = ModelAssetRegistry()
    diagnosis = registry.asset("zip", "diagnosis")
    policy = registry.asset("zip", "policy")

    assert registry.supported_formats() == ["zip"]
    assert diagnosis is not None and diagnosis.available
    assert diagnosis.semantics == "repair_actionable_root_v2"
    assert policy is not None and policy.available
    assert policy.semantics == "repair_graph_world_policy_uncertainty_v1"
    assert registry.asset("7z", "diagnosis") is None


def test_model_registry_loads_current_zip_models_on_cpu():
    status = ModelAssetRegistry().status(load=True, device="cpu")

    assert status["ok"] is True
    assert all(model["loaded"] for model in status["models"])


def test_current_zip_models_run_real_inference():
    diagnosis_request = SimpleNamespace(
        format="zip",
        job=SimpleNamespace(archive_key="model-smoke"),
        round_index=0,
        knowledge_payload={"analysis": {"summary": {"format": "zip"}}},
    )
    diagnosis = DiagnosisHGTProvider("zip").diagnose_state(diagnosis_request)

    assert len(diagnosis["root_case"]["scores"]) == 26
    assert diagnosis["root_case"]["ranked"]

    graph = {
        "nodes": [
            {
                "node_id": "root",
                "parent_id": "",
                "patch_digest": "root-digest",
                "patch_depth": 0,
                "module_name": "",
                "patch_status": "root",
                "recovery": {"score": 0.0},
                "diagnosis_hgt": diagnosis,
                "verification": {"summary": {"completeness": 0.0}},
            }
        ],
        "edges": [],
        "current_node_id": "root",
        "best_node_id": "root",
    }
    actions = [
        {"action_type": "stop", "action_id": "stop"},
        {
            "action_type": "module",
            "action_id": "module:zip_fix_eocd_record",
            "module_name": "zip_fix_eocd_record",
        },
    ]
    policy_request = SimpleNamespace(
        format="zip",
        job=SimpleNamespace(archive_key="model-smoke"),
        round_index=0,
        graph=graph,
        current_node_id="root",
        best_node_id="root",
        available_actions=actions,
        diagnosis_hgt=diagnosis,
        current_recovery={"score": 0.0},
        best_seen_recovery={"score": 0.0},
    )
    policy = RepairPolicyTransformerProvider("zip").score_actions(policy_request)

    assert len(policy["action_scores"]) == 2
    assert policy["action_predictions"]
    assert all("predicted_next_state" in row["metadata"] for row in policy["action_scores"])
