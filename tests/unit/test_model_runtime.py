from sunpack.repair.job import RepairJob
from sunpack.repair.model import ModelAssetRegistry, RepairModelRuntime
from sunpack.repair.search.types import PolicyExplorationGraph, PolicyGraphNode


def test_model_registry_starts_without_packaged_models():
    registry = ModelAssetRegistry()
    diagnosis = registry.asset("zip", "diagnosis")
    policy = registry.asset("zip", "policy")

    assert registry.supported_formats() == []
    assert diagnosis is None
    assert policy is None
    assert registry.asset("7z", "diagnosis") is None


def test_model_registry_reports_training_required_without_assets():
    status = ModelAssetRegistry().status(load=True, device="cpu")

    assert status["ok"] is False
    assert status["models"] == []


def test_repair_model_runtime_reports_missing_experts():
    runtime = RepairModelRuntime(assets=ModelAssetRegistry())
    job = RepairJob(
        source_input={"kind": "memory", "format_hint": "zip"},
        format="zip",
        archive_key="model-smoke",
        knowledge={"analysis": {"summary": {"format": "zip"}}},
    )
    graph = PolicyExplorationGraph(
        nodes={
            "root": PolicyGraphNode(
                node_id="root",
                patch_digest="root-digest",
                recovery={"score": 0.0},
            )
        },
        current_node_id="root",
        best_node_id="root",
    )

    diagnosis, diagnosis_status = runtime.diagnose_state(
        job=job,
        archive_state=None,
        graph=graph,
        round_index=0,
    )
    actions, policy_status = runtime.score_graph_actions(
        job=job,
        archive_state=None,
        graph=graph,
        available_actions=[
            {"action_type": "stop", "action_id": "stop"},
            {
                "action_type": "module",
                "action_id": "module:zip_fix_eocd_record",
                "module_name": "zip_fix_eocd_record",
            },
        ],
        diagnosis_hgt=diagnosis,
        current_recovery={"score": 0.0},
        best_seen_recovery={"score": 0.0},
        round_index=0,
    )

    assert diagnosis == {}
    assert diagnosis_status["decision_status"] == "unavailable"
    assert actions == []
    assert policy_status["decision_status"] == "unavailable"
