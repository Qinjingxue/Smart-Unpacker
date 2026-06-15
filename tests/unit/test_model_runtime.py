from sunpack.repair.job import RepairJob
from sunpack.repair.model import ModelAssetRegistry, RepairModelRuntime
from sunpack.repair.search.types import PolicyExplorationGraph, PolicyGraphNode


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


def test_repair_model_runtime_runs_current_zip_model_pair():
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

    assert diagnosis_status["decision_status"] == "diagnosed"
    assert len(diagnosis["root_case"]["scores"]) == 26
    assert diagnosis["root_case"]["ranked"]
    assert policy_status["decision_status"] == "scored"
    assert len(actions) == 2
    assert all("predicted_next_state" in action.metadata for action in actions)
