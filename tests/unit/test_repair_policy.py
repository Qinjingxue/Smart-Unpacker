from dataclasses import replace
from pathlib import Path

import pytest

from sunpack.contracts.archive_input import ArchiveInputDescriptor
from sunpack.contracts.archive_state import ArchiveState, PatchOperation, PatchPlan
from sunpack.repair.candidate import RepairCandidate, RepairCandidateBatch, materialize_candidate
from sunpack.repair.job import RepairJob
from sunpack.repair.pipeline.module import RepairModuleSpec, RepairRoute
from sunpack.repair.search import proposals as search_proposals
from sunpack.repair.search.recovery import PolicyRecoverySnapshot
from sunpack.repair.search.proposals import ModuleMaterializationResult, PolicyModuleProposal
from sunpack.repair.search.types import PolicyGraphAction
from sunpack.repair.scheduler import RepairScheduler


@pytest.fixture(autouse=True)
def _skip_module_discovery(monkeypatch):
    monkeypatch.setattr("sunpack.repair.scheduler.discover_repair_modules", lambda: None)


def test_model_runtime_uses_paired_diagnosis_and_graph_models(tmp_path, monkeypatch):
    models = _GraphModels([PolicyGraphAction(action_type="stop", action_id="stop", score=0.8)])
    scheduler = _scheduler(tmp_path)
    _install_models(scheduler, models)
    job = _job(tmp_path)
    graph = _root_graph(job)

    diagnosis, diagnosis_selection = scheduler.model_runtime.diagnose_state(
        job=job,
        archive_state=job.archive_state,
        graph=graph,
        recovery={"score": 0.2},
        round_index=1,
    )
    scores, score_selection = scheduler.model_runtime.score_graph_actions(
        job=job,
        archive_state=job.archive_state,
        graph=graph,
        available_actions=[{"action_type": "stop", "action_id": "stop"}],
        diagnosis_hgt=diagnosis,
        current_recovery={"score": 0.2},
        best_seen_recovery={"score": 0.2},
        round_index=1,
    )

    assert diagnosis_selection["decision_status"] == "diagnosed"
    assert diagnosis["root_case"]["selected"] == ["eocd.cd_size"]
    assert score_selection["decision_status"] == "scored"
    assert scores[0].action_type == "stop"


def test_policy_step_executes_one_selected_module_and_exits(tmp_path, monkeypatch):
    models = _GraphModels([PolicyGraphAction(action_type="module", module_name="patch_one", score=0.9)])
    source = tmp_path / "source.zip"
    source.write_bytes(b"broken")
    candidate = _patch_candidate("patch_one", source, b"fixed")
    scheduler = _scheduler(tmp_path)
    _install_models(scheduler, models)
    _install_policy_plugin(monkeypatch, [candidate])
    _patch_recovery(monkeypatch, root_score=0.0, patched_score=0.4)

    result = scheduler.repair(_job(tmp_path, source=source))

    assert result.status == "partial"
    assert result.repaired_state is not None
    assert result.repaired_state.patch_depth() == 1
    assert result.diagnosis["policy_loop"]["policy_step"] is True
    assert result.diagnosis["policy_loop"]["terminal_action"] == ""
    assert result.diagnosis["policy_loop"]["graph_operation"]["action"] == "forward"
    edge = next(iter(result.diagnosis["policy_loop"]["graph"]["edges"].values()))
    assert edge["predicted_next_state"]["predicted_recovery"]["score"] == pytest.approx(0.3)
    assert len(models.policy_samples) == 1
    assert {action.action_type for action in models.policy_samples[0].actions} == {"module", "stop"}
    assert all(action.action_type != "undo" for action in models.policy_samples[0].actions)


def test_policy_step_failed_module_creates_empty_patch_node(tmp_path, monkeypatch):
    models = _GraphModels([PolicyGraphAction(action_type="module", module_name="bad_lazy", score=0.9)])
    bad = RepairCandidate(
        module_name="bad_lazy",
        format="zip",
        confidence=0.8,
        actions=["bad_lazy"],
        materializer=lambda: [],
        materialized=False,
    )
    scheduler = _scheduler(tmp_path)
    _install_models(scheduler, models)
    _install_policy_plugin(monkeypatch, [bad])
    _patch_recovery(monkeypatch, root_score=0.0, patched_score=0.0)

    result = scheduler.repair(_job(tmp_path))

    loop = result.diagnosis["policy_loop"]
    assert result.repaired_state is not None
    assert result.repaired_state.patch_depth() == 1
    assert loop["graph_operation"]["patch_status"] == "empty_failed"
    assert loop["graph"]["nodes"][loop["current_node_id"]]["patch_status"] == "empty_failed"


def test_policy_step_undo_moves_to_parent_without_deleting_child(tmp_path, monkeypatch):
    module_models = _GraphModels([PolicyGraphAction(action_type="module", module_name="patch_one", score=0.9)])
    source = tmp_path / "source.zip"
    source.write_bytes(b"broken")
    scheduler = _scheduler(tmp_path)
    _install_models(scheduler, module_models)
    _install_policy_plugin(monkeypatch, [_patch_candidate("patch_one", source, b"fixed")])
    _patch_recovery(monkeypatch, root_score=0.0, patched_score=0.5)
    first = scheduler.repair(_job(tmp_path, source=source))

    undo_models = _GraphModels([PolicyGraphAction(action_type="undo", action_id="undo", score=1.0)])
    scheduler = _scheduler(tmp_path)
    _install_models(scheduler, undo_models)
    _install_policy_plugin(monkeypatch, [])
    job = _job(tmp_path, source=source, archive_state=first.repaired_state, repair_history={"items": [{"diagnosis": first.diagnosis}]})

    result = scheduler.repair(job)

    loop = result.diagnosis["policy_loop"]
    assert result.repaired_state is not None
    assert result.repaired_state.patch_depth() == 0
    assert loop["graph_operation"]["action"] == "undo"
    assert len(loop["graph"]["nodes"]) == 2
    child = next(node for node in loop["graph"]["nodes"].values() if node.get("parent_id"))
    assert child["prediction_error_from_parent"]["overall_prediction_error"] >= 0.0


def test_policy_step_stop_returns_best_state_and_sets_stop_signal(tmp_path, monkeypatch):
    models = _GraphModels([PolicyGraphAction(action_type="stop", action_id="stop", score=1.0, reason="model_stop")])
    scheduler = _scheduler(tmp_path)
    _install_models(scheduler, models)
    _install_policy_plugin(monkeypatch, [])
    _patch_recovery(monkeypatch, root_score=0.25, patched_score=0.25)

    result = scheduler.repair(_job(tmp_path))

    assert result.status == "partial"
    assert result.repaired_state is not None
    assert result.diagnosis["policy_stop_requested"] is True
    assert result.diagnosis["policy_loop"]["terminal_action"] == "stop"
    assert result.diagnosis["policy_loop"]["final_state_selection"] == "best_seen_graph_node"


def test_stale_best_forces_stop_before_policy_scorer(tmp_path, monkeypatch):
    models = _GraphModels([PolicyGraphAction(action_type="module", action_id="patch_one", module_name="patch_one", score=1.0)], raise_on_score=True)
    job = _job(tmp_path)
    graph = _root_graph(job)
    graph.stale_expansion_count = 5
    graph_payload = graph.to_dict()
    job = _job(tmp_path, repair_history={"items": [{"diagnosis": {"policy_loop": {"graph": graph_payload}}}]})
    scheduler = RepairScheduler({
        "repair": {
            "workspace": str(tmp_path / "repair"),
            "policy": {"graph_stop_stale_patience": 3},
        }
    })
    _install_models(scheduler, models)
    _install_policy_plugin(monkeypatch, [])
    _patch_recovery(monkeypatch, root_score=0.1, patched_score=0.1)

    result = scheduler.repair(job)

    assert result.diagnosis["policy_loop"]["terminal_action"] == "stop"
    assert result.diagnosis["policy_loop"]["stop_reason"] == "graph_stale_best"
    assert models.policy_samples == []


def test_zip_policy_plugin_enumerates_registry_without_rule_context(tmp_path, monkeypatch):
    module = _FakeZipModule()
    monkeypatch.setattr(search_proposals, "get_repair_module_registry", lambda: _FakeRegistry({"zip_fake_fix": module}))
    monkeypatch.setattr(search_proposals, "enabled_module_configs", lambda config: {})
    scheduler = _scheduler(tmp_path)
    scheduler.generate_policy_repair_candidates = lambda *args, **kwargs: (_ for _ in ()).throw(AssertionError("old policy candidate path must not run"))  # type: ignore[attr-defined]
    scheduler.diagnose = lambda *args, **kwargs: (_ for _ in ()).throw(AssertionError("rule diagnosis must not run"))  # type: ignore[method-assign]

    proposals = search_proposals.available_module_proposals(
        scheduler=scheduler,
        job=_job(tmp_path),
        diagnosis_hgt={"root_case": {"scores": {"eocd.cd_size": 0.9}, "selected": ["eocd.cd_size"]}},
        graph=_root_graph(_job(tmp_path)),
    )

    assert [proposal.module_name for proposal in proposals] == ["zip_fake_fix"]
    payload = proposals[0].to_action_payload()
    assert {key: payload[key] for key in ("action_type", "action_id", "candidate_id", "module_name")} == {
        "action_type": "module",
        "action_id": "zip_fake_fix:0",
        "candidate_id": "zip_fake_fix:0",
        "module_name": "zip_fake_fix",
    }
    assert payload["features"]["schema_version"] == "repair_action_v2"
    assert payload["features"]["granularity"] == "atomic"


def test_policy_proposals_keep_seven_zip_private_operation_with_shared_contract(tmp_path, monkeypatch):
    class SevenZipModule:
        spec = RepairModuleSpec(
            name="seven_zip_repair_folder_bind_pairs",
            formats=("7z", "seven_zip"),
            stage="deep",
            atomic=True,
            route_family="seven_zip_folder_graph",
        )

        def repair(self, job, diagnosis, workspace, config):
            raise AssertionError("proposal enumeration must stay lazy")

    monkeypatch.setattr(search_proposals, "get_repair_module_registry", lambda: _FakeRegistry({"7z": SevenZipModule()}))
    monkeypatch.setattr(search_proposals, "enabled_module_configs", lambda config: {})
    scheduler = _scheduler(tmp_path)
    job = replace(_job(tmp_path), format="7z", source_input={"kind": "file", "path": str(tmp_path / "source.zip"), "format_hint": "7z"})

    proposals = search_proposals.available_module_proposals(
        scheduler=scheduler,
        job=job,
        diagnosis_hgt={"root_case": {"scores": {"folder_bind_pairs_bad": 0.9}}},
        graph=_root_graph(job),
    )

    payload = proposals[0].to_action_payload()
    assert payload["module_name"] == "seven_zip_repair_folder_bind_pairs"
    assert payload["features"]["expert"] == "7z"
    assert payload["features"]["format_family"] == "coder_graph_container"
    assert payload["features"]["mutation_scope"] == "folder"


def test_missing_models_fall_back_to_registered_rule_experts(tmp_path, monkeypatch):
    scheduler = _scheduler(tmp_path)
    candidate = RepairCandidate(
        module_name="gzip_footer_fix",
        format="gzip",
        repaired_input={"kind": "file", "path": str(tmp_path / "fixed.gz"), "format_hint": "gzip"},
        status="repaired",
        confidence=0.8,
        actions=["fix_footer"],
    )
    job = replace(_job(tmp_path), format="gzip", source_input={"kind": "file", "path": str(tmp_path / "source.zip"), "format_hint": "gzip"})
    monkeypatch.setattr(scheduler, "generate_repair_candidates", lambda job: RepairCandidateBatch(candidates=[candidate]))
    monkeypatch.setattr("sunpack.repair.scheduler.CandidateSelector.select", lambda self, candidates: (candidate, {"selected_module": candidate.module_name}))

    result = scheduler.repair(job)

    assert result.status == "repaired"
    assert result.module_name == "gzip_footer_fix"
    assert result.diagnosis["candidate_selection"]["selection_mode"] == "rule_expert"


class _GraphModels:
    def __init__(self, actions: list[PolicyGraphAction], *, raise_on_score: bool = False):
        self.actions = list(actions)
        self.raise_on_score = raise_on_score
        self.diagnosis_samples = []
        self.policy_samples = []

    def predict_sample(self, sample):
        if not hasattr(sample, "actions"):
            self.diagnosis_samples.append(sample)
            return {
            "format": sample.format,
            "root_case": {
                "scores": {"eocd.cd_size": 0.9},
                "ranked": [{"root_case": "eocd.cd_size", "score": 0.9}],
                "selected": ["eocd.cd_size"],
            },
        }
        if self.raise_on_score:
            raise AssertionError("policy scorer should not be called")
        self.policy_samples.append(sample)
        predictions = {
            action.action_id or action.module_name or action.action_type: _test_prediction()
            for action in self.actions
        }
        return {
            "action_scores": [
                {**action.to_dict(), "metadata": {**dict(action.metadata or {}), "predicted_next_state": predictions[action.action_id or action.module_name or action.action_type]}}
                for action in self.actions
            ],
            "action_predictions": predictions,
        }


def _install_models(scheduler: RepairScheduler, models) -> None:
    scheduler.model_runtime._diagnosis_models["zip"] = models
    scheduler.model_runtime._policy_models["zip"] = models


def _test_prediction() -> dict:
    return {
        "predicted_recovery": {"score": 0.3, "completeness": 0.3},
        "predicted_recovery_delta": 0.1,
        "predicted_patch_status_hash": 0.2,
        "predicted_best_updated": False,
        "predicted_diagnosis_root_scores": {"eocd.cd_size": 0.8},
        "predicted_verification_summary": {"completeness": 0.3},
    }


def _install_policy_plugin(monkeypatch, candidates: list[RepairCandidate]) -> None:
    plugin = _TestPolicyPlugin(candidates)
    monkeypatch.setattr("sunpack.repair.scheduler.available_module_proposals", plugin.available_modules)
    monkeypatch.setattr("sunpack.repair.scheduler.materialize_module_proposal", plugin.materialize_module)


class _TestPolicyPlugin:
    format_name = "zip"

    def __init__(self, candidates: list[RepairCandidate]):
        self.candidates = list(candidates)

    def available_modules(self, *, scheduler, job, diagnosis_hgt, graph):
        proposals = []
        for index, candidate in enumerate(self.candidates):
            action_id = candidate.module_name or f"candidate_{index}"
            proposals.append(PolicyModuleProposal(
                action_id=action_id,
                module_name=candidate.module_name,
                payload={"action_id": action_id, "candidate_id": action_id, "module_name": candidate.module_name},
                candidate=candidate,
            ))
        return proposals

    def build_module_job(self, *, job, module_name, graph):
        return job

    def materialize_module(self, *, scheduler, proposal, job):
        materialized = materialize_candidate(proposal.candidate) if proposal.candidate is not None else []
        patched = [candidate for candidate in materialized if candidate.repaired_state is not None]
        if patched:
            return ModuleMaterializationResult(candidate=patched[0])
        return ModuleMaterializationResult(candidate=None, failure={"failure_reason": "proposal_materialization_failed"})


class _FakeRegistry:
    def __init__(self, modules):
        self._modules = modules

    def all(self):
        return dict(self._modules)


class _FakeZipModule:
    spec = RepairModuleSpec(
        name="zip_fake_fix",
        formats=("zip",),
        routes=(RepairRoute(formats=("zip",), require_any_flags=("field:eocd.cd_size",), base_score=0.7),),
        atomic=True,
    )

    def repair(self, job, diagnosis, workspace, config):
        raise AssertionError("proposal enumeration must not materialize the module")


def _scheduler(tmp_path: Path) -> RepairScheduler:
    return RepairScheduler({
        "repair": {
            "workspace": str(tmp_path / "repair"),
            "max_repair_rounds_per_task": 5,
        }
    })


def _patch_recovery(monkeypatch, *, root_score: float, patched_score: float) -> None:
    def recovery(self, job, state, **kwargs):
        depth = state.patch_depth() if state is not None else 0
        score = patched_score if depth > 0 else root_score
        return PolicyRecoverySnapshot(
            state_digest=state.effective_patch_digest() if state is not None else "",
            patch_depth=depth,
            score=score,
            status="partial" if score > 0 else "empty",
        )

    monkeypatch.setattr("sunpack.repair.scheduler.RecoveryEvaluator.evaluate_state", recovery)


def _patch_candidate(module: str, source: Path, replacement: bytes) -> RepairCandidate:
    descriptor = ArchiveInputDescriptor.from_parts(archive_path=str(source), format_hint="zip")
    base = ArchiveState.from_archive_input(descriptor)
    patch = PatchPlan(
        module=module,
        format="zip",
        operations=[
            PatchOperation(op="truncate", offset=0, size=source.stat().st_size),
            PatchOperation.append_bytes(replacement),
        ],
        confidence=0.8,
    )
    state = base.push_patch(patch)
    return RepairCandidate(
        module_name=module,
        format="zip",
        repaired_input={"kind": "archive_state", "patch_digest": state.effective_patch_digest(), "format_hint": "zip"},
        confidence=0.8,
        actions=[module],
        plan={"archive_state": state.to_dict(), "patch_plan": patch.to_dict()},
    )


def _job(
    tmp_path: Path,
    *,
    source: Path | None = None,
    archive_state: ArchiveState | None = None,
    repair_history: dict | None = None,
) -> RepairJob:
    source = source or (tmp_path / "source.zip")
    if not source.exists():
        source.write_bytes(b"broken")
    if archive_state is None:
        archive_state = ArchiveState.from_archive_input(ArchiveInputDescriptor.from_parts(archive_path=str(source), format_hint="zip"))
    knowledge = {
        "source": {"input": {"kind": "file", "path": str(source), "format_hint": "zip"}},
        "analysis": {"summary": {"format": "zip", "confidence": 0.5}},
        "extraction": {"failure": {"status": "failed"}},
        "verification": {"summary": {"decision_hint": "repair", "completeness": 0.0}},
        "repair": {"history": repair_history or {"items": []}},
    }
    return RepairJob(
        source_input={"kind": "file", "path": str(source), "format_hint": "zip"},
        format="zip",
        archive_key="source",
        workspace=str(tmp_path / "repair"),
        extraction_failure={"status": "failed"},
        knowledge=knowledge,
        archive_state=archive_state,
        repair_history=repair_history or {"items": []},
    )


def _root_graph(job: RepairJob):
    from sunpack.repair.search.graph import PolicyRepairGraph

    recovery = PolicyRecoverySnapshot(
        state_digest=job.archive_state.effective_patch_digest() if job.archive_state is not None else "",
        patch_depth=job.archive_state.patch_depth() if job.archive_state is not None else 0,
        score=0.0,
        status="empty",
    )
    return PolicyRepairGraph.initialize(job, recovery).graph
