import sys
import types
from pathlib import Path

import pytest

from sunpack.contracts.archive_input import ArchiveInputDescriptor
from sunpack.contracts.archive_state import ArchiveState, PatchOperation, PatchPlan
from sunpack.repair.candidate import RepairCandidate, RepairCandidateBatch
from sunpack.repair.config import normalize_repair_config
from sunpack.repair.job import RepairJob
from sunpack.repair.policy.recovery_evaluator import PolicyRecoverySnapshot
from sunpack.repair.policy.types import PolicyGraphAction
from sunpack.repair.scheduler import RepairScheduler


@pytest.fixture(autouse=True)
def _skip_module_discovery(monkeypatch):
    monkeypatch.setattr("sunpack.repair.scheduler.discover_repair_modules", lambda: None)


def test_policy_config_rejects_removed_compatibility_flags():
    config = normalize_repair_config({"policy": {"enabled": "true", "strict_provider_errors": "false"}})

    assert config["policy"]["enabled"] is True
    assert config["policy"]["strict_provider_errors"] is False
    assert config["policy"]["provider_package"] == "sunpack_repair_models"
    assert "fallback_to_selector" not in config["policy"]
    assert "disable_beam_when_model_active" not in config["policy"]
    assert "step_mode" not in config["policy"]

    with pytest.raises(ValueError, match="was removed"):
        normalize_repair_config({"policy": {"step_mode": True}})


def test_missing_policy_package_returns_unsupported_without_selector_fallback(tmp_path):
    scheduler = RepairScheduler({
        "repair": {
            "workspace": str(tmp_path / "repair"),
            "policy": {"provider_package": "sunpack_policy_test_missing_package"},
        }
    })

    def forbidden_selector_path(job):
        raise AssertionError("selector fallback must not run in graph policy runtime")

    scheduler.generate_repair_candidates = forbidden_selector_path  # type: ignore[method-assign]

    result = scheduler.repair(_job(tmp_path))

    assert result.status == "unsupported"
    assert result.module_name == "policy_unavailable"
    assert result.diagnosis["policy"]["fallback_reason"] == "policy_unavailable"


def test_policy_manager_uses_new_diagnosis_and_graph_scorer_interfaces(tmp_path, monkeypatch):
    provider = _GraphProvider([PolicyGraphAction(action_type="stop", action_id="stop", score=0.8)])
    _install_policy_package(monkeypatch, "sunpack_policy_test_graph_provider", provider)
    scheduler = RepairScheduler({
        "repair": {
            "workspace": str(tmp_path / "repair"),
            "policy": {"provider_package": "sunpack_policy_test_graph_provider"},
        }
    })
    job = _job(tmp_path)
    graph = _root_graph(job)

    diagnosis, diagnosis_selection = scheduler.policy_manager.diagnose_state(
        job=job,
        archive_state=job.archive_state,
        graph=graph,
        recovery={"score": 0.2},
        round_index=1,
    )
    scores, score_selection = scheduler.policy_manager.score_graph_actions(
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
    provider = _GraphProvider([PolicyGraphAction(action_type="module", module_name="patch_one", score=0.9)])
    _install_policy_package(monkeypatch, "sunpack_policy_test_module_step", provider)
    source = tmp_path / "source.zip"
    source.write_bytes(b"broken")
    candidate = _patch_candidate("patch_one", source, b"fixed")
    scheduler = _scheduler(tmp_path, "sunpack_policy_test_module_step")
    scheduler.generate_policy_repair_candidates = lambda job, **kwargs: RepairCandidateBatch(candidates=[candidate], diagnosis={"format": "zip"})  # type: ignore[method-assign]
    _patch_recovery(monkeypatch, root_score=0.0, patched_score=0.4)

    result = scheduler.repair(_job(tmp_path, source=source))

    assert result.status == "partial"
    assert result.repaired_state is not None
    assert result.repaired_state.patch_depth() == 1
    assert result.diagnosis["policy_loop"]["policy_step"] is True
    assert result.diagnosis["policy_loop"]["terminal_action"] == ""
    assert result.diagnosis["policy_loop"]["graph_operation"]["action"] == "forward"
    assert len(provider.score_requests) == 1


def test_policy_step_failed_module_creates_empty_patch_node(tmp_path, monkeypatch):
    provider = _GraphProvider([PolicyGraphAction(action_type="module", module_name="bad_lazy", score=0.9)])
    _install_policy_package(monkeypatch, "sunpack_policy_test_empty_patch", provider)
    bad = RepairCandidate(
        module_name="bad_lazy",
        format="zip",
        confidence=0.8,
        actions=["bad_lazy"],
        materializer=lambda: [],
        materialized=False,
    )
    scheduler = _scheduler(tmp_path, "sunpack_policy_test_empty_patch")
    scheduler.generate_policy_repair_candidates = lambda job, **kwargs: RepairCandidateBatch(candidates=[bad], diagnosis={"format": "zip"})  # type: ignore[method-assign]
    _patch_recovery(monkeypatch, root_score=0.0, patched_score=0.0)

    result = scheduler.repair(_job(tmp_path))

    loop = result.diagnosis["policy_loop"]
    assert result.repaired_state is not None
    assert result.repaired_state.patch_depth() == 1
    assert loop["graph_operation"]["patch_status"] == "empty_failed"
    assert loop["graph"]["nodes"][loop["current_node_id"]]["patch_status"] == "empty_failed"


def test_policy_step_undo_moves_to_parent_without_deleting_child(tmp_path, monkeypatch):
    module_provider = _GraphProvider([PolicyGraphAction(action_type="module", module_name="patch_one", score=0.9)])
    _install_policy_package(monkeypatch, "sunpack_policy_test_undo_module", module_provider)
    source = tmp_path / "source.zip"
    source.write_bytes(b"broken")
    scheduler = _scheduler(tmp_path, "sunpack_policy_test_undo_module")
    scheduler.generate_policy_repair_candidates = lambda job, **kwargs: RepairCandidateBatch(candidates=[_patch_candidate("patch_one", source, b"fixed")], diagnosis={"format": "zip"})  # type: ignore[method-assign]
    _patch_recovery(monkeypatch, root_score=0.0, patched_score=0.5)
    first = scheduler.repair(_job(tmp_path, source=source))

    undo_provider = _GraphProvider([PolicyGraphAction(action_type="undo", action_id="undo", score=1.0)])
    _install_policy_package(monkeypatch, "sunpack_policy_test_undo_parent", undo_provider)
    scheduler = _scheduler(tmp_path, "sunpack_policy_test_undo_parent")
    scheduler.generate_policy_repair_candidates = lambda job, **kwargs: RepairCandidateBatch(candidates=[], diagnosis={"format": "zip"})  # type: ignore[method-assign]
    job = _job(tmp_path, source=source, archive_state=first.repaired_state, repair_history={"items": [{"diagnosis": first.diagnosis}]})

    result = scheduler.repair(job)

    loop = result.diagnosis["policy_loop"]
    assert result.repaired_state is not None
    assert result.repaired_state.patch_depth() == 0
    assert loop["graph_operation"]["action"] == "undo"
    assert len(loop["graph"]["nodes"]) == 2


def test_policy_step_stop_returns_best_state_and_sets_stop_signal(tmp_path, monkeypatch):
    provider = _GraphProvider([PolicyGraphAction(action_type="stop", action_id="stop", score=1.0, reason="model_stop")])
    _install_policy_package(monkeypatch, "sunpack_policy_test_stop", provider)
    scheduler = _scheduler(tmp_path, "sunpack_policy_test_stop")
    scheduler.generate_policy_repair_candidates = lambda job, **kwargs: RepairCandidateBatch(candidates=[], diagnosis={"format": "zip"})  # type: ignore[method-assign]
    _patch_recovery(monkeypatch, root_score=0.25, patched_score=0.25)

    result = scheduler.repair(_job(tmp_path))

    assert result.status == "partial"
    assert result.repaired_state is not None
    assert result.diagnosis["policy_stop_requested"] is True
    assert result.diagnosis["policy_loop"]["terminal_action"] == "stop"
    assert result.diagnosis["policy_loop"]["final_state_selection"] == "best_seen_graph_node"


def test_stale_best_forces_stop_before_policy_scorer(tmp_path, monkeypatch):
    provider = _GraphProvider([PolicyGraphAction(action_type="module", action_id="patch_one", module_name="patch_one", score=1.0)], raise_on_score=True)
    _install_policy_package(monkeypatch, "sunpack_policy_test_stale_stop", provider)
    job = _job(tmp_path)
    graph = _root_graph(job)
    graph.stale_expansion_count = 5
    graph_payload = graph.to_dict()
    job = _job(tmp_path, repair_history={"items": [{"diagnosis": {"policy_loop": {"graph": graph_payload}}}]})
    scheduler = RepairScheduler({
        "repair": {
            "workspace": str(tmp_path / "repair"),
            "policy": {"provider_package": "sunpack_policy_test_stale_stop", "graph_stop_stale_patience": 3},
        }
    })
    scheduler.generate_policy_repair_candidates = lambda job, **kwargs: RepairCandidateBatch(candidates=[], diagnosis={"format": "zip"})  # type: ignore[method-assign]
    _patch_recovery(monkeypatch, root_score=0.1, patched_score=0.1)

    result = scheduler.repair(job)

    assert result.diagnosis["policy_loop"]["terminal_action"] == "stop"
    assert result.diagnosis["policy_loop"]["stop_reason"] == "graph_stale_best"
    assert provider.score_requests == []


class _GraphProvider:
    supported_formats = ["zip"]
    provider_id = "test_graph_provider"

    def __init__(self, actions: list[PolicyGraphAction], *, raise_on_score: bool = False):
        self.actions = list(actions)
        self.raise_on_score = raise_on_score
        self.diagnose_requests = []
        self.score_requests = []

    def available(self):
        return True

    def diagnose_state(self, request):
        self.diagnose_requests.append(request)
        return {
            "format": request.format,
            "root_case": {
                "scores": {"eocd.cd_size": 0.9},
                "ranked": [{"root_case": "eocd.cd_size", "score": 0.9}],
                "selected": ["eocd.cd_size"],
            },
            "confidence": 0.9,
        }

    def score_actions(self, request):
        if self.raise_on_score:
            raise AssertionError("policy scorer should not be called")
        self.score_requests.append(request)
        return list(self.actions)


def _install_policy_package(monkeypatch, name: str, provider) -> None:
    module = types.ModuleType(name)
    module.get_diagnosis_hgt_models = lambda: [provider]
    module.get_policy_graph_scorers = lambda: [provider]
    monkeypatch.setitem(sys.modules, name, module)


def _scheduler(tmp_path: Path, provider_package: str) -> RepairScheduler:
    return RepairScheduler({
        "repair": {
            "workspace": str(tmp_path / "repair"),
            "policy": {"provider_package": provider_package},
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
    from sunpack.repair.policy.graph import PolicyRepairGraph

    recovery = PolicyRecoverySnapshot(
        state_digest=job.archive_state.effective_patch_digest() if job.archive_state is not None else "",
        patch_depth=job.archive_state.patch_depth() if job.archive_state is not None else 0,
        score=0.0,
        status="empty",
    )
    return PolicyRepairGraph.initialize(job, recovery).graph
