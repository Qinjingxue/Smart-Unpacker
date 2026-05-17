import sys
import types
import json
from dataclasses import replace
from pathlib import Path

import pytest

from sunpack.contracts.detection import FactBag
from sunpack.contracts.archive_input import ArchiveInputDescriptor
from sunpack.contracts.archive_state import ArchiveState, PatchOperation, PatchPlan
from sunpack.contracts.tasks import ArchiveTask
from sunpack.coordinator.repair_runtime_transition import RepairRuntimeTransitionEvaluator
from sunpack.coordinator.repair_stage import ArchiveRepairStage
from sunpack.extraction.result import ExtractionResult
from sunpack.repair.candidate import CandidateValidation, RepairCandidate, RepairCandidateBatch
from sunpack.repair.config import normalize_repair_config
from sunpack.repair.job import RepairJob
from sunpack.repair.context import build_repair_context
from sunpack.repair.diagnosis import RepairDiagnosis
from sunpack.repair.policy.adapters import get_damage_analysis_adapter
from sunpack.repair.policy.manager import RepairPolicyManager
from sunpack.repair.policy.recovery_evaluator import PolicyRecoverySnapshot
from sunpack.repair.policy.training_runtime import candidate_snapshot, runtime_context_from_job
from sunpack.repair.policy.types import GraphActionPrior, PolicyExplorationGraph, PolicyGraphEdge, PolicyGraphNode
from sunpack.repair.result import RepairResult
from sunpack.repair.scheduler import RepairScheduler, _policy_loop_stop_plateau_satisfied, _policy_route_rejects_are_soft, _policy_step_decide_action
from sunpack.support import archive_knowledge_projection as knowledge_view
from sunpack.support.archive_state_view import ArchiveStateByteView
from sunpack.verification.result import ArchiveCoverageSummary, VerificationResult


@pytest.fixture(autouse=True)
def _skip_module_discovery(monkeypatch):
    monkeypatch.setattr("sunpack.repair.scheduler.discover_repair_modules", lambda: None)


def test_repair_policy_config_normalizes_defaults():
    config = normalize_repair_config({"policy": {"enabled": "true", "strict_provider_errors": "false"}})

    assert config["policy"]["enabled"] is True
    assert config["policy"]["fallback_to_selector"] is True
    assert config["policy"]["disable_beam_when_model_active"] is True
    assert config["policy"]["strict_provider_errors"] is False
    assert config["policy"]["provider_package"] == "sunpack_repair_models"


def test_missing_policy_package_falls_back_to_selector(tmp_path):
    first = _candidate("first", tmp_path / "first.zip", confidence=0.95)
    second = _candidate("second", tmp_path / "second.zip", confidence=0.1)
    scheduler = RepairScheduler({
        "repair": {
            "workspace": str(tmp_path / "repair"),
            "policy": {"provider_package": "sunpack_policy_test_missing_package"},
        }
    })
    scheduler.generate_repair_candidates = lambda job: RepairCandidateBatch(candidates=[first, second])  # type: ignore[method-assign]

    result = scheduler.repair(_job(tmp_path))

    assert result.ok
    assert result.module_name == "first"
    assert result.diagnosis["candidate_selection"]["policy"]["fallback_reason"] == "policy_unavailable"
    assert result.diagnosis["candidate_selection"]["policy_fallback"] is True


def test_state_value_manager_fallback_and_provider_result(tmp_path, monkeypatch):
    manager = RepairPolicyManager({"policy": {"provider_package": "sunpack_policy_test_missing_value"}})
    fallback, fallback_selection = manager.estimate_state_value(
        job=_job(tmp_path),
        archive_state=None,
        damage_analysis={},
        current_recovery={"score": 0.42},
    )

    assert fallback["reachable_recovery_value"] == 0.42
    assert fallback_selection["fallback_reason"] == "state_value_unavailable"

    provider = _StateValueProvider(0.87)
    _install_policy_package(monkeypatch, "sunpack_policy_test_value", provider)
    manager = RepairPolicyManager({"policy": {"provider_package": "sunpack_policy_test_value"}})
    result, selection = manager.estimate_state_value(
        job=_job(tmp_path),
        archive_state=None,
        damage_analysis={"damage_labels": ["field:eocd.cd_offset"]},
        current_recovery={"score": 0.1},
        frontier_summary={"frontier_count": 1},
    )

    assert result["reachable_recovery_value"] == 0.87
    assert result["provider_id"] == "test_value_policy"
    assert selection["decision_status"] == "estimated"


def test_dual_policy_loop_applies_patch_candidate(tmp_path, monkeypatch):
    _install_policy_package(monkeypatch, "sunpack_policy_test_dual_apply", _DualProvider(["expand_edge:patch_one", "stop_signal"]))
    source = tmp_path / "source.zip"
    source.write_bytes(b"broken")
    candidate = _patch_candidate("patch_one", source, b"fixed")
    scheduler = RepairScheduler({
        "repair": {
            "workspace": str(tmp_path / "repair"),
            "policy": {"provider_package": "sunpack_policy_test_dual_apply", "refresh_runtime_observation": False, "best_state_recovery_mode": "policy_light"},
            "max_repair_rounds_per_task": 3,
        }
    })
    scheduler.generate_policy_repair_candidates = lambda job, **kwargs: RepairCandidateBatch(candidates=[] if job.attempts else [candidate], diagnosis={"format": "zip", "confidence": 0.5})  # type: ignore[method-assign]

    result = scheduler.repair(_job(tmp_path))

    assert result.ok is True
    assert result.status == "partial"
    assert result.repaired_state is not None
    assert result.repaired_state.patch_depth() == 1
    assert result.diagnosis["policy_loop"]["terminal_action"] == "stop"


def test_policy_loop_does_not_preverify_candidates_but_keeps_state_values(tmp_path, monkeypatch):
    provider = _DualValueProvider(["expand_edge:patch_one", "stop_signal"], value=0.82)
    _install_policy_package(monkeypatch, "sunpack_policy_test_dual_pure_apply", provider)
    source = tmp_path / "source.zip"
    source.write_bytes(b"broken")
    candidate = _patch_candidate("patch_one", source, b"fixed")

    monkeypatch.setattr(
        "sunpack.repair.scheduler.RecoveryEvaluator.evaluate_state",
        lambda self, job, state, **kwargs: PolicyRecoverySnapshot(
            state_digest=state.effective_patch_digest() if state is not None else "",
            patch_depth=state.patch_depth() if state is not None else 0,
            score=0.4 if state is not None and state.patch_depth() > 0 else 0.0,
            status="partial" if state is not None and state.patch_depth() > 0 else "empty",
        ),
    )

    def fail_candidate_verification(*args, **kwargs):
        raise AssertionError("policy loop must not verify unchosen candidates")

    monkeypatch.setattr("sunpack.repair.scheduler.RecoveryEvaluator.evaluate_candidate", fail_candidate_verification)
    scheduler = RepairScheduler({
        "repair": {
            "workspace": str(tmp_path / "repair"),
            "policy": {"provider_package": "sunpack_policy_test_dual_pure_apply"},
            "max_repair_rounds_per_task": 3,
        }
    })
    scheduler.generate_policy_repair_candidates = lambda job, **kwargs: RepairCandidateBatch(candidates=[] if job.attempts else [candidate], diagnosis={"format": "zip", "confidence": 0.5})  # type: ignore[method-assign]

    result = scheduler.repair(_job(tmp_path))

    assert result.repaired_state is not None
    assert result.repaired_state.patch_depth() == 1
    first_choose = provider.choose_requests[0]
    assert first_choose.candidate_payloads
    assert not {"recovery_score", "recovery_delta", "recovery_status"} & set(first_choose.candidate_payloads[0])
    assert "state_value" in result.diagnosis["policy_loop"]["rounds"][0]
    assert any(
        request.archive_state is not None and request.archive_state.patch_depth() == 1
        for request in provider.estimate_requests
    )


def test_policy_loop_does_not_selector_filter_validation_rejected_candidates(tmp_path, monkeypatch):
    provider = _DualValueProvider(["expand_edge:patch_one", "stop_signal"], value=0.7)
    _install_policy_package(monkeypatch, "sunpack_policy_test_dual_validation_reject", provider)
    source = tmp_path / "source.zip"
    source.write_bytes(b"broken")
    candidate = replace(
        _patch_candidate("patch_one", source, b"fixed"),
        validations=[
            CandidateValidation(
                name="native_candidate_validation",
                accepted=False,
                score=0.0,
                warnings=["selector would reject this candidate"],
            )
        ],
    )

    monkeypatch.setattr(
        "sunpack.repair.scheduler.RecoveryEvaluator.evaluate_state",
        lambda self, job, state, **kwargs: PolicyRecoverySnapshot(
            state_digest=state.effective_patch_digest() if state is not None else "",
            patch_depth=state.patch_depth() if state is not None else 0,
            score=0.3 if state is not None and state.patch_depth() > 0 else 0.0,
            status="partial" if state is not None and state.patch_depth() > 0 else "empty",
        ),
    )
    scheduler = RepairScheduler({
        "repair": {
            "workspace": str(tmp_path / "repair"),
            "policy": {"provider_package": "sunpack_policy_test_dual_validation_reject"},
            "max_repair_rounds_per_task": 3,
        }
    })
    scheduler.generate_policy_repair_candidates = lambda job, **kwargs: RepairCandidateBatch(candidates=[] if job.attempts else [candidate], diagnosis={"format": "zip", "confidence": 0.5})  # type: ignore[method-assign]

    result = scheduler.repair(_job(tmp_path))

    assert result.repaired_state is not None
    assert result.repaired_state.patch_depth() == 1
    payload = provider.choose_requests[0].candidate_payloads[0]
    assert payload["module_name"] == "patch_one"
    assert payload["validation_summary"]["items"][0]["accepted"] is False


def test_policy_loop_excludes_file_only_candidates_from_model_selection(tmp_path, monkeypatch):
    provider = _DualValueProvider(["expand_edge:patch_one", "stop_signal"], value=0.7)
    _install_policy_package(monkeypatch, "sunpack_policy_test_dual_state_only", provider)
    source = tmp_path / "source.zip"
    source.write_bytes(b"broken")
    file_only = _candidate("file_only", tmp_path / "file-only.zip", confidence=0.9)
    patch_candidate = _patch_candidate("patch_one", source, b"fixed")

    scheduler = RepairScheduler({
        "repair": {
            "workspace": str(tmp_path / "repair"),
            "policy": {"provider_package": "sunpack_policy_test_dual_state_only", "refresh_runtime_observation": False, "best_state_recovery_mode": "policy_light"},
            "max_repair_rounds_per_task": 3,
        }
    })
    scheduler.generate_policy_repair_candidates = lambda job, **kwargs: RepairCandidateBatch(candidates=[] if job.attempts else [file_only, patch_candidate], diagnosis={"format": "zip", "confidence": 0.5})  # type: ignore[method-assign]

    result = scheduler.repair(_job(tmp_path))

    assert result.repaired_state is not None
    modules = [payload["module_name"] for payload in provider.choose_requests[0].candidate_payloads]
    assert modules == ["patch_one"]


def test_policy_loop_materializes_only_selected_lazy_proposal(tmp_path, monkeypatch):
    provider = _DualValueProvider(["expand_edge:patch_one", "stop_signal"], value=0.4)
    _install_policy_package(monkeypatch, "sunpack_policy_test_dual_lazy_expand", provider)
    source = tmp_path / "source.zip"
    source.write_bytes(b"broken")
    calls = {"patch_one": 0, "patch_alt": 0}

    def lazy_candidate(module: str, replacement: bytes) -> RepairCandidate:
        def materialize():
            calls[module] += 1
            return _patch_candidate(module, source, replacement)

        return RepairCandidate(
            module_name=module,
            format="zip",
            confidence=0.8,
            actions=["plan_repair", module],
            materializer=materialize,
            materialized=False,
            diagnosis={"repair_name": module},
        )

    monkeypatch.setattr(
        "sunpack.repair.scheduler.RecoveryEvaluator.evaluate_state",
        lambda self, job, state, **kwargs: PolicyRecoverySnapshot(
            state_digest=state.effective_patch_digest() if state is not None else "",
            patch_depth=state.patch_depth() if state is not None else 0,
            score=0.4 if state is not None and state.patch_depth() > 0 else 0.0,
            status="partial" if state is not None and state.patch_depth() > 0 else "empty",
        ),
    )
    scheduler = RepairScheduler({
        "repair": {
            "workspace": str(tmp_path / "repair"),
            "policy": {"provider_package": "sunpack_policy_test_dual_lazy_expand"},
            "max_repair_rounds_per_task": 3,
        }
    })
    scheduler.generate_policy_repair_candidates = lambda job, **kwargs: RepairCandidateBatch(  # type: ignore[method-assign]
        candidates=[] if job.attempts else [lazy_candidate("patch_one", b"fixed"), lazy_candidate("patch_alt", b"alt")],
        diagnosis={"format": "zip", "confidence": 0.5},
    )

    result = scheduler.repair(_job(tmp_path))

    assert result.repaired_state is not None
    assert result.repaired_state.patch_depth() == 1
    assert calls == {"patch_one": 1, "patch_alt": 0}
    payloads = provider.choose_requests[0].candidate_payloads
    assert {payload["module_name"] for payload in payloads} == {"patch_one", "patch_alt"}
    assert all(payload["lazy"] is True for payload in payloads)
    assert all(payload["has_archive_state_plan"] is False for payload in payloads)


def test_policy_loop_failed_lazy_materialization_exhausts_edge_and_continues(tmp_path, monkeypatch):
    provider = _DualValueProvider(["expand_edge:bad_lazy", "expand_edge:patch_alt", "stop_signal"], value=0.7)
    _install_policy_package(monkeypatch, "sunpack_policy_test_dual_lazy_failed_expand", provider)
    source = tmp_path / "source.zip"
    source.write_bytes(b"broken")

    bad = RepairCandidate(
        module_name="bad_lazy",
        format="zip",
        confidence=0.9,
        actions=["plan_repair", "bad_lazy"],
        materializer=lambda: [],
        materialized=False,
        diagnosis={"repair_name": "bad_lazy"},
    )
    good = RepairCandidate(
        module_name="patch_alt",
        format="zip",
        confidence=0.8,
        actions=["plan_repair", "patch_alt"],
        materializer=lambda: _patch_candidate("patch_alt", source, b"alt"),
        materialized=False,
        diagnosis={"repair_name": "patch_alt"},
    )

    monkeypatch.setattr(
        "sunpack.repair.scheduler.RecoveryEvaluator.evaluate_state",
        lambda self, job, state, **kwargs: PolicyRecoverySnapshot(
            state_digest=state.effective_patch_digest() if state is not None else "",
            patch_depth=state.patch_depth() if state is not None else 0,
            score=0.5 if state is not None and state.patch_depth() > 0 else 0.0,
            status="partial" if state is not None and state.patch_depth() > 0 else "empty",
        ),
    )
    scheduler = RepairScheduler({
        "repair": {
            "workspace": str(tmp_path / "repair"),
            "policy": {"provider_package": "sunpack_policy_test_dual_lazy_failed_expand"},
            "max_repair_rounds_per_task": 3,
        }
    })
    scheduler.generate_policy_repair_candidates = lambda job, **kwargs: RepairCandidateBatch(  # type: ignore[method-assign]
        candidates=[bad, good] if not job.attempts else [],
        diagnosis={"format": "zip", "confidence": 0.5},
    )

    result = scheduler.repair(_job(tmp_path))

    loop = result.diagnosis["policy_loop"]
    assert result.repaired_state is not None
    assert result.repaired_state.patch_depth() == 1
    assert loop["graph_summary"]["edge_status_counts"]["failed_materialization"] == 1
    assert loop["graph_summary"]["edge_status_counts"]["expanded"] == 1
    assert "policy selected a proposal that did not materialize to repaired_state" in result.warnings


def test_policy_step_mode_executes_one_expand_and_returns(tmp_path, monkeypatch):
    provider = _DualValueProvider(["expand_edge:patch_one", "expand_edge:patch_two"], value=0.7)
    _install_policy_package(monkeypatch, "sunpack_policy_test_step_once", provider)
    source = tmp_path / "source.zip"
    source.write_bytes(b"broken")
    calls = {"evaluate": 0}

    def recovery(self, job, state, **kwargs):
        calls["evaluate"] += 1
        return PolicyRecoverySnapshot(
            state_digest=state.effective_patch_digest() if state is not None else "",
            patch_depth=state.patch_depth() if state is not None else 0,
            score=0.0,
            status="empty",
        )

    monkeypatch.setattr("sunpack.repair.scheduler.RecoveryEvaluator.evaluate_state", recovery)
    scheduler = RepairScheduler({
        "repair": {
            "workspace": str(tmp_path / "repair"),
            "policy": {"provider_package": "sunpack_policy_test_step_once", "step_mode": True},
            "max_repair_rounds_per_task": 5,
        }
    })
    scheduler.generate_policy_repair_candidates = lambda job, **kwargs: RepairCandidateBatch(  # type: ignore[method-assign]
        candidates=[_patch_candidate("patch_one", source, b"one"), _patch_candidate("patch_two", source, b"two")],
        diagnosis={"format": "zip", "confidence": 0.5},
    )

    result = scheduler.repair(_job(tmp_path))

    assert result.ok is True
    assert result.module_name == "patch_one"
    assert result.repaired_state is not None
    assert ArchiveStateByteView(result.repaired_state).to_bytes().endswith(b"one")
    assert result.diagnosis["policy_loop"]["step_mode"] is True
    assert result.diagnosis["policy_loop"]["graph_summary"]["expansion_count"] == 1
    assert calls["evaluate"] <= 2


def test_policy_step_mode_failed_materialization_returns_empty_patch_node(tmp_path, monkeypatch):
    provider = _DualValueProvider(["expand_edge:bad_lazy"], value=0.7)
    _install_policy_package(monkeypatch, "sunpack_policy_test_step_empty_patch", provider)
    bad = RepairCandidate(
        module_name="bad_lazy",
        format="zip",
        confidence=0.9,
        actions=["plan_repair", "bad_lazy"],
        materializer=lambda: [],
        materialized=False,
        diagnosis={"repair_name": "bad_lazy"},
    )

    monkeypatch.setattr(
        "sunpack.repair.scheduler.RecoveryEvaluator.evaluate_state",
        lambda self, job, state, **kwargs: PolicyRecoverySnapshot(
            state_digest=state.effective_patch_digest() if state is not None else "",
            patch_depth=state.patch_depth() if state is not None else 0,
            score=0.0,
            status="empty",
        ),
    )
    scheduler = RepairScheduler({
        "repair": {
            "workspace": str(tmp_path / "repair"),
            "policy": {"provider_package": "sunpack_policy_test_step_empty_patch", "step_mode": True},
            "max_repair_rounds_per_task": 5,
        }
    })
    scheduler.generate_policy_repair_candidates = lambda job, **kwargs: RepairCandidateBatch(  # type: ignore[method-assign]
        candidates=[bad],
        diagnosis={"format": "zip", "confidence": 0.5},
    )

    result = scheduler.repair(_job(tmp_path))

    loop = result.diagnosis["policy_loop"]
    assert result.ok is True
    assert result.status == "partial"
    assert result.repaired_state is not None
    assert result.repaired_state.patch_depth() == 1
    assert loop["graph_operation"]["patch_status"] == "empty_failed"
    assert loop["graph_summary"]["edge_status_counts"]["expanded_failed"] == 1


def test_policy_step_stop_signal_requires_absolute_advantage():
    graph = PolicyExplorationGraph(
        nodes={"root": PolicyGraphNode(node_id="root", recovery={"score": 0.4})},
        edges={"e1": PolicyGraphEdge(edge_id="e1", from_node_id="root", candidate_id="c1", module_name="zip_fix")},
        current_node_id="root",
        best_node_id="root",
        frontier=["e1"],
    )
    close_stop = [
        GraphActionPrior(action_type="stop_signal", prior_score=0.8, confidence=0.9, reason="too_close"),
        GraphActionPrior(action_type="expand_edge", edge_id="e1", candidate_id="c1", prior_score=0.7, confidence=0.9),
    ]
    dominant_stop = [
        GraphActionPrior(action_type="stop_signal", prior_score=1.0, confidence=0.95, reason="dominant"),
        GraphActionPrior(action_type="expand_edge", edge_id="e1", candidate_id="c1", prior_score=0.2, confidence=0.9),
    ]

    keep_going = _policy_step_decide_action(
        graph,
        close_stop,
        stop_readiness={"should_force_stop": False},
        state_value={"reachable_recovery_value": 0.4},
        policy_config={},
    )
    stop = _policy_step_decide_action(
        graph,
        dominant_stop,
        stop_readiness={"should_force_stop": False},
        state_value={"reachable_recovery_value": 0.4},
        policy_config={},
    )

    assert keep_going.action == "expand"
    assert stop.action == "finish"
    assert stop.reason == "dominant"


def test_dual_policy_loop_apply_then_undo_checkouts_parent_without_dropping_best(tmp_path, monkeypatch):
    _install_policy_package(monkeypatch, "sunpack_policy_test_dual_checkout", _DualProvider(["expand_edge:patch_one", "checkout_node", "checkout_node"]))
    source = tmp_path / "source.zip"
    source.write_bytes(b"broken")
    root = ArchiveState.from_archive_input(ArchiveInputDescriptor.from_parts(archive_path=str(source), format_hint="zip"))
    candidate = _patch_candidate("patch_one", source, b"fixed")
    scheduler = RepairScheduler({
        "repair": {
            "workspace": str(tmp_path / "repair"),
            "policy": {"provider_package": "sunpack_policy_test_dual_checkout", "refresh_runtime_observation": False, "best_state_recovery_mode": "policy_light"},
            "max_repair_rounds_per_task": 4,
        }
    })
    scheduler.generate_policy_repair_candidates = lambda job, **kwargs: RepairCandidateBatch(candidates=[candidate] if job.archive_state and job.archive_state.patch_depth() == 0 else [], diagnosis={"format": "zip", "confidence": 0.5})  # type: ignore[method-assign]

    result = scheduler.repair(replace(_job(tmp_path), archive_state=root))

    assert result.status == "partial"
    assert result.diagnosis["policy_loop"]["terminal_action"] == "finish"
    assert result.diagnosis["policy_loop"]["patch_depth"] == 1
    assert result.diagnosis["policy_loop"]["terminal_patch_depth"] == 0
    assert result.diagnosis["policy_loop"]["final_state_selection"] == "best_seen_graph_node"
    assert result.diagnosis["policy_loop"]["graph_summary"]["node_count"] == 2


def test_dual_policy_loop_stop_signal_finishes(tmp_path, monkeypatch):
    _install_policy_package(monkeypatch, "sunpack_policy_test_dual_stop_empty", _DualProvider(["stop_signal"]))
    scheduler = RepairScheduler({
        "repair": {
            "workspace": str(tmp_path / "repair"),
            "policy": {"provider_package": "sunpack_policy_test_dual_stop_empty"},
        }
    })
    scheduler.generate_policy_repair_candidates = lambda job, **kwargs: RepairCandidateBatch(candidates=[], diagnosis={"format": "zip", "confidence": 0.5})  # type: ignore[method-assign]

    result = scheduler.repair(_job(tmp_path))

    assert result.status == "partial"
    assert result.module_name == "policy_finish"
    assert result.diagnosis["policy_loop"]["terminal_action"] == "stop"
    assert result.diagnosis["policy_loop"]["final_state_selection"] == "best_seen_graph_node"


def test_dual_policy_loop_checkout_reaches_remaining_frontier(tmp_path, monkeypatch):
    _install_policy_package(
        monkeypatch,
        "sunpack_policy_test_dual_checkout_frontier",
        _DualProvider(["expand_edge:patch_one", "checkout_node", "expand_edge:patch_alt", "stop_signal"]),
    )
    source = tmp_path / "source.zip"
    source.write_bytes(b"broken")
    root = ArchiveState.from_archive_input(ArchiveInputDescriptor.from_parts(archive_path=str(source), format_hint="zip"))

    def recovery_for_state(state):
        depth = state.patch_depth() if state is not None else 0
        digest = state.effective_patch_digest() if state is not None else ""
        score = 0.0
        if depth == 1:
            raw = ArchiveStateByteView(state).to_bytes()
            score = 0.9 if raw.endswith(b"alt") else 0.2
        return PolicyRecoverySnapshot(
            state_digest=digest,
            patch_depth=depth,
            score=score,
            status="partial" if score > 0 else "empty",
        )

    monkeypatch.setattr(
        "sunpack.repair.scheduler.RecoveryEvaluator.evaluate_state",
        lambda self, job, state, **kwargs: recovery_for_state(state),
    )

    def generate_candidates(job, **kwargs):
        state = job.archive_state or root
        if state.patch_depth() == 0:
            return RepairCandidateBatch(
                candidates=[
                    _patch_candidate_from_state("patch_one", state, b"one"),
                    _patch_candidate_from_state("patch_alt", state, b"alt"),
                ],
                diagnosis={"format": "zip", "confidence": 0.5},
            )
        return RepairCandidateBatch(candidates=[], diagnosis={"format": "zip", "confidence": 0.5})

    scheduler = RepairScheduler({
        "repair": {
            "workspace": str(tmp_path / "repair"),
            "policy": {"provider_package": "sunpack_policy_test_dual_checkout_frontier"},
            "max_repair_rounds_per_task": 4,
        }
    })
    scheduler.generate_policy_repair_candidates = generate_candidates  # type: ignore[method-assign]

    result = scheduler.repair(replace(_job(tmp_path), archive_state=root))

    loop = result.diagnosis["policy_loop"]
    assert result.repaired_state is not None
    assert ArchiveStateByteView(result.repaired_state).to_bytes().endswith(b"alt")
    assert loop["graph_summary"]["node_count"] == 3
    assert any(item["graph_action"]["action"] == "checkout" for item in loop["rounds"])
    assert loop["final_state_selection"] == "best_seen_graph_node"


def test_dual_policy_loop_stop_signal_returns_best_seen_state(tmp_path, monkeypatch):
    _install_policy_package(
        monkeypatch,
        "sunpack_policy_test_dual_stop_best_seen",
        _DualProvider(["expand_edge:patch_one", "expand_edge:patch_two", "stop_signal"]),
    )
    source = tmp_path / "source.zip"
    source.write_bytes(b"broken")

    def recovery_for_state(state):
        depth = state.patch_depth() if state is not None else 0
        score = {0: 0.0, 1: 0.8, 2: 0.2}.get(depth, 0.0)
        return PolicyRecoverySnapshot(
            state_digest=state.effective_patch_digest() if state is not None else "",
            patch_depth=depth,
            score=score,
            status="partial" if score > 0 else "empty",
        )

    monkeypatch.setattr(
        "sunpack.repair.scheduler.RecoveryEvaluator.evaluate_state",
        lambda self, job, state, **kwargs: recovery_for_state(state),
    )

    def generate_candidates(job, **kwargs):
        state = job.archive_state or ArchiveState.from_archive_input(
            ArchiveInputDescriptor.from_parts(archive_path=str(source), format_hint="zip")
        )
        if state.patch_depth() == 0:
            return RepairCandidateBatch(candidates=[_patch_candidate_from_state("patch_one", state, b"one")], diagnosis={"format": "zip", "confidence": 0.5})
        if state.patch_depth() == 1:
            return RepairCandidateBatch(candidates=[_patch_candidate_from_state("patch_two", state, b"two")], diagnosis={"format": "zip", "confidence": 0.5})
        return RepairCandidateBatch(candidates=[], diagnosis={"format": "zip", "confidence": 0.5})

    scheduler = RepairScheduler({
        "repair": {
            "workspace": str(tmp_path / "repair"),
            "policy": {"provider_package": "sunpack_policy_test_dual_stop_best_seen"},
            "max_repair_rounds_per_task": 3,
        }
    })
    scheduler.generate_policy_repair_candidates = generate_candidates  # type: ignore[method-assign]

    result = scheduler.repair(_job(tmp_path))

    assert result.status == "partial"
    assert result.repaired_state is not None
    assert result.repaired_state.patch_depth() == 1
    loop = result.diagnosis["policy_loop"]
    assert loop["terminal_action"] == "stop"
    assert loop["terminal_patch_depth"] == 2
    assert loop["patch_depth"] == 1
    assert loop["final_state_selection"] == "best_seen_graph_node"
    assert loop["recovery"]["score"] == 0.8
    assert loop["terminal_recovery"]["score"] == 0.2


def test_dual_policy_loop_stop_returns_best_seen_state(tmp_path, monkeypatch):
    _install_policy_package(
        monkeypatch,
        "sunpack_policy_test_dual_best_seen",
        _DualProvider(["expand_edge:patch_one", "expand_edge:patch_two", "stop_signal"]),
    )
    source = tmp_path / "source.zip"
    source.write_bytes(b"broken")

    def recovery_for_state(state):
        depth = state.patch_depth() if state is not None else 0
        score = {0: 0.0, 1: 0.9, 2: 0.2}.get(depth, 0.0)
        return PolicyRecoverySnapshot(
            state_digest=state.effective_patch_digest() if state is not None else "",
            patch_depth=depth,
            score=score,
            status="repaired" if score >= 0.999 else "partial" if score > 0 else "empty",
        )

    monkeypatch.setattr(
        "sunpack.repair.scheduler.RecoveryEvaluator.evaluate_state",
        lambda self, job, state, **kwargs: recovery_for_state(state),
    )
    monkeypatch.setattr(
        "sunpack.repair.scheduler.RecoveryEvaluator.evaluate_candidate",
        lambda self, job, candidate, **kwargs: recovery_for_state(candidate.repaired_state),
    )

    def generate_candidates(job, **kwargs):
        state = job.archive_state or ArchiveState.from_archive_input(
            ArchiveInputDescriptor.from_parts(archive_path=str(source), format_hint="zip")
        )
        if state.patch_depth() == 0:
            return RepairCandidateBatch(candidates=[_patch_candidate_from_state("patch_one", state, b"one")], diagnosis={"format": "zip", "confidence": 0.5})
        if state.patch_depth() == 1:
            return RepairCandidateBatch(candidates=[_patch_candidate_from_state("patch_two", state, b"two")], diagnosis={"format": "zip", "confidence": 0.5})
        return RepairCandidateBatch(candidates=[], diagnosis={"format": "zip", "confidence": 0.5})

    scheduler = RepairScheduler({
        "repair": {
            "workspace": str(tmp_path / "repair"),
            "policy": {"provider_package": "sunpack_policy_test_dual_best_seen"},
            "max_repair_rounds_per_task": 3,
        }
    })
    scheduler.generate_policy_repair_candidates = generate_candidates  # type: ignore[method-assign]

    result = scheduler.repair(_job(tmp_path))

    assert result.repaired_state is not None
    assert result.repaired_state.patch_depth() == 1
    loop = result.diagnosis["policy_loop"]
    assert loop["terminal_patch_depth"] == 2
    assert loop["patch_depth"] == 1
    assert loop["final_state_selection"] == "best_seen_graph_node"
    assert loop["recovery"]["score"] == 0.9
    assert loop["terminal_recovery"]["score"] == 0.2


def test_policy_loop_stop_plateau_requires_recent_window_without_best_state():
    recovery = PolicyRecoverySnapshot(score=0.8, status="partial")
    config = {"policy": {"stop_plateau_window_ratio": 0.5, "stop_plateau_min_rounds": 2}}

    assert not _policy_loop_stop_plateau_satisfied(
        round_index=3,
        max_rounds=6,
        best_round_index=1,
        current_recovery=recovery,
        config=config,
    )
    assert _policy_loop_stop_plateau_satisfied(
        round_index=4,
        max_rounds=6,
        best_round_index=1,
        current_recovery=recovery,
        config=config,
    )
    assert not _policy_loop_stop_plateau_satisfied(
        round_index=2,
        max_rounds=6,
        best_round_index=2,
        current_recovery=PolicyRecoverySnapshot(score=1.0, status="complete"),
        config=config,
    )


def test_repair_context_includes_policy_job_damage_flags(tmp_path):
    job = replace(
        _job(tmp_path),
        damage_flags=["policy_damage_analysis_route", "central_directory_offset_bad"],
        knowledge={"source": {"input": {"format_hint": "zip"}}},
    )
    context = build_repair_context(
        job,
        RepairDiagnosis(format="zip", categories=["directory_rebuild"], repairable=True),
    )

    assert "policy_damage_analysis_route" in context.damage_flags
    assert "central_directory_offset_bad" in context.damage_flags


def test_policy_route_bridge_softens_only_generic_content_rejects():
    flags = ["policy_damage_analysis_route", "central_directory_offset_bad", "checksum_error", "partial_entries_remaining"]

    assert _policy_route_rejects_are_soft(flags, {"checksum_error", "partial_entries_remaining"})
    assert not _policy_route_rejects_are_soft(flags, {"wrong_password"})
    assert not _policy_route_rejects_are_soft(["central_directory_offset_bad", "checksum_error"], {"checksum_error"})


def test_zip_damage_adapter_postprocesses_raw_scores():
    adapter = get_damage_analysis_adapter("zip")

    result = adapter.postprocess_scores(  # type: ignore[union-attr]
        {"field:local_header.crc": 0.42, "zone:zip64": 0.1, "field:zip64.extra_length": 0.22},
        {"default_threshold": 0.5, "thresholds": {"field:local_header.crc": 0.4, "field:zip64.extra_length": 0.21}},
        metadata={"model_id": "unit"},
    )

    assert result.route_hints == []
    assert "field:local_header.crc" in result.damage_labels
    assert "zone:local_header" in result.damage_labels
    assert "field:zip64.extra_length" in result.damage_labels
    assert "zone:zip64" in result.damage_labels
    assert {"kind": "local_header", "path": "local_header"} in result.damage_zones
    assert result.metadata["analysis_target"] == "parallel_world_and_location_models"
    assert result.metadata["location_model"]["raw_scores"]["field:local_header.crc"] == 0.42
    assert result.metadata["location_model"]["raw_scores"]["zone:zip64"] == 0.1


def test_policy_manager_coerces_raw_damage_scores(tmp_path, monkeypatch):
    provider = _RawDamageScoreProvider()
    _install_policy_package(monkeypatch, "sunpack_policy_test_raw_damage", provider)
    from sunpack.repair.policy.manager import RepairPolicyManager

    manager = RepairPolicyManager({"policy": {"provider_package": "sunpack_policy_test_raw_damage"}})
    analysis, selection = manager.analyze_damage(job=_job(tmp_path))

    assert selection["decision_status"] == "analyzed"
    assert selection["provider_id"] == "raw_damage_policy"
    assert analysis["route_hints"] == []
    assert "field:zip64.extra_length" in analysis["damage_labels"]
    assert "zone:zip64" in analysis["damage_labels"]
    assert analysis["metadata"]["provider_id"] == "raw_damage_policy"
    assert analysis["metadata"]["location_model"]["raw_scores"]["field:zip64.extra_length"] == 0.22


def test_candidate_snapshot_matches_training_action_shape_without_oracle(tmp_path):
    candidate = _candidate("zip_resolve_duplicate_entries", tmp_path / "fixed.zip", confidence=0.5)
    candidate = replace(
        candidate,
        diagnosis={
            "repair_name": "zip_resolve_duplicate_entries",
            "atomic_action_group": "duplicate_conflict",
            "route_family": "conflict",
            "native_key": "duplicate_policy_crc_match",
            "native_target": "duplicate_entries",
            "candidate_status": "complete",
            "patch_facts": ["resolved_duplicate_entries", "kept_entry_policy=crc_match"],
            "validation_details": {
                "policy": "crc_match",
                "duplicate_group_count": 1,
                "kept_entry_crc_match_count": 1,
                "kept_payload_verified_count": 1,
                "dropped_entry_count": 1,
            },
        },
    )
    payload = candidate_snapshot(candidate, index=3)

    assert payload["schema_version"] == 1
    assert payload["current_rank"] == 3
    assert payload["module_name"] == "zip_resolve_duplicate_entries"
    assert payload["action_type"] == "expand_edge"
    assert payload["patch_operation_count"] == 0
    assert payload["validation_summary"]["accepted"] is True
    assert not _contains_forbidden_policy_key(payload)


def test_runtime_transition_evaluator_applies_candidate_and_restores_task(tmp_path):
    task = _task(tmp_path / "broken.zip", fmt="zip")
    task.set_knowledge({"test": {"stable": True}})
    original_digest = task.archive_state().effective_patch_digest()
    candidate = _candidate("zip_fix_cd_offset", tmp_path / "fixed.zip", confidence=0.5)
    extracted = ExtractionResult(success=True, archive=task.main_path, out_dir=str(tmp_path / "out"), all_parts=[task.main_path])
    extractor = _FakeExtractor(extracted)
    verifier = _FakeVerifier(_verification())
    stage = ArchiveRepairStage({"repair": {"workspace": str(tmp_path / "repair"), "policy": {"enabled": False}}})
    evaluator = RepairRuntimeTransitionEvaluator(
        extractor=extractor,
        verifier=verifier,
        repair_stage=stage,
        source_digest=lambda payload: "digest",
    )

    transition = evaluator.evaluate(task, candidate, temp_dir=tmp_path / "eval")

    assert transition.result is extracted
    assert transition.verification.decision_hint == "repair"
    assert transition.source_digest == "digest"
    assert task.archive_state().effective_patch_digest() == original_digest
    restored_knowledge = task.knowledge().to_dict()
    assert restored_knowledge["test"]["stable"] is True
    assert "verification" not in restored_knowledge
    assert extractor.seen_archive_states


def test_runtime_repair_job_includes_descriptor_route_evidence(tmp_path):
    task = _task(tmp_path / "descriptor.zip", fmt="zip")
    _write_source_derivation(
        task,
        damage_profile="zip_data_descriptor_cd_conflict",
        zip_structure_features={"has_data_descriptor": True},
        zip_container_tags=["data_descriptor", "bit3"],
    )
    stage = ArchiveRepairStage({"repair": {"workspace": str(tmp_path / "repair"), "policy": {"enabled": False}}})
    job = stage._job_from_verification_assessment(task, _failed_extraction(task), _verification())  # noqa: SLF001

    assert job is not None
    assert "data_descriptor" in job.damage_flags
    assert "central_directory_offset_bad" in job.damage_flags
    assert "spurious_data_descriptor_candidate" in job.damage_flags
    assert "data_descriptor" in knowledge_view.repair_route_context(job.knowledge)["route_evidence_flags"]


def test_training_runtime_context_does_not_backfill_missing_archive_knowledge_from_job_fields(tmp_path):
    source = tmp_path / "source.zip"
    source.write_bytes(b"broken")
    job = RepairJob(
        source_input={"kind": "file", "path": str(source), "format_hint": "zip"},
        format="zip",
        analysis_prepass={"status": "ok", "selected_format": "zip"},
        extraction_failure={"status": "failed", "decision_hint": "repair"},
        damage_flags=["data_descriptor"],
        repair_history={"route_evidence_flags": ["data_descriptor"]},
        knowledge={},
    )

    context = runtime_context_from_job(job)

    assert "source.input" in context["knowledge_projection"]["missing_paths"]
    assert context["job_summary"]["route_evidence_flags"] == []


def test_training_runtime_source_has_no_legacy_repair_job_fallbacks():
    source = Path("sunpack/repair/policy/training_runtime.py").read_text(encoding="utf-8")
    forbidden = [
        "project_knowledge_sources",
        "_set_if_missing",
        "_feature_payload_sources",
        "_verification_summary_from_failure",
    ]

    for token in forbidden:
        assert token not in source


def test_runtime_repair_job_includes_non_utf8_route_evidence(tmp_path):
    task = _task(tmp_path / "names.zip", fmt="zip")
    _write_source_derivation(
        task,
        damage_profile="zip_non_utf8_filename_directory_rebuild",
        zip_structure_features={"has_filename_encoding_risk": True},
        zip_container_tags=["filename_encoding", "non_utf8_names"],
    )
    stage = ArchiveRepairStage({"repair": {"workspace": str(tmp_path / "repair"), "policy": {"enabled": False}}})
    job = stage._job_from_verification_assessment(task, _failed_extraction(task), _verification())  # noqa: SLF001

    assert job is not None
    assert "filename_encoding_bad" in job.damage_flags
    assert "raw_filename_bytes" in job.damage_flags


def test_runtime_repair_job_preserves_split_sidecars_without_unavailable_flag(tmp_path):
    task = _task(tmp_path / "split.zip", fmt="zip")
    part = tmp_path / "split.z01"
    part.write_bytes(b"part")
    task.all_parts = [task.main_path, str(part)]
    task.split_info.parts = list(task.all_parts)
    task.split_info.is_split = True
    task.set_archive_state(task.archive_state())
    _write_source_derivation(
        task,
        damage_profile="zip_split_missing_middle_volume",
        zip_structure_features={"has_split_sidecars": True},
    )
    stage = ArchiveRepairStage({"repair": {"workspace": str(tmp_path / "repair"), "policy": {"enabled": False}}})
    job = stage._job_from_verification_assessment(task, _failed_extraction(task), _verification())  # noqa: SLF001

    assert job is not None
    assert job.source_input.get("parts")
    assert "split_sidecars_available" in job.damage_flags
    assert "missing_volume_unavailable" not in job.damage_flags


class _MissingCandidateIdProvider:
    provider_id = "test_zip_policy"
    supported_formats = ("zip",)

    def available(self):
        return True

    def choose(self, request):
        return {
            "confidence": 0.9,
            "metadata": {
                "model_id": "test",
                "private_score": 123.0,
            },
        }


class _CandidateIdProvider:
    provider_id = "test_zip_policy"
    supported_formats = ("zip",)

    def __init__(self, *, selected_module: str = "", selected_candidate_id: str = ""):
        self.selected_module = selected_module
        self.selected_candidate_id = selected_candidate_id

    def available(self):
        return True

    def choose(self, request):
        selected_candidate_id = self.selected_candidate_id
        if not selected_candidate_id:
            for payload in getattr(request, "candidate_payloads", []) or []:
                if str(payload.get("module_name") or payload.get("module") or "") == self.selected_module:
                    selected_candidate_id = str(payload.get("candidate_id") or "")
                    break
        return {
            "selected_candidate_id": selected_candidate_id,
            "confidence": 0.9,
            "metadata": {
                "model_id": "test",
                "private_score": 123.0,
            },
        }


class _PriorProvider:
    provider_id = "test_action_prior_policy"
    supported_formats = ("zip",)

    def __init__(self, priors):
        self.priors = list(priors)

    def available(self):
        return True

    def analyze(self, request):
        return {"format": "zip", "damage_labels": [], "metadata": {"model_id": "test_damage"}}

    def choose_graph_action(self, request):
        return {
            "provider_id": self.provider_id,
            "graph_action_priors": list(self.priors),
            "metadata": {"model_id": "test_graph_action_prior"},
        }


class _FakeExtractor:
    def __init__(self, result):
        self.result = result
        self.seen_archive_states = []

    def extract(self, task, out_dir, runtime_scheduler=None, **kwargs):
        self.seen_archive_states.append(task.archive_state().effective_patch_digest())
        self.result.out_dir = str(out_dir)
        return self.result


class _FakeVerifier:
    config = {}

    def __init__(self, verification):
        self.verification = verification

    def verify(self, task, result):
        return self.verification


class _DualProvider:
    provider_id = "test_dual_policy"
    supported_formats = ("zip",)

    def __init__(self, actions):
        self.actions = list(actions)

    def available(self):
        return True

    def analyze(self, request):
        return {
            "format": request.format,
            "damage_labels": list(getattr(request.job, "damage_flags", []) or []),
            "confidence": 0.75,
            "metadata": {"model_id": "fake_damage", "model_version": "test"},
        }

    def choose_graph_action(self, request):
        step = self.actions[min(max(0, request.round_index - 1), len(self.actions) - 1)] if self.actions else "stop_signal"
        action, _, module = step.partition(":")
        if action == "expand_edge":
            for payload in request.candidate_payloads:
                if module in {payload.get("module_name"), payload.get("module")}:
                    return {"graph_action_priors": [{"action_type": action, "candidate_id": payload["candidate_id"], "prior_score": 1.0, "confidence": 1.0}]}
            for edge in request.frontier:
                if module == edge.get("module_name"):
                    return {"graph_action_priors": [{"action_type": action, "candidate_id": edge["candidate_id"], "edge_id": edge["edge_id"], "prior_score": 1.0, "confidence": 1.0}]}
            return {"graph_action_priors": [{"action_type": "stop_signal", "prior_score": 1.0, "reason": "missing_scripted_candidate"}]}
        if action == "checkout_node":
            graph = request.graph if isinstance(request.graph, dict) else {}
            nodes = graph.get("nodes") if isinstance(graph.get("nodes"), dict) else {}
            current = nodes.get(request.current_node_id) if isinstance(nodes.get(request.current_node_id), dict) else {}
            return {"graph_action_priors": [{"action_type": action, "node_id": current.get("parent_id") or request.best_node_id, "prior_score": 1.0, "confidence": 1.0, "reason": f"scripted_{action}"}]}
        return {"graph_action_priors": [{"action_type": action, "prior_score": 1.0, "confidence": 1.0, "reason": f"scripted_{action}"}]}


class _DualValueProvider(_DualProvider):
    def __init__(self, actions, value: float = 0.75):
        super().__init__(actions)
        self.value = value
        self.choose_requests = []
        self.estimate_requests = []

    def choose_graph_action(self, request):
        self.choose_requests.append(request)
        return super().choose_graph_action(request)

    def estimate(self, request):
        self.estimate_requests.append(request)
        return {
            "reachable_recovery_value": self.value,
            "confidence": 0.9,
            "metadata": {"model_id": "test_value"},
        }


class _RawDamageScoreProvider:
    provider_id = "raw_damage_policy"
    supported_formats = ("zip",)

    def available(self):
        return True

    def analyze(self, request):
        return {
            "format": request.format,
            "scores": {"field:zip64.extra_length": 0.22},
            "thresholds": {"default_threshold": 0.5, "thresholds": {"field:zip64.extra_length": 0.21}},
            "metadata": {"model_id": "raw_damage_unit"},
        }

    def choose_graph_action(self, request):
        return {"graph_action_priors": [{"action_type": "stop_signal", "prior_score": 1.0}]}


class _StateValueProvider:
    provider_id = "test_value_policy"
    supported_formats = ("zip",)

    def __init__(self, value):
        self.value = value
        self.requests = []

    def available(self):
        return True

    def estimate(self, request):
        self.requests.append(request)
        return {
            "reachable_recovery_value": self.value,
            "confidence": 0.9,
            "metadata": {"model_id": "test_value"},
        }


def _install_policy_package(monkeypatch, name: str, provider) -> None:
    module = types.ModuleType(name)
    module.get_damage_analysis_models = lambda: [provider] if callable(getattr(provider, "analyze", None)) else []
    module.get_graph_action_models = lambda: [provider] if callable(getattr(provider, "choose_graph_action", None)) else []
    module.get_graph_state_value_models = lambda: [provider] if callable(getattr(provider, "estimate", None)) else []
    monkeypatch.setitem(sys.modules, name, module)


def _candidate(module: str, path: Path, *, confidence: float) -> RepairCandidate:
    path.write_bytes(module.encode("utf-8"))
    return RepairCandidate(
        module_name=module,
        format="zip",
        repaired_input={"kind": "file", "path": str(path), "format_hint": "zip"},
        confidence=confidence,
        actions=[module],
        workspace_paths=[str(path)],
    )


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


def _patch_candidate_from_state(module: str, base: ArchiveState, replacement: bytes) -> RepairCandidate:
    patch = PatchPlan(
        module=module,
        format="zip",
        operations=[PatchOperation.append_bytes(replacement)],
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


def _job(tmp_path: Path) -> RepairJob:
    source = tmp_path / "source.zip"
    source.write_bytes(b"broken")
    knowledge = {
        "source": {"input": {"kind": "file", "path": str(source), "format_hint": "zip"}},
        "analysis": {"summary": {"format": "zip", "confidence": 0.5}},
        "extraction": {"failure": {"status": "failed"}},
        "verification": {"summary": {"decision_hint": "repair", "completeness": 0.0}},
        "repair": {"history": {"items": []}},
    }
    return RepairJob(
        source_input={"kind": "file", "path": str(source), "format_hint": "zip"},
        format="zip",
        archive_key="source",
        workspace=str(tmp_path / "repair"),
        extraction_failure={"status": "failed"},
        knowledge=knowledge,
    )


def _task(path: Path, *, fmt: str) -> ArchiveTask:
    path.write_bytes(b"broken")
    bag = FactBag()
    bag.set("analysis.selected_format", fmt)
    return ArchiveTask(
        fact_bag=bag,
        score=10,
        key=path.name,
        main_path=str(path),
        all_parts=[str(path)],
        logical_name=path.stem,
        detected_ext=fmt,
    ).ensure_archive_state()


def _write_source_derivation(task: ArchiveTask, **payload) -> None:
    knowledge = task.knowledge()
    knowledge.set("source.derivation", payload, source_layer="test", source_module="fixture")
    structure = payload.get("zip_structure_features")
    if isinstance(structure, dict):
        knowledge.set("format.zip.structure", structure, source_layer="test", source_module="fixture")
    tags = payload.get("zip_container_tags")
    if isinstance(tags, list):
        knowledge.set("format.zip.container_tags", tags, source_layer="test", source_module="fixture")
    if payload.get("damage_profile"):
        knowledge.set("source.profile", payload.get("damage_profile"), source_layer="test", source_module="fixture")
    task.set_knowledge(knowledge)


def _verification() -> VerificationResult:
    return VerificationResult(
        completeness=0.5,
        recoverable_upper_bound=1.0,
        assessment_status="partial",
        source_integrity="complete",
        decision_hint="repair",
        archive_coverage=ArchiveCoverageSummary(
            completeness=0.5,
            file_coverage=0.5,
            byte_coverage=0.5,
            expected_files=1,
            matched_files=0,
            complete_files=0,
            confidence=0.5,
        ),
    )


def _failed_extraction(task: ArchiveTask) -> ExtractionResult:
    return ExtractionResult(
        success=False,
        archive=task.main_path,
        out_dir="",
        all_parts=task.all_parts,
        error="archive is damaged",
        diagnostics={"result": {"status": "failed", "failure_stage": "extract", "failure_kind": "data_error"}},
    )


def _contains_forbidden_policy_key(value) -> bool:
    forbidden = ("oracle", "future_return", "terminal_reward")
    if isinstance(value, dict):
        for key, item in value.items():
            text = str(key).lower()
            if any(token in text for token in forbidden):
                return True
            if text in {"label", "reward"}:
                return True
            if _contains_forbidden_policy_key(item):
                return True
    elif isinstance(value, list):
        return any(_contains_forbidden_policy_key(item) for item in value)
    return False
