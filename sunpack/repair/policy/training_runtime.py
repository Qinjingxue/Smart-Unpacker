from __future__ import annotations

from typing import Any

from sunpack.contracts.archive_knowledge import ArchiveKnowledge
from sunpack.contracts.archive_state import ArchiveState
from sunpack.repair.candidate import (
    CandidateSelector,
    RepairCandidate,
    candidate_feature_payload,
    materialize_candidates,
)
from sunpack.repair.job import RepairJob
from sunpack.repair.policy.types import DamageAnalysisRequest, RepairActionRequest
from sunpack.repair.policy.recovery_evaluator import RecoveryEvaluator
from sunpack.support import archive_knowledge_projection as knowledge_view


POLICY_TRAINING_RUNTIME_SCHEMA_VERSION = 1
DAMAGE_ANALYSIS_FEATURE_SCHEMA_VERSION = 1
REPAIR_ACTION_FEATURE_SCHEMA_VERSION = 1


def archive_state_for_job(job: RepairJob) -> ArchiveState | None:
    if job.archive_state is not None:
        return job.archive_state
    try:
        return ArchiveState.from_archive_input(job.archive_input())
    except Exception:
        return None


def state_source_input(state: ArchiveState | None, job: RepairJob) -> dict[str, Any]:
    if state is None:
        return dict(job.source_input or {})
    payload: dict[str, Any] = {
        "kind": "archive_state",
        "patch_digest": state.effective_patch_digest(),
        "format_hint": state.format_hint or job.format,
    }
    if job.password is not None:
        payload["password"] = job.password
    return payload


def runtime_context_from_job(job: RepairJob) -> dict[str, Any]:
    knowledge = ArchiveKnowledge.from_any(getattr(job, "knowledge", {}))
    route_context = knowledge_view.repair_route_context(knowledge)
    history = knowledge_view.repair_history_summary(knowledge)
    authentication = knowledge_view.archive_authentication(knowledge)
    analysis_summary = _dict_at(knowledge, "analysis.summary") or _dict_at(knowledge, "analysis")
    prepass = _dict_at(knowledge, "analysis.prepass")
    fuzzy = _dict_at(knowledge, "analysis.fuzzy")
    failure = _dict_at(knowledge, "extraction.failure")
    diagnostics = _dict_at(knowledge, "extraction.diagnostics")
    verification = _dict_at(knowledge, "verification.summary")
    source = _dict_at(knowledge, "source.input")
    coverage = failure.get("archive_coverage") if isinstance(failure.get("archive_coverage"), dict) else _dict_at(knowledge, "verification.summary.archive_coverage")
    output_quality = verification.get("output_quality") if isinstance(verification.get("output_quality"), dict) else {}
    route_evidence_flags = [str(flag) for flag in route_context.get("route_evidence_flags") or [] if str(flag)]
    damage_flags = [str(flag) for flag in route_context.get("damage_flags") or getattr(job, "damage_flags", []) if str(flag)]
    return {
        "schema_version": POLICY_TRAINING_RUNTIME_SCHEMA_VERSION,
        "damage_analysis_feature_schema_version": DAMAGE_ANALYSIS_FEATURE_SCHEMA_VERSION,
        "repair_action_feature_schema_version": REPAIR_ACTION_FEATURE_SCHEMA_VERSION,
        "knowledge_projection": {
            "source_count": 1 if knowledge.to_dict() else 0,
            "has_archive_knowledge": bool(knowledge.to_dict()),
            "missing_paths": _missing_runtime_paths(knowledge),
            "source_fingerprint": knowledge_view.source_fingerprint(knowledge),
        },
        "analysis_summary": {
            "format": str(analysis_summary.get("format") or analysis_summary.get("selected_format") or job.format or ""),
            "confidence": _float(analysis_summary.get("confidence")),
            "prepass_status": str(prepass.get("status") or ""),
            "prepass_format": str(prepass.get("format") or prepass.get("selected_format") or ""),
            "prepass_confidence": _float(prepass.get("confidence")),
            "fuzzy_status": str(fuzzy.get("status") or ""),
            "fuzzy_archive_type": str(fuzzy.get("archive_type") or fuzzy.get("format") or ""),
            "fuzzy_confidence": _float(fuzzy.get("confidence")),
        },
        "analysis_native_probe": _analysis_native_probe(job, knowledge, route_evidence_flags),
        "archive_authentication": {
            "password_present": bool(authentication.get("password_present")),
            "password_required": bool(authentication.get("password_required")),
            "password_rejected": bool(authentication.get("password_rejected")),
            "encrypted_payload_present": bool(authentication.get("encrypted_payload_present")),
            "encrypted_header_present": bool(authentication.get("encrypted_header_present")),
            "authentication_blocking": bool(authentication.get("authentication_blocking")),
        },
        "extraction_summary": {
            "has_failure": bool(failure),
            "failure_stage": str(failure.get("failure_stage") or diagnostics.get("failure_stage") or ""),
            "failure_kind": str(failure.get("failure_kind") or diagnostics.get("failure_kind") or ""),
            "status": str(failure.get("status") or diagnostics.get("status") or ""),
            "native_status": str(diagnostics.get("native_status") or ""),
            "error_kind_present": bool(failure.get("error") or diagnostics.get("error")),
        },
        "verification_summary": {
            "decision_hint": str(failure.get("decision_hint") or verification.get("decision_hint") or ""),
            "assessment_status": str(failure.get("assessment_status") or verification.get("assessment_status") or ""),
            "source_integrity": str(failure.get("source_integrity") or verification.get("source_integrity") or ""),
            "completeness": _float(failure.get("completeness", verification.get("completeness"))),
            "recoverable_upper_bound": _float(failure.get("recoverable_upper_bound", verification.get("recoverable_upper_bound")), default=1.0),
            "output_quality_score": _float(failure.get("output_quality_score", verification.get("output_quality_score", output_quality.get("score")))),
            "output_complete_ratio": _float(failure.get("output_complete_ratio", verification.get("output_complete_ratio", output_quality.get("complete_ratio")))),
            "output_failed_ratio": _float(failure.get("output_failed_ratio", verification.get("output_failed_ratio", output_quality.get("failed_ratio")))),
            "output_file_count": _int(failure.get("output_file_count", verification.get("output_file_count", output_quality.get("file_count")))),
            "output_total_bytes": _int(failure.get("output_total_bytes", verification.get("output_total_bytes", output_quality.get("total_bytes")))),
            "complete_files": _int(failure.get("complete_files", verification.get("complete_files"))),
            "partial_files": _int(failure.get("partial_files", verification.get("partial_files"))),
            "failed_files": _int(failure.get("failed_files", verification.get("failed_files"))),
            "missing_files": _int(failure.get("missing_files", verification.get("missing_files"))),
            "archive_coverage": {
                "completeness": _float(coverage.get("completeness")),
                "file_coverage": _float(coverage.get("file_coverage")),
                "byte_coverage": _float(coverage.get("byte_coverage")),
                "expected_files": _int(coverage.get("expected_files")),
                "matched_files": _int(coverage.get("matched_files")),
            },
        },
        "previous_actions": _list_values(history, "previous_actions") or _list_values(history, "path_actions"),
        "previous_modules": _list_values(history, "previous_modules") or _list_values(history, "path_modules"),
        "job_summary": {
            "format": str(analysis_summary.get("format") or job.format or ""),
            "confidence": _float(analysis_summary.get("confidence"), default=float(job.confidence or 0.0)),
            "damage_flags": damage_flags,
            "damage_flag_count": len(damage_flags),
            "route_evidence_flags": route_evidence_flags,
            "route_evidence_flag_count": len(route_evidence_flags),
            "repair_history_flags": list(history.get("repair_history_flags") or []),
            "residual_damage_flags": list(route_context.get("residual_damage_flags") or history.get("residual_damage_flags") or []),
            "attempts": _int(job.attempts),
            "has_password": job.password is not None,
            "source_kind": str(source.get("kind") or source.get("open_mode") or ""),
            "source_format_hint": str(source.get("format_hint") or source.get("format") or ""),
            "has_archive_state": bool(archive_state_for_job(job)),
            "archive_state_patch_count": archive_state_for_job(job).patch_depth() if archive_state_for_job(job) is not None else 0,
        },
    }


def build_damage_analysis_request(
    job: RepairJob,
    state: ArchiveState | None,
    *,
    diagnosis: dict[str, Any] | None = None,
    round_index: int = 0,
) -> DamageAnalysisRequest:
    runtime_context = runtime_context_from_job(job)
    if state is not None:
        runtime_context["archive_state"] = _state_summary(state)
    return DamageAnalysisRequest(
        job=job,
        format=_normalize_format(job.format),
        archive_state=state,
        runtime_context=runtime_context,
        diagnosis=dict(diagnosis or {}),
        knowledge_projection=dict(getattr(job, "knowledge", {}) or {}),
        repair_history=dict(getattr(job, "repair_history", {}) or {}),
        config={},
        round_index=int(round_index or 0),
    )


def build_repair_action_request(
    job: RepairJob,
    state: ArchiveState | None,
    candidates: list[RepairCandidate],
    damage_analysis: dict[str, Any],
    *,
    diagnosis: dict[str, Any] | None = None,
    current_recovery: dict[str, Any] | None = None,
    best_seen_recovery: dict[str, Any] | None = None,
    parent_recovery: dict[str, Any] | None = None,
    round_index: int = 0,
) -> RepairActionRequest:
    return RepairActionRequest(
        job=job,
        format=_normalize_format(job.format),
        archive_state=state,
        candidates=list(candidates),
        candidate_payloads=candidate_snapshots(candidates, damage_analysis=damage_analysis),
        damage_analysis=dict(damage_analysis or {}),
        current_recovery=dict(current_recovery or {}),
        best_seen_recovery=dict(best_seen_recovery or {}),
        parent_recovery=dict(parent_recovery or {}),
        diagnosis=dict(diagnosis or {}),
        repair_history=dict(getattr(job, "repair_history", {}) or {}),
        config={},
        round_index=int(round_index or 0),
    )


def candidate_snapshot(
    candidate: RepairCandidate,
    *,
    index: int = 0,
    damage_analysis: dict[str, Any] | None = None,
    current_recovery: dict[str, Any] | None = None,
    recovery_snapshot: dict[str, Any] | None = None,
) -> dict[str, Any]:
    payload = candidate_feature_payload(candidate)
    state = candidate.repaired_state
    patch_plan = candidate.patch_plan
    validations = [
        {
            "name": validation.name,
            "accepted": bool(validation.accepted),
            "score": float(validation.score or 0.0),
            "warning_count": len(validation.warnings),
            "details": dict(validation.details or {}),
        }
        for validation in candidate.validations
    ]
    snapshot = {
        "schema_version": REPAIR_ACTION_FEATURE_SCHEMA_VERSION,
        "candidate_id": payload.get("candidate_id"),
        "module_name": payload.get("module_name") or payload.get("module") or candidate.module_name,
        "module": payload.get("module") or candidate.module_name,
        "format": candidate.format,
        "action_type": candidate.action_type or payload.get("action_type") or "apply_patch",
        "current_rank": int(index or 0),
        "patch_depth": state.patch_depth() if state is not None else 0,
        "patch_count": state.patch_depth() if state is not None else 0,
        "patch_operation_count": _patch_operation_count(patch_plan),
        "last_patch_module": _last_patch_module(state),
        "patch_digest": state.effective_patch_digest() if state is not None else "",
        "confidence": float(candidate.confidence or 0.0),
        "score_hint": float(candidate.score_hint or 0.0),
        "status": candidate.status,
        "partial": bool(candidate.partial),
        "lazy": bool(candidate.is_lazy),
        "materialized": bool(candidate.materialized),
        "requires_native_validation": bool(candidate.requires_native_validation),
        "control_action": bool(payload.get("control_action")),
        "noop": bool(payload.get("noop")),
        "validation_summary": {
            "count": len(validations),
            "accepted": all(item["accepted"] for item in validations),
            "score": max([float(item["score"]) for item in validations], default=0.0),
            "items": validations,
        },
        "has_archive_state_plan": state is not None,
        "branchable": _candidate_branchable(payload),
    }
    if damage_analysis is not None:
        snapshot["damage_analysis"] = dict(damage_analysis or {})
    if recovery_snapshot is not None:
        recovery = dict(recovery_snapshot or {})
        current = dict(current_recovery or {})
        snapshot["recovery_snapshot"] = recovery
        snapshot["recovery_score"] = float(recovery.get("score") or 0.0)
        snapshot["recovery_status"] = str(recovery.get("status") or "")
        snapshot["verification_summary"] = dict(recovery.get("verification") or {})
        snapshot["score_source"] = str((recovery.get("metadata") or {}).get("score_source") or "")
        snapshot["recovery_delta"] = float(recovery.get("score") or 0.0) - float(current.get("score") or 0.0)
    return snapshot


def candidate_snapshots(
    candidates: list[RepairCandidate],
    *,
    damage_analysis: dict[str, Any] | None = None,
) -> list[dict[str, Any]]:
    return [
        candidate_snapshot(candidate, index=index, damage_analysis=damage_analysis)
        for index, candidate in enumerate(candidates)
    ]


def validate_policy_candidates(config: dict[str, Any] | None, candidates: list[RepairCandidate]) -> list[RepairCandidate]:
    selector = CandidateSelector(config or {})
    materialized = materialize_candidates(candidates)
    return [selector._with_native_validation(candidate) for candidate in materialized]


def recovery_score_from_job(job: RepairJob) -> float:
    return float(RecoveryEvaluator().evaluate_state(job, archive_state_for_job(job), mode="policy_light").score or 0.0)


def request_to_dict(request: DamageAnalysisRequest | RepairActionRequest) -> dict[str, Any]:
    state = request.archive_state
    payload: dict[str, Any] = {
        "format": request.format,
        "archive_state": state.to_dict() if state is not None else None,
        "runtime_context": dict(getattr(request, "runtime_context", {}) or {}),
        "diagnosis": dict(getattr(request, "diagnosis", {}) or {}),
        "knowledge_projection": dict(getattr(request, "knowledge_projection", {}) or {}),
        "repair_history": dict(getattr(request, "repair_history", {}) or {}),
        "config": dict(getattr(request, "config", {}) or {}),
        "round_index": int(getattr(request, "round_index", 0) or 0),
    }
    payload["job"] = {
        "format": request.job.format,
        "confidence": request.job.confidence,
        "archive_key": request.job.archive_key,
        "attempts": request.job.attempts,
        "source_input": dict(request.job.source_input or {}),
        "damage_flags": list(request.job.damage_flags),
    }
    if isinstance(request, RepairActionRequest):
        payload.update({
            "candidate_payloads": [dict(item) for item in request.candidate_payloads],
            "damage_analysis": dict(request.damage_analysis or {}),
            "current_recovery": dict(request.current_recovery or {}),
            "best_seen_recovery": dict(request.best_seen_recovery or {}),
            "parent_recovery": dict(request.parent_recovery or {}),
        })
        payload["candidates"] = [candidate_snapshot(candidate, index=index) for index, candidate in enumerate(request.candidates)]
    return payload


def _analysis_native_probe(job: RepairJob, knowledge: ArchiveKnowledge, route_evidence_flags: list[str]) -> dict[str, Any]:
    route_context = knowledge_view.repair_route_context(knowledge)
    zip_facts = knowledge_view.zip_runtime_facts(knowledge)
    source = _dict_at(knowledge, "source.input")
    analysis_summary = _dict_at(knowledge, "analysis.summary") or _dict_at(knowledge, "analysis")
    probe: dict[str, Any] = {
        "format": str(analysis_summary.get("format") or analysis_summary.get("selected_format") or job.format or ""),
        "confidence": _float(analysis_summary.get("confidence"), default=float(job.confidence or 0.0)),
        "damage_flags": list(route_context.get("damage_flags") or []),
        "damage_flag_count": len(route_context.get("damage_flags") or []),
        "attempts": _int(job.attempts),
        "has_password": job.password is not None,
        "source_kind": str(source.get("kind") or source.get("open_mode") or ""),
        "source_format_hint": str(source.get("format_hint") or source.get("format") or ""),
        "has_archive_state": bool(archive_state_for_job(job)),
    }
    structure = zip_facts.get("structure") if isinstance(zip_facts.get("structure"), dict) else {}
    for key, value in structure.items():
        probe[str(key)] = _safe_feature_value(value)
    for tag in zip_facts.get("container_tags") or []:
        if str(tag):
            probe[f"zip_container_tag_{tag}"] = 1
    for flag in route_evidence_flags:
        if str(flag):
            probe[f"route_evidence_{flag}"] = 1
    return probe


def _state_summary(state: ArchiveState) -> dict[str, Any]:
    return {
        "schema_version": getattr(state, "schema_version", 0),
        "format": state.format_hint,
        "patch_depth": state.patch_depth(),
        "patch_digest": state.effective_patch_digest(),
        "state": state.to_dict(),
    }


def _patch_operation_count(patch_plan: Any) -> int:
    if patch_plan is None:
        return 0
    operations = getattr(patch_plan, "operations", None)
    return len(operations) if isinstance(operations, list) else 0


def _last_patch_module(state: ArchiveState | None) -> str:
    if state is None:
        return ""
    patch = state.last_patch()
    if patch is None:
        return ""
    if patch.module:
        return str(patch.module)
    provenance = patch.provenance if isinstance(patch.provenance, dict) else {}
    return str(provenance.get("module") or "")


def _candidate_branchable(payload: dict[str, Any]) -> bool:
    if payload.get("noop") or payload.get("control_action"):
        return False
    if payload.get("has_archive_state_plan"):
        return True
    if payload.get("materialized") is False and payload.get("lazy"):
        return False
    return True


def _missing_runtime_paths(knowledge: ArchiveKnowledge) -> list[str]:
    required = ("source.input", "analysis.summary", "extraction.failure", "verification.summary")
    missing = [path for path in required if knowledge.get(path) in (None, "", [], {})]
    sentinel = object()
    if knowledge.get("repair.history", sentinel) is sentinel:
        missing.append("repair.history")
    return missing


def _dict_at(knowledge: ArchiveKnowledge, path: str) -> dict[str, Any]:
    value = knowledge.get(path)
    return dict(value) if isinstance(value, dict) else {}


def _list_values(payload: dict[str, Any], key: str) -> list[str]:
    raw = payload.get(key)
    if isinstance(raw, (list, tuple, set)):
        return [str(item) for item in raw if str(item)]
    if isinstance(raw, str) and raw:
        return [raw]
    return []


def _safe_feature_value(value: Any) -> Any:
    if isinstance(value, bool | int | float | str):
        return value
    if value is None:
        return None
    return str(value)


def _normalize_format(value: Any) -> str:
    text = str(value or "").lower().lstrip(".")
    return {"gz": "gzip", "bz2": "bzip2", "seven_zip": "7z"}.get(text, text)


def _int(value: Any) -> int:
    try:
        if value is None:
            return 0
        return int(value)
    except Exception:
        return 0


def _float(value: Any, *, default: float = 0.0) -> float:
    try:
        if value is None:
            return default
        return float(value)
    except Exception:
        return default
