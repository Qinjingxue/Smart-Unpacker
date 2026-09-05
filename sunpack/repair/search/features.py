from __future__ import annotations

from typing import Any

from sunpack.contracts.archive_knowledge import ArchiveKnowledge
from sunpack.contracts.archive_state import ArchiveState
from sunpack.repair.job import RepairJob
from sunpack.repair.search.recovery import RecoveryEvaluator
from sunpack.support import archive_knowledge_projection as knowledge_view


POLICY_TRAINING_RUNTIME_SCHEMA_VERSION = 1
DAMAGE_ANALYSIS_FEATURE_SCHEMA_VERSION = 1


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
    analysis_summary = _dict_at(knowledge, "inspection.summary") or _dict_at(knowledge, "inspection")
    prepass = _dict_at(knowledge, "inspection.prepass")
    fuzzy = _dict_at(knowledge, "inspection.fuzzy")
    failure = _dict_at(knowledge, "extraction.failure")
    diagnostics = _dict_at(knowledge, "extraction.diagnostics")
    entry_outcomes = _dict_at(knowledge, "extraction.entry_outcomes")
    verification = _dict_at(knowledge, "verification.summary")
    coverage_breakdown = _dict_at(knowledge, "verification.coverage_breakdown") or _dict_at(knowledge, "verification.summary.coverage_breakdown")
    source = _dict_at(knowledge, "source.input")
    coverage = failure.get("archive_coverage") if isinstance(failure.get("archive_coverage"), dict) else _dict_at(knowledge, "verification.summary.archive_coverage")
    route_evidence_flags = [str(flag) for flag in route_context.get("route_evidence_flags") or [] if str(flag)]
    damage_flags = [str(flag) for flag in route_context.get("damage_flags") or getattr(job, "damage_flags", []) if str(flag)]
    return {
        "schema_version": POLICY_TRAINING_RUNTIME_SCHEMA_VERSION,
        "damage_analysis_feature_schema_version": DAMAGE_ANALYSIS_FEATURE_SCHEMA_VERSION,
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
            "failure_stage": str(failure.get("failure_stage") or diagnostics.get("failure_stage") or ""),
            "failure_kind": str(failure.get("failure_kind") or diagnostics.get("failure_kind") or ""),
            "status": str(failure.get("status") or diagnostics.get("status") or ""),
            "native_status": str(diagnostics.get("native_status") or ""),
            "entry_outcomes": entry_outcomes,
        },
        "verification_summary": {
            "decision_hint": str(failure.get("decision_hint") or verification.get("decision_hint") or ""),
            "assessment_status": str(failure.get("assessment_status") or verification.get("assessment_status") or ""),
            "content_integrity": str(failure.get("content_integrity") or verification.get("content_integrity") or ""),
            "container_integrity": str(failure.get("container_integrity") or verification.get("container_integrity") or ""),
            "completeness": _float(failure.get("completeness", verification.get("completeness"))),
            "recoverable_upper_bound": _float(failure.get("recoverable_upper_bound", verification.get("recoverable_upper_bound")), default=1.0),
            "archive_coverage": {
                "completeness": _float(coverage.get("completeness")),
                "file_coverage": _float(coverage.get("file_coverage")),
                "byte_coverage": _float(coverage.get("byte_coverage")),
                "expected_files": _int(coverage.get("expected_files")),
                "matched_files": _int(coverage.get("matched_files")),
            },
            "coverage_breakdown": coverage_breakdown,
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
) -> dict[str, Any]:
    knowledge_payload = ArchiveKnowledge.from_any(getattr(job, "knowledge", {})).to_dict()
    return knowledge_payload


def recovery_score_from_job(job: RepairJob) -> float:
    return float(RecoveryEvaluator().evaluate_state(job, archive_state_for_job(job), mode="policy_light").score or 0.0)


def request_to_dict(request: dict[str, Any]) -> dict[str, Any]:
    if isinstance(request, dict):
        return ArchiveKnowledge.from_any(request).to_dict()
    raise TypeError(f"unsupported request type: {type(request).__name__}")


def _analysis_native_probe(job: RepairJob, knowledge: ArchiveKnowledge, route_evidence_flags: list[str]) -> dict[str, Any]:
    route_context = knowledge_view.repair_route_context(knowledge)
    zip_facts = knowledge_view.zip_runtime_facts(knowledge)
    source = _dict_at(knowledge, "source.input")
    analysis_summary = _dict_at(knowledge, "inspection.summary") or _dict_at(knowledge, "inspection")
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
    if structure:
        enriched = dict(structure)
        extraction_outcomes = _dict_at(knowledge, "extraction.entry_outcomes")
        coverage_breakdown = _dict_at(knowledge, "verification.coverage_breakdown") or _dict_at(knowledge, "verification.summary.coverage_breakdown")
        runtime = dict(enriched.get("runtime") or {}) if isinstance(enriched.get("runtime"), dict) else {}
        if extraction_outcomes:
            runtime["extraction_entry_outcomes"] = extraction_outcomes
        if coverage_breakdown:
            runtime["verification_coverage_breakdown"] = coverage_breakdown
        if runtime:
            enriched["runtime"] = runtime
        probe["raw_structure"] = dict(enriched)
        probe["structure"] = dict(enriched)
    for key, value in structure.items():
        probe[str(key)] = _safe_feature_value(value)
    for tag in zip_facts.get("container_tags") or []:
        if str(tag):
            probe[f"zip_container_tag_{tag}"] = 1
    for flag in route_evidence_flags:
        if str(flag):
            probe[f"route_evidence_{flag}"] = 1
    return probe


def _missing_runtime_paths(knowledge: ArchiveKnowledge) -> list[str]:
    required = ("source.input", "inspection.summary", "extraction.failure", "verification.summary")
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
