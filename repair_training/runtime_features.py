from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

from sunpack.repair import RepairJob
from sunpack.repair.candidate import candidate_feature_payload


FEATURE_CONTRACT_VERSION = 1


@dataclass(frozen=True)
class RepairPrior:
    route_score: float | None = None
    fine_score: float | None = None
    generation_priority: float | None = None
    current_selector_rank: int | None = None
    module_selected_by_router: bool | None = None
    proposal_breakdowns: dict[str, Any] = field(default_factory=dict)


def build_runtime_feature_record(
    *,
    job: RepairJob,
    candidate: Any,
    previous_actions: list[str] | None = None,
    previous_modules: list[str] | None = None,
    runtime_state_summary: dict[str, Any] | None = None,
    repair_prior: RepairPrior | dict[str, Any] | None = None,
) -> dict[str, Any]:
    payload = candidate_feature_payload(candidate) if candidate is not None else {}
    prior_payload = _repair_prior_payload(repair_prior, payload)
    failure = job.extraction_failure if isinstance(job.extraction_failure, dict) else {}
    path_actions = previous_actions if previous_actions is not None else failure.get("previous_actions")
    path_modules = previous_modules if previous_modules is not None else failure.get("previous_modules")
    runtime_state = _runtime_state_summary(runtime_state_summary or {})
    return {
        "feature_contract_version": FEATURE_CONTRACT_VERSION,
        "runtime_context": {
            "analysis_summary": _analysis_summary(job),
            "extraction_summary": _extraction_summary(job),
            "verification_summary": _verification_summary(job),
            "repair_hints": _repair_hints(job),
            "previous_actions": list(path_actions or []),
            "previous_action_count": len(path_actions or []),
            "previous_modules": list(path_modules or []),
            "previous_module_count": len(path_modules or []),
            "runtime_state_summary": runtime_state,
            "job_summary": _job_summary(job),
            "native_feedback": _native_feedback(candidate),
        },
        "candidate_proposal": _candidate_proposal(payload, job=job, runtime_state_summary=runtime_state),
        "repair_prior_features": prior_payload,
    }


def _analysis_summary(job: RepairJob) -> dict[str, Any]:
    evidence = getattr(job, "analysis_evidence", None)
    prepass = job.analysis_prepass if isinstance(job.analysis_prepass, dict) else {}
    fuzzy = job.fuzzy_profile if isinstance(job.fuzzy_profile, dict) else {}
    return {
        "format": str(job.format or ""),
        "confidence": _float(job.confidence),
        "evidence_format": str(getattr(evidence, "format", "") or getattr(evidence, "archive_type", "") or ""),
        "evidence_confidence": _float(getattr(evidence, "confidence", None)),
        "prepass_status": str(prepass.get("status") or ""),
        "prepass_format": str(prepass.get("format") or prepass.get("selected_format") or ""),
        "prepass_confidence": _float(prepass.get("confidence")),
        "fuzzy_status": str(fuzzy.get("status") or ""),
        "fuzzy_archive_type": str(fuzzy.get("archive_type") or fuzzy.get("format") or ""),
        "fuzzy_confidence": _float(fuzzy.get("confidence")),
    }


def _extraction_summary(job: RepairJob) -> dict[str, Any]:
    failure = job.extraction_failure if isinstance(job.extraction_failure, dict) else {}
    diagnostics = job.extraction_diagnostics if isinstance(job.extraction_diagnostics, dict) else {}
    worker = diagnostics.get("result") if isinstance(diagnostics.get("result"), dict) else {}
    return {
        "has_failure": bool(failure),
        "failure_stage": str(failure.get("failure_stage") or diagnostics.get("failure_stage") or worker.get("failure_stage") or ""),
        "failure_kind": str(failure.get("failure_kind") or diagnostics.get("failure_kind") or worker.get("failure_kind") or ""),
        "status": str(failure.get("status") or worker.get("status") or ""),
        "native_status": str(worker.get("native_status") or diagnostics.get("native_status") or ""),
        "files_written": _int(worker.get("files_written") if worker else diagnostics.get("files_written")),
        "bytes_written": _int(worker.get("bytes_written") if worker else diagnostics.get("bytes_written")),
        "error_kind_present": bool(failure.get("error") or diagnostics.get("error") or worker.get("message")),
    }


def _verification_summary(job: RepairJob) -> dict[str, Any]:
    failure = job.extraction_failure if isinstance(job.extraction_failure, dict) else {}
    coverage = failure.get("archive_coverage") if isinstance(failure.get("archive_coverage"), dict) else {}
    return {
        "decision_hint": str(failure.get("decision_hint") or ""),
        "assessment_status": str(failure.get("assessment_status") or ""),
        "source_integrity": str(failure.get("source_integrity") or ""),
        "completeness": _float(failure.get("completeness")),
        "recoverable_upper_bound": _float(failure.get("recoverable_upper_bound"), default=1.0),
        "complete_files": _int(failure.get("complete_files")),
        "partial_files": _int(failure.get("partial_files")),
        "failed_files": _int(failure.get("failed_files")),
        "missing_files": _int(failure.get("missing_files")),
        "unverified_files": _int(failure.get("unverified_files")),
        "archive_coverage": {
            "completeness": _float(coverage.get("completeness")),
            "expected_files": _int(coverage.get("expected_files")),
            "complete_files": _int(coverage.get("complete_files")),
            "partial_files": _int(coverage.get("partial_files")),
            "failed_files": _int(coverage.get("failed_files")),
            "missing_files": _int(coverage.get("missing_files")),
        },
    }


def _repair_hints(job: RepairJob) -> dict[str, Any]:
    failure = job.extraction_failure if isinstance(job.extraction_failure, dict) else {}
    hints = failure.get("repair_hints") if isinstance(failure.get("repair_hints"), dict) else {}
    return {
        "selected_format": str(hints.get("selected_format") or ""),
        "analysis_status": str(hints.get("analysis_status") or ""),
        "analysis_confidence": _float(hints.get("analysis_confidence")),
        "source_integrity": str(hints.get("source_integrity") or ""),
        "likely_truncated": bool(hints.get("likely_truncated", False)),
        "likely_payload_damage": bool(hints.get("likely_payload_damage", False)),
        "boundary_untrusted": bool(hints.get("boundary_untrusted", False)),
    }


def _runtime_state_summary(summary: dict[str, Any]) -> dict[str, Any]:
    return {
        "format_detected": bool(summary.get("format_detected")),
        "boundary_trusted": bool(summary.get("boundary_trusted")),
        "directory_detected": bool(summary.get("directory_detected")),
        "entry_count": _int(summary.get("entry_count")),
        "readable_entry_count": _int(summary.get("readable_entry_count")),
        "damage_flags": list(summary.get("damage_flags") or []),
        "runtime_status": str(summary.get("runtime_status") or ""),
        "runtime_score": _float(summary.get("runtime_score")),
    }


def _job_summary(job: RepairJob) -> dict[str, Any]:
    archive_state = job.archive_state
    source = job.source_input if isinstance(job.source_input, dict) else {}
    return {
        "format": str(job.format or ""),
        "confidence": _float(job.confidence),
        "damage_flags": list(job.damage_flags or []),
        "attempts": _int(job.attempts),
        "has_password": job.password is not None,
        "source_kind": str(source.get("kind") or source.get("open_mode") or ""),
        "source_format_hint": str(source.get("format_hint") or source.get("format") or ""),
        "has_archive_state": archive_state is not None,
    }


def _candidate_proposal(payload: dict[str, Any], *, job: RepairJob | None = None, runtime_state_summary: dict[str, Any] | None = None) -> dict[str, Any]:
    output = {
        key: payload.get(key)
        for key in (
            "module",
            "format",
            "stage",
            "confidence",
            "score_hint",
            "actions",
            "damage_flags",
            "patch_cost",
            "requires_native_validation",
            "has_archive_state_plan",
            "requires_materialization",
            "plan_kind",
            "estimated_cost",
            "input_kind",
            "partial",
            "lazy",
            "patch_span_count",
            "patch_operation_count",
            "affected_entry_count",
        )
        if key in payload
    }
    if str(output.get("plan_kind") or "") == "materialized":
        output.pop("plan_kind", None)
    for group, safe_names in _SAFE_BREAKDOWNS.items():
        breakdown = payload.get(group)
        if isinstance(breakdown, dict):
            safe = _safe_breakdown(breakdown, safe_names)
            if safe:
                output[group] = safe
    ltr = payload.get("ltr_features")
    if isinstance(ltr, dict):
        output["proposal_ltr"] = {
            key: ltr.get(key)
            for key in (
                "confidence",
                "score_hint",
                "patch_cost",
                "patch_quality",
                "partial",
                "lazy",
                "requires_native_validation",
                "requires_materialization",
                "plan_kind",
                "estimated_cost",
                "has_archive_state_plan",
                "damage_flag_count",
                "action_count",
                "history_available",
                "history_sample_count",
                "history_score",
            )
            if key in ltr
        }
        if str(output["proposal_ltr"].get("plan_kind") or "") == "materialized":
            output["proposal_ltr"].pop("plan_kind", None)
    output.update(_zip_plan_risk_features(payload, job=job, runtime_state_summary=runtime_state_summary or {}))
    return output


def _zip_plan_risk_features(payload: dict[str, Any], *, job: RepairJob | None, runtime_state_summary: dict[str, Any]) -> dict[str, Any]:
    module = str(payload.get("module") or "").lower()
    actions = [str(action).lower() for action in payload.get("actions") or []]
    text = " ".join([module, *actions])
    hints = _repair_hints(job) if job is not None else {}
    raw_damage_flags = payload.get("damage_flags") or (getattr(job, "damage_flags", None) if job is not None else None) or []
    damage_flags = {str(flag).lower() for flag in raw_damage_flags}
    context_flags = {str(flag).lower() for flag in runtime_state_summary.get("damage_flags") or []}
    all_flags = damage_flags | context_flags
    directory_detected = bool(runtime_state_summary.get("directory_detected"))
    entry_count = _int(runtime_state_summary.get("entry_count"))
    boundary_untrusted = bool(hints.get("boundary_untrusted")) or "boundary_unreliable" in all_flags or "trailing_junk" in all_flags
    likely_payload_damage = bool(hints.get("likely_payload_damage")) or "payload_damage" in all_flags or "crc_error" in all_flags or "checksum_error" in all_flags

    requires_existing_cd = any(token in text for token in ("comment_length", "central_directory_offset", "central_directory_count", "data_descriptor"))
    requires_valid_eocd = any(token in text for token in ("eocd", "comment_length", "central_directory_offset", "central_directory_count"))
    uses_data_descriptor = "data_descriptor" in text or "descriptor" in text
    touches_payload = any(token in text for token in ("payload", "partial", "deep", "quarantine", "descriptor"))
    directory_rewrite = any(token in text for token in ("central_directory", "directory", "eocd", "rebuild", "comment_length"))
    boundary_trim = any(token in text for token in ("trim", "trailing", "boundary"))

    expected_output_kind = "generic"
    if boundary_trim:
        expected_output_kind = "boundary_trim"
    elif "quarantine" in text:
        expected_output_kind = "partial_quarantine"
    elif "partial" in text or "deep" in text:
        expected_output_kind = "partial_deep"
    elif directory_rewrite:
        expected_output_kind = "directory_repair"
    elif uses_data_descriptor:
        expected_output_kind = "descriptor_recovery"

    directory_confidence = 0.0
    if directory_detected:
        directory_confidence += 0.55
    if entry_count > 0:
        directory_confidence += 0.25
    if requires_valid_eocd and boundary_untrusted:
        directory_confidence -= 0.25
    if "missing_directory" in all_flags or "central_directory_damaged" in all_flags:
        directory_confidence -= 0.20
    directory_confidence = _clamp01(directory_confidence)

    offset_confidence = 0.45
    if directory_detected:
        offset_confidence += 0.20
    if boundary_untrusted:
        offset_confidence -= 0.20
    if "offset" in text:
        offset_confidence -= 0.10
    offset_confidence = _clamp01(offset_confidence)

    risk = 0.0
    if requires_existing_cd and not directory_detected:
        risk += 0.28
    if requires_valid_eocd and boundary_untrusted:
        risk += 0.18
    if uses_data_descriptor and entry_count <= 0:
        risk += 0.20
    if touches_payload and likely_payload_damage:
        risk += 0.18
    if boundary_trim and not boundary_untrusted:
        risk += 0.12
    if "comment_length" in text:
        risk += 0.08
    no_output_risk_score = _clamp01(risk)

    return {
        "plan_requires_existing_cd": requires_existing_cd,
        "plan_requires_valid_eocd": requires_valid_eocd,
        "plan_uses_data_descriptor": uses_data_descriptor,
        "plan_touches_payload": touches_payload,
        "plan_expected_output_kind": expected_output_kind,
        "plan_directory_rewrite": directory_rewrite,
        "plan_boundary_trim": boundary_trim,
        "offset_confidence": offset_confidence,
        "directory_confidence": directory_confidence,
        "no_output_prone_candidate": no_output_risk_score >= 0.35,
        "no_output_risk_score": no_output_risk_score,
    }


def _native_feedback(candidate: Any) -> dict[str, Any]:
    """Extract native diagnostics from candidate's diagnosis dict.

    The Rust rewrite layer now returns a `diagnostics` dict inside native result
    sub-dicts (e.g. native_zip_deep_recovery.diagnostics, native_zip_directory_field_repair.diagnostics).
    """
    diagnosis = getattr(candidate, "diagnosis", None) if candidate is not None else None
    if not isinstance(diagnosis, dict):
        diagnosis = {}
    
    _NATIVE_KEYS = (
        "native_zip_deep_recovery",
        "native_zip_directory_field_repair",
        "native_zip_rebuild",
        "native_zip_conflict_resolver",
        "native_zip_verified_entry_salvage",
        "native_zip_cd_local_header_reconcile",
        "native_zip_salvage_deep",
        "native_zip_salvage_reconcile",
        "native_zip_salvage_quarantine",
        "native_zip_entry_quarantine",
        "native_zip_resolve_conflicts",
    )
    for key in _NATIVE_KEYS:
        native = diagnosis.get(key)
        if isinstance(native, dict):
            diag = native.get("diagnostics") or native.get("diagnostic")
            if isinstance(diag, dict):
                return dict(diag)
    return {}


def _repair_prior_payload(repair_prior: RepairPrior | dict[str, Any] | None, payload: dict[str, Any]) -> dict[str, Any]:
    if repair_prior is None:
        prior = RepairPrior()
    elif isinstance(repair_prior, RepairPrior):
        prior = repair_prior
    else:
        prior = RepairPrior(
            route_score=repair_prior.get("route_score"),
            fine_score=repair_prior.get("fine_score"),
            generation_priority=repair_prior.get("generation_priority"),
            current_selector_rank=repair_prior.get("current_selector_rank"),
            module_selected_by_router=repair_prior.get("module_selected_by_router"),
            proposal_breakdowns=dict(repair_prior.get("proposal_breakdowns") or {}),
        )
    return {
        "route_score": _optional_float(prior.route_score),
        "fine_score": _optional_float(prior.fine_score),
        "generation_priority": _optional_float(prior.generation_priority if prior.generation_priority is not None else payload.get("generation_priority")),
        "current_selector_rank": _optional_int(prior.current_selector_rank),
        "module_selected_by_router": prior.module_selected_by_router,
        "proposal_breakdowns": prior.proposal_breakdowns or {
            group: _safe_breakdown(payload.get(group) if isinstance(payload.get(group), dict) else {}, names)
            for group, names in _SAFE_BREAKDOWNS.items()
        },
    }


_SAFE_BREAKDOWNS = {
    "benefit_breakdown": {"confidence", "score_hint"},
    "evidence_breakdown": {"patch_quality"},
    "cost_breakdown": {"stage", "lazy_materialization", "native_validation", "patch_complexity"},
    "risk_breakdown": {
        "partial_candidate",
        "content_damage",
        "content_damage_without_native_validation",
        "deep_without_native_validation",
    },
}


def _safe_breakdown(breakdown: dict[str, Any], safe_names: set[str]) -> dict[str, dict[str, Any]]:
    output: dict[str, dict[str, Any]] = {}
    for key, value in breakdown.items():
        if key not in safe_names or not isinstance(value, dict):
            continue
        output[key] = {
            inner_key: inner_value
            for inner_key, inner_value in value.items()
            if inner_key in {"value", "weight", "contribution"}
        }
    return output


def _float(value: Any, *, default: float = 0.0) -> float:
    try:
        if value is None:
            return float(default)
        return float(value)
    except Exception:
        return float(default)


def _clamp01(value: float) -> float:
    return max(0.0, min(1.0, float(value or 0.0)))


def _optional_float(value: Any) -> float | None:
    if value is None:
        return None
    return _float(value)


def _int(value: Any) -> int:
    try:
        if value is None:
            return 0
        return int(value)
    except Exception:
        return 0


def _optional_int(value: Any) -> int | None:
    if value is None:
        return None
    return _int(value)
