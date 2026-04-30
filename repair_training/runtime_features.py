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
    payload = candidate_feature_payload(candidate)
    prior_payload = _repair_prior_payload(repair_prior, payload)
    return {
        "feature_contract_version": FEATURE_CONTRACT_VERSION,
        "runtime_context": {
            "analysis_summary": _analysis_summary(job),
            "extraction_summary": _extraction_summary(job),
            "verification_summary": _verification_summary(job),
            "repair_hints": _repair_hints(job),
            "previous_actions": list(previous_actions or []),
            "previous_action_count": len(previous_actions or []),
            "previous_modules": list(previous_modules or []),
            "previous_module_count": len(previous_modules or []),
            "runtime_state_summary": _runtime_state_summary(runtime_state_summary or {}),
            "job_summary": _job_summary(job),
        },
        "candidate_proposal": _candidate_proposal(payload),
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


def _candidate_proposal(payload: dict[str, Any]) -> dict[str, Any]:
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
        )
        if key in payload
    }
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
    return output


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
