from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

from sunpack.repair import RepairJob
from sunpack.repair.candidate import candidate_feature_payload
from sunpack.repair.policy.runtime_features import (
    FEATURE_CONTRACT_VERSION as PRODUCTION_FEATURE_CONTRACT_VERSION,
    candidate_proposal_from_payload as production_candidate_proposal_from_payload,
    policy_candidate_payload,
    runtime_context_from_job,
)


FEATURE_CONTRACT_VERSION = PRODUCTION_FEATURE_CONTRACT_VERSION


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
    runtime_payload = (
        policy_candidate_payload(job, candidate, index=_current_rank_from_prior(repair_prior))
        if candidate is not None
        else {
            "feature_contract_version": FEATURE_CONTRACT_VERSION,
            "runtime_context": runtime_context_from_job(job),
            "candidate_proposal": production_candidate_proposal_from_payload(payload, job=job),
        }
    )
    runtime_context = dict(runtime_payload.get("runtime_context") or {})
    if previous_actions is not None:
        runtime_context["previous_actions"] = list(previous_actions)
        runtime_context["previous_action_count"] = len(previous_actions)
    if previous_modules is not None:
        runtime_context["previous_modules"] = list(previous_modules)
        runtime_context["previous_module_count"] = len(previous_modules)
    if runtime_state_summary is not None:
        runtime_context["runtime_state_summary"] = _runtime_state_summary(runtime_state_summary)
    return {
        "feature_contract_version": FEATURE_CONTRACT_VERSION,
        "runtime_context": runtime_context,
        "candidate_proposal": dict(runtime_payload.get("candidate_proposal") or {}),
        "repair_prior_features": _repair_prior_payload(repair_prior, payload),
    }


def _current_rank_from_prior(repair_prior: RepairPrior | dict[str, Any] | None) -> int:
    if isinstance(repair_prior, RepairPrior):
        return _int(repair_prior.current_selector_rank)
    if isinstance(repair_prior, dict):
        return _int(repair_prior.get("current_selector_rank") or repair_prior.get("current_rank"))
    return 0


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
        "generation_priority": _optional_float(
            prior.generation_priority if prior.generation_priority is not None else payload.get("generation_priority")
        ),
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
    "cost_breakdown": {"lazy_materialization", "native_validation", "patch_complexity"},
    "risk_breakdown": {
        "partial_candidate",
        "content_damage",
        "content_damage_without_native_validation",
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
