from __future__ import annotations

from typing import Any

from sunpack.repair.candidate import CandidateValidation, RepairCandidate
from sunpack.repair.job import RepairJob


ACCEPT_CURRENT_STATE_MODULE = "repair_accept_current_state"
ACCEPT_CURRENT_STATE_REPAIR_NAME = "accept_current_state"


def accept_current_state_candidate(job: RepairJob) -> RepairCandidate:
    """Return a control candidate that accepts the current archive state as-is."""
    repaired_input = _current_source_input(job)
    diagnosis: dict[str, Any] = {
        "repair_name": ACCEPT_CURRENT_STATE_REPAIR_NAME,
        "native_key": ACCEPT_CURRENT_STATE_REPAIR_NAME,
        "native_target": ACCEPT_CURRENT_STATE_REPAIR_NAME,
        "candidate_status": ACCEPT_CURRENT_STATE_REPAIR_NAME,
        "atomic_action_group": "control",
        "route_family": "policy_control",
        "patch_facts": ["accept_current_state", "noop"],
        "residual_facts": _residual_facts(job),
        "validation_details": {
            "policy": ACCEPT_CURRENT_STATE_REPAIR_NAME,
            "accepted": True,
            "native_target": ACCEPT_CURRENT_STATE_REPAIR_NAME,
        },
        "control_action": True,
        "noop": True,
    }
    plan: dict[str, Any] = {
        "kind": "control",
        "control_action": ACCEPT_CURRENT_STATE_REPAIR_NAME,
        "source_input": dict(repaired_input),
    }
    if job.archive_state is not None:
        plan["archive_state"] = job.archive_state.to_dict()
        diagnosis["patch_facts"].append("accept_archive_state")

    return RepairCandidate(
        module_name=ACCEPT_CURRENT_STATE_MODULE,
        format=str(job.format or repaired_input.get("format_hint") or repaired_input.get("format") or ""),
        repaired_input=repaired_input,
        status="skipped",
        confidence=1.0,
        partial=False,
        requires_native_validation=False,
        actions=[ACCEPT_CURRENT_STATE_REPAIR_NAME],
        damage_flags=list(job.damage_flags or []),
        diagnosis=diagnosis,
        message="accept current archive state without applying another repair",
        validations=[
            CandidateValidation(
                name=ACCEPT_CURRENT_STATE_REPAIR_NAME,
                accepted=True,
                score=1.0,
                details={"control_action": True, "noop": True},
            )
        ],
        score_hint=1.0,
        materialized=True,
        plan=plan,
    )


def with_accept_current_state_candidate(candidates: list[RepairCandidate], job: RepairJob) -> list[RepairCandidate]:
    return [accept_current_state_candidate(job), *list(candidates or [])]


def is_accept_current_state_candidate(candidate: RepairCandidate) -> bool:
    diagnosis = candidate.diagnosis if isinstance(candidate.diagnosis, dict) else {}
    return bool(
        candidate.module_name == ACCEPT_CURRENT_STATE_MODULE
        or diagnosis.get("noop")
        or diagnosis.get("control_action") == ACCEPT_CURRENT_STATE_REPAIR_NAME
    )


def _current_source_input(job: RepairJob) -> dict[str, Any]:
    try:
        payload = job.archive_input().to_source_input()
    except Exception:
        payload = dict(job.source_input or {})
    if not isinstance(payload, dict):
        payload = dict(job.source_input or {})
    output = dict(payload)
    if job.format and not output.get("format_hint"):
        output["format_hint"] = job.format
    if job.password is not None and "password" not in output:
        output["password"] = job.password
    return output


def _residual_facts(job: RepairJob) -> list[str]:
    knowledge = job.knowledge if isinstance(job.knowledge, dict) else {}
    verification = knowledge.get("verification") if isinstance(knowledge.get("verification"), dict) else {}
    residual = verification.get("residual") if isinstance(verification.get("residual"), dict) else {}
    flags = residual.get("flags") if isinstance(residual.get("flags"), list) else []
    return [str(item) for item in flags if str(item)]
