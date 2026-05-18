from __future__ import annotations

from dataclasses import replace
from typing import Any

from sunpack.repair.candidate import RepairCandidate, candidate_feature_payload, materialize_candidate
from sunpack.repair.job import RepairJob
from sunpack.repair.policy.formats.registry import ModuleMaterializationResult, PolicyModuleProposal
from sunpack.repair.policy.types import PolicyExplorationGraph


class ZipRepairFormatRuntimePlugin:
    format_name = "zip"

    def available_modules(
        self,
        *,
        scheduler: Any,
        job: RepairJob,
        diagnosis_hgt: dict[str, Any],
        graph: PolicyExplorationGraph,
    ) -> list[PolicyModuleProposal]:
        effective_job = replace(job, damage_flags=_root_cases_to_route_flags(diagnosis_hgt))
        batch = scheduler.generate_policy_repair_candidates(effective_job)
        proposals: list[PolicyModuleProposal] = []
        for index, candidate in enumerate(batch.candidates):
            if not _policy_candidate_available(candidate):
                continue
            payload = candidate_feature_payload(candidate)
            action_id = str(payload.get("candidate_id") or f"{candidate.module_name}:{index}")
            payload.update({
                "action_id": action_id,
                "candidate_id": action_id,
                "module_name": candidate.module_name,
                "module": candidate.module_name,
                "diagnosis_hgt": dict(diagnosis_hgt or {}),
            })
            proposals.append(PolicyModuleProposal(action_id=action_id, module_name=candidate.module_name, payload=payload, candidate=candidate))
        return proposals

    def build_module_job(
        self,
        *,
        job: RepairJob,
        module_name: str,
        graph: PolicyExplorationGraph,
    ) -> RepairJob:
        return job

    def materialize_module(
        self,
        *,
        scheduler: Any,
        proposal: PolicyModuleProposal,
        job: RepairJob,
    ) -> ModuleMaterializationResult:
        materialized = materialize_candidate(proposal.candidate) if proposal.candidate is not None else []
        patch_state_candidates = [candidate for candidate in materialized if candidate.repaired_state is not None]
        selected = _select_materialized_candidate(patch_state_candidates)
        if selected is not None:
            return ModuleMaterializationResult(candidate=selected)
        return ModuleMaterializationResult(
            candidate=None,
            failure={
                "failure_reason": "proposal_materialization_failed",
                "module_name": proposal.module_name,
                "materialized_candidate_count": len(materialized),
                "patch_state_candidate_count": 0,
                "materialization_errors": _materialization_errors(materialized),
            },
        )


def _root_cases_to_route_flags(diagnosis_hgt: dict[str, Any]) -> list[str]:
    root = diagnosis_hgt.get("root_case") if isinstance(diagnosis_hgt.get("root_case"), dict) else {}
    selected = [str(item) for item in root.get("selected") or [] if str(item)]
    if not selected and isinstance(root.get("ranked"), list):
        selected = [str(item.get("root_case")) for item in root["ranked"][:5] if isinstance(item, dict) and item.get("root_case")]
    return [f"field:{item}" for item in selected]


def _policy_candidate_available(candidate: RepairCandidate) -> bool:
    return str(candidate.action_type or "apply_patch") == "apply_patch"


def _select_materialized_candidate(candidates: list[RepairCandidate]) -> RepairCandidate | None:
    if not candidates:
        return None
    return max(candidates, key=lambda candidate: (float(candidate.score_hint or 0.0), float(candidate.confidence or 0.0), 0 if candidate.partial else 1))


def _materialization_errors(candidates: list[RepairCandidate]) -> list[str]:
    errors: list[str] = []
    for candidate in candidates:
        diagnosis = candidate.diagnosis if isinstance(candidate.diagnosis, dict) else {}
        error = str(diagnosis.get("materialization_error") or "")
        if error:
            errors.append(error)
        errors.extend(str(item) for item in candidate.warnings or [] if str(item))
    return sorted(set(errors))
