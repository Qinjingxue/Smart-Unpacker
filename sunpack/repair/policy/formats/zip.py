from __future__ import annotations

from dataclasses import replace
from typing import Any

from sunpack.repair.candidate import CandidateValidation, RepairCandidate, materialize_candidate
from sunpack.repair.config import enabled_module_configs
from sunpack.repair.diagnosis import RepairDiagnosis
from sunpack.repair.job import RepairJob
from sunpack.repair.pipeline.modules._common import repair_operation_cache_key
from sunpack.repair.pipeline.registry import get_repair_module_registry
from sunpack.repair.policy.formats.registry import ModuleMaterializationResult, PolicyModuleProposal
from sunpack.repair.policy.types import PolicyExplorationGraph
from sunpack.repair.result import RepairResult


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
        effective_job = job
        if effective_job.repair_cache is None:
            effective_job = replace(effective_job, repair_cache=scheduler.repair_cache)
        diagnosis = _policy_zip_diagnosis(effective_job)
        workspace = scheduler._workspace_for(effective_job)
        workspace.mkdir(parents=True, exist_ok=True)
        module_configs = enabled_module_configs(scheduler.config)
        proposals: list[PolicyModuleProposal] = []
        for index, module in enumerate(_zip_policy_modules(scheduler, effective_job, module_configs)):
            module_config = scheduler._module_runtime_config(module.spec.name, module_configs)
            candidate = _lazy_zip_policy_candidate(
                module=module,
                job=effective_job,
                diagnosis=diagnosis,
                workspace=str(workspace),
                module_config=module_config,
            )
            if not _policy_candidate_available(candidate):
                continue
            action_id = f"{candidate.module_name}:{index}"
            payload = {}
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


def _zip_policy_modules(scheduler: Any, job: RepairJob, module_configs: dict[str, dict[str, Any]]) -> list[Any]:
    modules = []
    for module in get_repair_module_registry().all().values():
        spec = module.spec
        formats = {_normalize_format(item) for item in spec.formats}
        if "zip" not in formats and "archive" not in formats:
            continue
        if module_configs and spec.name not in module_configs:
            continue
        module_config = scheduler._module_runtime_config(spec.name, module_configs)
        if scheduler._safety_reasons(module, module_config):
            continue
        if not scheduler._module_input_allowed(job, module_config):
            continue
        modules.append(module)
    return sorted(modules, key=lambda module: module.spec.name)


def _policy_zip_diagnosis(job: RepairJob) -> RepairDiagnosis:
    return RepairDiagnosis(
        format="zip",
        categories=["policy_graph"],
        severity="unknown",
        confidence=float(job.confidence or 0.0),
        repairable=True,
        notes=["policy_zip_format_module_proposal"],
    )


def _lazy_zip_policy_candidate(
    *,
    module: Any,
    job: RepairJob,
    diagnosis: RepairDiagnosis,
    workspace: str,
    module_config: dict[str, Any],
) -> RepairCandidate:
    module_name = module.spec.name
    route_family = str(getattr(module.spec, "route_family", "") or "")
    atomic_action_group = route_family or module_name

    def materialize():
        def compute():
            if hasattr(module, "generate_candidates"):
                return _with_job_password_candidates(list(module.generate_candidates(  # type: ignore[attr-defined]
                    job,
                    diagnosis,
                    workspace,
                    {**module_config, "virtual_patch_candidate": True},
                ) or []), job)
            result = module.repair(job, diagnosis, workspace, {**module_config, "virtual_patch_candidate": True})
            if result.ok:
                return RepairCandidate.from_result(
                    _with_job_password_result(result, job),
                    score_hint=0.0,
                    stage=module.spec.stage,
                )
            return None

        cache = getattr(job, "repair_cache", None)
        if cache is None:
            return compute()
        return cache.get_or_compute(
            "materialize_candidate",
            repair_operation_cache_key(
                job,
                module_name,
                {
                    "module_config": module_config,
                    "virtual_patch_candidate": True,
                    "materialization_semantics": "graph_patch_state_v2",
                    "policy_proposal_source": "zip_format_module_registry",
                },
            ),
            compute,
        )

    diagnosis_payload = dict(diagnosis.as_dict())
    diagnosis_payload.update({
        "repair_name": module_name,
        "native_key": "",
        "atomic_action_group": atomic_action_group,
        "route_family": route_family,
        "route_reject_reason": "",
        "policy_proposal_source": "zip_format_module_registry",
    })
    return RepairCandidate(
        module_name=module_name,
        format="zip",
        repaired_input={},
        status="partial" if module.spec.partial else "repaired",
        stage=module.spec.stage,
        confidence=0.0,
        partial=bool(module.spec.partial),
        actions=["plan_repair", module_name],
        damage_flags=list(job.damage_flags),
        diagnosis=diagnosis_payload,
        message="ZIP policy graph module proposal pending materialization",
        validations=[
            CandidateValidation(
                name="policy_graph_proposal",
                accepted=True,
                score=0.0,
                details={
                    "module": module_name,
                    "stage": module.spec.stage,
                    "lazy": True,
                    "atomic": bool(getattr(module.spec, "atomic", False)),
                    "route_family": route_family,
                },
            )
        ],
        score_hint=0.0,
        materializer=materialize,
        materialized=False,
        plan={
            "module": module_name,
            "stage": module.spec.stage,
            "workspace": workspace,
            "lazy": True,
            "plan_kind": "lazy_repair",
            "requires_materialization": True,
            "estimated_cost": 0.5,
        },
    )


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


def _with_job_password_candidates(candidates: list[RepairCandidate], job: RepairJob) -> list[RepairCandidate]:
    if job.password is None:
        return candidates
    return [
        replace(candidate, repaired_input=_with_password(candidate.repaired_input, job.password))
        if isinstance(candidate.repaired_input, dict) and candidate.repaired_input
        else candidate
        for candidate in candidates
    ]


def _with_job_password_result(result: RepairResult, job: RepairJob) -> RepairResult:
    if job.password is None or not isinstance(result.repaired_input, dict):
        return result
    return replace(result, repaired_input=_with_password(result.repaired_input, job.password))


def _with_password(payload: dict[str, Any], password: str) -> dict[str, Any]:
    output = dict(payload)
    output["password"] = password
    return output


def _normalize_format(value: Any) -> str:
    return str(value or "").lower().lstrip(".")
