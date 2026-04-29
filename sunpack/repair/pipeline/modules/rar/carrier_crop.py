from __future__ import annotations

from dataclasses import replace
from pathlib import Path

from sunpack.repair.diagnosis import RepairDiagnosis
from sunpack.repair.job import RepairJob
from sunpack.repair.pipeline.module import RepairModuleSpec, RepairRoute
from sunpack.repair.pipeline.modules._common import copy_range_to_file, source_input_for_job
from sunpack.repair.pipeline.modules.archive_carrier_crop import _result_from_native, attach_native_crop_patch_plans, normalize_native_candidate_lengths
from sunpack.repair.pipeline.modules._native_candidates import candidates_from_native_result
from sunpack.repair.pipeline.registry import register_repair_module

from sunpack_native import archive_carrier_crop_recovery as _native_archive_carrier_crop_recovery
from sunpack_native import rar_block_chain_trim_recovery as _native_rar_block_chain_trim_recovery


class RarCarrierCropDeepRecovery:
    spec = RepairModuleSpec(
        name="rar_carrier_crop_deep_recovery",
        formats=("rar",),
        categories=("boundary_repair", "content_recovery", "directory_rebuild"),
        stage="deep",
        safe=True,
        routes=(
            RepairRoute(
                formats=("rar",),
                require_any_categories=("boundary_repair", "content_recovery", "directory_rebuild"),
                require_any_flags=("carrier_archive", "sfx", "embedded_archive", "carrier_prefix", "boundary_unreliable", "start_trusted_only"),
                require_any_fuzzy_hints=("carrier_prefix_likely", "entropy_boundary_shift"),
                require_any_failure_kinds=("structure_recognition",),
                base_score=0.86,
            ),
        ),
    )

    def can_handle(self, job: RepairJob, diagnosis: RepairDiagnosis, config: dict) -> float:
        flags = set(job.damage_flags)
        if flags & {"carrier_archive", "sfx", "embedded_archive", "carrier_prefix"}:
            return 1.0
        if flags & {"boundary_unreliable", "start_trusted_only"}:
            return 0.92
        if "boundary_repair" in diagnosis.categories:
            return 0.76
        return 0.0

    def repair(self, job: RepairJob, diagnosis: RepairDiagnosis, workspace: str, config: dict):
        result = self._run_native(job, workspace, config)
        repair_result = _result_from_native(self.spec.name, result, job, diagnosis, config)
        if repair_result.ok and repair_result.repaired_input:
            trimmed = _trimmed_rar_file_to_end(str(repair_result.repaired_input.get("path") or ""), workspace)
            if trimmed:
                repaired_input = dict(repair_result.repaired_input)
                repaired_input["path"] = trimmed
                repair_result = replace(
                    repair_result,
                    repaired_input=repaired_input,
                    workspace_paths=[trimmed, *[item for item in repair_result.workspace_paths if item != trimmed]],
                )
        return repair_result

    def generate_candidates(self, job: RepairJob, diagnosis: RepairDiagnosis, workspace: str, config: dict):
        result = self._run_native(job, workspace, config)
        normalize_native_candidate_lengths(result)
        if bool(config.get("virtual_patch_candidate")):
            attach_native_crop_patch_plans(result, job, self.spec.name)
        candidates = candidates_from_native_result(
            self.spec.name,
            result,
            job,
            diagnosis,
            native_key="native_archive_deep_repair",
            format_hint="rar",
            default_confidence=0.86,
            default_message="RAR carrier crop produced a candidate",
            prefer_patch_plan=bool(config.get("virtual_patch_candidate")),
        )
        return [
            _trim_rar_candidate(_isolate_candidate_path(_boost_rar_specific_candidate(candidate), workspace))
            for candidate in candidates
        ]

    def _run_native(self, job: RepairJob, workspace: str, config: dict) -> dict:
        deep = config.get("deep") if isinstance(config.get("deep"), dict) else {}
        return _native_archive_carrier_crop_recovery(
            source_input_for_job(job),
            "rar",
            workspace,
            float(deep.get("max_input_size_mb", 512) or 0),
            int(deep.get("max_candidates_per_module", 8) or 1),
        )


register_repair_module(RarCarrierCropDeepRecovery())


def _boost_rar_specific_candidate(candidate):
    validations = [
        replace(validation, score=min(1.0, float(validation.score or 0.0) + 0.04))
        if validation.name == "native_candidate"
        else validation
        for validation in candidate.validations
    ]
    return replace(
        candidate,
        confidence=min(1.0, float(candidate.confidence or 0.0) + 0.04),
        validations=validations,
    )


def _isolate_candidate_path(candidate, workspace: str):
    repaired_input = dict(candidate.repaired_input or {})
    path = Path(str(repaired_input.get("path") or ""))
    if not path.is_file():
        return candidate
    target = Path(workspace) / f"{candidate.module_name}_{path.name}"
    if path.resolve() != target.resolve():
        target.parent.mkdir(parents=True, exist_ok=True)
        copy_range_to_file(str(path), 0, None, str(target))
    repaired_input["path"] = str(target)
    workspace_paths = [str(target), *[item for item in candidate.workspace_paths if item != str(target)]]
    return replace(candidate, repaired_input=repaired_input, workspace_paths=workspace_paths)


def _trim_rar_candidate(candidate):
    repaired_input = dict(candidate.repaired_input or {})
    path = str(repaired_input.get("path") or "")
    trimmed = _trimmed_rar_file_to_end(path, str(Path(path).parent) if path else "")
    if not trimmed:
        return candidate
    repaired_input["path"] = trimmed
    workspace_paths = [trimmed, *[item for item in candidate.workspace_paths if item != trimmed]]
    return replace(candidate, repaired_input=repaired_input, workspace_paths=workspace_paths)


def _trimmed_rar_file_to_end(path: str, workspace: str) -> str:
    if not path:
        return ""
    result = _native_rar_block_chain_trim_recovery(
        {"kind": "file", "path": path, "format_hint": "rar"},
        workspace or str(Path(path).parent),
        512.0,
        1,
    )
    candidates = result.get("candidates") if isinstance(result, dict) else None
    if not candidates:
        return ""
    first = candidates[0]
    if not isinstance(first, dict):
        return ""
    return str(first.get("path") or "")
