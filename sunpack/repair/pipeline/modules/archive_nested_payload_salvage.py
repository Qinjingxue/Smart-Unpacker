from __future__ import annotations

from sunpack.repair.diagnosis import RepairDiagnosis
from sunpack.repair.job import RepairJob
from sunpack.repair.pipeline.module import RepairModuleSpec, RepairRoute
from sunpack.repair.pipeline.modules._common import source_input_for_job, module_limits
from sunpack.repair.pipeline.modules._native_candidates import candidates_from_native_result
from sunpack.repair.pipeline.modules.archive_carrier_crop import (
    _result_from_native,
    attach_native_crop_patch_plans,
    normalize_native_candidate_lengths,
)
from sunpack.repair.pipeline.registry import register_repair_module
from sunpack_native import archive_nested_payload_salvage as _native_nested_payload_salvage


class ArchiveNestedPayloadSalvage:
    spec = RepairModuleSpec(
        name="archive_nested_payload_salvage",
        formats=("zip", "7z", "seven_zip", "rar", "tar", "gzip", "archive"),
        categories=("content_recovery", "boundary_repair", "directory_rebuild"),
        stage="deep",
        safe=True,
        partial=True,
        routes=(
            RepairRoute(
                formats=("zip", "7z", "seven_zip", "rar", "tar", "gzip", "archive"),
                require_any_categories=(),
                require_any_flags=("outer_container_bad", "nested_archive"),
                reject_any_flags=("carrier_archive", "sfx", "carrier_prefix"),
                base_score=0.8,
            ),
        ),
    )

    def can_handle(self, job: RepairJob, diagnosis: RepairDiagnosis, config: dict) -> float:
        flags = set(job.damage_flags)
        if flags & {"carrier_archive", "sfx", "carrier_prefix"}:
            return 0.0
        if flags & {"nested_archive", "outer_container_bad"}:
            return 0.94
        return 0.0

    def repair(self, job: RepairJob, diagnosis: RepairDiagnosis, workspace: str, config: dict):
        result = self._run_native(job, workspace, config)
        return _result_from_native(self.spec.name, result, job, diagnosis, config)

    def generate_candidates(self, job: RepairJob, diagnosis: RepairDiagnosis, workspace: str, config: dict):
        result = self._run_native(job, workspace, config)
        normalize_native_candidate_lengths(result)
        if bool(config.get("virtual_patch_candidate")):
            attach_native_crop_patch_plans(result, job, self.spec.name)
        return candidates_from_native_result(
            self.spec.name,
            result,
            job,
            diagnosis,
            native_key="native_nested_payload_salvage",
            partial_default=True,
            default_confidence=0.72,
            default_message="nested archive salvage produced a candidate",
            prefer_patch_plan=bool(config.get("virtual_patch_candidate")),
            force_archive_state=bool(config.get("virtual_patch_candidate")),
        )

    def _run_native(self, job: RepairJob, workspace: str, config: dict) -> dict:
        limits = module_limits(config)
        return dict(
            _native_nested_payload_salvage(
                source_input_for_job(job),
                workspace,
                float(limits.get("max_input_size_mb", 512) or 0),
                int(limits.get("max_candidates_per_module", 8) or 1),
            )
        )


register_repair_module(ArchiveNestedPayloadSalvage())
