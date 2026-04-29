from __future__ import annotations

from sunpack.repair.diagnosis import RepairDiagnosis
from sunpack.repair.job import RepairJob
from sunpack.repair.pipeline.module import RepairModuleSpec, RepairRoute
from sunpack.repair.pipeline.modules._common import source_input_for_job
from sunpack.repair.pipeline.registry import register_repair_module
from sunpack.repair.result import RepairResult
from sunpack_native import zip_directory_field_repair as _native_zip_directory_field_repair

from ._native_field_result import repair_result_from_native_zip_field


class ZipEocdRepair:
    spec = RepairModuleSpec(
        name="zip_eocd_repair",
        formats=("zip",),
        categories=("directory_rebuild", "boundary_repair"),
        stage="targeted",
        routes=(
            RepairRoute(
                formats=("zip",),
                require_any_flags=("eocd_bad", "central_directory_bad", "directory_integrity_bad_or_unknown"),
                require_any_failure_kinds=("structure_recognition", "corrupted_data"),
                reject_any_flags=("wrong_password", "carrier_archive", "sfx", "embedded_archive", "carrier_prefix"),
                base_score=0.82,
            ),
        ),
    )

    def can_handle(self, job: RepairJob, diagnosis: RepairDiagnosis, config: dict) -> float:
        flags = set(job.damage_flags)
        if flags & {"carrier_archive", "sfx", "embedded_archive", "carrier_prefix"}:
            return 0.0
        if flags & {"eocd_bad", "central_directory_bad", "directory_integrity_bad_or_unknown"}:
            return 0.97 if "eocd_bad" in flags else 0.9
        return 0.0

    def repair(self, job: RepairJob, diagnosis: RepairDiagnosis, workspace: str, config: dict) -> RepairResult:
        deep = config.get("deep") if isinstance(config.get("deep"), dict) else {}
        result = _native_zip_directory_field_repair(
            source_input_for_job(job),
            workspace,
            self.spec.name,
            float(deep.get("max_input_size_mb", 512) or 0),
        )
        return repair_result_from_native_zip_field(self.spec.name, dict(result), job, diagnosis, config)


register_repair_module(ZipEocdRepair())
