from __future__ import annotations

from sunpack.repair.diagnosis import RepairDiagnosis
from sunpack.repair.job import RepairJob
from sunpack.repair.pipeline.module import RepairModuleSpec, RepairRoute
from sunpack.repair.pipeline.modules._common import source_input_for_job
from sunpack.repair.pipeline.registry import register_repair_module
from sunpack.repair.result import RepairResult
from sunpack_native import zip_directory_field_repair as _native_zip_directory_field_repair

from ._native_field_result import repair_result_from_native_zip_field


class Zip64FieldRepair:
    spec = RepairModuleSpec(
        name="zip64_field_repair",
        formats=("zip",),
        categories=("directory_rebuild",),
        stage="targeted",
        routes=(
            RepairRoute(
                formats=("zip",),
                require_any_flags=(
                    "zip64",
                    "zip64_eocd_bad",
                    "zip64_locator_bad",
                    "zip64_extra_bad",
                    "central_directory_bad",
                ),
                require_any_failure_kinds=("structure_recognition",),
                base_score=0.9,
            ),
        ),
    )

    def can_handle(self, job: RepairJob, diagnosis: RepairDiagnosis, config: dict) -> float:
        flags = set(job.damage_flags)
        if flags & {"zip64_eocd_bad", "zip64_locator_bad", "zip64_extra_bad"}:
            return 0.99
        if "zip64" in flags and flags & {"central_directory_bad", "compressed_size_bad", "local_header_bad"}:
            return 0.88
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


register_repair_module(Zip64FieldRepair())
