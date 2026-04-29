from __future__ import annotations

from packrelic.repair.diagnosis import RepairDiagnosis
from packrelic.repair.job import RepairJob
from packrelic.repair.pipeline.module import RepairModuleSpec, RepairRoute
from packrelic.repair.pipeline.modules._common import source_input_for_job
from packrelic.repair.pipeline.registry import register_repair_module
from packrelic.repair.result import RepairResult
from packrelic_native import zip_directory_field_repair as _native_zip_directory_field_repair

from ._native_field_result import repair_result_from_native_zip_field


class ZipLocalHeaderFieldRepair:
    spec = RepairModuleSpec(
        name="zip_local_header_field_repair",
        formats=("zip",),
        categories=("directory_rebuild",),
        stage="targeted",
        routes=(
            RepairRoute(
                formats=("zip",),
                require_any_flags=(
                    "local_header_bad",
                    "local_header_length_bad",
                    "local_header_size_bad",
                    "bit3_data_descriptor",
                    "data_descriptor",
                ),
                require_any_failure_kinds=("corrupted_data", "structure_recognition", "checksum_error"),
                base_score=0.82,
            ),
        ),
    )

    def can_handle(self, job: RepairJob, diagnosis: RepairDiagnosis, config: dict) -> float:
        flags = set(job.damage_flags)
        if flags & {"local_header_bad", "local_header_length_bad", "local_header_size_bad"}:
            return 0.93
        if flags & {"bit3_data_descriptor", "data_descriptor"} and "central_directory_bad" not in flags:
            return 0.74
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


register_repair_module(ZipLocalHeaderFieldRepair())
