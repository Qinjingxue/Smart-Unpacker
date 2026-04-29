from __future__ import annotations

from sunpack.repair.diagnosis import RepairDiagnosis
from sunpack.repair.job import RepairJob
from sunpack.repair.pipeline.module import RepairModuleSpec, RepairRoute
from sunpack.repair.pipeline.modules._common import source_input_for_job
from sunpack.repair.pipeline.modules.archive_carrier_crop import _result_from_native
from sunpack.repair.pipeline.registry import register_repair_module
from sunpack_native import seven_zip_next_header_field_repair as _native_seven_zip_next_header_field_repair

from sunpack.repair.result import RepairResult


class SevenZipNextHeaderFieldRepair:
    spec = RepairModuleSpec(
        name="seven_zip_next_header_field_repair",
        formats=("7z", "seven_zip"),
        categories=("directory_rebuild", "safe_repair"),
        stage="targeted",
        routes=(
            RepairRoute(
                formats=("7z", "seven_zip"),
                require_any_flags=("next_header_offset_bad", "next_header_size_bad", "next_header_out_of_range", "start_header_corrupt"),
                require_any_failure_kinds=("structure_recognition",),
                base_score=0.84,
            ),
        ),
    )

    def can_handle(self, job: RepairJob, diagnosis: RepairDiagnosis, config: dict) -> float:
        flags = set(job.damage_flags)
        if flags & {"next_header_offset_bad", "next_header_size_bad", "next_header_out_of_range"}:
            return 0.94
        if "start_header_corrupt" in flags and "next_header_crc_bad" not in flags:
            return 0.72
        return 0.0

    def repair(self, job: RepairJob, diagnosis: RepairDiagnosis, workspace: str, config: dict) -> RepairResult:
        deep = config.get("deep") if isinstance(config.get("deep"), dict) else {}
        result = _native_seven_zip_next_header_field_repair(
            source_input_for_job(job),
            workspace,
            float(deep.get("max_input_size_mb", 512) or 0),
            int(deep.get("max_next_header_scan_bytes", 1024 * 1024) or 1024 * 1024),
        )
        return _result_from_native(self.spec.name, dict(result), job, diagnosis, config)


register_repair_module(SevenZipNextHeaderFieldRepair())
