from __future__ import annotations

from sunpack.repair.diagnosis import RepairDiagnosis
from sunpack.repair.job import RepairJob
from sunpack.repair.pipeline.module import RepairModuleSpec, RepairRoute
from sunpack.repair.pipeline.modules._common import source_input_for_job
from sunpack.repair.pipeline.modules.archive_carrier_crop import _result_from_native
from sunpack.repair.pipeline.modules._native_candidates import candidates_from_native_result
from sunpack.repair.pipeline.registry import register_repair_module

from sunpack_native import seven_zip_crc_field_repair as _native_seven_zip_crc_field_repair


class SevenZipCrcFieldRepair:
    spec = RepairModuleSpec(
        name="seven_zip_crc_field_repair",
        formats=("7z", "seven_zip"),
        categories=("directory_rebuild", "safe_repair", "boundary_repair"),
        stage="deep",
        safe=True,
        routes=(
            RepairRoute(
                formats=("7z", "seven_zip"),
                require_any_flags=("next_header_crc_bad", "start_header_corrupt"),
                reject_any_flags=("wrong_password", "next_header_offset_bad", "next_header_size_bad", "next_header_out_of_range"),
                require_any_failure_kinds=("structure_recognition", "checksum_error"),
                base_score=0.86,
            ),
        ),
    )

    def can_handle(self, job: RepairJob, diagnosis: RepairDiagnosis, config: dict) -> float:
        flags = set(job.damage_flags)
        if flags & {"next_header_offset_bad", "next_header_size_bad", "next_header_out_of_range"} and "next_header_crc_bad" not in flags:
            return 0.0
        if flags & {"next_header_crc_bad", "start_header_corrupt"}:
            return 0.94
        if "start_header_crc_bad" in flags:
            return 0.0
        if diagnosis.format in {"7z", "seven_zip"} and "directory_rebuild" in diagnosis.categories:
            return 0.78
        return 0.0

    def repair(self, job: RepairJob, diagnosis: RepairDiagnosis, workspace: str, config: dict):
        result = self._run_native(job, workspace, config)
        return _result_from_native(self.spec.name, result, job, diagnosis, config)

    def generate_candidates(self, job: RepairJob, diagnosis: RepairDiagnosis, workspace: str, config: dict):
        result = self._run_native(job, workspace, config)
        return candidates_from_native_result(
            self.spec.name,
            result,
            job,
            diagnosis,
            native_key="native_archive_deep_repair",
            format_hint="7z",
            default_confidence=0.9,
            default_message="7z CRC field repair produced a candidate",
        )

    def _run_native(self, job: RepairJob, workspace: str, config: dict) -> dict:
        deep = config.get("deep") if isinstance(config.get("deep"), dict) else {}
        return _native_seven_zip_crc_field_repair(
            source_input_for_job(job),
            workspace,
            float(deep.get("max_input_size_mb", 512) or 0),
            int(deep.get("max_candidates_per_module", 8) or 1),
        )


register_repair_module(SevenZipCrcFieldRepair())
