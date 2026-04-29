from __future__ import annotations

from sunpack.repair.diagnosis import RepairDiagnosis
from sunpack.repair.job import RepairJob
from sunpack.repair.pipeline.module import RepairModuleSpec, RepairRoute
from sunpack.repair.pipeline.modules._common import source_input_for_job
from sunpack.repair.pipeline.modules._native_candidates import candidates_from_native_result
from sunpack.repair.pipeline.modules.archive_carrier_crop import _result_from_native
from sunpack.repair.pipeline.registry import register_repair_module
from sunpack_native import seven_zip_solid_block_partial_salvage as _native_7z_solid_salvage


class SevenZipSolidBlockPartialSalvage:
    spec = RepairModuleSpec(
        name="seven_zip_solid_block_partial_salvage",
        formats=("7z", "seven_zip"),
        categories=("content_recovery", "directory_rebuild"),
        stage="deep",
        safe=True,
        partial=True,
        routes=(
            RepairRoute(
                formats=("7z", "seven_zip"),
                require_any_categories=("content_recovery", "directory_rebuild"),
                require_any_flags=("solid_block_damaged", "packed_stream_bad", "folder_bad", "damaged", "crc_error", "checksum_error"),
                require_any_failure_kinds=("corrupted_data", "data_error", "checksum_error"),
                base_score=0.9,
            ),
        ),
    )

    def can_handle(self, job: RepairJob, diagnosis: RepairDiagnosis, config: dict) -> float:
        flags = set(job.damage_flags)
        if flags & {"solid_block_damaged", "packed_stream_bad", "folder_bad"}:
            return 0.96
        if diagnosis.format in {"7z", "seven_zip"} and flags & {"damaged", "crc_error", "checksum_error"}:
            return 0.86
        if diagnosis.format in {"7z", "seven_zip"} and "content_recovery" in diagnosis.categories:
            return 0.82
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
            native_key="native_7z_solid_block_salvage",
            format_hint="zip",
            partial_default=True,
            default_confidence=0.7,
            default_message="7z block salvage produced a ZIP candidate",
        )

    def _run_native(self, job: RepairJob, workspace: str, config: dict) -> dict:
        deep = config.get("deep") if isinstance(config.get("deep"), dict) else {}
        return dict(
            _native_7z_solid_salvage(
                source_input_for_job(job),
                workspace,
                float(deep.get("max_input_size_mb", 512) or 0),
                float(deep.get("max_output_size_mb", 2048) or 0),
                int(deep.get("max_entries", 20000) or 20000),
            )
        )


register_repair_module(SevenZipSolidBlockPartialSalvage())
