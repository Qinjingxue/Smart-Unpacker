from __future__ import annotations

from sunpack.repair.diagnosis import RepairDiagnosis
from sunpack.repair.job import RepairJob
from sunpack.repair.pipeline.module import RepairModuleSpec, RepairRoute
from sunpack.repair.pipeline.modules._common import source_input_for_job
from sunpack.repair.pipeline.modules._native_candidates import candidates_from_native_result
from sunpack.repair.pipeline.modules.archive_carrier_crop import _result_from_native
from sunpack.repair.pipeline.registry import register_repair_module
from sunpack_native import rar_file_quarantine_rebuild as _native_rar_file_quarantine


class RarFileQuarantineRebuild:
    spec = RepairModuleSpec(
        name="rar_file_quarantine_rebuild",
        formats=("rar",),
        categories=("content_recovery", "directory_rebuild"),
        stage="deep",
        safe=True,
        partial=True,
        routes=(
            RepairRoute(
                formats=("rar",),
                require_any_categories=("content_recovery", "directory_rebuild"),
                require_any_flags=("file_block_bad", "damaged", "crc_error", "checksum_error", "data_error"),
                require_any_failure_kinds=("corrupted_data", "data_error", "checksum_error"),
                reject_any_flags=("wrong_password", "encrypted"),
                base_score=0.88,
            ),
        ),
    )

    def can_handle(self, job: RepairJob, diagnosis: RepairDiagnosis, config: dict) -> float:
        flags = set(job.damage_flags)
        if flags & {"wrong_password", "encrypted"}:
            return 0.0
        if flags & {"file_block_bad", "damaged", "crc_error", "checksum_error", "data_error"}:
            return 0.92
        if diagnosis.format == "rar" and "content_recovery" in diagnosis.categories:
            return 0.84
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
            native_key="native_rar_file_quarantine",
            format_hint="rar",
            partial_default=True,
            default_confidence=0.72,
            default_message="RAR file quarantine produced a candidate",
        )

    def _run_native(self, job: RepairJob, workspace: str, config: dict) -> dict:
        deep = config.get("deep") if isinstance(config.get("deep"), dict) else {}
        return dict(
            _native_rar_file_quarantine(
                source_input_for_job(job),
                workspace,
                float(deep.get("max_input_size_mb", 512) or 0),
                int(deep.get("max_candidates_per_module", 8) or 1),
            )
        )


register_repair_module(RarFileQuarantineRebuild())
