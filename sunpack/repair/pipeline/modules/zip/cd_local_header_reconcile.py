from __future__ import annotations

from sunpack.repair.coverage import coverage_view_from_job
from sunpack.repair.diagnosis import RepairDiagnosis
from sunpack.repair.job import RepairJob
from sunpack.repair.pipeline.module import RepairModuleSpec, RepairRoute
from sunpack.repair.pipeline.registry import register_repair_module
from sunpack.repair.result import RepairResult

from ._entry_salvage import run_verified_entry_salvage


class ZipCdLocalHeaderReconcileRebuild:
    spec = RepairModuleSpec(
        name="zip_cd_local_header_reconcile_rebuild",
        formats=("zip",),
        categories=("directory_rebuild", "content_recovery"),
        stage="deep",
        safe=True,
        partial=True,
        routes=(
            RepairRoute(
                formats=("zip",),
                require_any_categories=("directory_rebuild", "content_recovery"),
                require_any_flags=(
                    "central_directory_offset_bad",
                    "central_directory_bad",
                    "central_directory_count_bad",
                    "directory_integrity_bad_or_unknown",
                    "local_header_conflict",
                    "local_header_recovery",
                    "crc_error",
                    "checksum_error",
                ),
                require_any_failure_kinds=("structure_recognition", "corrupted_data", "checksum_error", "data_error"),
                base_score=0.94,
            ),
        ),
    )

    def can_handle(self, job: RepairJob, diagnosis: RepairDiagnosis, config: dict) -> float:
        flags = set(job.damage_flags)
        coverage = coverage_view_from_job(job)
        if flags & {"local_header_conflict", "central_directory_offset_bad"}:
            return 0.98
        if flags & {"central_directory_bad", "directory_integrity_bad_or_unknown"} and coverage.has_payload_damage:
            return 0.96
        if flags & {"central_directory_bad", "directory_integrity_bad_or_unknown", "local_header_recovery"}:
            return 0.9
        if coverage.mixed_damage_suspected:
            return 0.88
        return 0.0

    def repair(self, job: RepairJob, diagnosis: RepairDiagnosis, workspace: str, config: dict) -> RepairResult:
        return run_verified_entry_salvage(
            module_name=self.spec.name,
            job=job,
            diagnosis=diagnosis,
            workspace=workspace,
            config=config,
            confidence=0.9,
            message="rebuilt ZIP after cross-checking central directory entries against physical local headers",
        )


register_repair_module(ZipCdLocalHeaderReconcileRebuild())
