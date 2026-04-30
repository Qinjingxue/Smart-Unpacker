from __future__ import annotations

from sunpack.repair.coverage import coverage_view_from_job
from sunpack.repair.diagnosis import RepairDiagnosis
from sunpack.repair.job import RepairJob
from sunpack.repair.pipeline.module import RepairModuleSpec, RepairRoute
from sunpack.repair.pipeline.registry import register_repair_module
from sunpack.repair.result import RepairResult

from ._entry_salvage import run_verified_entry_salvage


class ZipLocalHeaderVerifiedSalvage:
    spec = RepairModuleSpec(
        name="zip_local_header_verified_salvage",
        formats=("zip",),
        categories=("content_recovery", "directory_rebuild"),
        stage="deep",
        safe=True,
        partial=True,
        routes=(
            RepairRoute(
                formats=("zip",),
                require_any_categories=("content_recovery", "directory_rebuild"),
                require_any_flags=(
                    "crc_error",
                    "checksum_error",
                    "payload_damaged",
                    "entry_payload_bad",
                    "corrupted_data",
                    "central_directory_bad",
                    "directory_integrity_bad_or_unknown",
                    "local_header_recovery",
                ),
                require_any_failure_kinds=("checksum_error", "corrupted_data", "data_error", "structure_recognition"),
                base_score=0.93,
            ),
        ),
    )

    def can_handle(self, job: RepairJob, diagnosis: RepairDiagnosis, config: dict) -> float:
        flags = set(job.damage_flags)
        coverage = coverage_view_from_job(job)
        if coverage.mixed_damage_suspected:
            return 0.97
        if coverage.payload_only_suspected:
            return 0.95
        if flags & {"crc_error", "checksum_error", "payload_damaged", "entry_payload_bad", "corrupted_data"}:
            return 0.92
        if flags & {"central_directory_bad", "directory_integrity_bad_or_unknown", "local_header_recovery"}:
            return 0.76
        if "content_recovery" in diagnosis.categories:
            return 0.82
        return 0.0

    def repair(self, job: RepairJob, diagnosis: RepairDiagnosis, workspace: str, config: dict) -> RepairResult:
        return run_verified_entry_salvage(
            module_name=self.spec.name,
            job=job,
            diagnosis=diagnosis,
            workspace=workspace,
            config=config,
            confidence=0.88,
            message="rebuilt ZIP from local headers, keeping only entries that pass native payload verification",
        )


register_repair_module(ZipLocalHeaderVerifiedSalvage())
