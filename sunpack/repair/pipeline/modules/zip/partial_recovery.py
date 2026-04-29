from __future__ import annotations

from pathlib import Path

from sunpack.repair.diagnosis import RepairDiagnosis
from sunpack.repair.job import RepairJob
from sunpack.repair.pipeline.module import RepairModuleSpec, RepairRoute
from sunpack.repair.pipeline.modules._common import source_input_for_job
from sunpack.repair.pipeline.registry import register_repair_module
from sunpack.repair.result import RepairResult
from sunpack.repair.coverage import coverage_view_from_job

from ._rebuild import rebuild_zip_from_source


class ZipPartialRecovery:
    spec = RepairModuleSpec(
        name="zip_partial_recovery",
        formats=("zip",),
        categories=("content_recovery", "directory_rebuild"),
        stage="safe_repair",
        partial=True,
        routes=(
            RepairRoute(
                formats=("zip",),
                require_any_categories=("content_recovery", "directory_rebuild"),
                require_any_flags=("damaged", "crc_error", "checksum_error", "local_header_recovery", "corrupted_data"),
                require_any_failure_stages=("item_extract",),
                require_any_failure_kinds=("checksum_error", "corrupted_data", "data_error"),
                base_score=0.76,
            ),
        ),
    )

    def can_handle(self, job: RepairJob, diagnosis: RepairDiagnosis, config: dict) -> float:
        flags = set(job.damage_flags)
        coverage = coverage_view_from_job(job)
        if coverage.mixed_damage_suspected:
            return 0.9
        if coverage.payload_only_suspected:
            return 0.88
        if coverage.directory_only_suspected and coverage.has_recovered_output:
            return 0.78
        if "content_recovery" in diagnosis.categories:
            return 0.85
        if flags & {"damaged", "crc_error", "checksum_error", "local_header_recovery"}:
            return 0.75
        if "directory_rebuild" in diagnosis.categories:
            return 0.55
        return 0.0

    def repair(self, job: RepairJob, diagnosis: RepairDiagnosis, workspace: str, config: dict) -> RepairResult:
        flags = set(job.damage_flags)
        if "crc_error" in flags and not (
            flags & {"local_header_recovery", "central_directory_bad", "directory_integrity_bad_or_unknown"}
        ):
            return RepairResult(
                status="unrepairable",
                confidence=0.0,
                format="zip",
                module_name=self.spec.name,
                diagnosis=diagnosis.as_dict(),
                message="payload checksum damage requires deep ZIP partial recovery",
            )
        candidate = Path(workspace) / "zip_partial_recovery.zip"
        scan = rebuild_zip_from_source(source_input_for_job(job), candidate, config=config)
        if not scan.entries:
            return RepairResult(
                status="unrepairable",
                confidence=0.0,
                format="zip",
                module_name=self.spec.name,
                diagnosis=diagnosis.as_dict(),
                warnings=scan.warnings,
                message="no intact ZIP entries could be recovered",
            )

        coverage = coverage_view_from_job(job)
        warnings = list(scan.warnings)
        if scan.skipped_offsets:
            warnings.append(f"skipped {len(scan.skipped_offsets)} damaged ZIP local header(s)")
        if coverage.failed_names:
            warnings.append(f"prior extraction reported failed payloads: {', '.join(coverage.failed_names[:5])}")
        if coverage.partial_names:
            warnings.append(f"prior extraction reported partial payloads: {', '.join(coverage.partial_names[:5])}")
        confidence = 0.65 if scan.skipped_offsets else 0.78
        confidence += coverage.score_hint(payload=0.08, mixed=0.06, directory=0.02, partial=0.03)
        if coverage.low_yield_partial:
            confidence -= 0.08
        confidence = max(0.1, min(0.95, confidence))
        return RepairResult(
            status="partial",
            confidence=confidence,
            format="zip",
            repaired_input={"kind": "file", "path": str(candidate), "format_hint": "zip"},
            actions=["scan_local_file_headers", "skip_unrecoverable_entries", "write_partial_zip"],
            damage_flags=list(job.damage_flags),
            warnings=warnings,
            workspace_paths=[str(candidate)],
            partial=True,
            module_name=self.spec.name,
            diagnosis={
                **diagnosis.as_dict(),
                "archive_coverage": coverage.as_dict(),
                "coverage_strategy": "keep_complete_and_best_partial_entries",
            },
        )


register_repair_module(ZipPartialRecovery())
