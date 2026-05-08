from __future__ import annotations

from pathlib import Path

from sunpack.repair.coverage import coverage_view_from_job
from sunpack.repair.diagnosis import RepairDiagnosis
from sunpack.repair.job import RepairJob
from sunpack.repair.pipeline.module import RepairModuleSpec, RepairRoute
from sunpack.repair.pipeline.modules._common import source_input_for_job
from sunpack.repair.pipeline.registry import register_repair_module
from sunpack.repair.result import RepairResult

from ._rebuild import rebuild_zip_from_source


class ZipRebuild:
    spec = RepairModuleSpec(
        name="zip_rebuild",
        formats=("zip",),
        categories=("directory_rebuild", "content_recovery"),
        stage="targeted",
        routes=(
            RepairRoute(
                formats=("zip",),
                require_any_categories=("directory_rebuild", "content_recovery"),
                require_any_flags=(
                    "central_directory_bad", "directory_integrity_bad_or_unknown",
                    "local_header_recovery", "data_descriptor", "compressed_size_bad",
                    "bit3_data_descriptor",
                ),
                require_any_failure_kinds=("structure_recognition", "corrupted_data"),
                reject_any_flags=("missing_volume",),
                base_score=0.84,
            ),
        ),
    )

    def can_handle(self, job: RepairJob, diagnosis: RepairDiagnosis, config: dict) -> float:
        flags = set(job.damage_flags)
        coverage = coverage_view_from_job(job)
        if "missing_volume" in flags:
            return 0.0
        if "eocd_bad" in flags and "local_header_recovery" not in flags:
            return 0.0
        if flags & {"data_descriptor", "compressed_size_bad", "bit3_data_descriptor"}:
            return 0.90
        if coverage.payload_only_suspected and "directory_rebuild" not in diagnosis.categories:
            return 0.15
        if coverage.directory_only_suspected:
            return 0.94
        if coverage.mixed_damage_suspected:
            return 0.88
        if flags & {"central_directory_bad", "central_directory_offset_bad", "central_directory_count_bad"} and flags & {
            "checksum_error", "crc_error", "damaged", "entry_payload_bad",
        }:
            return 0.97
        if flags & {"central_directory_offset_bad", "central_directory_count_bad"} and not (
            flags & {"central_directory_bad", "directory_integrity_bad_or_unknown", "local_header_recovery"}
        ):
            return 0.0
        if flags & {"central_directory_bad", "directory_integrity_bad_or_unknown", "local_header_recovery"}:
            return 0.90
        if "content_recovery" in diagnosis.categories:
            return 0.85
        if "safe_repair" in diagnosis.categories:
            return 0.25
        return 0.0

    def repair(self, job: RepairJob, diagnosis: RepairDiagnosis, workspace: str, config: dict) -> RepairResult:
        flags = set(job.damage_flags)
        coverage = coverage_view_from_job(job)

        if "eocd_bad" in flags and "local_header_recovery" not in flags:
            return RepairResult(
                status="unrepairable", confidence=0.0, format="zip",
                module_name=self.spec.name, diagnosis=diagnosis.as_dict(),
                message="EOCD-only damage should be handled by fix_pointers first",
            )

        require_dd = bool(flags & {"data_descriptor", "compressed_size_bad", "bit3_data_descriptor"})
        candidate = Path(workspace) / "zip_rebuild.zip"
        scan = rebuild_zip_from_source(
            source_input_for_job(job), candidate,
            require_data_descriptor=require_dd, config=config,
        )

        if not scan.entries:
            return RepairResult(
                status="unrepairable", confidence=0.0, format="zip",
                module_name=self.spec.name, diagnosis=diagnosis.as_dict(),
                warnings=scan.warnings,
                message="no recoverable ZIP entries were found",
            )

        payload_damage_flags = {
            "checksum_error", "crc_error", "damaged", "entry_payload_bad", "payload_bad", "data_error",
        }
        partial = (
            not scan.complete
            or (coverage.known and scan.entries and coverage.has_missing_entries)
            or coverage.has_payload_damage
            or bool(flags & payload_damage_flags)
        )
        confidence = 0.72 if partial else 0.92
        confidence += coverage.score_hint(directory=0.04, mixed=-0.04, payload=-0.12)
        confidence = max(0.1, min(0.98, confidence))

        return RepairResult(
            status="partial" if partial else "repaired",
            confidence=confidence, format="zip",
            repaired_input={"kind": "file", "path": str(candidate), "format_hint": "zip"},
            actions=["scan_local_file_headers", "rebuild_zip_central_directory", "write_repaired_zip"],
            damage_flags=list(job.damage_flags), warnings=scan.warnings,
            workspace_paths=[str(candidate)], partial=partial, module_name=self.spec.name,
            diagnosis={
                **diagnosis.as_dict(),
                "archive_coverage": coverage.as_dict(),
                "coverage_strategy": "directory_rebuild" if not coverage.payload_only_suspected else "low_priority_payload_only",
            },
        )


# Legacy coarse module kept for historical imports only. ZIP repair registration
# now happens through atomic.py.
