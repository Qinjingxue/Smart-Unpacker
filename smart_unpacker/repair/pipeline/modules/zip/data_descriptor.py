from __future__ import annotations

from pathlib import Path

from smart_unpacker.repair.diagnosis import RepairDiagnosis
from smart_unpacker.repair.job import RepairJob
from smart_unpacker.repair.pipeline.module import RepairModuleSpec, RepairRoute
from smart_unpacker.repair.pipeline.modules._common import source_input_for_job
from smart_unpacker.repair.pipeline.registry import register_repair_module
from smart_unpacker.repair.result import RepairResult
from smart_unpacker.repair.coverage import coverage_view_from_job

from ._rebuild import rebuild_zip_from_source


class ZipDataDescriptorRecovery:
    spec = RepairModuleSpec(
        name="zip_data_descriptor_recovery",
        formats=("zip",),
        categories=("directory_rebuild", "boundary_repair"),
        stage="targeted",
        routes=(
            RepairRoute(
                formats=("zip",),
                require_any_categories=("directory_rebuild", "boundary_repair"),
                require_any_flags=("data_descriptor", "compressed_size_bad", "bit3_data_descriptor"),
                require_any_failure_kinds=("corrupted_data", "checksum_error"),
                base_score=0.8,
            ),
        ),
    )

    def can_handle(self, job: RepairJob, diagnosis: RepairDiagnosis, config: dict) -> float:
        flags = set(job.damage_flags)
        coverage = coverage_view_from_job(job)
        if flags & {"data_descriptor", "compressed_size_bad", "bit3_data_descriptor"}:
            return 0.9
        if coverage.payload_only_suspected and coverage.has_recovered_output:
            return 0.82
        if coverage.mixed_damage_suspected:
            return 0.76
        if coverage.directory_only_suspected:
            return 0.35
        if "directory_rebuild" in diagnosis.categories or "boundary_repair" in diagnosis.categories:
            return 0.65
        return 0.0

    def repair(self, job: RepairJob, diagnosis: RepairDiagnosis, workspace: str, config: dict) -> RepairResult:
        candidate = Path(workspace) / "zip_data_descriptor_recovery.zip"
        scan = rebuild_zip_from_source(source_input_for_job(job), candidate, require_data_descriptor=True, config=config)
        if not scan.entries or scan.descriptor_entries <= 0:
            return RepairResult(
                status="unrepairable",
                confidence=0.0,
                format="zip",
                module_name=self.spec.name,
                diagnosis=diagnosis.as_dict(),
                warnings=scan.warnings,
                message="no recoverable ZIP data descriptor entries were found",
            )

        coverage = coverage_view_from_job(job)
        partial = not scan.complete or coverage.has_payload_damage
        confidence = 0.68 if partial else 0.86
        confidence += coverage.score_hint(payload=0.06, mixed=0.02, directory=-0.1, partial=0.02)
        confidence = max(0.1, min(0.96, confidence))
        return RepairResult(
            status="partial" if partial else "repaired",
            confidence=confidence,
            format="zip",
            repaired_input={"kind": "file", "path": str(candidate), "format_hint": "zip"},
            actions=["scan_zip_data_descriptors", "materialize_descriptor_sizes", "write_repaired_zip"],
            damage_flags=list(job.damage_flags),
            warnings=scan.warnings,
            workspace_paths=[str(candidate)],
            partial=partial,
            module_name=self.spec.name,
            diagnosis={
                **diagnosis.as_dict(),
                "archive_coverage": coverage.as_dict(),
                "coverage_strategy": "descriptor_payload_recovery" if coverage.has_payload_damage else "descriptor_directory_recovery",
            },
        )


register_repair_module(ZipDataDescriptorRecovery())
