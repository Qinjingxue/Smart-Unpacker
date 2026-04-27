from __future__ import annotations

from pathlib import Path

from smart_unpacker.repair.diagnosis import RepairDiagnosis
from smart_unpacker.repair.job import RepairJob
from smart_unpacker.repair.pipeline.module import RepairModuleSpec
from smart_unpacker.repair.pipeline.registry import register_repair_module
from smart_unpacker.repair.result import RepairResult

from ._rebuild import load_source_bytes, rebuild_zip_from_entries, scan_local_file_headers, write_rebuilt_zip


class ZipPartialRecovery:
    spec = RepairModuleSpec(
        name="zip_partial_recovery",
        formats=("zip",),
        categories=("content_recovery", "directory_rebuild"),
        stage="safe_fallback",
    )

    def can_handle(self, job: RepairJob, diagnosis: RepairDiagnosis, config: dict) -> float:
        flags = set(job.damage_flags)
        if "content_recovery" in diagnosis.categories:
            return 0.85
        if flags & {"damaged", "crc_error", "checksum_error", "local_header_recovery"}:
            return 0.75
        if "directory_rebuild" in diagnosis.categories:
            return 0.55
        return 0.0

    def repair(self, job: RepairJob, diagnosis: RepairDiagnosis, workspace: str, config: dict) -> RepairResult:
        data = load_source_bytes(job.source_input)
        scan = scan_local_file_headers(data)
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

        candidate = Path(workspace) / "zip_partial_recovery.zip"
        write_rebuilt_zip(rebuild_zip_from_entries(scan.entries), candidate)
        warnings = list(scan.warnings)
        if scan.skipped_offsets:
            warnings.append(f"skipped {len(scan.skipped_offsets)} damaged ZIP local header(s)")
        return RepairResult(
            status="partial",
            confidence=0.65 if scan.skipped_offsets else 0.78,
            format="zip",
            repaired_input={"kind": "file", "path": str(candidate), "format_hint": "zip"},
            actions=["scan_local_file_headers", "skip_unrecoverable_entries", "write_partial_zip"],
            damage_flags=list(job.damage_flags),
            warnings=warnings,
            workspace_paths=[str(candidate)],
            partial=True,
            module_name=self.spec.name,
            diagnosis=diagnosis.as_dict(),
        )


register_repair_module(ZipPartialRecovery())
