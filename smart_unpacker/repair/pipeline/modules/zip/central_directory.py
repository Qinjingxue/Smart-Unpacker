from __future__ import annotations

from pathlib import Path

from smart_unpacker.repair.diagnosis import RepairDiagnosis
from smart_unpacker.repair.job import RepairJob
from smart_unpacker.repair.pipeline.module import RepairModuleSpec
from smart_unpacker.repair.pipeline.registry import register_repair_module
from smart_unpacker.repair.result import RepairResult

from ._rebuild import load_source_bytes, rebuild_zip_from_entries, scan_local_file_headers, write_rebuilt_zip


class ZipCentralDirectoryRebuild:
    spec = RepairModuleSpec(
        name="zip_central_directory_rebuild",
        formats=("zip",),
        categories=("directory_rebuild",),
        stage="targeted",
    )

    def can_handle(self, job: RepairJob, diagnosis: RepairDiagnosis, config: dict) -> float:
        flags = set(job.damage_flags)
        if "directory_rebuild" in diagnosis.categories:
            return 0.95
        if flags & {"central_directory_bad", "directory_integrity_bad_or_unknown", "local_header_recovery"}:
            return 0.9
        if "safe_fallback" in diagnosis.categories:
            return 0.25
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
                message="no recoverable ZIP local file headers were found",
            )

        candidate = Path(workspace) / "zip_central_directory_rebuild.zip"
        write_rebuilt_zip(rebuild_zip_from_entries(scan.entries), candidate)
        partial = not scan.complete
        return RepairResult(
            status="partial" if partial else "repaired",
            confidence=0.72 if partial else 0.92,
            format="zip",
            repaired_input={"kind": "file", "path": str(candidate), "format_hint": "zip"},
            actions=["scan_local_file_headers", "rebuild_zip_central_directory", "write_repaired_zip"],
            damage_flags=list(job.damage_flags),
            warnings=scan.warnings,
            workspace_paths=[str(candidate)],
            partial=partial,
            module_name=self.spec.name,
            diagnosis=diagnosis.as_dict(),
        )


register_repair_module(ZipCentralDirectoryRebuild())
