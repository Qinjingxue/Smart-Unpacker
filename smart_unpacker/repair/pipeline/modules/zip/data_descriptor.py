from __future__ import annotations

from pathlib import Path

from smart_unpacker.repair.diagnosis import RepairDiagnosis
from smart_unpacker.repair.job import RepairJob
from smart_unpacker.repair.pipeline.module import RepairModuleSpec
from smart_unpacker.repair.pipeline.registry import register_repair_module
from smart_unpacker.repair.result import RepairResult

from ._rebuild import load_source_bytes, rebuild_zip_from_entries, scan_local_file_headers, write_rebuilt_zip


class ZipDataDescriptorRecovery:
    spec = RepairModuleSpec(
        name="zip_data_descriptor_recovery",
        formats=("zip",),
        categories=("directory_rebuild", "boundary_repair"),
        stage="targeted",
    )

    def can_handle(self, job: RepairJob, diagnosis: RepairDiagnosis, config: dict) -> float:
        flags = set(job.damage_flags)
        if flags & {"data_descriptor", "compressed_size_bad", "bit3_data_descriptor"}:
            return 0.9
        if "directory_rebuild" in diagnosis.categories or "boundary_repair" in diagnosis.categories:
            return 0.65
        return 0.0

    def repair(self, job: RepairJob, diagnosis: RepairDiagnosis, workspace: str, config: dict) -> RepairResult:
        data = load_source_bytes(job.source_input)
        scan = scan_local_file_headers(data, require_data_descriptor=True)
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

        candidate = Path(workspace) / "zip_data_descriptor_recovery.zip"
        write_rebuilt_zip(rebuild_zip_from_entries(scan.entries), candidate)
        partial = not scan.complete
        return RepairResult(
            status="partial" if partial else "repaired",
            confidence=0.68 if partial else 0.86,
            format="zip",
            repaired_input={"kind": "file", "path": str(candidate), "format_hint": "zip"},
            actions=["scan_zip_data_descriptors", "materialize_descriptor_sizes", "write_repaired_zip"],
            damage_flags=list(job.damage_flags),
            warnings=scan.warnings,
            workspace_paths=[str(candidate)],
            partial=partial,
            module_name=self.spec.name,
            diagnosis=diagnosis.as_dict(),
        )


register_repair_module(ZipDataDescriptorRecovery())
