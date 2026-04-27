from __future__ import annotations

from smart_unpacker.repair.diagnosis import RepairDiagnosis
from smart_unpacker.repair.job import RepairJob
from smart_unpacker.repair.pipeline.module import RepairModuleSpec
from pathlib import Path

from smart_unpacker.repair.pipeline.modules._common import copy_source_prefix_to_file, load_source_bytes
from smart_unpacker.repair.pipeline.registry import register_repair_module
from smart_unpacker.repair.result import RepairResult

from ._structure import parse_start_header


class SevenZipBoundaryTrim:
    spec = RepairModuleSpec(
        name="seven_zip_boundary_trim",
        formats=("7z", "seven_zip"),
        categories=("boundary_repair",),
        stage="safe_repair",
    )

    def can_handle(self, job: RepairJob, diagnosis: RepairDiagnosis, config: dict) -> float:
        flags = set(job.damage_flags)
        if flags & {"trailing_junk", "boundary_unreliable"}:
            return 0.86
        if "boundary_repair" in diagnosis.categories:
            return 0.7
        return 0.0

    def repair(self, job: RepairJob, diagnosis: RepairDiagnosis, workspace: str, config: dict) -> RepairResult:
        data = load_source_bytes(job.source_input)
        header = parse_start_header(data)
        if header is None or not header.start_crc_ok:
            return RepairResult(status="unrepairable", confidence=0.0, format="7z", module_name=self.spec.name, diagnosis=diagnosis.as_dict(), message="7z boundary is not trusted without a valid start header")
        if header.archive_end == len(data):
            return RepairResult(status="unrepairable", confidence=0.0, format="7z", module_name=self.spec.name, diagnosis=diagnosis.as_dict(), message="no trailing bytes after 7z archive end")
        path = copy_source_prefix_to_file(
            job.source_input,
            header.archive_end,
            str(Path(workspace) / "seven_zip_boundary_trim.7z"),
        )
        warnings = [] if header.next_header_crc_ok else ["next header CRC is invalid; trim only repaired outer boundary"]
        return RepairResult(
            status="repaired",
            confidence=0.9 if header.next_header_crc_ok else 0.68,
            format="7z",
            repaired_input={"kind": "file", "path": path, "format_hint": "7z"},
            actions=["trim_after_7z_next_header"],
            damage_flags=list(job.damage_flags),
            warnings=warnings,
            workspace_paths=[path],
            module_name=self.spec.name,
            diagnosis=diagnosis.as_dict(),
        )


register_repair_module(SevenZipBoundaryTrim())
