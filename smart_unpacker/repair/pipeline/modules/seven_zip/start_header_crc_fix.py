from __future__ import annotations

from smart_unpacker.repair.diagnosis import RepairDiagnosis
from smart_unpacker.repair.job import RepairJob
from smart_unpacker.repair.pipeline.module import RepairModuleSpec
from pathlib import Path
import struct

from smart_unpacker.repair.pipeline.modules._common import load_source_bytes, patch_file, write_candidate
from smart_unpacker.repair.pipeline.registry import register_repair_module
from smart_unpacker.repair.result import RepairResult

from ._structure import parse_start_header, rewrite_start_crc


class SevenZipStartHeaderCrcFix:
    spec = RepairModuleSpec(
        name="seven_zip_start_header_crc_fix",
        formats=("7z", "seven_zip"),
        categories=("directory_rebuild", "safe_repair"),
        stage="targeted",
    )

    def can_handle(self, job: RepairJob, diagnosis: RepairDiagnosis, config: dict) -> float:
        flags = set(job.damage_flags)
        if flags & {"start_header_crc_bad", "start_header_corrupt"}:
            return 0.86
        if diagnosis.format in {"7z", "seven_zip"} and "safe_repair" in diagnosis.categories:
            return 0.35
        return 0.0

    def repair(self, job: RepairJob, diagnosis: RepairDiagnosis, workspace: str, config: dict) -> RepairResult:
        data = load_source_bytes(job.source_input)
        header = parse_start_header(data)
        if header is None:
            return RepairResult(status="unrepairable", confidence=0.0, format="7z", module_name=self.spec.name, diagnosis=diagnosis.as_dict(), message="7z start header fields are not safely parseable")
        if header.start_crc_ok:
            return RepairResult(status="unrepairable", confidence=0.0, format="7z", module_name=self.spec.name, diagnosis=diagnosis.as_dict(), message="7z start header CRC is already valid")
        output_path = str(Path(workspace) / "seven_zip_start_header_crc_fix.7z")
        if str(job.source_input.get("kind") or "file") == "file":
            path = patch_file(
                str(job.source_input["path"]),
                [{"offset": 8, "data": struct.pack("<I", header.computed_start_crc)}],
                output_path,
            )
        else:
            path = write_candidate(rewrite_start_crc(data, header), workspace, "seven_zip_start_header_crc_fix.7z")
        warnings = [] if header.next_header_crc_ok else ["next header CRC is still invalid after start header CRC repair"]
        return RepairResult(
            status="repaired",
            confidence=0.86 if header.next_header_crc_ok else 0.62,
            format="7z",
            repaired_input={"kind": "file", "path": path, "format_hint": "7z"},
            actions=["recompute_7z_start_header_crc"],
            damage_flags=list(job.damage_flags),
            warnings=warnings,
            workspace_paths=[path],
            module_name=self.spec.name,
            diagnosis=diagnosis.as_dict(),
        )


register_repair_module(SevenZipStartHeaderCrcFix())
