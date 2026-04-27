from __future__ import annotations

from smart_unpacker.repair.diagnosis import RepairDiagnosis
from smart_unpacker.repair.job import RepairJob
from smart_unpacker.repair.pipeline.module import RepairModuleSpec
from pathlib import Path

from smart_unpacker.repair.pipeline.modules._common import copy_source_prefix_to_file, load_source_bytes
from smart_unpacker.repair.pipeline.registry import register_repair_module
from smart_unpacker.repair.result import RepairResult

from ._structure import walk_rar_blocks


class RarTrailingJunkTrim:
    spec = RepairModuleSpec(
        name="rar_trailing_junk_trim",
        formats=("rar",),
        categories=("boundary_repair",),
        stage="safe_repair",
    )

    def can_handle(self, job: RepairJob, diagnosis: RepairDiagnosis, config: dict) -> float:
        flags = set(job.damage_flags)
        if flags & {"trailing_junk", "boundary_unreliable"}:
            return 0.84
        if "boundary_repair" in diagnosis.categories:
            return 0.68
        return 0.0

    def repair(self, job: RepairJob, diagnosis: RepairDiagnosis, workspace: str, config: dict) -> RepairResult:
        data = load_source_bytes(job.source_input)
        walk = walk_rar_blocks(data)
        if walk is None:
            return RepairResult(status="unrepairable", confidence=0.0, format="rar", module_name=self.spec.name, diagnosis=diagnosis.as_dict(), message="RAR signature was not found at input start")
        if not walk.end_block_found or walk.end_offset is None:
            return RepairResult(status="unrepairable", confidence=0.0, format="rar", module_name=self.spec.name, diagnosis=diagnosis.as_dict(), warnings=walk.warnings, message="RAR end block was not found")
        if walk.end_offset == len(data):
            return RepairResult(status="unrepairable", confidence=0.0, format="rar", module_name=self.spec.name, diagnosis=diagnosis.as_dict(), message="no trailing bytes after RAR end block")
        path = copy_source_prefix_to_file(
            job.source_input,
            walk.end_offset,
            str(Path(workspace) / "rar_trailing_junk_trim.rar"),
        )
        return RepairResult(
            status="repaired",
            confidence=0.86,
            format="rar",
            repaired_input={"kind": "file", "path": path, "format_hint": "rar"},
            actions=[f"walk_rar{walk.version}_blocks", "trim_after_rar_end_block"],
            damage_flags=list(job.damage_flags),
            warnings=walk.warnings,
            workspace_paths=[path],
            module_name=self.spec.name,
            diagnosis=diagnosis.as_dict(),
        )


register_repair_module(RarTrailingJunkTrim())
