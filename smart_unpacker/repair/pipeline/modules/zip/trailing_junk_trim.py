from __future__ import annotations

from smart_unpacker.repair.diagnosis import RepairDiagnosis
from smart_unpacker.repair.job import RepairJob
from smart_unpacker.repair.pipeline.module import RepairModuleSpec
from pathlib import Path

from smart_unpacker.repair.pipeline.modules._common import copy_source_prefix_to_file, load_source_bytes
from smart_unpacker.repair.pipeline.registry import register_repair_module
from smart_unpacker.repair.result import RepairResult

from ._directory import find_eocd


class ZipTrailingJunkTrim:
    spec = RepairModuleSpec(
        name="zip_trailing_junk_trim",
        formats=("zip",),
        categories=("boundary_repair",),
        stage="safe_repair",
    )

    def can_handle(self, job: RepairJob, diagnosis: RepairDiagnosis, config: dict) -> float:
        flags = set(job.damage_flags)
        if flags & {"trailing_junk", "boundary_unreliable"}:
            return 0.88
        if "boundary_repair" in diagnosis.categories:
            return 0.74
        return 0.0

    def repair(self, job: RepairJob, diagnosis: RepairDiagnosis, workspace: str, config: dict) -> RepairResult:
        data = load_source_bytes(job.source_input)
        eocd = find_eocd(data, allow_trailing_junk=True)
        if eocd is None:
            return RepairResult(
                status="unrepairable",
                confidence=0.0,
                format="zip",
                module_name=self.spec.name,
                diagnosis=diagnosis.as_dict(),
                message="EOCD was not found",
            )
        if eocd.end == len(data):
            return RepairResult(
                status="unrepairable",
                confidence=0.0,
                format="zip",
                module_name=self.spec.name,
                diagnosis=diagnosis.as_dict(),
                message="no trailing bytes after EOCD",
            )
        path = copy_source_prefix_to_file(
            job.source_input,
            eocd.end,
            str(Path(workspace) / "zip_trailing_junk_trim.zip"),
        )
        return RepairResult(
            status="repaired",
            confidence=0.88,
            format="zip",
            repaired_input={"kind": "file", "path": path, "format_hint": "zip"},
            actions=["trim_after_eocd"],
            damage_flags=list(job.damage_flags),
            workspace_paths=[path],
            module_name=self.spec.name,
            diagnosis=diagnosis.as_dict(),
        )


register_repair_module(ZipTrailingJunkTrim())
