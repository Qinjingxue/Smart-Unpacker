from __future__ import annotations

from pathlib import Path

from smart_unpacker.repair.diagnosis import RepairDiagnosis
from smart_unpacker.repair.job import RepairJob
from smart_unpacker.repair.pipeline.module import RepairModuleSpec
from smart_unpacker.repair.pipeline.modules._common import copy_source_prefix_to_file, load_source_bytes
from smart_unpacker.repair.pipeline.registry import register_repair_module
from smart_unpacker.repair.result import RepairResult

from .trailing_zero_repair import _canonical_tar_end, _walk_payload_end


class TarTrailingJunkTrim:
    spec = RepairModuleSpec(
        name="tar_trailing_junk_trim",
        formats=("tar",),
        categories=("boundary_repair",),
        stage="safe_repair",
    )

    def can_handle(self, job: RepairJob, diagnosis: RepairDiagnosis, config: dict) -> float:
        flags = set(job.damage_flags)
        if flags & {"trailing_junk", "boundary_unreliable"}:
            return 0.84
        if diagnosis.format == "tar" and "boundary_repair" in diagnosis.categories:
            return 0.62
        return 0.0

    def repair(self, job: RepairJob, diagnosis: RepairDiagnosis, workspace: str, config: dict) -> RepairResult:
        data = load_source_bytes(job.source_input)
        payload_end = _walk_payload_end(data)
        if payload_end is None:
            return RepairResult(status="unrepairable", confidence=0.0, format="tar", module_name=self.spec.name, diagnosis=diagnosis.as_dict(), message="TAR entries could not be walked safely")
        end = _canonical_tar_end(data, payload_end)
        if end - payload_end < 1024:
            return RepairResult(status="unrepairable", confidence=0.0, format="tar", module_name=self.spec.name, diagnosis=diagnosis.as_dict(), message="TAR does not have two trusted trailing zero blocks")
        if end == len(data):
            return RepairResult(status="unrepairable", confidence=0.0, format="tar", module_name=self.spec.name, diagnosis=diagnosis.as_dict(), message="no trailing bytes after TAR zero blocks")
        path = copy_source_prefix_to_file(
            job.source_input,
            end,
            str(Path(workspace) / "tar_trailing_junk_trim.tar"),
        )
        return RepairResult(
            status="repaired",
            confidence=0.86,
            format="tar",
            repaired_input={"kind": "file", "path": path, "format_hint": "tar"},
            actions=["trim_after_tar_zero_blocks"],
            damage_flags=list(job.damage_flags),
            workspace_paths=[path],
            module_name=self.spec.name,
            diagnosis=diagnosis.as_dict(),
        )


register_repair_module(TarTrailingJunkTrim())
