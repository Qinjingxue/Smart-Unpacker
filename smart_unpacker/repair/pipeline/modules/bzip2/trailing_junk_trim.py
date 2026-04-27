from __future__ import annotations

import bz2
from pathlib import Path

from smart_unpacker.repair.diagnosis import RepairDiagnosis
from smart_unpacker.repair.job import RepairJob
from smart_unpacker.repair.pipeline.module import RepairModuleSpec
from smart_unpacker.repair.pipeline.modules._common import copy_source_prefix_to_file, load_source_bytes
from smart_unpacker.repair.pipeline.registry import register_repair_module
from smart_unpacker.repair.result import RepairResult


class Bzip2TrailingJunkTrim:
    spec = RepairModuleSpec(
        name="bzip2_trailing_junk_trim",
        formats=("bzip2", "bz2"),
        categories=("boundary_repair",),
        stage="safe_repair",
    )

    def can_handle(self, job: RepairJob, diagnosis: RepairDiagnosis, config: dict) -> float:
        flags = set(job.damage_flags)
        if flags & {"trailing_junk", "boundary_unreliable"}:
            return 0.84
        if "boundary_repair" in diagnosis.categories:
            return 0.58
        return 0.0

    def repair(self, job: RepairJob, diagnosis: RepairDiagnosis, workspace: str, config: dict) -> RepairResult:
        data = load_source_bytes(job.source_input)
        decompressor = bz2.BZ2Decompressor()
        try:
            decompressor.decompress(data)
        except OSError as exc:
            return RepairResult(status="unrepairable", confidence=0.0, format="bzip2", module_name=self.spec.name, diagnosis=diagnosis.as_dict(), message=f"bzip2 stream could not be decoded: {exc}")
        if not decompressor.eof or not decompressor.unused_data:
            return RepairResult(status="unrepairable", confidence=0.0, format="bzip2", module_name=self.spec.name, diagnosis=diagnosis.as_dict(), message="no trailing junk after complete bzip2 stream")
        stream_end = len(data) - len(decompressor.unused_data)
        path = copy_source_prefix_to_file(
            job.source_input,
            stream_end,
            str(Path(workspace) / "bzip2_trailing_junk_trim.bz2"),
        )
        return RepairResult(
            status="repaired",
            confidence=0.84,
            format="bzip2",
            repaired_input={"kind": "file", "path": path, "format_hint": "bzip2"},
            actions=["trim_after_bzip2_stream"],
            damage_flags=list(job.damage_flags),
            workspace_paths=[path],
            module_name=self.spec.name,
            diagnosis=diagnosis.as_dict(),
        )


register_repair_module(Bzip2TrailingJunkTrim())
