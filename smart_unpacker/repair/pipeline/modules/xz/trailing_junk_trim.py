from __future__ import annotations

import lzma

from smart_unpacker.repair.diagnosis import RepairDiagnosis
from smart_unpacker.repair.job import RepairJob
from smart_unpacker.repair.pipeline.module import RepairModuleSpec
from smart_unpacker.repair.pipeline.modules._common import load_source_bytes, write_candidate
from smart_unpacker.repair.pipeline.registry import register_repair_module
from smart_unpacker.repair.result import RepairResult


class XzTrailingJunkTrim:
    spec = RepairModuleSpec(
        name="xz_trailing_junk_trim",
        formats=("xz",),
        categories=("boundary_repair",),
        stage="safe_repair",
    )

    def can_handle(self, job: RepairJob, diagnosis: RepairDiagnosis, config: dict) -> float:
        flags = set(job.damage_flags)
        if flags & {"trailing_junk", "boundary_unreliable"}:
            return 0.86
        if "boundary_repair" in diagnosis.categories:
            return 0.65
        return 0.0

    def repair(self, job: RepairJob, diagnosis: RepairDiagnosis, workspace: str, config: dict) -> RepairResult:
        data = load_source_bytes(job.source_input)
        decompressor = lzma.LZMADecompressor(format=lzma.FORMAT_XZ)
        try:
            decompressor.decompress(data)
        except lzma.LZMAError as exc:
            return RepairResult(status="unrepairable", confidence=0.0, format="xz", module_name=self.spec.name, diagnosis=diagnosis.as_dict(), message=f"xz stream could not be decoded: {exc}")
        if not decompressor.eof or not decompressor.unused_data:
            return RepairResult(status="unrepairable", confidence=0.0, format="xz", module_name=self.spec.name, diagnosis=diagnosis.as_dict(), message="no trailing junk after complete xz stream")
        repaired = data[:len(data) - len(decompressor.unused_data)]
        path = write_candidate(repaired, workspace, "xz_trailing_junk_trim.xz")
        return RepairResult(
            status="repaired",
            confidence=0.86,
            format="xz",
            repaired_input={"kind": "file", "path": path, "format_hint": "xz"},
            actions=["trim_after_xz_stream"],
            damage_flags=list(job.damage_flags),
            workspace_paths=[path],
            module_name=self.spec.name,
            diagnosis=diagnosis.as_dict(),
        )


register_repair_module(XzTrailingJunkTrim())
