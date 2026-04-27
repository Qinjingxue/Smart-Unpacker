from __future__ import annotations

from pathlib import Path
import zlib

from smart_unpacker.repair.diagnosis import RepairDiagnosis
from smart_unpacker.repair.job import RepairJob
from smart_unpacker.repair.pipeline.module import RepairModuleSpec
from smart_unpacker.repair.pipeline.modules._common import copy_source_prefix_to_file, load_source_bytes
from smart_unpacker.repair.pipeline.registry import register_repair_module
from smart_unpacker.repair.result import RepairResult


class GzipTrailingJunkTrim:
    spec = RepairModuleSpec(
        name="gzip_trailing_junk_trim",
        formats=("gzip", "gz"),
        categories=("boundary_repair",),
        stage="safe_fallback",
    )

    def can_handle(self, job: RepairJob, diagnosis: RepairDiagnosis, config: dict) -> float:
        flags = set(job.damage_flags)
        if flags & {"trailing_junk", "boundary_unreliable"}:
            return 0.86
        if "boundary_repair" in diagnosis.categories:
            return 0.6
        return 0.0

    def repair(self, job: RepairJob, diagnosis: RepairDiagnosis, workspace: str, config: dict) -> RepairResult:
        data = load_source_bytes(job.source_input)
        decompressor = zlib.decompressobj(16 + zlib.MAX_WBITS)
        try:
            decompressor.decompress(data)
        except zlib.error as exc:
            return RepairResult(status="unrepairable", confidence=0.0, format="gzip", module_name=self.spec.name, diagnosis=diagnosis.as_dict(), message=f"gzip stream could not be decoded: {exc}")
        if not decompressor.eof or not decompressor.unused_data:
            return RepairResult(status="unrepairable", confidence=0.0, format="gzip", module_name=self.spec.name, diagnosis=diagnosis.as_dict(), message="no trailing junk after complete gzip stream")
        stream_end = len(data) - len(decompressor.unused_data)
        path = copy_source_prefix_to_file(
            job.source_input,
            stream_end,
            str(Path(workspace) / "gzip_trailing_junk_trim.gz"),
        )
        return RepairResult(
            status="repaired",
            confidence=0.86,
            format="gzip",
            repaired_input={"kind": "file", "path": path, "format_hint": "gzip"},
            actions=["trim_after_gzip_stream"],
            damage_flags=list(job.damage_flags),
            workspace_paths=[path],
            module_name=self.spec.name,
            diagnosis=diagnosis.as_dict(),
        )


register_repair_module(GzipTrailingJunkTrim())
