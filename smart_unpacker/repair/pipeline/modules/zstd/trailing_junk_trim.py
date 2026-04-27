from __future__ import annotations

from smart_unpacker.repair.diagnosis import RepairDiagnosis
from smart_unpacker.repair.job import RepairJob
from smart_unpacker.repair.pipeline.module import RepairModuleSpec
from smart_unpacker.repair.pipeline.modules._common import load_source_bytes, write_candidate
from smart_unpacker.repair.pipeline.registry import register_repair_module
from smart_unpacker.repair.result import RepairResult


class ZstdTrailingJunkTrim:
    spec = RepairModuleSpec(
        name="zstd_trailing_junk_trim",
        formats=("zstd", "zst"),
        categories=("boundary_repair",),
        stage="safe_repair",
    )

    def can_handle(self, job: RepairJob, diagnosis: RepairDiagnosis, config: dict) -> float:
        flags = set(job.damage_flags)
        if flags & {"trailing_junk", "boundary_unreliable"}:
            return 0.78
        if "boundary_repair" in diagnosis.categories:
            return 0.55
        return 0.0

    def repair(self, job: RepairJob, diagnosis: RepairDiagnosis, workspace: str, config: dict) -> RepairResult:
        import zstandard as zstd

        data = load_source_bytes(job.source_input)
        decompressor = zstd.ZstdDecompressor().decompressobj()
        try:
            decompressor.decompress(data)
        except zstd.ZstdError as exc:
            return RepairResult(status="unrepairable", confidence=0.0, format="zstd", module_name=self.spec.name, diagnosis=diagnosis.as_dict(), message=f"zstd stream could not be decoded: {exc}")
        unused = getattr(decompressor, "unused_data", b"")
        if not unused:
            return RepairResult(status="unrepairable", confidence=0.0, format="zstd", module_name=self.spec.name, diagnosis=diagnosis.as_dict(), message="no trailing junk after complete zstd stream")
        repaired = data[:len(data) - len(unused)]
        path = write_candidate(repaired, workspace, "zstd_trailing_junk_trim.zst")
        return RepairResult(
            status="repaired",
            confidence=0.78,
            format="zstd",
            repaired_input={"kind": "file", "path": path, "format_hint": "zstd"},
            actions=["trim_after_zstd_stream"],
            damage_flags=list(job.damage_flags),
            workspace_paths=[path],
            module_name=self.spec.name,
            diagnosis=diagnosis.as_dict(),
        )


register_repair_module(ZstdTrailingJunkTrim())
