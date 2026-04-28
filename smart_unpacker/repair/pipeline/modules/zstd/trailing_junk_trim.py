from __future__ import annotations

from smart_unpacker.repair.diagnosis import RepairDiagnosis
from smart_unpacker.repair.job import RepairJob
from smart_unpacker.repair.pipeline.module import RepairModuleSpec, RepairRoute
from smart_unpacker.repair.pipeline.modules._common import load_job_source_bytes, patch_plan_for_truncate, patch_repair_result
from smart_unpacker.repair.pipeline.registry import register_repair_module
from smart_unpacker.repair.result import RepairResult


class ZstdTrailingJunkTrim:
    spec = RepairModuleSpec(
        name="zstd_trailing_junk_trim",
        formats=("zstd", "zst"),
        categories=("boundary_repair",),
        stage="safe_repair",
        routes=(
            RepairRoute(
                formats=("zstd", "zst"),
                require_any_categories=("boundary_repair",),
                require_any_flags=("trailing_junk", "boundary_unreliable", "trailing_padding"),
                require_any_fuzzy_hints=("trailing_text_junk_likely", "trailing_padding_likely"),
                base_score=0.68,
            ),
        ),
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

        data = load_job_source_bytes(job)
        decompressor = zstd.ZstdDecompressor().decompressobj()
        try:
            decompressor.decompress(data)
        except zstd.ZstdError as exc:
            return RepairResult(status="unrepairable", confidence=0.0, format="zstd", module_name=self.spec.name, diagnosis=diagnosis.as_dict(), message=f"zstd stream could not be decoded: {exc}")
        unused = getattr(decompressor, "unused_data", b"")
        if not unused:
            return RepairResult(status="unrepairable", confidence=0.0, format="zstd", module_name=self.spec.name, diagnosis=diagnosis.as_dict(), message="no trailing junk after complete zstd stream")
        stream_end = len(data) - len(unused)
        actions = ["trim_after_zstd_stream"]
        patch_plan = patch_plan_for_truncate(job, self.spec.name, stream_end, confidence=0.78, actions=actions)
        return patch_repair_result(
            job=job,
            diagnosis=diagnosis,
            module_name=self.spec.name,
            fmt="zstd",
            patch_plan=patch_plan,
            confidence=0.78,
            actions=actions,
            workspace=workspace,
            filename="zstd_trailing_junk_trim.zst",
            config=config,
            materialized_data=data[:stream_end],
        )


register_repair_module(ZstdTrailingJunkTrim())
