from __future__ import annotations

import lzma

from smart_unpacker.repair.diagnosis import RepairDiagnosis
from smart_unpacker.repair.job import RepairJob
from smart_unpacker.repair.pipeline.module import RepairModuleSpec, RepairRoute
from smart_unpacker.repair.pipeline.modules._common import load_job_source_bytes, patch_plan_for_truncate, patch_repair_result
from smart_unpacker.repair.pipeline.registry import register_repair_module
from smart_unpacker.repair.result import RepairResult


class XzTrailingJunkTrim:
    spec = RepairModuleSpec(
        name="xz_trailing_junk_trim",
        formats=("xz",),
        categories=("boundary_repair",),
        stage="safe_repair",
        routes=(
            RepairRoute(
                formats=("xz",),
                require_any_categories=("boundary_repair",),
                require_any_flags=("trailing_junk", "boundary_unreliable", "trailing_padding"),
                require_any_fuzzy_hints=("trailing_text_junk_likely", "trailing_padding_likely"),
                base_score=0.74,
            ),
        ),
    )

    def can_handle(self, job: RepairJob, diagnosis: RepairDiagnosis, config: dict) -> float:
        flags = set(job.damage_flags)
        if flags & {"trailing_junk", "boundary_unreliable"}:
            return 0.86
        if "boundary_repair" in diagnosis.categories:
            return 0.65
        return 0.0

    def repair(self, job: RepairJob, diagnosis: RepairDiagnosis, workspace: str, config: dict) -> RepairResult:
        data = load_job_source_bytes(job)
        decompressor = lzma.LZMADecompressor(format=lzma.FORMAT_XZ)
        try:
            decompressor.decompress(data)
        except lzma.LZMAError as exc:
            return RepairResult(status="unrepairable", confidence=0.0, format="xz", module_name=self.spec.name, diagnosis=diagnosis.as_dict(), message=f"xz stream could not be decoded: {exc}")
        if not decompressor.eof or not decompressor.unused_data:
            return RepairResult(status="unrepairable", confidence=0.0, format="xz", module_name=self.spec.name, diagnosis=diagnosis.as_dict(), message="no trailing junk after complete xz stream")
        stream_end = len(data) - len(decompressor.unused_data)
        actions = ["trim_after_xz_stream"]
        patch_plan = patch_plan_for_truncate(job, self.spec.name, stream_end, confidence=0.86, actions=actions)
        return patch_repair_result(
            job=job,
            diagnosis=diagnosis,
            module_name=self.spec.name,
            fmt="xz",
            patch_plan=patch_plan,
            confidence=0.86,
            actions=actions,
            workspace=workspace,
            filename="xz_trailing_junk_trim.xz",
            config=config,
            materialized_data=data[:stream_end],
        )


register_repair_module(XzTrailingJunkTrim())
