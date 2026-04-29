from __future__ import annotations

from packrelic.repair.diagnosis import RepairDiagnosis
from packrelic.repair.job import RepairJob
from packrelic.repair.pipeline.module import RepairModuleSpec, RepairRoute
from packrelic.repair.pipeline.modules._native_stream_trim import native_stream_trailing_trim_result
from packrelic.repair.pipeline.registry import register_repair_module
from packrelic.repair.result import RepairResult


class Bzip2TrailingJunkTrim:
    spec = RepairModuleSpec(
        name="bzip2_trailing_junk_trim",
        formats=("bzip2", "bz2"),
        categories=("boundary_repair",),
        stage="safe_repair",
        routes=(
            RepairRoute(
                formats=("bzip2", "bz2"),
                require_any_categories=("boundary_repair",),
                require_any_flags=("trailing_junk", "boundary_unreliable", "trailing_padding"),
                require_any_fuzzy_hints=("trailing_text_junk_likely", "trailing_padding_likely"),
                base_score=0.72,
            ),
        ),
    )

    def can_handle(self, job: RepairJob, diagnosis: RepairDiagnosis, config: dict) -> float:
        flags = set(job.damage_flags)
        if flags & {"trailing_junk", "boundary_unreliable"}:
            return 0.84
        if "boundary_repair" in diagnosis.categories:
            return 0.58
        return 0.0

    def repair(self, job: RepairJob, diagnosis: RepairDiagnosis, workspace: str, config: dict) -> RepairResult:
        return native_stream_trailing_trim_result(
            module_name=self.spec.name,
            fmt="bzip2",
            job=job,
            diagnosis=diagnosis,
            workspace=workspace,
            config=config,
        )


register_repair_module(Bzip2TrailingJunkTrim())
