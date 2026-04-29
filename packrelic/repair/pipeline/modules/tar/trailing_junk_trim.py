from __future__ import annotations

from packrelic.repair.diagnosis import RepairDiagnosis
from packrelic.repair.job import RepairJob
from packrelic.repair.pipeline.module import RepairModuleSpec, RepairRoute
from packrelic.repair.pipeline.modules._native_patch_result import native_patch_repair_result
from packrelic.repair.pipeline.registry import register_repair_module
from packrelic.repair.result import RepairResult

from .checksum_fix import _run_native_tar_boundary


class TarTrailingJunkTrim:
    spec = RepairModuleSpec(
        name="tar_trailing_junk_trim",
        formats=("tar",),
        categories=("boundary_repair",),
        stage="safe_repair",
        routes=(
            RepairRoute(
                formats=("tar",),
                require_any_categories=("boundary_repair",),
                require_any_flags=("trailing_junk", "boundary_unreliable", "trailing_padding"),
                require_any_fuzzy_hints=("trailing_text_junk_likely", "trailing_padding_likely", "tail_printable_region"),
                base_score=0.72,
            ),
        ),
    )

    def can_handle(self, job: RepairJob, diagnosis: RepairDiagnosis, config: dict) -> float:
        flags = set(job.damage_flags)
        if flags & {"trailing_junk", "boundary_unreliable"}:
            return 0.84
        if diagnosis.format == "tar" and "boundary_repair" in diagnosis.categories:
            return 0.62
        return 0.0

    def repair(self, job: RepairJob, diagnosis: RepairDiagnosis, workspace: str, config: dict) -> RepairResult:
        result = _run_native_tar_boundary(job, workspace, config, self.spec.name)
        return native_patch_repair_result(
            module_name=self.spec.name,
            fmt="tar",
            native_key="native_tar_boundary_repair",
            result=result,
            job=job,
            diagnosis=diagnosis,
            config=config,
        )


register_repair_module(TarTrailingJunkTrim())
