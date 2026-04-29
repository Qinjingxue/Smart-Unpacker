from __future__ import annotations

from sunpack.repair.diagnosis import RepairDiagnosis
from sunpack.repair.job import RepairJob
from sunpack.repair.pipeline.module import RepairModuleSpec, RepairRoute
from sunpack.repair.pipeline.modules._native_patch_result import native_patch_repair_result
from sunpack.repair.pipeline.registry import register_repair_module
from sunpack.repair.result import RepairResult

from .checksum_fix import _run_native_tar_boundary


class TarTrailingZeroBlockRepair:
    spec = RepairModuleSpec(
        name="tar_trailing_zero_block_repair",
        formats=("tar",),
        categories=("boundary_repair",),
        stage="safe_repair",
        routes=(
            RepairRoute(
                formats=("tar",),
                require_any_categories=("boundary_repair",),
                require_any_flags=("missing_end_block", "probably_truncated", "boundary_unreliable", "trailing_padding"),
                require_any_fuzzy_hints=("trailing_padding_likely",),
                require_any_failure_kinds=("unexpected_end",),
                base_score=0.74,
            ),
        ),
    )

    def can_handle(self, job: RepairJob, diagnosis: RepairDiagnosis, config: dict) -> float:
        flags = set(job.damage_flags)
        if flags & {"missing_end_block", "probably_truncated", "boundary_unreliable"}:
            return 0.82
        if diagnosis.format == "tar" and "boundary_repair" in diagnosis.categories:
            return 0.7
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


register_repair_module(TarTrailingZeroBlockRepair())
