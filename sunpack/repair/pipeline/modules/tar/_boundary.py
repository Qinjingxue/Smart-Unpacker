from __future__ import annotations

from sunpack.repair.diagnosis import RepairDiagnosis
from sunpack.repair.job import RepairJob
from sunpack.repair.pipeline.module import RepairModuleSpec
from sunpack.repair.pipeline.modules._common import module_limits, source_input_for_job
from sunpack.repair.pipeline.modules._native_patch_result import native_patch_repair_result
from sunpack.repair.result import RepairResult
from sunpack_native import tar_boundary_repair as _native_tar_boundary_repair


class TarBoundaryRepairModule:
    """Execution helper for one named TAR boundary mutation."""

    spec: RepairModuleSpec

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


def _run_native_tar_boundary(job: RepairJob, workspace: str, config: dict, repair_name: str) -> dict:
    limits = module_limits(config)
    return dict(
        _native_tar_boundary_repair(
            source_input_for_job(job),
            workspace,
            repair_name,
            float(limits.get("max_input_size_mb", 512) or 0),
            float(limits.get("max_output_size_mb", 2048) or 0),
            int(limits.get("max_entries", 20000) or 20000),
        )
    )
