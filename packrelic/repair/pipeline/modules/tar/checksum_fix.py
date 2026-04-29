from __future__ import annotations

from packrelic.repair.diagnosis import RepairDiagnosis
from packrelic.repair.job import RepairJob
from packrelic.repair.pipeline.module import RepairModuleSpec, RepairRoute
from packrelic.repair.pipeline.modules._common import source_input_for_job
from packrelic.repair.pipeline.modules._native_patch_result import native_patch_repair_result
from packrelic.repair.pipeline.registry import register_repair_module
from packrelic.repair.result import RepairResult
from packrelic_native import tar_boundary_repair as _native_tar_boundary_repair


class TarHeaderChecksumFix:
    spec = RepairModuleSpec(
        name="tar_header_checksum_fix",
        formats=("tar",),
        categories=("directory_rebuild", "safe_repair"),
        stage="targeted",
        routes=(
            RepairRoute(
                formats=("tar",),
                require_any_categories=("directory_rebuild", "safe_repair"),
                require_any_flags=("tar_checksum_bad", "header_checksum_bad"),
                require_any_failure_kinds=("structure_recognition", "corrupted_data"),
                base_score=0.78,
            ),
        ),
    )

    def can_handle(self, job: RepairJob, diagnosis: RepairDiagnosis, config: dict) -> float:
        flags = set(job.damage_flags)
        if flags & {"tar_checksum_bad", "header_checksum_bad"}:
            return 0.9
        if diagnosis.format == "tar" and "safe_repair" in diagnosis.categories:
            return 0.45
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


def _run_native_tar_boundary(job: RepairJob, workspace: str, config: dict, repair_name: str) -> dict:
    deep = config.get("deep") if isinstance(config.get("deep"), dict) else {}
    return dict(
        _native_tar_boundary_repair(
            source_input_for_job(job),
            workspace,
            repair_name,
            float(deep.get("max_input_size_mb", 512) or 0),
            float(deep.get("max_output_size_mb", 2048) or 0),
            int(deep.get("max_entries", 20000) or 20000),
        )
    )


register_repair_module(TarHeaderChecksumFix())
