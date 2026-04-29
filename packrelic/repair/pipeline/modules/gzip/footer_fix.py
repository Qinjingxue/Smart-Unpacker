from __future__ import annotations

from packrelic.repair.diagnosis import RepairDiagnosis
from packrelic.repair.job import RepairJob
from packrelic.repair.pipeline.module import RepairModuleSpec, RepairRoute
from packrelic.repair.pipeline.modules._common import source_input_for_job
from packrelic.repair.pipeline.modules._native_patch_result import native_patch_repair_result
from packrelic.repair.pipeline.registry import register_repair_module
from packrelic.repair.result import RepairResult
from packrelic_native import gzip_footer_fix_repair as _native_gzip_footer_fix_repair


class GzipFooterFix:
    spec = RepairModuleSpec(
        name="gzip_footer_fix",
        formats=("gzip", "gz"),
        categories=("content_recovery", "boundary_repair"),
        stage="targeted",
        routes=(
            RepairRoute(
                formats=("gzip", "gz"),
                require_any_categories=("content_recovery",),
                require_any_flags=("gzip_footer_bad", "crc_error", "checksum_error"),
                require_any_failure_kinds=("checksum_error", "corrupted_data", "data_error"),
                reject_any_flags=("damaged", "data_error"),
                base_score=0.78,
            ),
        ),
    )

    def can_handle(self, job: RepairJob, diagnosis: RepairDiagnosis, config: dict) -> float:
        flags = set(job.damage_flags)
        if flags & {"damaged", "data_error"} and not flags & {"gzip_footer_bad", "crc_error"}:
            return 0.0
        if flags & {"gzip_footer_bad", "crc_error", "checksum_error"}:
            return 0.88
        if "content_recovery" in diagnosis.categories:
            return 0.62
        return 0.0

    def repair(self, job: RepairJob, diagnosis: RepairDiagnosis, workspace: str, config: dict) -> RepairResult:
        deep = config.get("deep") if isinstance(config.get("deep"), dict) else {}
        result = dict(
            _native_gzip_footer_fix_repair(
                source_input_for_job(job),
                workspace,
                float(deep.get("max_input_size_mb", 512) or 0),
            )
        )
        return native_patch_repair_result(
            module_name=self.spec.name,
            fmt="gzip",
            native_key="native_gzip_footer_fix",
            result=result,
            job=job,
            diagnosis=diagnosis,
            config=config,
        )


register_repair_module(GzipFooterFix())
