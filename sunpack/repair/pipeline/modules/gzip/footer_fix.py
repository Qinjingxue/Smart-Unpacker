from __future__ import annotations

from sunpack.repair.diagnosis import RepairDiagnosis
from sunpack.repair.job import RepairJob
from sunpack.repair.pipeline.module import RepairModuleSpec, RepairRoute
from sunpack.repair.pipeline.modules._common import source_input_for_job, module_limits
from sunpack.repair.pipeline.modules._native_patch_result import native_patch_repair_result
from sunpack.repair.pipeline.registry import register_repair_module
from sunpack.repair.result import RepairResult
from sunpack_native import gzip_footer_fix_repair as _native_gzip_footer_fix_repair


_BOUNDARY_UNTRUSTED_FLAGS = {"trailing_junk", "trailing_padding", "boundary_unreliable"}


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
        if flags & _BOUNDARY_UNTRUSTED_FLAGS and "gzip_footer_bad" not in flags:
            return 0.0
        if flags & {"damaged", "data_error"} and not flags & {"gzip_footer_bad", "crc_error"}:
            return 0.0
        if flags & {"gzip_footer_bad", "crc_error", "checksum_error"}:
            return 0.88
        if "content_recovery" in diagnosis.categories:
            return 0.62
        return 0.0

    def repair(self, job: RepairJob, diagnosis: RepairDiagnosis, workspace: str, config: dict) -> RepairResult:
        limits = module_limits(config)
        try:
            result = dict(
                _native_gzip_footer_fix_repair(
                    source_input_for_job(job),
                    workspace,
                    float(limits.get("max_input_size_mb", 512) or 0),
                    float(limits.get("max_seconds_per_module", 30.0) or 0),
                    float(limits.get("max_gzip_footer_fix_decode_mb", 32) or 0),
                )
            )
        except TypeError:
            result = dict(
                _native_gzip_footer_fix_repair(
                    source_input_for_job(job),
                    workspace,
                    float(limits.get("max_input_size_mb", 512) or 0),
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
