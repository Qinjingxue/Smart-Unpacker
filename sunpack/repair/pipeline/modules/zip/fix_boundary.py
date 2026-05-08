from __future__ import annotations

from pathlib import Path

from sunpack.repair.coverage import coverage_view_from_job
from sunpack.repair.diagnosis import RepairDiagnosis
from sunpack.repair.job import RepairJob
from sunpack.repair.pipeline.module import RepairModuleSpec, RepairRoute
from sunpack.repair.pipeline.modules._common import source_input_for_job, module_limits
from sunpack.repair.pipeline.registry import register_repair_module
from sunpack.repair.result import RepairResult
from sunpack_native import zip_directory_field_repair as _native_zip_directory_field_repair

from ._rebuild import rebuild_zip_from_source
from ._native_field_result import repair_result_from_native_zip_field


class ZipFixBoundary:
    spec = RepairModuleSpec(
        name="zip_fix_boundary",
        formats=("zip",),
        categories=("directory_rebuild", "boundary_repair"),
        stage="targeted",
        routes=(
            RepairRoute(
                formats=("zip",),
                require_any_categories=("directory_rebuild", "boundary_repair"),
                require_any_flags=(
                    "zip_comment_length_bad", "comment_length_bad", "eocd_bad",
                    "trailing_junk", "boundary_unreliable", "trailing_padding",
                ),
                require_any_fuzzy_hints=("trailing_text_junk_likely", "tail_printable_region", "trailing_padding_likely"),
                reject_any_flags=("wrong_password", "carrier_archive", "embedded_archive", "carrier_prefix"),
                base_score=0.80,
            ),
        ),
    )

    def can_handle(self, job: RepairJob, diagnosis: RepairDiagnosis, config: dict) -> float:
        flags = set(job.damage_flags)
        if flags & {"carrier_archive", "embedded_archive", "carrier_prefix"}:
            return 0.0
        if flags & {"trailing_junk", "boundary_unreliable"}:
            return 0.88
        if "sfx" in flags and flags & {"trailing_junk", "boundary_unreliable"}:
            return 0.70
        if flags & {"zip_comment_length_bad", "comment_length_bad", "eocd_bad"}:
            if flags & {"trailing_junk"}:
                return 0.50
            return 0.90
        if "boundary_repair" in diagnosis.categories:
            return 0.74
        return 0.0

    def repair(self, job: RepairJob, diagnosis: RepairDiagnosis, workspace: str, config: dict) -> RepairResult:
        flags = set(job.damage_flags)
        limits = module_limits(config)
        source_input = source_input_for_job(job)

        if flags & {"trailing_junk", "boundary_unreliable"}:
            repair_name = "zip_trailing_junk_trim"
        else:
            repair_name = "zip_comment_length_fix"

        result = _native_zip_directory_field_repair(
            source_input, workspace, repair_name,
            float(limits.get("max_input_size_mb", 512) or 0),
        )
        if str(dict(result).get("status") or "") != "repaired":
            coverage = coverage_view_from_job(job)
            if coverage.has_recovered_output or flags & {"central_directory_bad", "directory_integrity_bad_or_unknown"} or True:
                output = Path(workspace) / "zip_fix_boundary_fallback.zip"
                scan = rebuild_zip_from_source(source_input, output, config=config)
                if scan.entries and scan.complete:
                    return RepairResult(
                        status="repaired", confidence=0.82, format="zip",
                        repaired_input={"kind": "file", "path": str(output), "format_hint": "zip"},
                        actions=["native_rebuild_zip_from_local_headers"],
                        damage_flags=list(job.damage_flags), warnings=scan.warnings,
                        workspace_paths=[str(output)], module_name=self.spec.name,
                        diagnosis={**diagnosis.as_dict(), "native_zip_rebuild": scan.__dict__},
                        message="ZIP rebuilt from local headers after boundary repair could not trust the directory",
                    )
        return repair_result_from_native_zip_field(self.spec.name, dict(result), job, diagnosis, config)


# Legacy coarse module kept for historical imports only. ZIP repair registration
# now happens through atomic.py.
