from __future__ import annotations

from packrelic.repair.diagnosis import RepairDiagnosis
from packrelic.repair.job import RepairJob
from packrelic.repair.pipeline.module import RepairModuleSpec, RepairRoute
from packrelic.repair.pipeline.modules._common import source_input_for_job
from packrelic.repair.pipeline.registry import register_repair_module
from packrelic.repair.result import RepairResult
from packrelic.repair.pipeline.modules.zip._rebuild import rebuild_zip_from_source
from packrelic_native import zip_directory_field_repair as _native_zip_directory_field_repair

from ._native_field_result import repair_result_from_native_zip_field


class ZipCommentLengthFix:
    spec = RepairModuleSpec(
        name="zip_comment_length_fix",
        formats=("zip",),
        categories=("directory_rebuild", "boundary_repair"),
        stage="targeted",
        routes=(
            RepairRoute(
                formats=("zip",),
                require_any_categories=("directory_rebuild", "boundary_repair"),
                require_any_flags=("zip_comment_length_bad", "comment_length_bad", "eocd_bad", "trailing_junk"),
                require_any_fuzzy_hints=("trailing_text_junk_likely", "tail_printable_region"),
                reject_any_flags=("wrong_password", "carrier_archive", "sfx", "embedded_archive", "carrier_prefix"),
                base_score=0.78,
            ),
        ),
    )

    def can_handle(self, job: RepairJob, diagnosis: RepairDiagnosis, config: dict) -> float:
        flags = set(job.damage_flags)
        if flags & {"carrier_archive", "sfx", "embedded_archive", "carrier_prefix"}:
            return 0.0
        if flags & {"zip_comment_length_bad", "comment_length_bad", "eocd_bad"}:
            return 0.9
        if "directory_rebuild" in diagnosis.categories:
            return 0.55
        return 0.0

    def repair(self, job: RepairJob, diagnosis: RepairDiagnosis, workspace: str, config: dict) -> RepairResult:
        deep = config.get("deep") if isinstance(config.get("deep"), dict) else {}
        result = _native_zip_directory_field_repair(
            source_input_for_job(job),
            workspace,
            self.spec.name,
            float(deep.get("max_input_size_mb", 512) or 0),
        )
        if str(dict(result).get("status") or "") != "repaired":
            from pathlib import Path

            output = Path(workspace) / "zip_comment_length_fix.zip"
            scan = rebuild_zip_from_source(source_input_for_job(job), output, config=config)
            if scan.entries and scan.complete:
                return RepairResult(
                    status="repaired",
                    confidence=0.82,
                    format="zip",
                    repaired_input={"kind": "file", "path": str(output), "format_hint": "zip"},
                    actions=["native_rebuild_zip_from_local_headers"],
                    damage_flags=list(job.damage_flags),
                    warnings=scan.warnings,
                    workspace_paths=[str(output)],
                    module_name=self.spec.name,
                    diagnosis={**diagnosis.as_dict(), "native_zip_rebuild": scan.__dict__},
                    message="ZIP was rebuilt natively from local headers after EOCD comment repair could not trust the directory",
                )
        return repair_result_from_native_zip_field(self.spec.name, dict(result), job, diagnosis, config)


register_repair_module(ZipCommentLengthFix())
