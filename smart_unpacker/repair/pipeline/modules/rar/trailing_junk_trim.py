from __future__ import annotations

from smart_unpacker.repair.diagnosis import RepairDiagnosis
from smart_unpacker.repair.job import RepairJob
from smart_unpacker.repair.pipeline.module import RepairModuleSpec, RepairRoute

from smart_unpacker.repair.pipeline.modules._common import load_job_source_bytes, patch_plan_for_truncate, patch_repair_result
from smart_unpacker.repair.pipeline.registry import register_repair_module
from smart_unpacker.repair.result import RepairResult

from ._structure import walk_rar_blocks


class RarTrailingJunkTrim:
    spec = RepairModuleSpec(
        name="rar_trailing_junk_trim",
        formats=("rar",),
        categories=("boundary_repair",),
        stage="safe_repair",
        routes=(
            RepairRoute(
                formats=("rar",),
                require_any_categories=("boundary_repair",),
                require_any_flags=("trailing_junk", "boundary_unreliable", "trailing_padding"),
                require_any_fuzzy_hints=("trailing_text_junk_likely", "trailing_padding_likely"),
                base_score=0.76,
            ),
        ),
    )

    def can_handle(self, job: RepairJob, diagnosis: RepairDiagnosis, config: dict) -> float:
        flags = set(job.damage_flags)
        if flags & {"trailing_junk", "boundary_unreliable"}:
            return 0.84
        if "boundary_repair" in diagnosis.categories:
            return 0.68
        return 0.0

    def repair(self, job: RepairJob, diagnosis: RepairDiagnosis, workspace: str, config: dict) -> RepairResult:
        data = load_job_source_bytes(job)
        walk = walk_rar_blocks(data)
        if walk is None:
            return RepairResult(status="unrepairable", confidence=0.0, format="rar", module_name=self.spec.name, diagnosis=diagnosis.as_dict(), message="RAR signature was not found at input start")
        if not walk.end_block_found or walk.end_offset is None:
            return RepairResult(status="unrepairable", confidence=0.0, format="rar", module_name=self.spec.name, diagnosis=diagnosis.as_dict(), warnings=walk.warnings, message="RAR end block was not found")
        if walk.end_offset == len(data):
            return RepairResult(status="unrepairable", confidence=0.0, format="rar", module_name=self.spec.name, diagnosis=diagnosis.as_dict(), message="no trailing bytes after RAR end block")
        actions = [f"walk_rar{walk.version}_blocks", "trim_after_rar_end_block"]
        patch_plan = patch_plan_for_truncate(job, self.spec.name, walk.end_offset, confidence=0.86, actions=actions)
        return patch_repair_result(
            job=job,
            diagnosis=diagnosis,
            module_name=self.spec.name,
            fmt="rar",
            patch_plan=patch_plan,
            confidence=0.86,
            warnings=walk.warnings,
            actions=actions,
            workspace=workspace,
            filename="rar_trailing_junk_trim.rar",
            config=config,
            materialized_data=data[:walk.end_offset],
        )


register_repair_module(RarTrailingJunkTrim())
