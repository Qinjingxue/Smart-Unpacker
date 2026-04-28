from __future__ import annotations

from smart_unpacker.repair.diagnosis import RepairDiagnosis
from smart_unpacker.repair.job import RepairJob
from smart_unpacker.repair.pipeline.module import RepairModuleSpec, RepairRoute
from smart_unpacker.repair.pipeline.modules._common import load_job_source_bytes, patch_plan_for_truncate, patch_repair_result
from smart_unpacker.repair.pipeline.registry import register_repair_module
from smart_unpacker.repair.result import RepairResult

from .trailing_zero_repair import _canonical_tar_end, _walk_payload_end


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
        data = load_job_source_bytes(job)
        payload_end = _walk_payload_end(data)
        if payload_end is None:
            return RepairResult(status="unrepairable", confidence=0.0, format="tar", module_name=self.spec.name, diagnosis=diagnosis.as_dict(), message="TAR entries could not be walked safely")
        end = _canonical_tar_end(data, payload_end)
        if end - payload_end < 1024:
            return RepairResult(status="unrepairable", confidence=0.0, format="tar", module_name=self.spec.name, diagnosis=diagnosis.as_dict(), message="TAR does not have two trusted trailing zero blocks")
        if end == len(data):
            return RepairResult(status="unrepairable", confidence=0.0, format="tar", module_name=self.spec.name, diagnosis=diagnosis.as_dict(), message="no trailing bytes after TAR zero blocks")
        actions = ["trim_after_tar_zero_blocks"]
        patch_plan = patch_plan_for_truncate(job, self.spec.name, end, confidence=0.86, actions=actions)
        return patch_repair_result(
            job=job,
            diagnosis=diagnosis,
            module_name=self.spec.name,
            fmt="tar",
            patch_plan=patch_plan,
            confidence=0.86,
            actions=actions,
            workspace=workspace,
            filename="tar_trailing_junk_trim.tar",
            config=config,
            materialized_data=data[:end],
        )


register_repair_module(TarTrailingJunkTrim())
