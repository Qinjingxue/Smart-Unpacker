from __future__ import annotations

from smart_unpacker.repair.diagnosis import RepairDiagnosis
from smart_unpacker.repair.job import RepairJob
from smart_unpacker.repair.pipeline.module import RepairModuleSpec, RepairRoute
from pathlib import Path

from smart_unpacker.repair.pipeline.modules._common import (
    copy_source_prefix_to_file,
    load_job_source_bytes,
    patch_diagnosis,
    patch_plan_for_truncate,
    patched_state_for_job,
    should_materialize_candidate,
    virtual_patch_repaired_input,
    write_candidate,
)
from smart_unpacker.repair.pipeline.registry import register_repair_module
from smart_unpacker.repair.result import RepairResult

from ._directory import find_eocd


class ZipTrailingJunkTrim:
    spec = RepairModuleSpec(
        name="zip_trailing_junk_trim",
        formats=("zip",),
        categories=("boundary_repair",),
        stage="safe_repair",
        routes=(
            RepairRoute(
                formats=("zip",),
                require_any_categories=("boundary_repair",),
                require_any_flags=("trailing_junk", "boundary_unreliable", "trailing_padding"),
                require_any_fuzzy_hints=("trailing_text_junk_likely", "trailing_padding_likely", "tail_printable_region"),
                reject_any_flags=("wrong_password", "carrier_archive", "sfx", "embedded_archive", "carrier_prefix"),
                base_score=0.82,
            ),
        ),
    )

    def can_handle(self, job: RepairJob, diagnosis: RepairDiagnosis, config: dict) -> float:
        flags = set(job.damage_flags)
        if flags & {"carrier_archive", "sfx", "embedded_archive", "carrier_prefix"}:
            return 0.0
        if flags & {"trailing_junk", "boundary_unreliable"}:
            return 0.88
        if "boundary_repair" in diagnosis.categories:
            return 0.74
        return 0.0

    def repair(self, job: RepairJob, diagnosis: RepairDiagnosis, workspace: str, config: dict) -> RepairResult:
        data = load_job_source_bytes(job)
        eocd = find_eocd(data, allow_trailing_junk=True)
        if eocd is None:
            return RepairResult(
                status="unrepairable",
                confidence=0.0,
                format="zip",
                module_name=self.spec.name,
                diagnosis=diagnosis.as_dict(),
                message="EOCD was not found",
            )
        if eocd.end == len(data):
            return RepairResult(
                status="unrepairable",
                confidence=0.0,
                format="zip",
                module_name=self.spec.name,
                diagnosis=diagnosis.as_dict(),
                message="no trailing bytes after EOCD",
            )
        actions = ["trim_after_eocd"]
        patch_plan = patch_plan_for_truncate(job, self.spec.name, eocd.end, confidence=0.88, actions=actions)
        repaired_state = patched_state_for_job(job, patch_plan)
        if not should_materialize_candidate(config):
            path = ""
            repaired_input = virtual_patch_repaired_input(repaired_state)
        elif job.archive_state and job.archive_state.patches:
            path = write_candidate(data[:eocd.end], workspace, "zip_trailing_junk_trim.zip")
            repaired_input = {"kind": "file", "path": path, "format_hint": "zip"}
        else:
            path = copy_source_prefix_to_file(
                job.source_input,
                eocd.end,
                str(Path(workspace) / "zip_trailing_junk_trim.zip"),
            )
            repaired_input = {"kind": "file", "path": path, "format_hint": "zip"}
        return RepairResult(
            status="repaired",
            confidence=0.88,
            format="zip",
            repaired_input=repaired_input,
            actions=actions,
            damage_flags=list(job.damage_flags),
            workspace_paths=[path] if path else [],
            module_name=self.spec.name,
            diagnosis=patch_diagnosis(diagnosis.as_dict(), patch_plan, repaired_state),
            repaired_state=repaired_state,
        )


register_repair_module(ZipTrailingJunkTrim())
