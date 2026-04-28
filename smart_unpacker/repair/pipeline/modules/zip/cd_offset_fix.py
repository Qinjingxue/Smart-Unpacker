from __future__ import annotations

from smart_unpacker.repair.diagnosis import RepairDiagnosis
from smart_unpacker.repair.job import RepairJob
from smart_unpacker.repair.pipeline.module import RepairModuleSpec, RepairRoute
from smart_unpacker.repair.pipeline.modules._common import (
    load_job_source_bytes,
    patch_diagnosis,
    patch_plan_for_truncate_append,
    patched_state_for_job,
    should_materialize_candidate,
    virtual_patch_repaired_input,
    write_candidate,
)
from smart_unpacker.repair.pipeline.registry import register_repair_module
from smart_unpacker.repair.result import RepairResult

from ._directory import find_eocd, find_valid_central_directory, rewrite_eocd


class ZipCentralDirectoryOffsetFix:
    spec = RepairModuleSpec(
        name="zip_central_directory_offset_fix",
        formats=("zip",),
        categories=("directory_rebuild",),
        stage="targeted",
        routes=(
            RepairRoute(
                formats=("zip",),
                require_any_flags=("central_directory_offset_bad", "central_directory_bad"),
                require_any_failure_kinds=("structure_recognition",),
                base_score=0.8,
            ),
        ),
    )

    def can_handle(self, job: RepairJob, diagnosis: RepairDiagnosis, config: dict) -> float:
        flags = set(job.damage_flags)
        if flags & {"carrier_archive", "sfx", "embedded_archive", "carrier_prefix"}:
            return 0.0
        if flags & {"central_directory_offset_bad", "central_directory_bad"}:
            return 0.92
        return 0.0

    def repair(self, job: RepairJob, diagnosis: RepairDiagnosis, workspace: str, config: dict) -> RepairResult:
        data = load_job_source_bytes(job)
        eocd = find_eocd(data, allow_trailing_junk=True)
        cd = find_valid_central_directory(data)
        if eocd is None or cd is None:
            return RepairResult(
                status="unrepairable",
                confidence=0.0,
                format="zip",
                module_name=self.spec.name,
                diagnosis=diagnosis.as_dict(),
                message="EOCD or central directory is missing",
            )
        if eocd.cd_offset == cd.offset and eocd.cd_size == cd.end - cd.offset and eocd.total_entries == cd.count:
            return RepairResult(
                status="unrepairable",
                confidence=0.0,
                format="zip",
                module_name=self.spec.name,
                diagnosis=diagnosis.as_dict(),
                message="central directory offset already matches parsed central directory",
            )
        repaired = rewrite_eocd(data, cd, comment=eocd.comment)
        actions = ["scan_central_directory", "rewrite_eocd_cd_offset_size_count"]
        patch_plan = patch_plan_for_truncate_append(job, self.spec.name, cd.end, repaired[cd.end:], confidence=0.9, actions=actions)
        repaired_state = patched_state_for_job(job, patch_plan)
        if should_materialize_candidate(config):
            path = write_candidate(repaired, workspace, "zip_central_directory_offset_fix.zip")
            repaired_input = {"kind": "file", "path": path, "format_hint": "zip"}
        else:
            path = ""
            repaired_input = virtual_patch_repaired_input(repaired_state)
        return RepairResult(
            status="repaired",
            confidence=0.9,
            format="zip",
            repaired_input=repaired_input,
            actions=actions,
            damage_flags=list(job.damage_flags),
            workspace_paths=[path] if path else [],
            module_name=self.spec.name,
            diagnosis=patch_diagnosis(diagnosis.as_dict(), patch_plan, repaired_state),
            repaired_state=repaired_state,
        )


register_repair_module(ZipCentralDirectoryOffsetFix())
