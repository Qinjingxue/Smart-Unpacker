from __future__ import annotations

from smart_unpacker.repair.diagnosis import RepairDiagnosis
from smart_unpacker.repair.job import RepairJob
from smart_unpacker.repair.pipeline.module import RepairModuleSpec, RepairRoute
from smart_unpacker.repair.pipeline.modules._common import (
    load_job_source_bytes,
    patch_diagnosis,
    patch_plan_for_truncate,
    patch_plan_for_truncate_append,
    patched_state_for_job,
    should_materialize_candidate,
    virtual_patch_repaired_input,
    write_candidate,
)
from smart_unpacker.repair.pipeline.registry import register_repair_module
from smart_unpacker.repair.result import RepairResult

from ._directory import find_eocd, find_valid_central_directory, rewrite_eocd, trim_to_eocd, walk_central_directory


class ZipEocdRepair:
    spec = RepairModuleSpec(
        name="zip_eocd_repair",
        formats=("zip",),
        categories=("directory_rebuild", "boundary_repair"),
        stage="targeted",
        routes=(
            RepairRoute(
                formats=("zip",),
                require_any_flags=("eocd_bad", "central_directory_bad", "directory_integrity_bad_or_unknown"),
                require_any_failure_kinds=("structure_recognition", "corrupted_data"),
                reject_any_flags=("wrong_password", "carrier_archive", "sfx", "embedded_archive", "carrier_prefix"),
                base_score=0.82,
            ),
        ),
    )

    def can_handle(self, job: RepairJob, diagnosis: RepairDiagnosis, config: dict) -> float:
        flags = set(job.damage_flags)
        if flags & {"carrier_archive", "sfx", "embedded_archive", "carrier_prefix"}:
            return 0.0
        if flags & {"eocd_bad", "central_directory_bad", "directory_integrity_bad_or_unknown"}:
            return 0.97 if "eocd_bad" in flags else 0.9
        return 0.0

    def repair(self, job: RepairJob, diagnosis: RepairDiagnosis, workspace: str, config: dict) -> RepairResult:
        data = load_job_source_bytes(job)
        eocd = find_eocd(data, allow_trailing_junk=True)
        if eocd is not None:
            cd = walk_central_directory(data, eocd.cd_offset, expected_end=eocd.cd_offset + eocd.cd_size)
            if cd.valid:
                repaired = trim_to_eocd(data, eocd)
                if repaired == data:
                    return _failed(self.spec.name, diagnosis, "EOCD and central directory already look consistent")
                actions = ["trim_after_eocd"]
                patch_plan = patch_plan_for_truncate(job, self.spec.name, eocd.end, confidence=0.9, actions=actions)
                repaired_state = patched_state_for_job(job, patch_plan)
                path = "" if not should_materialize_candidate(config) else write_candidate(repaired, workspace, "zip_eocd_repair.zip")
                return _ok(self.spec.name, diagnosis, job, path, 0.9, actions, patch_plan=patch_plan, repaired_state=repaired_state)

        cd = find_valid_central_directory(data)
        if cd is None:
            return _failed(self.spec.name, diagnosis, "no valid central directory was found for EOCD rebuild")
        repaired = rewrite_eocd(data, cd)
        actions = ["scan_central_directory", "rebuild_eocd"]
        patch_plan = patch_plan_for_truncate_append(job, self.spec.name, cd.end, repaired[cd.end:], confidence=0.94, actions=actions)
        repaired_state = patched_state_for_job(job, patch_plan)
        path = "" if not should_materialize_candidate(config) else write_candidate(repaired, workspace, "zip_eocd_repair.zip")
        return _ok(self.spec.name, diagnosis, job, path, 0.94, actions, patch_plan=patch_plan, repaired_state=repaired_state)


def _ok(module_name, diagnosis, job, path, confidence, actions, *, patch_plan=None, repaired_state=None):
    diagnosis_payload = diagnosis.as_dict()
    if patch_plan is not None and repaired_state is not None:
        diagnosis_payload = patch_diagnosis(diagnosis_payload, patch_plan, repaired_state)
    return RepairResult(
        status="repaired",
        confidence=confidence,
        format="zip",
        repaired_input={"kind": "file", "path": path, "format_hint": "zip"} if path else virtual_patch_repaired_input(repaired_state),
        actions=actions,
        damage_flags=list(job.damage_flags),
        workspace_paths=[path] if path else [],
        module_name=module_name,
        diagnosis=diagnosis_payload,
        repaired_state=repaired_state,
    )


def _failed(module_name, diagnosis, message):
    return RepairResult(
        status="unrepairable",
        confidence=0.0,
        format="zip",
        module_name=module_name,
        diagnosis=diagnosis.as_dict(),
        message=message,
    )


register_repair_module(ZipEocdRepair())
