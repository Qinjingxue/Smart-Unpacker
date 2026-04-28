from __future__ import annotations

from pathlib import Path
import struct

from smart_unpacker.repair.diagnosis import RepairDiagnosis
from smart_unpacker.repair.job import RepairJob
from smart_unpacker.repair.pipeline.module import RepairModuleSpec, RepairRoute
from smart_unpacker.repair.pipeline.modules._common import (
    load_job_source_bytes,
    patch_diagnosis,
    patch_file,
    patch_plan_for_byte_patches,
    patched_state_for_job,
    should_materialize_candidate,
    virtual_patch_repaired_input,
    write_candidate,
)
from smart_unpacker.repair.pipeline.registry import register_repair_module
from smart_unpacker.repair.result import RepairResult

from ._directory import find_eocd, walk_central_directory


class ZipCentralDirectoryCountFix:
    spec = RepairModuleSpec(
        name="zip_central_directory_count_fix",
        formats=("zip",),
        categories=("directory_rebuild",),
        stage="targeted",
        routes=(
            RepairRoute(
                formats=("zip",),
                require_any_flags=("central_directory_count_bad", "central_directory_bad"),
                require_any_failure_kinds=("structure_recognition",),
                base_score=0.78,
            ),
        ),
    )

    def can_handle(self, job: RepairJob, diagnosis: RepairDiagnosis, config: dict) -> float:
        flags = set(job.damage_flags)
        if flags & {"central_directory_count_bad", "central_directory_bad"}:
            return 0.88
        return 0.0

    def repair(self, job: RepairJob, diagnosis: RepairDiagnosis, workspace: str, config: dict) -> RepairResult:
        data = load_job_source_bytes(job)
        eocd = find_eocd(data, allow_trailing_junk=False)
        if eocd is None:
            return _failed(self.spec.name, diagnosis, "trusted EOCD was not found")
        cd = walk_central_directory(data, eocd.cd_offset, expected_end=eocd.cd_offset + eocd.cd_size)
        if not cd.valid:
            return _failed(self.spec.name, diagnosis, "central directory range is not trusted")
        if eocd.disk_entries == cd.count and eocd.total_entries == cd.count:
            return _failed(self.spec.name, diagnosis, "central directory count already matches walked entries")
        if cd.count > 0xFFFF:
            return _failed(self.spec.name, diagnosis, "ZIP64 central directory count patch is not supported here")
        output_path = str(Path(workspace) / "zip_central_directory_count_fix.zip")
        patches = [
            {"offset": eocd.offset + 8, "data": struct.pack("<H", cd.count)},
            {"offset": eocd.offset + 10, "data": struct.pack("<H", cd.count)},
        ]
        actions = ["patch_zip_eocd_entry_counts"]
        patch_plan = patch_plan_for_byte_patches(job, self.spec.name, patches, confidence=0.88, actions=actions)
        repaired_state = patched_state_for_job(job, patch_plan)
        if not should_materialize_candidate(config):
            path = ""
            repaired_input = virtual_patch_repaired_input(repaired_state)
        elif str(job.source_input.get("kind") or "file") == "file" and not (job.archive_state and job.archive_state.patches):
            path = patch_file(str(job.source_input["path"]), patches, output_path)
            repaired_input = {"kind": "file", "path": path, "format_hint": "zip"}
        else:
            repaired = bytearray(data)
            for patch in patches:
                offset = patch["offset"]
                repaired[offset:offset + 2] = patch["data"]
            path = write_candidate(bytes(repaired), workspace, "zip_central_directory_count_fix.zip")
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


def _failed(module_name, diagnosis, message):
    return RepairResult(
        status="unrepairable",
        confidence=0.0,
        format="zip",
        module_name=module_name,
        diagnosis=diagnosis.as_dict(),
        message=message,
    )


register_repair_module(ZipCentralDirectoryCountFix())
