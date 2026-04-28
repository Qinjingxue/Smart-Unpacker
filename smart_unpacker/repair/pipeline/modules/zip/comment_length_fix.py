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

from ._directory import walk_central_directory
from ._rebuild import EOCD_SIG


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
                base_score=0.78,
            ),
        ),
    )

    def can_handle(self, job: RepairJob, diagnosis: RepairDiagnosis, config: dict) -> float:
        flags = set(job.damage_flags)
        if flags & {"zip_comment_length_bad", "comment_length_bad", "eocd_bad"}:
            return 0.9
        if "directory_rebuild" in diagnosis.categories:
            return 0.55
        return 0.0

    def repair(self, job: RepairJob, diagnosis: RepairDiagnosis, workspace: str, config: dict) -> RepairResult:
        data = load_job_source_bytes(job)
        offset = data.rfind(EOCD_SIG)
        if offset < 0 or offset + 22 > len(data):
            return _failed(self.spec.name, diagnosis, "EOCD fixed header was not found")
        try:
            cd_size = struct.unpack_from("<I", data, offset + 12)[0]
            cd_offset = struct.unpack_from("<I", data, offset + 16)[0]
            stored_comment_len = struct.unpack_from("<H", data, offset + 20)[0]
        except struct.error:
            return _failed(self.spec.name, diagnosis, "EOCD fixed fields are incomplete")
        cd = walk_central_directory(data, cd_offset, expected_end=cd_offset + cd_size)
        if not cd.valid:
            return _failed(self.spec.name, diagnosis, "central directory range is not trusted")
        actual_comment_len = len(data) - offset - 22
        if actual_comment_len < 0 or actual_comment_len > 0xFFFF:
            return _failed(self.spec.name, diagnosis, "actual ZIP comment length is out of range")
        if stored_comment_len == actual_comment_len:
            return _failed(self.spec.name, diagnosis, "ZIP comment length already matches file length")
        output_path = str(Path(workspace) / "zip_comment_length_fix.zip")
        patch = {"offset": offset + 20, "data": struct.pack("<H", actual_comment_len)}
        actions = ["patch_zip_eocd_comment_length"]
        patch_plan = patch_plan_for_byte_patches(job, self.spec.name, [patch], confidence=0.86, actions=actions)
        repaired_state = patched_state_for_job(job, patch_plan)
        if not should_materialize_candidate(config):
            path = ""
            repaired_input = virtual_patch_repaired_input(repaired_state)
        elif str(job.source_input.get("kind") or "file") == "file" and not (job.archive_state and job.archive_state.patches):
            path = patch_file(str(job.source_input["path"]), [patch], output_path)
            repaired_input = {"kind": "file", "path": path, "format_hint": "zip"}
        else:
            repaired = bytearray(data)
            repaired[offset + 20:offset + 22] = patch["data"]
            path = write_candidate(bytes(repaired), workspace, "zip_comment_length_fix.zip")
            repaired_input = {"kind": "file", "path": path, "format_hint": "zip"}
        return RepairResult(
            status="repaired",
            confidence=0.86,
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


register_repair_module(ZipCommentLengthFix())
