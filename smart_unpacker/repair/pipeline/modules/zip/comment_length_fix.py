from __future__ import annotations

from pathlib import Path
import struct

from smart_unpacker.repair.diagnosis import RepairDiagnosis
from smart_unpacker.repair.job import RepairJob
from smart_unpacker.repair.pipeline.module import RepairModuleSpec
from smart_unpacker.repair.pipeline.modules._common import load_source_bytes, patch_file, write_candidate
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
    )

    def can_handle(self, job: RepairJob, diagnosis: RepairDiagnosis, config: dict) -> float:
        flags = set(job.damage_flags)
        if flags & {"zip_comment_length_bad", "comment_length_bad", "eocd_bad"}:
            return 0.9
        if "directory_rebuild" in diagnosis.categories:
            return 0.55
        return 0.0

    def repair(self, job: RepairJob, diagnosis: RepairDiagnosis, workspace: str, config: dict) -> RepairResult:
        data = load_source_bytes(job.source_input)
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
        if str(job.source_input.get("kind") or "file") == "file":
            path = patch_file(str(job.source_input["path"]), [patch], output_path)
        else:
            repaired = bytearray(data)
            repaired[offset + 20:offset + 22] = patch["data"]
            path = write_candidate(bytes(repaired), workspace, "zip_comment_length_fix.zip")
        return RepairResult(
            status="repaired",
            confidence=0.86,
            format="zip",
            repaired_input={"kind": "file", "path": path, "format_hint": "zip"},
            actions=["patch_zip_eocd_comment_length"],
            damage_flags=list(job.damage_flags),
            workspace_paths=[path],
            module_name=self.spec.name,
            diagnosis=diagnosis.as_dict(),
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
