from __future__ import annotations

import math

from smart_unpacker.repair.diagnosis import RepairDiagnosis
from smart_unpacker.repair.job import RepairJob
from smart_unpacker.repair.pipeline.module import RepairModuleSpec, RepairRoute
from smart_unpacker.repair.pipeline.modules._common import load_job_source_bytes, patch_plan_for_byte_patches, patch_repair_result
from smart_unpacker.repair.pipeline.registry import register_repair_module
from smart_unpacker.repair.result import RepairResult


class TarHeaderChecksumFix:
    spec = RepairModuleSpec(
        name="tar_header_checksum_fix",
        formats=("tar",),
        categories=("directory_rebuild", "safe_repair"),
        stage="targeted",
        routes=(
            RepairRoute(
                formats=("tar",),
                require_any_categories=("directory_rebuild", "safe_repair"),
                require_any_flags=("tar_checksum_bad", "header_checksum_bad"),
                require_any_failure_kinds=("structure_recognition", "corrupted_data"),
                base_score=0.78,
            ),
        ),
    )

    def can_handle(self, job: RepairJob, diagnosis: RepairDiagnosis, config: dict) -> float:
        flags = set(job.damage_flags)
        if flags & {"tar_checksum_bad", "header_checksum_bad"}:
            return 0.9
        if diagnosis.format == "tar" and "safe_repair" in diagnosis.categories:
            return 0.45
        return 0.0

    def repair(self, job: RepairJob, diagnosis: RepairDiagnosis, workspace: str, config: dict) -> RepairResult:
        data = bytearray(load_job_source_bytes(job))
        fixed = 0
        patches = []
        for offset in _tar_header_offsets(data):
            stored = _parse_octal(data[offset + 148:offset + 156])
            computed = _tar_checksum(data[offset:offset + 512])
            if stored != computed:
                checksum = _format_checksum(computed)
                data[offset + 148:offset + 156] = checksum
                patches.append({"offset": offset + 148, "data": checksum})
                fixed += 1
        if fixed <= 0:
            return RepairResult(status="unrepairable", confidence=0.0, format="tar", module_name=self.spec.name, diagnosis=diagnosis.as_dict(), message="no TAR header checksum mismatch was found")
        actions = ["recompute_tar_header_checksum"]
        patch_plan = patch_plan_for_byte_patches(job, self.spec.name, patches, confidence=0.88, actions=actions)
        return patch_repair_result(
            job=job,
            diagnosis=diagnosis,
            module_name=self.spec.name,
            fmt="tar",
            patch_plan=patch_plan,
            confidence=0.88,
            actions=actions,
            workspace=workspace,
            filename="tar_header_checksum_fix.tar",
            config=config,
            materialized_data=bytes(data),
        )


def _tar_header_offsets(data: bytearray | bytes):
    offset = 0
    while offset + 512 <= len(data):
        header = data[offset:offset + 512]
        if header == b"\0" * 512:
            break
        size = _parse_octal(header[124:136])
        if size is None:
            break
        yield offset
        offset += 512 + int(math.ceil(size / 512) * 512)


def _tar_checksum(header: bytearray | bytes) -> int:
    block = bytearray(header)
    block[148:156] = b"        "
    return sum(block)


def _parse_octal(value: bytes | bytearray) -> int | None:
    text = bytes(value).strip(b"\0 ").decode("ascii", errors="ignore")
    if not text:
        return 0
    try:
        return int(text, 8)
    except ValueError:
        return None


def _format_checksum(value: int) -> bytes:
    return f"{value:06o}\0 ".encode("ascii")


register_repair_module(TarHeaderChecksumFix())
