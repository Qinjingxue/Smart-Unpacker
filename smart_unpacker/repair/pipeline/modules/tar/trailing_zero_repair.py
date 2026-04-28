from __future__ import annotations

import math

from smart_unpacker.repair.diagnosis import RepairDiagnosis
from smart_unpacker.repair.job import RepairJob
from smart_unpacker.repair.pipeline.module import RepairModuleSpec, RepairRoute
from smart_unpacker.repair.pipeline.modules._common import load_job_source_bytes, patch_plan_for_truncate, patch_plan_for_truncate_append, patch_repair_result
from smart_unpacker.repair.pipeline.registry import register_repair_module
from smart_unpacker.repair.result import RepairResult


class TarTrailingZeroBlockRepair:
    spec = RepairModuleSpec(
        name="tar_trailing_zero_block_repair",
        formats=("tar",),
        categories=("boundary_repair",),
        stage="safe_repair",
        routes=(
            RepairRoute(
                formats=("tar",),
                require_any_categories=("boundary_repair",),
                require_any_flags=("missing_end_block", "probably_truncated", "boundary_unreliable", "trailing_padding"),
                require_any_fuzzy_hints=("trailing_padding_likely",),
                require_any_failure_kinds=("unexpected_end",),
                base_score=0.74,
            ),
        ),
    )

    def can_handle(self, job: RepairJob, diagnosis: RepairDiagnosis, config: dict) -> float:
        flags = set(job.damage_flags)
        if flags & {"missing_end_block", "probably_truncated", "boundary_unreliable"}:
            return 0.82
        if diagnosis.format == "tar" and "boundary_repair" in diagnosis.categories:
            return 0.7
        return 0.0

    def repair(self, job: RepairJob, diagnosis: RepairDiagnosis, workspace: str, config: dict) -> RepairResult:
        data = load_job_source_bytes(job)
        payload_end = _walk_payload_end(data)
        if payload_end is None:
            return RepairResult(status="unrepairable", confidence=0.0, format="tar", module_name=self.spec.name, diagnosis=diagnosis.as_dict(), message="TAR entries could not be walked safely")
        end = _canonical_tar_end(data, payload_end)
        zero_bytes_present = max(0, end - payload_end)
        missing_zeros = max(0, 1024 - min(1024, zero_bytes_present))
        if end == len(data) and missing_zeros == 0:
            return RepairResult(status="unrepairable", confidence=0.0, format="tar", module_name=self.spec.name, diagnosis=diagnosis.as_dict(), message="TAR already has canonical zero block ending")
        actions = ["trim_or_append_tar_zero_blocks"]
        if missing_zeros == 0:
            repaired = data[:end]
            patch_plan = patch_plan_for_truncate(job, self.spec.name, end, confidence=0.84, actions=actions)
        else:
            repaired = data[:end] + (b"\0" * missing_zeros)
            patch_plan = patch_plan_for_truncate_append(job, self.spec.name, end, b"\0" * missing_zeros, confidence=0.84, actions=actions)
        return patch_repair_result(
            job=job,
            diagnosis=diagnosis,
            module_name=self.spec.name,
            fmt="tar",
            patch_plan=patch_plan,
            confidence=0.84,
            actions=actions,
            workspace=workspace,
            filename="tar_trailing_zero_block_repair.tar",
            config=config,
            materialized_data=repaired,
        )


def _walk_payload_end(data: bytes) -> int | None:
    offset = 0
    while offset + 512 <= len(data):
        header = data[offset:offset + 512]
        if header == b"\0" * 512:
            return offset
        size = _parse_octal(header[124:136])
        if size is None:
            return None
        offset += 512 + int(math.ceil(size / 512) * 512)
    return offset if offset == len(data) else None


def _canonical_tar_end(data: bytes, payload_end: int) -> int:
    end = payload_end
    while end + 512 <= len(data) and data[end:end + 512] == b"\0" * 512:
        end += 512
        if end >= payload_end + 1024:
            break
    return end


def _parse_octal(value: bytes) -> int | None:
    text = value.strip(b"\0 ").decode("ascii", errors="ignore")
    if not text:
        return 0
    try:
        return int(text, 8)
    except ValueError:
        return None


register_repair_module(TarTrailingZeroBlockRepair())
