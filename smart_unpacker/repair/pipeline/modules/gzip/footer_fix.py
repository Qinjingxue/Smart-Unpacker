from __future__ import annotations

import struct
import zlib

from smart_unpacker.repair.diagnosis import RepairDiagnosis
from smart_unpacker.repair.job import RepairJob
from smart_unpacker.repair.pipeline.module import RepairModuleSpec, RepairRoute
from smart_unpacker.repair.pipeline.modules._common import load_job_source_bytes, patch_plan_for_truncate_append, patch_repair_result
from smart_unpacker.repair.pipeline.registry import register_repair_module
from smart_unpacker.repair.result import RepairResult


class GzipFooterFix:
    spec = RepairModuleSpec(
        name="gzip_footer_fix",
        formats=("gzip", "gz"),
        categories=("content_recovery", "boundary_repair"),
        stage="targeted",
        routes=(
            RepairRoute(
                formats=("gzip", "gz"),
                require_any_categories=("content_recovery",),
                require_any_flags=("gzip_footer_bad", "crc_error", "checksum_error"),
                require_any_failure_kinds=("checksum_error", "corrupted_data", "data_error"),
                base_score=0.78,
            ),
        ),
    )

    def can_handle(self, job: RepairJob, diagnosis: RepairDiagnosis, config: dict) -> float:
        flags = set(job.damage_flags)
        if flags & {"gzip_footer_bad", "crc_error", "checksum_error"}:
            return 0.88
        if "content_recovery" in diagnosis.categories:
            return 0.62
        return 0.0

    def repair(self, job: RepairJob, diagnosis: RepairDiagnosis, workspace: str, config: dict) -> RepairResult:
        data = load_job_source_bytes(job)
        header_end = _gzip_header_end(data)
        if header_end is None or len(data) < header_end + 8:
            return RepairResult(status="unrepairable", confidence=0.0, format="gzip", module_name=self.spec.name, diagnosis=diagnosis.as_dict(), message="invalid gzip header")
        decompressor = zlib.decompressobj(-15)
        try:
            payload = decompressor.decompress(data[header_end:-8]) + decompressor.flush()
        except zlib.error as exc:
            return RepairResult(status="unrepairable", confidence=0.0, format="gzip", module_name=self.spec.name, diagnosis=diagnosis.as_dict(), message=f"deflate stream could not be decoded: {exc}")
        consumed = len(data[header_end:-8]) - len(decompressor.unused_data)
        stream_end = header_end + consumed
        footer = struct.pack("<II", zlib.crc32(payload) & 0xFFFFFFFF, len(payload) & 0xFFFFFFFF)
        repaired = data[:stream_end] + footer
        if repaired == data:
            return RepairResult(status="unrepairable", confidence=0.0, format="gzip", module_name=self.spec.name, diagnosis=diagnosis.as_dict(), message="gzip footer already matches decoded payload")
        actions = ["decode_deflate_payload", "rewrite_gzip_footer"]
        patch_plan = patch_plan_for_truncate_append(job, self.spec.name, stream_end, footer, confidence=0.88, actions=actions)
        return patch_repair_result(
            job=job,
            diagnosis=diagnosis,
            module_name=self.spec.name,
            fmt="gzip",
            patch_plan=patch_plan,
            confidence=0.88,
            actions=actions,
            workspace=workspace,
            filename="gzip_footer_fix.gz",
            config=config,
            materialized_data=repaired,
        )


def _gzip_header_end(data: bytes) -> int | None:
    if len(data) < 10 or data[:2] != b"\x1f\x8b" or data[2] != 8:
        return None
    flags = data[3]
    offset = 10
    if flags & 0x04:
        if offset + 2 > len(data):
            return None
        extra_len = struct.unpack_from("<H", data, offset)[0]
        offset += 2 + extra_len
    if flags & 0x08:
        offset = _skip_c_string(data, offset)
        if offset is None:
            return None
    if flags & 0x10:
        offset = _skip_c_string(data, offset)
    if offset is None:
        return None
    if flags & 0x02:
        offset += 2
    return offset if offset <= len(data) else None


def _skip_c_string(data: bytes, offset: int) -> int | None:
    end = data.find(b"\0", offset)
    return None if end < 0 else end + 1


register_repair_module(GzipFooterFix())
