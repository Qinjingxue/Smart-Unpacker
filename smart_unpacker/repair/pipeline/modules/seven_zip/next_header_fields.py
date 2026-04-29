from __future__ import annotations

import struct
import zlib

from smart_unpacker.repair.diagnosis import RepairDiagnosis
from smart_unpacker.repair.job import RepairJob
from smart_unpacker.repair.pipeline.module import RepairModuleSpec, RepairRoute
from smart_unpacker.repair.pipeline.modules._common import load_job_source_bytes, patch_plan_for_byte_patches, patch_repair_result
from smart_unpacker.repair.pipeline.registry import register_repair_module
from smart_unpacker.repair.result import RepairResult

from ._structure import SEVEN_ZIP_MAGIC


class SevenZipNextHeaderFieldRepair:
    spec = RepairModuleSpec(
        name="seven_zip_next_header_field_repair",
        formats=("7z", "seven_zip"),
        categories=("directory_rebuild", "safe_repair"),
        stage="targeted",
        routes=(
            RepairRoute(
                formats=("7z", "seven_zip"),
                require_any_flags=("next_header_offset_bad", "next_header_size_bad", "next_header_out_of_range", "start_header_corrupt"),
                require_any_failure_kinds=("structure_recognition",),
                base_score=0.84,
            ),
        ),
    )

    def can_handle(self, job: RepairJob, diagnosis: RepairDiagnosis, config: dict) -> float:
        flags = set(job.damage_flags)
        if flags & {"next_header_offset_bad", "next_header_size_bad", "next_header_out_of_range"}:
            return 0.94
        if "start_header_corrupt" in flags and "next_header_crc_bad" not in flags:
            return 0.72
        return 0.0

    def repair(self, job: RepairJob, diagnosis: RepairDiagnosis, workspace: str, config: dict) -> RepairResult:
        data = load_job_source_bytes(job)
        candidate = _find_next_header_candidate(data, config)
        if candidate is None:
            return RepairResult(
                status="unrepairable",
                confidence=0.0,
                format="7z",
                module_name=self.spec.name,
                diagnosis=diagnosis.as_dict(),
                message="7z next header offset/size could not be inferred from the stored next-header CRC",
            )
        next_offset, next_size = candidate
        current_offset, current_size, next_crc = struct.unpack_from("<QQI", data, 12)
        start_header = struct.pack("<QQI", next_offset, next_size, next_crc)
        start_crc = zlib.crc32(start_header) & 0xFFFFFFFF
        patches = []
        if current_offset != next_offset:
            patches.append({"offset": 12, "data": struct.pack("<Q", next_offset)})
        if current_size != next_size:
            patches.append({"offset": 20, "data": struct.pack("<Q", next_size)})
        if struct.unpack_from("<I", data, 8)[0] != start_crc:
            patches.append({"offset": 8, "data": struct.pack("<I", start_crc)})
        if not patches:
            return RepairResult(
                status="unrepairable",
                confidence=0.0,
                format="7z",
                module_name=self.spec.name,
                diagnosis=diagnosis.as_dict(),
                message="7z next header offset and size already match the inferred segment",
            )

        repaired = bytearray(data)
        for patch in patches:
            offset = int(patch["offset"])
            payload = bytes(patch["data"])
            repaired[offset:offset + len(payload)] = payload
        actions = ["repair_7z_next_header_offset_size", "recompute_7z_start_header_crc"]
        patch_plan = patch_plan_for_byte_patches(job, self.spec.name, patches, confidence=0.9, actions=actions)
        return patch_repair_result(
            job=job,
            diagnosis=diagnosis,
            module_name=self.spec.name,
            fmt="7z",
            patch_plan=patch_plan,
            confidence=0.9,
            actions=actions,
            workspace=workspace,
            filename="seven_zip_next_header_field_repair.7z",
            config=config,
            materialized_data=bytes(repaired),
        )


def _find_next_header_candidate(data: bytes, config: dict) -> tuple[int, int] | None:
    if len(data) < 33 or data[:6] != SEVEN_ZIP_MAGIC:
        return None
    stored_offset, stored_size, stored_crc = struct.unpack_from("<QQI", data, 12)
    max_scan = _max_scan_bytes(config)
    scan_end = min(len(data), 32 + max_scan)
    preferred_start = 32 + stored_offset
    starts: list[int] = []
    if 32 <= preferred_start < scan_end:
        starts.append(preferred_start)
    starts.extend(index for index in range(32, scan_end) if data[index] in {0x01, 0x17} and index not in starts)
    best: tuple[int, int] | None = None
    best_score: tuple[int, int] | None = None
    for start in starts:
        if data[start] not in {0x01, 0x17}:
            continue
        crc = 0
        max_end = min(len(data), start + max_scan)
        for end in range(start + 1, max_end + 1):
            crc = zlib.crc32(data[end - 1:end], crc) & 0xFFFFFFFF
            if crc != stored_crc:
                continue
            next_offset = start - 32
            next_size = end - start
            score = (0 if next_offset == stored_offset else 1, abs(next_size - stored_size))
            if best is None or score < best_score:
                best = (next_offset, next_size)
                best_score = score
    return best


def _max_scan_bytes(config: dict) -> int:
    deep = config.get("deep") if isinstance(config.get("deep"), dict) else {}
    value = deep.get("max_next_header_scan_bytes", 1024 * 1024)
    try:
        return max(1, int(value))
    except (TypeError, ValueError):
        return 1024 * 1024


register_repair_module(SevenZipNextHeaderFieldRepair())
