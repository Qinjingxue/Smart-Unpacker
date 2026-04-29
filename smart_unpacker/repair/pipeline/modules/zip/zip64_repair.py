from __future__ import annotations

import struct

from smart_unpacker.repair.diagnosis import RepairDiagnosis
from smart_unpacker.repair.job import RepairJob
from smart_unpacker.repair.pipeline.module import RepairModuleSpec, RepairRoute
from smart_unpacker.repair.pipeline.modules._common import (
    load_job_source_bytes,
    patch_plan_for_byte_patches,
    patch_plan_for_truncate_append,
    patch_repair_result,
)
from smart_unpacker.repair.pipeline.registry import register_repair_module
from smart_unpacker.repair.result import RepairResult

from ._directory import (
    CentralDirectoryEntry,
    LocalHeaderRecord,
    find_eocd,
    find_valid_central_directory,
    find_zip64_eocd,
    find_zip64_locator,
    parse_central_directory_entries,
    parse_local_header,
    parse_zip64_extra,
    walk_central_directory,
)


class Zip64FieldRepair:
    spec = RepairModuleSpec(
        name="zip64_field_repair",
        formats=("zip",),
        categories=("directory_rebuild",),
        stage="targeted",
        routes=(
            RepairRoute(
                formats=("zip",),
                require_any_flags=(
                    "zip64",
                    "zip64_eocd_bad",
                    "zip64_locator_bad",
                    "zip64_extra_bad",
                    "central_directory_bad",
                ),
                require_any_failure_kinds=("structure_recognition",),
                base_score=0.9,
            ),
        ),
    )

    def can_handle(self, job: RepairJob, diagnosis: RepairDiagnosis, config: dict) -> float:
        flags = set(job.damage_flags)
        if flags & {"zip64_eocd_bad", "zip64_locator_bad", "zip64_extra_bad"}:
            return 0.99
        if "zip64" in flags and flags & {"central_directory_bad", "compressed_size_bad", "local_header_bad"}:
            return 0.88
        return 0.0

    def repair(self, job: RepairJob, diagnosis: RepairDiagnosis, workspace: str, config: dict) -> RepairResult:
        data = load_job_source_bytes(job)
        tail_result = _repair_zip64_tail(data)
        if tail_result is not None:
            repaired, tail_start, actions, confidence = tail_result
            patch_plan = patch_plan_for_truncate_append(
                job,
                self.spec.name,
                tail_start,
                repaired[tail_start:],
                confidence=confidence,
                actions=actions,
            )
            return patch_repair_result(
                job=job,
                diagnosis=diagnosis,
                module_name=self.spec.name,
                fmt="zip",
                patch_plan=patch_plan,
                confidence=confidence,
                actions=actions,
                workspace=workspace,
                filename="zip64_field_repair.zip",
                config=config,
                materialized_data=repaired,
            )

        patches, repaired = _repair_zip64_central_extra(data)
        if patches:
            actions = ["reconcile_zip64_central_extra_fields"]
            patch_plan = patch_plan_for_byte_patches(job, self.spec.name, patches, confidence=0.96, actions=actions)
            return patch_repair_result(
                job=job,
                diagnosis=diagnosis,
                module_name=self.spec.name,
                fmt="zip",
                patch_plan=patch_plan,
                confidence=0.96,
                actions=actions,
                workspace=workspace,
                filename="zip64_field_repair.zip",
                config=config,
                materialized_data=repaired,
            )

        return RepairResult(
            status="unrepairable",
            confidence=0.0,
            format="zip",
            module_name=self.spec.name,
            diagnosis=diagnosis.as_dict(),
            message="no ZIP64 tail or extra field mismatch was safely repairable",
        )


def _repair_zip64_tail(data: bytes) -> tuple[bytes, int, list[str], float] | None:
    eocd = find_eocd(data, allow_trailing_junk=True)
    if eocd is None:
        return None
    zip64 = find_zip64_eocd(data, before=eocd.offset)
    if zip64 is None:
        return None
    cd = walk_central_directory(data, zip64.cd_offset, expected_end=zip64.cd_offset + zip64.cd_size)
    if not cd.valid:
        cd = find_valid_central_directory(data)
    if cd is None or not cd.valid:
        return None

    record = bytearray(data[zip64.offset:zip64.end])
    expected_record_size = zip64.end - zip64.offset - 12
    expected_values = {
        4: struct.pack("<Q", expected_record_size),
        24: struct.pack("<Q", cd.count),
        32: struct.pack("<Q", cd.count),
        40: struct.pack("<Q", cd.end - cd.offset),
        48: struct.pack("<Q", cd.offset),
    }
    actions: list[str] = []
    for offset, value in expected_values.items():
        if record[offset:offset + len(value)] != value:
            record[offset:offset + len(value)] = value
            actions.append("rewrite_zip64_eocd_fields")
    locator = find_zip64_locator(data, eocd.offset)
    expected_locator = struct.pack("<IIQI", 0x07064B50, 0, zip64.offset, 1)
    if locator is None or locator.zip64_eocd_offset != zip64.offset or locator.total_disks < 1:
        actions.append("rewrite_zip64_eocd_locator")
    elif data[locator.offset:locator.end] != expected_locator:
        actions.append("normalize_zip64_eocd_locator")
    else:
        expected_locator = data[locator.offset:locator.end]

    if not actions:
        return None
    tail_start = zip64.offset
    repaired = data[:tail_start] + bytes(record) + expected_locator + data[eocd.offset:eocd.end]
    return repaired, tail_start, sorted(set(actions)), 0.98


def _repair_zip64_central_extra(data: bytes) -> tuple[list[dict], bytes]:
    eocd = find_eocd(data, allow_trailing_junk=True)
    if eocd is None:
        return [], data
    zip64 = find_zip64_eocd(data, before=eocd.offset)
    if zip64 is not None:
        cd_offset = zip64.cd_offset
        cd_end = zip64.cd_offset + zip64.cd_size
    else:
        cd_offset = eocd.cd_offset
        cd_end = eocd.cd_offset + eocd.cd_size
    entries = parse_central_directory_entries(data, cd_offset, expected_end=cd_end)
    if not entries:
        return [], data

    output = bytearray(data)
    patches: list[dict] = []
    for entry in entries:
        local = _find_local_for_central(data, entry)
        if local is None:
            continue
        central_zip64 = parse_zip64_extra(entry.extra, absolute_extra_offset=entry.extra_offset)
        local_zip64 = parse_zip64_extra(local.extra, absolute_extra_offset=local.extra_offset)
        if central_zip64 is None or local_zip64 is None:
            continue
        expected = _expected_zip64_values(entry, local)
        if not expected or len(central_zip64.values) < len(expected):
            continue
        for index, value in enumerate(expected):
            if central_zip64.values[index] == value:
                continue
            offset = central_zip64.values_offset + index * 8
            encoded = struct.pack("<Q", value)
            patches.append({"offset": offset, "data": encoded})
            output[offset:offset + 8] = encoded
    return patches, bytes(output)


def _find_local_for_central(data: bytes, entry: CentralDirectoryEntry) -> LocalHeaderRecord | None:
    candidates = []
    if entry.local_header_offset != 0xFFFFFFFF:
        candidates.append(entry.local_header_offset)
    central_zip64 = parse_zip64_extra(entry.extra, absolute_extra_offset=entry.extra_offset)
    if central_zip64 is not None and len(central_zip64.values) >= 3:
        candidates.append(central_zip64.values[2])
    for offset in candidates:
        local = parse_local_header(data, int(offset))
        if local is not None and local.name == entry.name:
            return local
    pos = data.find(b"PK\x03\x04")
    while pos >= 0:
        local = parse_local_header(data, pos)
        if local is not None and local.name == entry.name:
            return local
        pos = data.find(b"PK\x03\x04", pos + 4)
    return None


def _expected_zip64_values(entry: CentralDirectoryEntry, local: LocalHeaderRecord) -> list[int]:
    local_zip64 = parse_zip64_extra(local.extra, absolute_extra_offset=local.extra_offset)
    local_values = list(local_zip64.values if local_zip64 is not None else ())
    expected: list[int] = []
    if entry.uncompressed_size == 0xFFFFFFFF:
        if not local_values:
            return []
        expected.append(local_values.pop(0))
    if entry.compressed_size == 0xFFFFFFFF:
        if not local_values:
            return []
        expected.append(local_values.pop(0))
    if entry.local_header_offset == 0xFFFFFFFF:
        expected.append(local.offset)
    return expected


register_repair_module(Zip64FieldRepair())
