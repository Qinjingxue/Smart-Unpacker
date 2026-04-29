from __future__ import annotations

import struct

from smart_unpacker.repair.diagnosis import RepairDiagnosis
from smart_unpacker.repair.job import RepairJob
from smart_unpacker.repair.pipeline.module import RepairModuleSpec, RepairRoute
from smart_unpacker.repair.pipeline.modules._common import load_job_source_bytes, patch_plan_for_byte_patches, patch_repair_result
from smart_unpacker.repair.pipeline.registry import register_repair_module
from smart_unpacker.repair.result import RepairResult

from ._directory import find_eocd, parse_central_directory_entries, parse_local_header


class ZipLocalHeaderFieldRepair:
    spec = RepairModuleSpec(
        name="zip_local_header_field_repair",
        formats=("zip",),
        categories=("directory_rebuild",),
        stage="targeted",
        routes=(
            RepairRoute(
                formats=("zip",),
                require_any_flags=(
                    "local_header_bad",
                    "local_header_length_bad",
                    "local_header_size_bad",
                    "bit3_data_descriptor",
                    "data_descriptor",
                ),
                require_any_failure_kinds=("corrupted_data", "structure_recognition", "checksum_error"),
                base_score=0.82,
            ),
        ),
    )

    def can_handle(self, job: RepairJob, diagnosis: RepairDiagnosis, config: dict) -> float:
        flags = set(job.damage_flags)
        if flags & {"local_header_bad", "local_header_length_bad", "local_header_size_bad"}:
            return 0.93
        if flags & {"bit3_data_descriptor", "data_descriptor"} and "central_directory_bad" not in flags:
            return 0.74
        return 0.0

    def repair(self, job: RepairJob, diagnosis: RepairDiagnosis, workspace: str, config: dict) -> RepairResult:
        data = load_job_source_bytes(job)
        patches, repaired = _repair_local_headers(data)
        if not patches:
            return RepairResult(
                status="unrepairable",
                confidence=0.0,
                format="zip",
                module_name=self.spec.name,
                diagnosis=diagnosis.as_dict(),
                message="no ZIP local header field mismatch was safely repairable",
            )
        actions = ["reconcile_zip_local_header_fields_with_central_directory"]
        patch_plan = patch_plan_for_byte_patches(job, self.spec.name, patches, confidence=0.9, actions=actions)
        return patch_repair_result(
            job=job,
            diagnosis=diagnosis,
            module_name=self.spec.name,
            fmt="zip",
            patch_plan=patch_plan,
            confidence=0.9,
            actions=actions,
            workspace=workspace,
            filename="zip_local_header_field_repair.zip",
            config=config,
            materialized_data=repaired,
        )


def _repair_local_headers(data: bytes) -> tuple[list[dict], bytes]:
    eocd = find_eocd(data, allow_trailing_junk=False)
    if eocd is None:
        return [], data
    entries = parse_central_directory_entries(data, eocd.cd_offset, expected_end=eocd.cd_offset + eocd.cd_size)
    if not entries:
        return [], data
    output = bytearray(data)
    patches: list[dict] = []
    for entry in entries:
        if entry.local_header_offset == 0xFFFFFFFF:
            continue
        local = parse_local_header(data, entry.local_header_offset)
        if local is None:
            continue
        entry_name_at_local = data[local.offset + 30:local.offset + 30 + entry.name_len]
        if local.name_len != entry.name_len and entry_name_at_local == entry.name:
            _add_patch(patches, output, local.offset + 26, struct.pack("<H", entry.name_len))
            local = parse_local_header(bytes(output), entry.local_header_offset) or local
        if local.extra_len != entry.extra_len:
            expected_extra = data[local.offset + 30 + entry.name_len:local.offset + 30 + entry.name_len + entry.extra_len]
            if len(expected_extra) == entry.extra_len and expected_extra == entry.extra:
                _add_patch(patches, output, local.offset + 28, struct.pack("<H", entry.extra_len))
                local = parse_local_header(bytes(output), entry.local_header_offset) or local
        local_field_patches = _field_patches_for_entry(entry, local)
        for offset, payload in local_field_patches:
            _add_patch(patches, output, offset, payload)
    return patches, bytes(output)


def _field_patches_for_entry(entry, local) -> list[tuple[int, bytes]]:
    patches: list[tuple[int, bytes]] = []
    if local.flags != entry.flags:
        patches.append((local.offset + 6, struct.pack("<H", entry.flags)))
    if local.method != entry.method:
        patches.append((local.offset + 8, struct.pack("<H", entry.method)))
    if entry.flags & 0x08:
        return patches
    if local.crc32 != entry.crc32:
        patches.append((local.offset + 14, struct.pack("<I", entry.crc32)))
    if entry.compressed_size != 0xFFFFFFFF and local.compressed_size != entry.compressed_size:
        patches.append((local.offset + 18, struct.pack("<I", entry.compressed_size)))
    if entry.uncompressed_size != 0xFFFFFFFF and local.uncompressed_size != entry.uncompressed_size:
        patches.append((local.offset + 22, struct.pack("<I", entry.uncompressed_size)))
    return patches


def _add_patch(patches: list[dict], output: bytearray, offset: int, payload: bytes) -> None:
    if output[offset:offset + len(payload)] == payload:
        return
    output[offset:offset + len(payload)] = payload
    patches.append({"offset": offset, "data": payload})


register_repair_module(ZipLocalHeaderFieldRepair())
