from __future__ import annotations

import struct
from typing import Iterable
import zlib

from sunpack.repair.diagnosis import RepairDiagnosis
from sunpack.repair.job import RepairJob
from sunpack.repair.pipeline.module import RepairModuleSpec, RepairRoute
from sunpack.repair.pipeline.modules._python_atomic import AtomicMutation, PythonAtomicRepair
from sunpack.repair.pipeline.registry import register_repair_module


_GZIP_MAGIC = b"\x1f\x8b"
_FHCRC = 0x02
_FEXTRA = 0x04
_FNAME = 0x08
_FCOMMENT = 0x10
_RESERVED = 0xE0


def _header_crc_offset(data: bytes, *, flags: int | None = None) -> int | None:
    if len(data) < 10 or not data.startswith(_GZIP_MAGIC) or data[2] != 8:
        return None
    flags = data[3] if flags is None else flags
    pos = 10
    if flags & _FEXTRA:
        if pos + 2 > len(data):
            return None
        size = struct.unpack_from("<H", data, pos)[0]
        pos += 2 + size
        if pos > len(data):
            return None
    for bit in (_FNAME, _FCOMMENT):
        if not flags & bit:
            continue
        end = data.find(b"\x00", pos)
        if end < 0:
            return None
        pos = end + 1
    if flags & _FHCRC:
        return pos if pos + 2 <= len(data) else None
    return pos


class _GzipHeaderAtomicRepair(PythonAtomicRepair):
    format_hint = "gzip"
    output_extension = "gz"

    def can_handle(self, job: RepairJob, diagnosis: RepairDiagnosis, config: dict) -> float:
        flags = set(job.damage_flags)
        if flags & {"wrong_password", "password_required"}:
            return 0.0
        if flags & set(self.spec.routes[0].require_any_flags):
            return 0.9
        return 0.0


class GzipHeaderCrcRepair(_GzipHeaderAtomicRepair):
    spec = RepairModuleSpec(
        name="gzip_header_crc_repair",
        formats=("gzip", "gz"),
        categories=("safe_repair", "header_repair"),
        stage="targeted",
        safe=True,
        atomic=True,
        route_family="gzip_header_integrity",
        routes=(
            RepairRoute(
                formats=("gzip", "gz"),
                require_any_flags=("gzip_header_crc_bad", "header_crc_bad", "checksum_error"),
                require_any_failure_kinds=("checksum_error", "corrupted_data", "structure_recognition"),
                base_score=0.86,
            ),
        ),
    )
    native_key = "python_gzip_header_crc_repair"
    default_message = "GZIP header CRC16 repair produced a candidate"

    def mutations(self, data: bytes, config: dict) -> Iterable[AtomicMutation]:
        if len(data) < 12 or not data.startswith(_GZIP_MAGIC) or not data[3] & _FHCRC:
            return
        crc_offset = _header_crc_offset(data)
        if crc_offset is None or crc_offset + 2 > len(data):
            return
        stored = struct.unpack_from("<H", data, crc_offset)[0]
        computed = zlib.crc32(data[:crc_offset]) & 0xFFFF
        if stored == computed:
            return
        repaired = bytearray(data)
        struct.pack_into("<H", repaired, crc_offset, computed)
        yield AtomicMutation(
            name="gzip_header_crc16",
            data=bytes(repaired),
            action="repair_gzip_header_crc16",
            confidence=0.92,
            details={
                "header_crc_offset": crc_offset,
                "stored_crc16": stored,
                "computed_crc16": computed,
                "mutation_scope": "single_header_crc",
            },
        )


class GzipReservedFlagsRepair(_GzipHeaderAtomicRepair):
    spec = RepairModuleSpec(
        name="gzip_reserved_flags_repair",
        formats=("gzip", "gz"),
        categories=("safe_repair", "header_repair"),
        stage="targeted",
        safe=True,
        atomic=True,
        route_family="gzip_header_flags",
        routes=(
            RepairRoute(
                formats=("gzip", "gz"),
                require_any_flags=("gzip_reserved_flags_set", "gzip_header_bad", "header_flags_bad"),
                require_any_failure_kinds=("structure_recognition", "corrupted_data"),
                base_score=0.82,
            ),
        ),
    )
    native_key = "python_gzip_reserved_flags_repair"
    default_message = "GZIP reserved header flag repair produced a candidate"

    def mutations(self, data: bytes, config: dict) -> Iterable[AtomicMutation]:
        if len(data) < 10 or not data.startswith(_GZIP_MAGIC) or data[2] != 8:
            return
        original_flags = data[3]
        if not original_flags & _RESERVED:
            return
        normalized_flags = original_flags & ~_RESERVED
        crc_offset = _header_crc_offset(data, flags=normalized_flags)
        if crc_offset is None:
            return
        repaired = bytearray(data)
        repaired[3] = normalized_flags
        crc_updated = False
        if normalized_flags & _FHCRC:
            if crc_offset + 2 > len(repaired):
                return
            struct.pack_into("<H", repaired, crc_offset, zlib.crc32(repaired[:crc_offset]) & 0xFFFF)
            crc_updated = True
        yield AtomicMutation(
            name="gzip_clear_reserved_flags",
            data=bytes(repaired),
            action="clear_gzip_reserved_header_flags",
            confidence=0.88,
            details={
                "original_flags": original_flags,
                "normalized_flags": normalized_flags,
                "header_crc_updated": crc_updated,
                "mutation_scope": "single_member_header",
            },
        )


register_repair_module(GzipHeaderCrcRepair())
register_repair_module(GzipReservedFlagsRepair())
