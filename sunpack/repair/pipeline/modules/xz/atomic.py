from __future__ import annotations

import struct
from typing import Iterable
import zlib

from sunpack.repair.diagnosis import RepairDiagnosis
from sunpack.repair.job import RepairJob
from sunpack.repair.pipeline.module import RepairModuleSpec, RepairRoute
from sunpack.repair.pipeline.modules._python_atomic import AtomicMutation, PythonAtomicRepair
from sunpack.repair.pipeline.registry import register_repair_module


_XZ_MAGIC = b"\xfd7zXZ\x00"
_XZ_FOOTER_MAGIC = b"YZ"
_DEFINED_CHECK_IDS = {0, 1, 4, 10}


def _valid_stream_flags(flags: bytes) -> bool:
    return len(flags) == 2 and flags[0] == 0 and flags[1] in _DEFINED_CHECK_IDS


class _XzIntegrityFieldRepair(PythonAtomicRepair):
    format_hint = "xz"
    output_extension = "xz"

    def can_handle(self, job: RepairJob, diagnosis: RepairDiagnosis, config: dict) -> float:
        flags = set(job.damage_flags)
        if flags & set(self.spec.routes[0].require_any_flags):
            return 0.9
        return 0.0


class XzStreamHeaderCrcRepair(_XzIntegrityFieldRepair):
    spec = RepairModuleSpec(
        name="xz_stream_header_crc_repair",
        formats=("xz",),
        categories=("safe_repair", "header_repair"),
        stage="targeted",
        safe=True,
        atomic=True,
        route_family="xz_stream_integrity",
        routes=(
            RepairRoute(
                formats=("xz",),
                require_any_flags=("xz_header_crc_bad", "xz_stream_header_bad", "header_crc_bad", "checksum_error"),
                require_any_failure_kinds=("checksum_error", "corrupted_data", "structure_recognition"),
                base_score=0.86,
            ),
        ),
    )
    native_key = "python_xz_header_crc_repair"
    default_message = "XZ Stream Header CRC32 repair produced a candidate"

    def mutations(self, data: bytes, config: dict) -> Iterable[AtomicMutation]:
        if len(data) < 12 or not data.startswith(_XZ_MAGIC):
            return
        flags = data[6:8]
        if not _valid_stream_flags(flags):
            return
        stored = struct.unpack_from("<I", data, 8)[0]
        computed = zlib.crc32(flags) & 0xFFFFFFFF
        if stored == computed:
            return
        repaired = bytearray(data)
        struct.pack_into("<I", repaired, 8, computed)
        yield AtomicMutation(
            name="xz_stream_header_crc32",
            data=bytes(repaired),
            action="repair_xz_stream_header_crc32",
            confidence=0.94,
            details={
                "header_offset": 0,
                "stored_crc32": stored,
                "computed_crc32": computed,
                "check_id": flags[1],
                "mutation_scope": "stream_header_crc",
            },
        )


class XzStreamFooterCrcRepair(_XzIntegrityFieldRepair):
    spec = RepairModuleSpec(
        name="xz_stream_footer_crc_repair",
        formats=("xz",),
        categories=("safe_repair", "boundary_repair"),
        stage="targeted",
        safe=True,
        atomic=True,
        route_family="xz_stream_integrity",
        routes=(
            RepairRoute(
                formats=("xz",),
                require_any_flags=("xz_footer_crc_bad", "xz_stream_footer_bad", "footer_crc_bad", "checksum_error"),
                require_any_failure_kinds=("checksum_error", "corrupted_data", "structure_recognition"),
                base_score=0.86,
            ),
        ),
    )
    native_key = "python_xz_footer_crc_repair"
    default_message = "XZ Stream Footer CRC32 repair produced a candidate"

    def mutations(self, data: bytes, config: dict) -> Iterable[AtomicMutation]:
        if len(data) < 24 or data[-2:] != _XZ_FOOTER_MAGIC:
            return
        footer_offset = len(data) - 12
        footer_fields = data[footer_offset + 4 : footer_offset + 10]
        footer_flags = footer_fields[4:6]
        if not _valid_stream_flags(footer_flags):
            return
        if data.startswith(_XZ_MAGIC) and data[6:8] != footer_flags:
            return
        backward_size = (struct.unpack_from("<I", footer_fields, 0)[0] + 1) * 4
        index_offset = footer_offset - backward_size
        if index_offset < 12 or index_offset >= footer_offset or data[index_offset] != 0:
            return
        stored = struct.unpack_from("<I", data, footer_offset)[0]
        computed = zlib.crc32(footer_fields) & 0xFFFFFFFF
        if stored == computed:
            return
        repaired = bytearray(data)
        struct.pack_into("<I", repaired, footer_offset, computed)
        yield AtomicMutation(
            name="xz_stream_footer_crc32",
            data=bytes(repaired),
            action="repair_xz_stream_footer_crc32",
            confidence=0.94,
            details={
                "footer_offset": footer_offset,
                "index_offset": index_offset,
                "backward_size": backward_size,
                "stored_crc32": stored,
                "computed_crc32": computed,
                "mutation_scope": "stream_footer_crc",
            },
        )


register_repair_module(XzStreamHeaderCrcRepair())
register_repair_module(XzStreamFooterCrcRepair())
