from __future__ import annotations

from dataclasses import dataclass
import struct
from typing import Iterable
import zlib

from sunpack.repair.diagnosis import RepairDiagnosis
from sunpack.repair.job import RepairJob
from sunpack.repair.pipeline.module import RepairModuleSpec, RepairRoute
from sunpack.repair.pipeline.modules._python_atomic import AtomicMutation, PythonAtomicRepair
from sunpack.repair.pipeline.modules.rar._structure import RAR4_MAGIC, RAR5_MAGIC
from sunpack.repair.pipeline.registry import register_repair_module


@dataclass(frozen=True)
class _RarHeader:
    version: int
    offset: int
    header_end: int
    block_end: int
    block_type: int
    common_flags: int
    body_offset: int
    stored_crc: int
    computed_crc: int


def _read_vint(data: bytes, offset: int) -> tuple[int | None, int | None]:
    value = 0
    shift = 0
    pos = offset
    while pos < len(data) and shift <= 63:
        byte = data[pos]
        if shift == 63 and byte & 0x7E:
            return None, None
        value |= (byte & 0x7F) << shift
        pos += 1
        if not byte & 0x80:
            return value, pos
        shift += 7
    return None, None


def _rar_headers(data: bytes) -> Iterable[_RarHeader]:
    if data.startswith(RAR4_MAGIC):
        pos = len(RAR4_MAGIC)
        while pos + 7 <= len(data):
            header_size = struct.unpack_from("<H", data, pos + 5)[0]
            if header_size < 7 or pos + header_size > len(data):
                return
            flags = struct.unpack_from("<H", data, pos + 3)[0]
            add_size = 0
            if flags & 0x8000:
                if pos + 11 > pos + header_size:
                    return
                add_size = struct.unpack_from("<I", data, pos + 7)[0]
            block_end = pos + header_size + add_size
            if block_end > len(data):
                return
            yield _RarHeader(
                version=4,
                offset=pos,
                header_end=pos + header_size,
                block_end=block_end,
                block_type=data[pos + 2],
                common_flags=flags,
                body_offset=pos + 7 + (4 if flags & 0x8000 else 0),
                stored_crc=struct.unpack_from("<H", data, pos)[0],
                computed_crc=zlib.crc32(data[pos + 2 : pos + header_size]) & 0xFFFF,
            )
            pos = block_end
        return

    if not data.startswith(RAR5_MAGIC):
        return
    pos = len(RAR5_MAGIC)
    while pos + 5 <= len(data):
        header_size, fields_start = _read_vint(data, pos + 4)
        if header_size is None or fields_start is None or fields_start - (pos + 4) > 3:
            return
        header_end = fields_start + header_size
        if header_end > len(data):
            return
        block_type, cursor = _read_vint(data, fields_start)
        flags, cursor = _read_vint(data, cursor or fields_start)
        if block_type is None or flags is None or cursor is None:
            return
        if flags & 0x0001:
            _, cursor = _read_vint(data, cursor)
            if cursor is None:
                return
        data_size = 0
        if flags & 0x0002:
            data_size, cursor = _read_vint(data, cursor)
            if data_size is None or cursor is None:
                return
        if cursor > header_end:
            return
        block_end = header_end + data_size
        if block_end > len(data):
            return
        yield _RarHeader(
            version=5,
            offset=pos,
            header_end=header_end,
            block_end=block_end,
            block_type=block_type,
            common_flags=flags,
            body_offset=cursor,
            stored_crc=struct.unpack_from("<I", data, pos)[0],
            computed_crc=zlib.crc32(data[pos + 4 : header_end]) & 0xFFFFFFFF,
        )
        if block_type == 4:  # Subsequent headers are encrypted.
            return
        pos = block_end


class _RarHeaderCrcRepair(PythonAtomicRepair):
    format_hint = "rar"
    output_extension = "rar"
    native_key = "python_rar_header_crc_repair"
    block_types: tuple[tuple[int, int], ...] = ()
    confidence = 0.82

    def can_handle(self, job: RepairJob, diagnosis: RepairDiagnosis, config: dict) -> float:
        flags = set(job.damage_flags)
        if flags & {"wrong_password", "password_required", "header_encrypted"}:
            return 0.0
        if flags & {"rar_header_crc_bad", "header_crc_bad", "checksum_error", "crc_error"}:
            return self.confidence
        return 0.0

    def mutations(self, data: bytes, config: dict) -> Iterable[AtomicMutation]:
        for header in _rar_headers(data):
            if (header.version, header.block_type) not in self.block_types:
                continue
            if header.stored_crc == header.computed_crc:
                continue
            repaired = bytearray(data)
            if header.version == 4:
                struct.pack_into("<H", repaired, header.offset, header.computed_crc)
            else:
                struct.pack_into("<I", repaired, header.offset, header.computed_crc)
            action = f"repair_rar{header.version}_header_crc@{header.offset}"
            yield AtomicMutation(
                name=f"rar{header.version}_block_{header.block_type}_crc_{header.offset}",
                data=bytes(repaired),
                action=action,
                confidence=self.confidence,
                details={
                    "version": header.version,
                    "block_type": header.block_type,
                    "header_offset": header.offset,
                    "stored_crc": header.stored_crc,
                    "computed_crc": header.computed_crc,
                    "mutation_scope": "single_header_crc",
                },
            )


def _crc_spec(name: str, route_family: str, flags: tuple[str, ...]) -> RepairModuleSpec:
    return RepairModuleSpec(
        name=name,
        formats=("rar",),
        categories=("safe_repair", "header_repair"),
        stage="targeted",
        safe=True,
        atomic=True,
        route_family=route_family,
        routes=(
            RepairRoute(
                formats=("rar",),
                require_any_flags=flags,
                require_any_failure_kinds=("checksum_error", "corrupted_data", "structure_recognition"),
                base_score=0.82,
            ),
        ),
    )


class RarMainHeaderCrcRepair(_RarHeaderCrcRepair):
    spec = _crc_spec(
        "rar_main_header_crc_repair",
        "rar_header_integrity",
        ("rar_main_header_crc_bad", "rar_header_crc_bad", "header_crc_bad", "checksum_error"),
    )
    block_types = ((4, 0x73), (5, 1))
    confidence = 0.9


class RarFileHeaderCrcRepair(_RarHeaderCrcRepair):
    spec = _crc_spec(
        "rar_file_header_crc_repair",
        "rar_header_integrity",
        ("rar_file_header_crc_bad", "rar_header_crc_bad", "header_crc_bad", "checksum_error"),
    )
    block_types = ((4, 0x74), (5, 2))
    confidence = 0.84


class RarServiceHeaderCrcRepair(_RarHeaderCrcRepair):
    spec = _crc_spec(
        "rar_service_header_crc_repair",
        "rar_service_integrity",
        ("rar_service_header_crc_bad", "rar_header_crc_bad", "header_crc_bad", "checksum_error"),
    )
    block_types = ((4, 0x75), (4, 0x7A), (5, 3))
    confidence = 0.78


class RarEndHeaderCrcRepair(_RarHeaderCrcRepair):
    spec = _crc_spec(
        "rar_end_header_crc_repair",
        "rar_boundary_integrity",
        ("rar_end_header_crc_bad", "rar_header_crc_bad", "header_crc_bad", "checksum_error"),
    )
    block_types = ((4, 0x7B), (5, 5))
    confidence = 0.9


def _rar_is_solid(data: bytes, headers: list[_RarHeader]) -> bool:
    main = next((item for item in headers if (item.version, item.block_type) in {(4, 0x73), (5, 1)}), None)
    if main is None:
        return True
    if main.version == 4:
        return bool(main.common_flags & 0x0008)
    archive_flags, _ = _read_vint(data, main.body_offset)
    return archive_flags is None or bool(archive_flags & 0x0004)


class _RarSingleBlockQuarantine(PythonAtomicRepair):
    format_hint = "rar"
    output_extension = "rar"
    native_key = "python_rar_single_block_quarantine"
    block_types: tuple[tuple[int, int], ...] = ()
    confidence = 0.72
    reject_solid = False

    def can_handle(self, job: RepairJob, diagnosis: RepairDiagnosis, config: dict) -> float:
        flags = set(job.damage_flags)
        if flags & {"wrong_password", "password_required", "header_encrypted"}:
            return 0.0
        if flags & set(self.spec.routes[0].require_any_flags):
            return self.confidence
        return 0.0

    def mutations(self, data: bytes, config: dict) -> Iterable[AtomicMutation]:
        headers = list(_rar_headers(data))
        if self.reject_solid and _rar_is_solid(data, headers):
            return
        for header in headers:
            if (header.version, header.block_type) not in self.block_types:
                continue
            if header.stored_crc == header.computed_crc:
                continue
            repaired = data[: header.offset] + data[header.block_end :]
            action = f"quarantine_rar{header.version}_block@{header.offset}"
            yield AtomicMutation(
                name=f"rar{header.version}_quarantine_{header.block_type}_{header.offset}",
                data=repaired,
                action=action,
                confidence=self.confidence,
                partial=True,
                details={
                    "version": header.version,
                    "block_type": header.block_type,
                    "removed_offset": header.offset,
                    "removed_length": header.block_end - header.offset,
                    "header_crc_mismatch": True,
                    "solid_archive": _rar_is_solid(data, headers),
                    "mutation_scope": "single_archive_block",
                },
            )


class RarInvalidFileBlockQuarantine(_RarSingleBlockQuarantine):
    spec = RepairModuleSpec(
        name="rar_invalid_file_block_quarantine",
        formats=("rar",),
        categories=("content_recovery", "quarantine"),
        stage="deep",
        safe=True,
        partial=True,
        lossy=True,
        atomic=True,
        route_family="rar_file_block_quarantine",
        routes=(
            RepairRoute(
                formats=("rar",),
                require_any_flags=("rar_file_block_bad", "rar_file_header_bad", "rar_block_crc_bad", "corrupted_data"),
                require_any_failure_kinds=("corrupted_data", "data_error", "structure_recognition"),
                base_score=0.7,
            ),
        ),
    )
    block_types = ((4, 0x74), (5, 2))
    confidence = 0.72
    reject_solid = True


class RarInvalidServiceBlockQuarantine(_RarSingleBlockQuarantine):
    spec = RepairModuleSpec(
        name="rar_invalid_service_block_quarantine",
        formats=("rar",),
        categories=("content_recovery", "quarantine"),
        stage="deep",
        safe=True,
        partial=True,
        lossy=True,
        atomic=True,
        route_family="rar_service_block_quarantine",
        routes=(
            RepairRoute(
                formats=("rar",),
                require_any_flags=("rar_service_block_bad", "rar_service_header_bad", "rar_block_crc_bad", "corrupted_data"),
                require_any_failure_kinds=("corrupted_data", "data_error", "structure_recognition"),
                base_score=0.74,
            ),
        ),
    )
    block_types = ((4, 0x75), (4, 0x7A), (5, 3))
    confidence = 0.76


register_repair_module(RarMainHeaderCrcRepair())
register_repair_module(RarFileHeaderCrcRepair())
register_repair_module(RarServiceHeaderCrcRepair())
register_repair_module(RarEndHeaderCrcRepair())
register_repair_module(RarInvalidFileBlockQuarantine())
register_repair_module(RarInvalidServiceBlockQuarantine())
