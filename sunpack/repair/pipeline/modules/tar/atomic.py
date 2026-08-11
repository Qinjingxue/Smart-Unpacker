from __future__ import annotations

from dataclasses import dataclass
from typing import Iterable

from sunpack.repair.diagnosis import RepairDiagnosis
from sunpack.repair.job import RepairJob
from sunpack.repair.pipeline.module import RepairModuleSpec, RepairRoute
from sunpack.repair.pipeline.modules._python_atomic import AtomicMutation, PythonAtomicRepair
from sunpack.repair.pipeline.registry import register_repair_module


_BLOCK = 512


@dataclass(frozen=True)
class _TarEntry:
    offset: int
    end: int
    size: int
    typeflag: int
    header: bytes
    payload: bytes


def _tar_number(field: bytes) -> int | None:
    if not field:
        return None
    if field[0] & 0x80:
        raw = bytearray(field)
        raw[0] &= 0x7F
        return int.from_bytes(raw, "big", signed=False)
    text = field.rstrip(b"\x00 ").lstrip(b" ")
    if not text:
        return 0
    if any(byte < ord("0") or byte > ord("7") for byte in text):
        return None
    return int(text, 8)


def _checksum_field(value: int) -> bytes:
    return f"{value:06o}\0 ".encode("ascii")


def _tar_entries(data: bytes, max_entries: int) -> Iterable[_TarEntry]:
    offset = 0
    entries = 0
    while offset + _BLOCK <= len(data) and entries < max_entries:
        header = data[offset : offset + _BLOCK]
        if not any(header):
            return
        size = _tar_number(header[124:136])
        if size is None:
            return
        padded_size = ((size + _BLOCK - 1) // _BLOCK) * _BLOCK
        end = offset + _BLOCK + padded_size
        if end <= offset or end > len(data):
            return
        yield _TarEntry(
            offset=offset,
            end=end,
            size=size,
            typeflag=header[156],
            header=header,
            payload=data[offset + _BLOCK : offset + _BLOCK + size],
        )
        offset = end
        entries += 1


def _header_checksum_valid(header: bytes) -> bool:
    stored = _tar_number(header[148:156])
    if stored is None:
        return False
    view = bytearray(header)
    view[148:156] = b" " * 8
    return stored == sum(view)


def _valid_pax_payload(payload: bytes) -> bool:
    pos = 0
    while pos < len(payload):
        space = payload.find(b" ", pos)
        if space <= pos:
            return False
        length_text = payload[pos:space]
        if not length_text.isdigit():
            return False
        length = int(length_text)
        end = pos + length
        if length <= space - pos + 2 or end > len(payload) or payload[end - 1 : end] != b"\n":
            return False
        record = payload[space + 1 : end - 1]
        if b"=" not in record:
            return False
        pos = end
    return pos == len(payload)


class TarSingleHeaderChecksumRepair(PythonAtomicRepair):
    spec = RepairModuleSpec(
        name="tar_single_header_checksum_repair",
        formats=("tar",),
        categories=("safe_repair", "header_repair"),
        stage="targeted",
        safe=True,
        atomic=True,
        route_family="tar_header_integrity",
        routes=(
            RepairRoute(
                formats=("tar",),
                require_any_flags=("tar_checksum_bad", "header_checksum_bad"),
                require_any_failure_kinds=("checksum_error", "corrupted_data", "structure_recognition"),
                base_score=0.88,
            ),
        ),
    )
    format_hint = "tar"
    output_extension = "tar"
    native_key = "python_tar_single_header_checksum_repair"
    default_message = "single TAR member-header checksum repair produced candidates"

    def can_handle(self, job: RepairJob, diagnosis: RepairDiagnosis, config: dict) -> float:
        if set(job.damage_flags) & {"tar_checksum_bad", "header_checksum_bad"}:
            return 0.94
        return 0.0

    def mutations(self, data: bytes, config: dict) -> Iterable[AtomicMutation]:
        offset = 0
        entries = 0
        max_entries = max(1, int(config.get("max_entries", 20000) or 20000))
        while offset + _BLOCK <= len(data) and entries < max_entries:
            header = data[offset : offset + _BLOCK]
            if not any(header):
                return
            size = _tar_number(header[124:136])
            stored = _tar_number(header[148:156])
            if size is None or stored is None:
                return
            checksum_view = bytearray(header)
            checksum_view[148:156] = b" " * 8
            computed = sum(checksum_view)
            if stored != computed:
                repaired = bytearray(data)
                repaired[offset + 148 : offset + 156] = _checksum_field(computed)
                yield AtomicMutation(
                    name=f"tar_header_checksum_{offset}",
                    data=bytes(repaired),
                    action=f"repair_tar_header_checksum@{offset}",
                    confidence=0.96,
                    details={
                        "header_offset": offset,
                        "stored_checksum": stored,
                        "computed_checksum": computed,
                        "member_size": size,
                        "member_type": chr(header[156]) if header[156] else "0",
                        "mutation_scope": "single_member_header",
                    },
                )
            padded_size = ((size + _BLOCK - 1) // _BLOCK) * _BLOCK
            next_offset = offset + _BLOCK + padded_size
            if next_offset <= offset or next_offset > len(data):
                return
            offset = next_offset
            entries += 1


class _TarSingleMetadataMemberQuarantine(PythonAtomicRepair):
    format_hint = "tar"
    output_extension = "tar"
    native_key = "python_tar_single_metadata_member_quarantine"
    typeflags: tuple[int, ...] = ()
    confidence = 0.74

    def can_handle(self, job: RepairJob, diagnosis: RepairDiagnosis, config: dict) -> float:
        if set(job.damage_flags) & set(self.spec.routes[0].require_any_flags):
            return self.confidence
        return 0.0

    def entry_is_invalid(self, entry: _TarEntry) -> bool:
        return not _header_checksum_valid(entry.header)

    def mutations(self, data: bytes, config: dict) -> Iterable[AtomicMutation]:
        max_entries = max(1, int(config.get("max_entries", 20000) or 20000))
        entries = list(_tar_entries(data, max_entries))
        for index, entry in enumerate(entries):
            if entry.typeflag not in self.typeflags or not self.entry_is_invalid(entry):
                continue
            # Per-file PAX and GNU longname/longlink records are inseparable
            # from the following member.  Removing only the metadata changes
            # that member's path or size semantics.  A global PAX record may
            # affect every later member and has no safe local quarantine.
            if entry.typeflag == ord("g"):
                continue
            target = entries[index + 1] if entry.typeflag in {ord("x"), ord("L"), ord("K")} and index + 1 < len(entries) else None
            quarantine_end = target.end if target is not None else entry.end
            yield AtomicMutation(
                name=f"{self.spec.name}_{entry.offset}",
                data=data[: entry.offset] + data[quarantine_end :],
                action=f"quarantine_tar_metadata_member@{entry.offset}",
                confidence=self.confidence,
                partial=True,
                details={
                    "member_offset": entry.offset,
                    "member_end": entry.end,
                    "dependent_member_end": quarantine_end if target is not None else None,
                    "member_size": entry.size,
                    "member_type": chr(entry.typeflag),
                    "header_checksum_valid": _header_checksum_valid(entry.header),
                    "mutation_scope": "single_metadata_member",
                },
            )


class TarPaxHeaderQuarantine(_TarSingleMetadataMemberQuarantine):
    spec = RepairModuleSpec(
        name="tar_pax_header_quarantine",
        formats=("tar",),
        categories=("content_recovery", "quarantine"),
        stage="deep",
        safe=False,
        partial=True,
        lossy=True,
        atomic=True,
        route_family="tar_pax_metadata_quarantine",
        routes=(
            RepairRoute(
                formats=("tar",),
                require_any_flags=("pax_header_bad", "tar_metadata_bad"),
                require_any_failure_kinds=("corrupted_data", "structure_recognition"),
                base_score=0.74,
            ),
        ),
    )
    typeflags = (ord("x"), ord("g"))
    confidence = 0.78

    def entry_is_invalid(self, entry: _TarEntry) -> bool:
        return not _header_checksum_valid(entry.header) or not _valid_pax_payload(entry.payload)


class TarGnuLongNameQuarantine(_TarSingleMetadataMemberQuarantine):
    spec = RepairModuleSpec(
        name="tar_gnu_longname_quarantine",
        formats=("tar",),
        categories=("content_recovery", "quarantine"),
        stage="deep",
        safe=False,
        partial=True,
        lossy=True,
        atomic=True,
        route_family="tar_gnu_name_quarantine",
        routes=(
            RepairRoute(
                formats=("tar",),
                require_any_flags=("gnu_longname_bad", "gnu_longlink_bad", "tar_metadata_bad"),
                require_any_failure_kinds=("corrupted_data", "structure_recognition"),
                base_score=0.72,
            ),
        ),
    )
    typeflags = (ord("L"), ord("K"))
    confidence = 0.76

    def entry_is_invalid(self, entry: _TarEntry) -> bool:
        return not _header_checksum_valid(entry.header) or not entry.payload.endswith(b"\x00")


class TarSparseEntryQuarantine(_TarSingleMetadataMemberQuarantine):
    spec = RepairModuleSpec(
        name="tar_sparse_entry_quarantine",
        formats=("tar",),
        categories=("content_recovery", "quarantine"),
        stage="deep",
        safe=False,
        partial=True,
        lossy=True,
        atomic=True,
        route_family="tar_sparse_entry_quarantine",
        routes=(
            RepairRoute(
                formats=("tar",),
                require_any_flags=("sparse_header_bad", "sparse_metadata_bad", "tar_size_bad"),
                require_any_failure_kinds=("corrupted_data", "data_error", "structure_recognition"),
                base_score=0.68,
            ),
        ),
    )
    typeflags = (ord("S"),)
    confidence = 0.7


register_repair_module(TarSingleHeaderChecksumRepair())
register_repair_module(TarPaxHeaderQuarantine())
register_repair_module(TarGnuLongNameQuarantine())
register_repair_module(TarSparseEntryQuarantine())
