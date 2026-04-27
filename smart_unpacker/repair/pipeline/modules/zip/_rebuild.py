from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
import struct
from typing import Any


LFH_SIG = b"PK\x03\x04"
DD_SIG = b"PK\x07\x08"
CD_SIG = b"PK\x01\x02"
EOCD_SIG = b"PK\x05\x06"
ZIP64_EOCD_SIG = b"PK\x06\x06"
ZIP64_LOCATOR_SIG = b"PK\x06\x07"


@dataclass(frozen=True)
class ZipEntryCandidate:
    name: bytes
    payload: bytes
    version_needed: int
    flags: int
    method: int
    mod_time: int
    mod_date: int
    crc32: int
    compressed_size: int
    uncompressed_size: int
    local_offset: int
    data_descriptor: bool = False


@dataclass(frozen=True)
class ZipScanResult:
    entries: list[ZipEntryCandidate]
    warnings: list[str]
    skipped_offsets: list[int]
    descriptor_entries: int = 0
    encrypted_entries: int = 0

    @property
    def complete(self) -> bool:
        return not self.skipped_offsets and not self.encrypted_entries


def load_source_bytes(source_input: dict[str, Any]) -> bytes:
    kind = str(source_input.get("kind") or "file")
    if kind == "file":
        return Path(source_input["path"]).read_bytes()
    if kind == "file_range":
        path = Path(source_input["path"])
        start = int(source_input.get("start") or 0)
        end = source_input.get("end")
        with path.open("rb") as handle:
            handle.seek(start)
            if end is None:
                return handle.read()
            return handle.read(max(0, int(end) - start))
    if kind == "concat_ranges":
        chunks = []
        for item in source_input.get("ranges") or []:
            chunks.append(load_source_bytes({"kind": "file_range", **item}))
        return b"".join(chunks)
    raise ValueError(f"unsupported repair input kind: {kind}")


def scan_local_file_headers(data: bytes, *, require_data_descriptor: bool = False) -> ZipScanResult:
    entries: list[ZipEntryCandidate] = []
    warnings: list[str] = []
    skipped_offsets: list[int] = []
    descriptor_entries = 0
    encrypted_entries = 0

    offset = data.find(LFH_SIG)
    while offset >= 0:
        parsed = _parse_entry(data, offset)
        if parsed is None:
            skipped_offsets.append(offset)
            offset = data.find(LFH_SIG, offset + 4)
            continue
        entry, next_offset, warning = parsed
        if warning:
            warnings.append(warning)
        if entry.flags & 0x01:
            encrypted_entries += 1
            warnings.append(f"encrypted ZIP entry skipped at offset {offset}")
        elif not require_data_descriptor or entry.data_descriptor:
            entries.append(entry)
        if entry.data_descriptor:
            descriptor_entries += 1
        offset = data.find(LFH_SIG, max(next_offset, offset + 4))

    return ZipScanResult(
        entries=entries,
        warnings=_dedupe(warnings),
        skipped_offsets=skipped_offsets,
        descriptor_entries=descriptor_entries,
        encrypted_entries=encrypted_entries,
    )


def rebuild_zip_from_entries(entries: list[ZipEntryCandidate]) -> bytes:
    output = bytearray()
    central_directory = bytearray()

    for entry in entries:
        local_offset = len(output)
        flags = entry.flags & ~0x08
        output.extend(struct.pack(
            "<IHHHHHIIIHH",
            0x04034B50,
            entry.version_needed,
            flags,
            entry.method,
            entry.mod_time,
            entry.mod_date,
            entry.crc32,
            entry.compressed_size,
            entry.uncompressed_size,
            len(entry.name),
            0,
        ))
        output.extend(entry.name)
        output.extend(entry.payload)

        central_directory.extend(struct.pack(
            "<IHHHHHHIIIHHHHHII",
            0x02014B50,
            20,
            entry.version_needed,
            flags,
            entry.method,
            entry.mod_time,
            entry.mod_date,
            entry.crc32,
            entry.compressed_size,
            entry.uncompressed_size,
            len(entry.name),
            0,
            0,
            0,
            0,
            0,
            local_offset,
        ))
        central_directory.extend(entry.name)

    cd_offset = len(output)
    output.extend(central_directory)
    output.extend(struct.pack(
        "<IHHHHIIH",
        0x06054B50,
        0,
        0,
        len(entries),
        len(entries),
        len(central_directory),
        cd_offset,
        0,
    ))
    return bytes(output)


def write_rebuilt_zip(data: bytes, path: Path) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(data)


def _parse_entry(data: bytes, offset: int) -> tuple[ZipEntryCandidate, int, str] | None:
    if offset + 30 > len(data):
        return None
    try:
        (
            signature,
            version_needed,
            flags,
            method,
            mod_time,
            mod_date,
            crc32,
            compressed_size,
            uncompressed_size,
            name_len,
            extra_len,
        ) = struct.unpack_from("<IHHHHHIIIHH", data, offset)
    except struct.error:
        return None
    if signature != 0x04034B50:
        return None
    name_start = offset + 30
    data_start = name_start + name_len + extra_len
    if name_len <= 0 or name_len > 4096 or extra_len > 65535 or data_start > len(data):
        return None
    name = data[name_start:name_start + name_len]
    if b"\x00" in name:
        return None

    warning = ""
    if flags & 0x08:
        descriptor = _find_data_descriptor(data, data_start)
        if descriptor is None:
            return None
        descriptor_start, next_offset, crc32, compressed_size, uncompressed_size = descriptor
        payload = data[data_start:descriptor_start]
        return (
            ZipEntryCandidate(
                name=name,
                payload=payload,
                version_needed=version_needed,
                flags=flags,
                method=method,
                mod_time=mod_time,
                mod_date=mod_date,
                crc32=crc32,
                compressed_size=compressed_size,
                uncompressed_size=uncompressed_size,
                local_offset=offset,
                data_descriptor=True,
            ),
            next_offset,
            warning,
        )

    data_end = data_start + compressed_size
    if data_end > len(data):
        return None
    if _looks_like_directory_or_archive_tail(data, data_start):
        return None
    payload = data[data_start:data_end]
    return (
        ZipEntryCandidate(
            name=name,
            payload=payload,
            version_needed=version_needed,
            flags=flags,
            method=method,
            mod_time=mod_time,
            mod_date=mod_date,
            crc32=crc32,
            compressed_size=compressed_size,
            uncompressed_size=uncompressed_size,
            local_offset=offset,
            data_descriptor=False,
        ),
        data_end,
        warning,
    )


def _find_data_descriptor(data: bytes, data_start: int) -> tuple[int, int, int, int, int] | None:
    next_sig = _find_next_zip_record(data, data_start)
    if next_sig is None:
        return None
    for descriptor_len, has_signature, zip64 in (
        (24, True, True),
        (20, False, True),
        (16, True, False),
        (12, False, False),
    ):
        descriptor_start = next_sig - descriptor_len
        if descriptor_start < data_start:
            continue
        if has_signature:
            if data[descriptor_start:descriptor_start + 4] != DD_SIG:
                continue
            if zip64:
                crc32, compressed_size, uncompressed_size = struct.unpack_from("<IQQ", data, descriptor_start + 4)
            else:
                crc32, compressed_size, uncompressed_size = struct.unpack_from("<III", data, descriptor_start + 4)
        else:
            if data[descriptor_start - 4:descriptor_start] == DD_SIG:
                continue
            if zip64:
                crc32, compressed_size, uncompressed_size = struct.unpack_from("<IQQ", data, descriptor_start)
            else:
                crc32, compressed_size, uncompressed_size = struct.unpack_from("<III", data, descriptor_start)
        if compressed_size == descriptor_start - data_start:
            return descriptor_start, next_sig, crc32, compressed_size, uncompressed_size
    return None


def _find_next_zip_record(data: bytes, start: int) -> int | None:
    candidates = [
        item for item in (
            data.find(LFH_SIG, start),
            data.find(CD_SIG, start),
            data.find(EOCD_SIG, start),
            data.find(ZIP64_EOCD_SIG, start),
            data.find(ZIP64_LOCATOR_SIG, start),
        )
        if item >= 0
    ]
    if not candidates:
        return None
    return min(candidates)


def _looks_like_directory_or_archive_tail(data: bytes, offset: int) -> bool:
    return data[offset:offset + 4] in {CD_SIG, EOCD_SIG, ZIP64_EOCD_SIG, ZIP64_LOCATOR_SIG}


def _dedupe(values: list[str]) -> list[str]:
    result = []
    seen = set()
    for value in values:
        if value in seen:
            continue
        seen.add(value)
        result.append(value)
    return result
