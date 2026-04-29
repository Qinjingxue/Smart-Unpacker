from __future__ import annotations

from dataclasses import dataclass
import struct

from ._rebuild import CD_SIG, EOCD_SIG, ZIP64_EOCD_SIG, ZIP64_LOCATOR_SIG


@dataclass(frozen=True)
class EocdRecord:
    offset: int
    end: int
    disk_no: int
    cd_disk_no: int
    disk_entries: int
    total_entries: int
    cd_size: int
    cd_offset: int
    comment: bytes


@dataclass(frozen=True)
class CentralDirectoryWalk:
    offset: int
    end: int
    count: int
    valid: bool


@dataclass(frozen=True)
class Zip64EocdRecord:
    offset: int
    end: int
    record_size: int
    disk_no: int
    cd_disk_no: int
    disk_entries: int
    total_entries: int
    cd_size: int
    cd_offset: int


@dataclass(frozen=True)
class Zip64LocatorRecord:
    offset: int
    end: int
    zip64_eocd_offset: int
    disk_no: int
    total_disks: int


@dataclass(frozen=True)
class CentralDirectoryEntry:
    offset: int
    end: int
    name: bytes
    extra: bytes
    comment: bytes
    flags: int
    method: int
    crc32: int
    compressed_size: int
    uncompressed_size: int
    local_header_offset: int
    name_len: int
    extra_len: int
    comment_len: int
    extra_offset: int


@dataclass(frozen=True)
class LocalHeaderRecord:
    offset: int
    data_offset: int
    name: bytes
    extra: bytes
    flags: int
    method: int
    crc32: int
    compressed_size: int
    uncompressed_size: int
    name_len: int
    extra_len: int
    extra_offset: int


@dataclass(frozen=True)
class Zip64ExtraField:
    offset: int
    size: int
    values_offset: int
    values: tuple[int, ...]


def find_eocd(data: bytes, *, allow_trailing_junk: bool = True) -> EocdRecord | None:
    pos = data.rfind(EOCD_SIG)
    while pos >= 0:
        record = _parse_eocd_at(data, pos)
        if record and (allow_trailing_junk or record.end == len(data)):
            return record
        pos = data.rfind(EOCD_SIG, 0, pos)
    return None


def find_valid_central_directory(data: bytes) -> CentralDirectoryWalk | None:
    pos = data.find(CD_SIG)
    best: CentralDirectoryWalk | None = None
    while pos >= 0:
        walk = walk_central_directory(data, pos)
        if walk.valid:
            if best is None or walk.count > best.count:
                best = walk
        pos = data.find(CD_SIG, pos + 4)
    return best


def walk_central_directory(data: bytes, offset: int, *, expected_end: int | None = None) -> CentralDirectoryWalk:
    pos = offset
    count = 0
    while pos + 46 <= len(data) and data[pos:pos + 4] == CD_SIG:
        try:
            name_len, extra_len, comment_len = struct.unpack_from("<HHH", data, pos + 28)
        except struct.error:
            break
        record_len = 46 + name_len + extra_len + comment_len
        if record_len < 46 or pos + record_len > len(data):
            break
        pos += record_len
        count += 1
        if expected_end is not None and pos >= expected_end:
            break
    valid = count > 0 and (expected_end is None or pos == expected_end)
    return CentralDirectoryWalk(offset=offset, end=pos, count=count, valid=valid)


def parse_central_directory_entries(
    data: bytes,
    offset: int,
    *,
    expected_end: int | None = None,
) -> list[CentralDirectoryEntry]:
    entries: list[CentralDirectoryEntry] = []
    pos = offset
    while pos + 46 <= len(data) and data[pos:pos + 4] == CD_SIG:
        try:
            (
                _signature,
                _version_made,
                _version_needed,
                flags,
                method,
                _mtime,
                _mdate,
                crc32,
                compressed_size,
                uncompressed_size,
                name_len,
                extra_len,
                comment_len,
                _disk_start,
                _internal_attr,
                _external_attr,
                local_header_offset,
            ) = struct.unpack_from("<IHHHHHHIIIHHHHHII", data, pos)
        except struct.error:
            break
        name_offset = pos + 46
        extra_offset = name_offset + name_len
        comment_offset = extra_offset + extra_len
        end = comment_offset + comment_len
        if end > len(data) or (expected_end is not None and end > expected_end):
            break
        entries.append(CentralDirectoryEntry(
            offset=pos,
            end=end,
            name=data[name_offset:extra_offset],
            extra=data[extra_offset:comment_offset],
            comment=data[comment_offset:end],
            flags=flags,
            method=method,
            crc32=crc32,
            compressed_size=compressed_size,
            uncompressed_size=uncompressed_size,
            local_header_offset=local_header_offset,
            name_len=name_len,
            extra_len=extra_len,
            comment_len=comment_len,
            extra_offset=extra_offset,
        ))
        pos = end
    if expected_end is not None and pos != expected_end:
        return []
    return entries


def parse_local_header(data: bytes, offset: int) -> LocalHeaderRecord | None:
    if offset < 0 or offset + 30 > len(data) or data[offset:offset + 4] != b"PK\x03\x04":
        return None
    try:
        (
            _signature,
            _version_needed,
            flags,
            method,
            _mtime,
            _mdate,
            crc32,
            compressed_size,
            uncompressed_size,
            name_len,
            extra_len,
        ) = struct.unpack_from("<IHHHHHIIIHH", data, offset)
    except struct.error:
        return None
    name_offset = offset + 30
    extra_offset = name_offset + name_len
    data_offset = extra_offset + extra_len
    if data_offset > len(data):
        return None
    return LocalHeaderRecord(
        offset=offset,
        data_offset=data_offset,
        name=data[name_offset:extra_offset],
        extra=data[extra_offset:data_offset],
        flags=flags,
        method=method,
        crc32=crc32,
        compressed_size=compressed_size,
        uncompressed_size=uncompressed_size,
        name_len=name_len,
        extra_len=extra_len,
        extra_offset=extra_offset,
    )


def find_zip64_eocd(data: bytes, *, before: int | None = None) -> Zip64EocdRecord | None:
    limit = len(data) if before is None else max(0, min(len(data), before))
    pos = data.rfind(ZIP64_EOCD_SIG, 0, limit)
    while pos >= 0:
        record = parse_zip64_eocd_at(data, pos)
        if record and record.end <= limit:
            return record
        pos = data.rfind(ZIP64_EOCD_SIG, 0, pos)
    return None


def parse_zip64_eocd_at(data: bytes, offset: int) -> Zip64EocdRecord | None:
    if offset + 56 > len(data) or data[offset:offset + 4] != ZIP64_EOCD_SIG:
        return None
    try:
        (
            _signature,
            record_size,
            _version_made,
            _version_needed,
            disk_no,
            cd_disk_no,
            disk_entries,
            total_entries,
            cd_size,
            cd_offset,
        ) = struct.unpack_from("<IQHHIIQQQQ", data, offset)
    except struct.error:
        return None
    end = offset + 12 + record_size
    if end < offset + 56 or end > len(data):
        return None
    return Zip64EocdRecord(
        offset=offset,
        end=end,
        record_size=record_size,
        disk_no=disk_no,
        cd_disk_no=cd_disk_no,
        disk_entries=disk_entries,
        total_entries=total_entries,
        cd_size=cd_size,
        cd_offset=cd_offset,
    )


def parse_zip64_locator_at(data: bytes, offset: int) -> Zip64LocatorRecord | None:
    if offset < 0 or offset + 20 > len(data) or data[offset:offset + 4] != ZIP64_LOCATOR_SIG:
        return None
    try:
        _signature, disk_no, zip64_eocd_offset, total_disks = struct.unpack_from("<IIQI", data, offset)
    except struct.error:
        return None
    return Zip64LocatorRecord(
        offset=offset,
        end=offset + 20,
        zip64_eocd_offset=zip64_eocd_offset,
        disk_no=disk_no,
        total_disks=total_disks,
    )


def find_zip64_locator(data: bytes, eocd_offset: int) -> Zip64LocatorRecord | None:
    direct = parse_zip64_locator_at(data, eocd_offset - 20)
    if direct is not None:
        return direct
    pos = data.rfind(ZIP64_LOCATOR_SIG, 0, eocd_offset)
    return parse_zip64_locator_at(data, pos) if pos >= 0 else None


def parse_zip64_extra(extra: bytes, *, absolute_extra_offset: int) -> Zip64ExtraField | None:
    pos = 0
    while pos + 4 <= len(extra):
        header_id, size = struct.unpack_from("<HH", extra, pos)
        start = pos + 4
        end = start + size
        if end > len(extra):
            return None
        if header_id == 0x0001:
            values = []
            value_pos = start
            while value_pos + 8 <= end:
                values.append(struct.unpack_from("<Q", extra, value_pos)[0])
                value_pos += 8
            return Zip64ExtraField(
                offset=absolute_extra_offset + pos,
                size=size,
                values_offset=absolute_extra_offset + start,
                values=tuple(values),
            )
        pos = end
    return None


def rewrite_eocd(data: bytes, cd: CentralDirectoryWalk, *, comment: bytes = b"") -> bytes:
    output = bytearray(data[:cd.end])
    output.extend(struct.pack(
        "<IHHHHIIH",
        0x06054B50,
        0,
        0,
        min(cd.count, 0xFFFF),
        min(cd.count, 0xFFFF),
        cd.end - cd.offset,
        cd.offset,
        len(comment),
    ))
    output.extend(comment)
    return bytes(output)


def trim_to_eocd(data: bytes, eocd: EocdRecord) -> bytes:
    zip64_tail = _zip64_tail_start(data, eocd.offset)
    if zip64_tail is None:
        return data[:eocd.end]
    return data[:eocd.end]


def _parse_eocd_at(data: bytes, offset: int) -> EocdRecord | None:
    if offset + 22 > len(data) or data[offset:offset + 4] != EOCD_SIG:
        return None
    try:
        (
            signature,
            disk_no,
            cd_disk_no,
            disk_entries,
            total_entries,
            cd_size,
            cd_offset,
            comment_len,
        ) = struct.unpack_from("<IHHHHIIH", data, offset)
    except struct.error:
        return None
    if signature != 0x06054B50:
        return None
    end = offset + 22 + comment_len
    if end > len(data):
        return None
    return EocdRecord(
        offset=offset,
        end=end,
        disk_no=disk_no,
        cd_disk_no=cd_disk_no,
        disk_entries=disk_entries,
        total_entries=total_entries,
        cd_size=cd_size,
        cd_offset=cd_offset,
        comment=data[offset + 22:end],
    )


def _zip64_tail_start(data: bytes, eocd_offset: int) -> int | None:
    locator = data.rfind(ZIP64_LOCATOR_SIG, 0, eocd_offset)
    if locator < 0:
        return None
    record = data.rfind(ZIP64_EOCD_SIG, 0, locator)
    return record if record >= 0 else locator
