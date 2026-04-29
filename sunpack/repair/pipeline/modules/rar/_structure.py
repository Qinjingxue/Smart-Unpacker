from __future__ import annotations

from dataclasses import dataclass
import struct


RAR4_MAGIC = b"Rar!\x1a\x07\x00"
RAR5_MAGIC = b"Rar!\x1a\x07\x01\x00"


@dataclass(frozen=True)
class RarWalkResult:
    version: int
    end_offset: int | None
    end_block_found: bool
    warnings: list[str]
    last_complete_offset: int | None = None


def walk_rar_blocks(data: bytes) -> RarWalkResult | None:
    if data.startswith(RAR4_MAGIC):
        return _walk_rar4(data)
    if data.startswith(RAR5_MAGIC):
        return _walk_rar5(data)
    return None


def _walk_rar4(data: bytes) -> RarWalkResult:
    pos = len(RAR4_MAGIC)
    last_complete = pos
    warnings: list[str] = []
    while pos + 7 <= len(data):
        header_type = data[pos + 2]
        flags = struct.unpack_from("<H", data, pos + 3)[0]
        header_size = struct.unpack_from("<H", data, pos + 5)[0]
        if header_size < 7 or pos + header_size > len(data):
            warnings.append("rar4 header size is out of range")
            break
        add_size = 0
        if flags & 0x8000:
            if pos + 11 > len(data):
                warnings.append("rar4 add_size is truncated")
                break
            add_size = struct.unpack_from("<I", data, pos + 7)[0]
        end = pos + header_size + add_size
        if end > len(data):
            warnings.append("rar4 block data is truncated")
            break
        if header_type == 0x7B:
            return RarWalkResult(version=4, end_offset=end, end_block_found=True, warnings=warnings, last_complete_offset=end)
        last_complete = end
        pos = end
    return RarWalkResult(version=4, end_offset=None, end_block_found=False, warnings=warnings, last_complete_offset=last_complete)


def _walk_rar5(data: bytes) -> RarWalkResult:
    pos = len(RAR5_MAGIC)
    last_complete = pos
    warnings: list[str] = []
    while pos + 5 <= len(data):
        header_start = pos + 4
        header_size, fields_start = _read_vint(data, header_start)
        if header_size is None or fields_start is None:
            warnings.append("rar5 header size vint is truncated")
            break
        fields_end = fields_start + header_size
        if fields_end > len(data):
            warnings.append("rar5 header is truncated")
            break
        block_type, after_type = _read_vint(data, fields_start)
        flags, after_flags = _read_vint(data, after_type or fields_start)
        if block_type is None or flags is None or after_flags is None:
            warnings.append("rar5 block type or flags vint is truncated")
            break
        cursor = after_flags
        if flags & 0x0001:
            _, cursor = _read_vint(data, cursor)
            if cursor is None:
                warnings.append("rar5 extra area size vint is truncated")
                break
        data_size = 0
        if flags & 0x0002:
            value, cursor = _read_vint(data, cursor)
            if value is None or cursor is None:
                warnings.append("rar5 data size vint is truncated")
                break
            data_size = value
        end = fields_end + data_size
        if end > len(data):
            warnings.append("rar5 block data is truncated")
            break
        if block_type == 5:
            return RarWalkResult(version=5, end_offset=end, end_block_found=True, warnings=warnings, last_complete_offset=end)
        last_complete = end
        pos = end
    return RarWalkResult(version=5, end_offset=None, end_block_found=False, warnings=warnings, last_complete_offset=last_complete)


def _read_vint(data: bytes, offset: int) -> tuple[int | None, int | None]:
    value = 0
    shift = 0
    pos = offset
    while pos < len(data) and shift <= 63:
        byte = data[pos]
        value |= (byte & 0x7F) << shift
        pos += 1
        if not byte & 0x80:
            return value, pos
        shift += 7
    return None, None
