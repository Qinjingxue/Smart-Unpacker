from __future__ import annotations

from dataclasses import dataclass
import struct
import zlib


SEVEN_ZIP_MAGIC = b"7z\xbc\xaf\x27\x1c"


@dataclass(frozen=True)
class SevenZipStartHeader:
    start_crc: int
    computed_start_crc: int
    next_header_offset: int
    next_header_size: int
    next_header_crc: int
    archive_end: int
    next_header_crc_ok: bool

    @property
    def start_crc_ok(self) -> bool:
        return self.start_crc == self.computed_start_crc


def parse_start_header(data: bytes) -> SevenZipStartHeader | None:
    if len(data) < 32 or data[:6] != SEVEN_ZIP_MAGIC:
        return None
    try:
        start_crc = struct.unpack_from("<I", data, 8)[0]
        start_header = data[12:32]
        next_header_offset, next_header_size, next_header_crc = struct.unpack_from("<QQI", start_header)
    except struct.error:
        return None
    archive_end = 32 + next_header_offset + next_header_size
    if archive_end < 32 or archive_end > len(data):
        return None
    next_header = data[32 + next_header_offset:archive_end]
    return SevenZipStartHeader(
        start_crc=start_crc,
        computed_start_crc=zlib.crc32(start_header) & 0xFFFFFFFF,
        next_header_offset=next_header_offset,
        next_header_size=next_header_size,
        next_header_crc=next_header_crc,
        archive_end=archive_end,
        next_header_crc_ok=(zlib.crc32(next_header) & 0xFFFFFFFF) == next_header_crc,
    )

