import os
import struct
import zlib
from typing import Any

from smart_unpacker.detection.pipeline.processors.context import FactProcessorContext
from smart_unpacker.detection.pipeline.processors.registry import register_processor


XZ_MAGIC = b"\xfd7zXZ\x00"
ZSTD_MAGIC = b"\x28\xb5\x2f\xfd"


def _empty_result(
    error: str = "",
    archive_format: str = "",
    detected_ext: str = "",
    magic_matched: bool = False,
) -> dict[str, Any]:
    return {
        "plausible": False,
        "error": error,
        "magic_matched": magic_matched,
        "format": archive_format,
        "detected_ext": detected_ext,
        "confidence": "none",
        "evidence": [f"{archive_format}:magic"] if archive_format and magic_matched else [],
    }


def _crc32_le(data: bytes) -> int:
    return zlib.crc32(data) & 0xFFFFFFFF


def _inspect_gzip(header: bytes, file_size: int) -> dict[str, Any]:
    if file_size < 18:
        return _empty_result("gzip_too_small", "gzip", ".gz", True)
    if len(header) < 10:
        return _empty_result("short_gzip_header", "gzip", ".gz", header.startswith(b"\x1f\x8b"))
    if header[:3] != b"\x1f\x8b\x08":
        return _empty_result("gzip_magic_not_found")
    flags = header[3]
    if flags & 0xE0:
        return _empty_result("gzip_reserved_flags_set", "gzip", ".gz", True)
    return {
        "plausible": True,
        "error": "",
        "magic_matched": True,
        "format": "gzip",
        "detected_ext": ".gz",
        "confidence": "medium",
        "evidence": ["gzip:magic", "gzip:method:deflate", "gzip:flags_valid"],
    }


def _inspect_bzip2(header: bytes, file_size: int) -> dict[str, Any]:
    if file_size < 14:
        return _empty_result("bzip2_too_small", "bzip2", ".bz2", True)
    if len(header) < 10:
        return _empty_result("short_bzip2_header", "bzip2", ".bz2", header.startswith(b"BZh"))
    if not header.startswith(b"BZh") or header[3:4] not in b"123456789":
        return _empty_result("bzip2_magic_not_found", "bzip2", ".bz2", header.startswith(b"BZh"))
    marker = header[4:10]
    if marker not in {b"\x31\x41\x59\x26\x53\x59", b"\x17\x72\x45\x38\x50\x90"}:
        return _empty_result("bzip2_block_marker_not_found", "bzip2", ".bz2", True)
    return {
        "plausible": True,
        "error": "",
        "magic_matched": True,
        "format": "bzip2",
        "detected_ext": ".bz2",
        "confidence": "strong",
        "evidence": ["bzip2:magic", "bzip2:block_marker"],
    }


def _inspect_xz(path: str, header: bytes, file_size: int) -> dict[str, Any]:
    if file_size < 24:
        return _empty_result("xz_too_small", "xz", ".xz", True)
    if len(header) < 12 or not header.startswith(XZ_MAGIC):
        return _empty_result("xz_magic_not_found", "xz", ".xz", header.startswith(XZ_MAGIC))
    stream_flags = header[6:8]
    stored_header_crc = struct.unpack("<I", header[8:12])[0]
    if stored_header_crc != _crc32_le(stream_flags):
        return _empty_result("xz_header_crc_mismatch", "xz", ".xz", True)
    try:
        with open(path, "rb") as handle:
            handle.seek(file_size - 12)
            footer = handle.read(12)
    except OSError as exc:
        return _empty_result(f"os_error:{exc}", "xz", ".xz", True)
    if len(footer) != 12 or footer[-2:] != b"YZ":
        return _empty_result("xz_footer_magic_not_found", "xz", ".xz", True)
    stored_footer_crc = struct.unpack("<I", footer[:4])[0]
    if stored_footer_crc != _crc32_le(footer[4:10]):
        return _empty_result("xz_footer_crc_mismatch", "xz", ".xz", True)
    if footer[8:10] != stream_flags:
        return _empty_result("xz_stream_flags_mismatch", "xz", ".xz", True)
    return {
        "plausible": True,
        "error": "",
        "magic_matched": True,
        "format": "xz",
        "detected_ext": ".xz",
        "confidence": "strong",
        "evidence": ["xz:magic", "xz:header_crc", "xz:footer_crc"],
    }


def _inspect_zstd(header: bytes, file_size: int) -> dict[str, Any]:
    if file_size < 6:
        return _empty_result("zstd_too_small", "zstd", ".zst", True)
    if not header.startswith(ZSTD_MAGIC):
        return _empty_result("zstd_magic_not_found")
    descriptor = header[4]
    if descriptor & 0x08:
        return _empty_result("zstd_reserved_bit_set", "zstd", ".zst", True)
    single_segment = bool(descriptor & 0x20)
    if not single_segment and len(header) < 6:
        return _empty_result("zstd_window_descriptor_missing", "zstd", ".zst", True)
    return {
        "plausible": True,
        "error": "",
        "magic_matched": True,
        "format": "zstd",
        "detected_ext": ".zst",
        "confidence": "medium",
        "evidence": ["zstd:magic", "zstd:frame_descriptor"],
    }


def inspect_compression_stream_structure(path: str) -> dict[str, Any]:
    try:
        file_size = os.path.getsize(path)
        with open(path, "rb") as handle:
            header = handle.read(32)
    except OSError as exc:
        return _empty_result(f"os_error:{exc}")

    if header.startswith(b"\x1f\x8b"):
        return _inspect_gzip(header, file_size)
    if header.startswith(b"BZh"):
        return _inspect_bzip2(header, file_size)
    if header.startswith(XZ_MAGIC):
        return _inspect_xz(path, header, file_size)
    if header.startswith(ZSTD_MAGIC):
        return _inspect_zstd(header, file_size)
    return _empty_result("compression_stream_magic_not_found")


@register_processor(
    "compression_stream_structure",
    input_facts={"file.path"},
    output_facts={"compression.stream_structure"},
    schemas={
        "compression.stream_structure": {
            "type": "dict",
            "description": "Lightweight gzip, bzip2, xz, or zstd stream structure check derived from the candidate file.",
        },
    },
)
def process_compression_stream_structure(context: FactProcessorContext) -> dict[str, Any]:
    return inspect_compression_stream_structure(context.fact_bag.get("file.path") or "")
