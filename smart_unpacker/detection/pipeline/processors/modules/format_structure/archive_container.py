import os
import struct
import zlib
from typing import Any

from smart_unpacker.detection.pipeline.processors.context import FactProcessorContext
from smart_unpacker.detection.pipeline.processors.registry import register_processor


def _empty_result(error: str = "") -> dict[str, Any]:
    return {
        "plausible": False,
        "error": error,
        "format": "",
        "detected_ext": "",
        "confidence": "none",
        "evidence": [],
    }


def _inspect_cab(path: str, header: bytes, file_size: int) -> dict[str, Any]:
    if file_size < 36 or len(header) < 36:
        return _empty_result("cab_too_small")
    if header[:8] != b"MSCF\x00\x00\x00\x00":
        return _empty_result("cab_magic_not_found")
    cab_size = struct.unpack("<I", header[8:12])[0]
    files_offset = struct.unpack("<I", header[16:20])[0]
    version_minor = header[24]
    version_major = header[25]
    folder_count = struct.unpack("<H", header[26:28])[0]
    file_count = struct.unpack("<H", header[28:30])[0]
    if version_major != 1 or version_minor > 4:
        return _empty_result("cab_version_unsupported")
    if cab_size < 36 or cab_size > file_size:
        return _empty_result("cab_size_out_of_range")
    if folder_count == 0 or file_count == 0:
        return _empty_result("cab_empty_folder_or_file_count")
    if files_offset < 36 or files_offset >= cab_size:
        return _empty_result("cab_files_offset_out_of_range")
    return {
        "plausible": True,
        "error": "",
        "format": "cab",
        "detected_ext": ".cab",
        "confidence": "strong",
        "evidence": ["cab:magic", "cab:header_fields"],
    }


def _inspect_arj(header: bytes, file_size: int) -> dict[str, Any]:
    if file_size < 10 or len(header) < 10:
        return _empty_result("arj_too_small")
    if header[:2] != b"\x60\xea":
        return _empty_result("arj_magic_not_found")
    header_size = struct.unpack("<H", header[2:4])[0]
    header_end = 4 + header_size
    if header_size < 30 or header_end + 4 > file_size or header_end + 4 > len(header):
        return _empty_result("arj_header_size_out_of_range")
    header_data = header[4:header_end]
    stored_crc = struct.unpack("<I", header[header_end:header_end + 4])[0]
    if stored_crc != (zlib.crc32(header_data) & 0xFFFFFFFF):
        return _empty_result("arj_header_crc_mismatch")
    return {
        "plausible": True,
        "error": "",
        "format": "arj",
        "detected_ext": ".arj",
        "confidence": "strong",
        "evidence": ["arj:magic", "arj:header_crc"],
    }


def _parse_hex_field(value: bytes) -> int | None:
    try:
        return int(value.decode("ascii"), 16)
    except (UnicodeDecodeError, ValueError):
        return None


def _inspect_cpio(header: bytes, file_size: int) -> dict[str, Any]:
    if file_size < 110 or len(header) < 110:
        return _empty_result("cpio_too_small")
    if header[:6] not in {b"070701", b"070702"}:
        return _empty_result("cpio_magic_not_found")
    namesize = _parse_hex_field(header[94:102])
    member_size = _parse_hex_field(header[54:62])
    mode = _parse_hex_field(header[14:22])
    if namesize is None or namesize <= 0 or namesize > 4096:
        return _empty_result("cpio_invalid_namesize")
    if member_size is None:
        return _empty_result("cpio_invalid_filesize")
    if mode is None:
        return _empty_result("cpio_invalid_mode")
    if 110 + namesize > file_size:
        return _empty_result("cpio_name_out_of_range")
    return {
        "plausible": True,
        "error": "",
        "format": "cpio",
        "detected_ext": ".cpio",
        "confidence": "strong",
        "evidence": ["cpio:newc_magic", "cpio:hex_fields"],
    }


def inspect_archive_container_structure(path: str) -> dict[str, Any]:
    try:
        file_size = os.path.getsize(path)
        read_size = min(max(file_size, 0), 4096)
        with open(path, "rb") as handle:
            header = handle.read(read_size)
    except OSError as exc:
        return _empty_result(f"os_error:{exc}")

    if header.startswith(b"MSCF\x00\x00\x00\x00"):
        return _inspect_cab(path, header, file_size)
    if header.startswith(b"\x60\xea"):
        return _inspect_arj(header, file_size)
    if header.startswith((b"070701", b"070702")):
        return _inspect_cpio(header, file_size)
    return _empty_result("archive_container_magic_not_found")


@register_processor(
    "archive_container_structure",
    input_facts={"file.path"},
    output_facts={"archive.container_structure"},
    schemas={
        "archive.container_structure": {
            "type": "dict",
            "description": "Lightweight CAB, ARJ, or CPIO container structure check derived from the candidate file.",
        },
    },
)
def process_archive_container_structure(context: FactProcessorContext) -> dict[str, Any]:
    return inspect_archive_container_structure(context.fact_bag.get("file.path") or "")
