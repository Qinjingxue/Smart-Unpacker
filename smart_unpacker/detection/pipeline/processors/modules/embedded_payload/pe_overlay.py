import os
import struct
from typing import Any

from smart_unpacker.detection.pipeline.processors.modules.format_structure.zip_local_header import inspect_zip_local_header
from smart_unpacker.detection.pipeline.processors.context import FactProcessorContext
from smart_unpacker.detection.pipeline.processors.registry import register_processor

try:
    from smart_unpacker_native import inspect_pe_overlay_structure as _native_inspect_pe_overlay_structure
except ImportError:  # pragma: no cover - exercised when native extension is absent
    _native_inspect_pe_overlay_structure = None


OVERLAY_SCAN_WINDOW_BYTES = 65536
PE_SIGNATURE = b"PE\x00\x00"
SECTION_HEADER_SIZE = 40

ARCHIVE_MAGICS = (
    (b"7z\xbc\xaf\x27\x1c", "7z", ".7z"),
    (b"Rar!\x1a\x07\x01\x00", "rar", ".rar"),
    (b"Rar!\x1a\x07\x00", "rar", ".rar"),
    (b"PK\x03\x04", "zip", ".zip"),
    (b"\x1f\x8b\x08", "gzip", ".gz"),
    (b"BZh", "bzip2", ".bz2"),
    (b"\xfd7zXZ\x00", "xz", ".xz"),
    (b"\x28\xb5\x2f\xfd", "zstd", ".zst"),
)


def _empty_result(error: str = "") -> dict[str, Any]:
    return {
        "is_pe": False,
        "has_overlay": False,
        "archive_like": False,
        "error": error,
        "pe_header_offset": 0,
        "section_count": 0,
        "overlay_offset": 0,
        "overlay_size": 0,
        "archive_offset": 0,
        "offset_delta_from_overlay": 0,
        "format": "",
        "detected_ext": "",
        "confidence": "none",
        "evidence": [],
        "zip_local_header": {},
    }


def _find_archive_magic(sample: bytes) -> tuple[str, str, int] | None:
    best: tuple[str, str, int] | None = None
    for magic, archive_format, detected_ext in ARCHIVE_MAGICS:
        index = sample.find(magic)
        if index < 0:
            continue
        if best is None or index < best[2]:
            best = (archive_format, detected_ext, index)
    return best


def inspect_pe_overlay_structure(path: str, file_size: int | None = None, magic_bytes: bytes | None = None) -> dict[str, Any]:
    if _native_inspect_pe_overlay_structure is not None:
        try:
            return dict(_native_inspect_pe_overlay_structure(path, file_size, magic_bytes or b""))
        except Exception:
            pass

    try:
        actual_size = os.path.getsize(path) if file_size is None or file_size < 0 else int(file_size)
        with open(path, "rb") as handle:
            prefix = magic_bytes or b""
            if len(prefix) < 64:
                handle.seek(0)
                prefix = handle.read(64)
            if len(prefix) < 64 or not prefix.startswith(b"MZ"):
                return _empty_result("mz_magic_not_found")

            pe_header_offset = struct.unpack("<I", prefix[0x3C:0x40])[0]
            if pe_header_offset < 64 or pe_header_offset + 24 > actual_size:
                return _empty_result("pe_header_offset_out_of_range")

            handle.seek(pe_header_offset)
            pe_header = handle.read(24)
            if len(pe_header) < 24 or pe_header[:4] != PE_SIGNATURE:
                return _empty_result("pe_signature_not_found")

            section_count = struct.unpack("<H", pe_header[6:8])[0]
            optional_header_size = struct.unpack("<H", pe_header[20:22])[0]
            section_table_offset = pe_header_offset + 24 + optional_header_size
            section_table_size = section_count * SECTION_HEADER_SIZE
            if section_count <= 0 or section_table_offset + section_table_size > actual_size:
                return _empty_result("section_table_out_of_range")

            handle.seek(section_table_offset)
            section_table = handle.read(section_table_size)
    except OSError as exc:
        return _empty_result(f"os_error:{exc}")

    pe_end = 0
    for index in range(section_count):
        section = section_table[index * SECTION_HEADER_SIZE:(index + 1) * SECTION_HEADER_SIZE]
        raw_size = struct.unpack("<I", section[16:20])[0]
        raw_pointer = struct.unpack("<I", section[20:24])[0]
        if raw_pointer and raw_size:
            pe_end = max(pe_end, raw_pointer + raw_size)

    result = _empty_result()
    result.update({
        "is_pe": True,
        "error": "",
        "pe_header_offset": pe_header_offset,
        "section_count": section_count,
        "overlay_offset": pe_end,
        "overlay_size": max(0, actual_size - pe_end),
        "evidence": ["pe:valid_headers"],
    })

    if pe_end <= 0 or pe_end >= actual_size:
        result["error"] = "overlay_not_found"
        return result
    result["has_overlay"] = True
    result["evidence"].append("pe:overlay_present")

    try:
        with open(path, "rb") as handle:
            handle.seek(pe_end)
            sample = handle.read(min(OVERLAY_SCAN_WINDOW_BYTES, actual_size - pe_end))
    except OSError as exc:
        result["error"] = f"os_error:{exc}"
        return result

    match = _find_archive_magic(sample)
    if match is None:
        result["error"] = "overlay_archive_magic_not_found"
        return result

    archive_format, detected_ext, relative_offset = match
    archive_offset = pe_end + relative_offset
    result.update({
        "archive_like": True,
        "error": "",
        "archive_offset": archive_offset,
        "offset_delta_from_overlay": relative_offset,
        "format": archive_format,
        "detected_ext": detected_ext,
        "confidence": "strong" if relative_offset == 0 else "medium",
    })
    result["evidence"].append(
        "overlay:archive_magic_at_start" if relative_offset == 0 else "overlay:archive_magic_near_start"
    )
    if detected_ext == ".zip":
        zip_header = inspect_zip_local_header(path, archive_offset)
        result["zip_local_header"] = zip_header
        if zip_header.get("plausible"):
            result["evidence"].append("zip_local_header:plausible")
        else:
            result["confidence"] = "medium"
            result["evidence"].append("zip_local_header:implausible")
    return result


@register_processor(
    "pe_overlay_structure",
    input_facts={"file.path", "file.size", "file.magic_bytes"},
    output_facts={"pe.overlay_structure"},
    schemas={
        "pe.overlay_structure": {
            "type": "dict",
            "description": "PE header, overlay range, and archive-like overlay evidence derived from the candidate file.",
        },
    },
)
def process_pe_overlay_structure(context: FactProcessorContext) -> dict[str, Any]:
    facts = context.fact_bag
    return inspect_pe_overlay_structure(
        facts.get("file.path") or "",
        facts.get("file.size"),
        facts.get("file.magic_bytes") or b"",
    )
