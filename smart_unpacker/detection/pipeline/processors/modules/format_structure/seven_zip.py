import os
import struct
import zlib
from typing import Any

from smart_unpacker.detection.pipeline.processors.context import FactProcessorContext
from smart_unpacker.detection.pipeline.processors.registry import register_processor


SEVEN_Z_SIGNATURE = b"7z\xbc\xaf\x27\x1c"
HEADER_SIZE = 32
DEFAULT_MAX_NEXT_HEADER_CHECK_BYTES = 1024 * 1024


def _empty_result(error: str = "") -> dict[str, Any]:
    return {
        "plausible": False,
        "error": error,
        "magic_matched": False,
        "format": "",
        "detected_ext": "",
        "version_major": 0,
        "version_minor": 0,
        "next_header_offset": 0,
        "next_header_size": 0,
        "next_header_crc": 0,
        "start_header_crc_ok": False,
        "next_header_crc_checked": False,
        "next_header_crc_ok": False,
        "strong_accept": False,
        "confidence": "none",
        "evidence": [],
    }


def inspect_seven_zip_structure(
    path: str,
    magic_bytes: bytes | None = None,
    max_next_header_check_bytes: int = DEFAULT_MAX_NEXT_HEADER_CHECK_BYTES,
) -> dict[str, Any]:
    try:
        file_size = os.path.getsize(path)
        with open(path, "rb") as handle:
            header = magic_bytes or b""
            if len(header) < HEADER_SIZE:
                handle.seek(0)
                header = handle.read(HEADER_SIZE)
    except OSError as exc:
        return _empty_result(f"os_error:{exc}")

    if file_size < HEADER_SIZE:
        result = _empty_result("file_too_small")
        if header.startswith(SEVEN_Z_SIGNATURE):
            result.update({
                "magic_matched": True,
                "format": "7z",
                "detected_ext": ".7z",
                "evidence": ["7z:signature"],
            })
        return result
    if len(header) < HEADER_SIZE:
        return _empty_result("short_header")
    if not header.startswith(SEVEN_Z_SIGNATURE):
        return _empty_result("7z_signature_not_found")

    version_major = header[6]
    version_minor = header[7]
    stored_start_crc = struct.unpack("<I", header[8:12])[0]
    start_header = header[12:32]
    computed_start_crc = zlib.crc32(start_header) & 0xFFFFFFFF
    next_header_offset, next_header_size, next_header_crc = struct.unpack("<QQI", start_header)

    result = {
        "plausible": False,
        "error": "",
        "magic_matched": True,
        "format": "7z",
        "detected_ext": ".7z",
        "version_major": version_major,
        "version_minor": version_minor,
        "next_header_offset": next_header_offset,
        "next_header_size": next_header_size,
        "next_header_crc": next_header_crc,
        "start_header_crc_ok": stored_start_crc == computed_start_crc,
        "next_header_crc_checked": False,
        "next_header_crc_ok": False,
        "strong_accept": False,
        "confidence": "none",
        "evidence": ["7z:signature"],
    }

    if version_major != 0:
        result["error"] = "unsupported_version"
        return result
    if stored_start_crc != computed_start_crc:
        result["error"] = "start_header_crc_mismatch"
        return result
    next_header_start = HEADER_SIZE + next_header_offset
    if next_header_size <= 0 or next_header_start < HEADER_SIZE:
        result["error"] = "invalid_next_header_range"
        return result
    if next_header_start + next_header_size > file_size:
        result["error"] = "next_header_out_of_range"
        return result

    result["plausible"] = True
    result["confidence"] = "strong"
    result["evidence"].extend(["7z:start_header_crc", "7z:next_header_range"])
    if next_header_size <= max(0, int(max_next_header_check_bytes or 0)):
        try:
            with open(path, "rb") as handle:
                handle.seek(next_header_start)
                next_header = handle.read(next_header_size)
        except OSError as exc:
            result["error"] = f"os_error:{exc}"
            return result
        result["next_header_crc_checked"] = True
        result["next_header_crc_ok"] = (zlib.crc32(next_header) & 0xFFFFFFFF) == next_header_crc
        if result["next_header_crc_ok"]:
            result["strong_accept"] = True
            result["evidence"].append("7z:next_header_crc")
        else:
            result["error"] = "next_header_crc_mismatch"
    return result


@register_processor(
    "seven_zip_structure",
    input_facts={"file.path", "file.magic_bytes"},
    output_facts={"7z.structure"},
    schemas={
        "7z.structure": {
            "type": "dict",
            "description": "7z signature, version, start-header CRC, next-header range, and optional next-header CRC check.",
        },
    },
)
def process_seven_zip_structure(context: FactProcessorContext) -> dict[str, Any]:
    facts = context.fact_bag
    return inspect_seven_zip_structure(
        facts.get("file.path") or "",
        facts.get("file.magic_bytes") or b"",
        int(context.fact_config.get("max_next_header_check_bytes", DEFAULT_MAX_NEXT_HEADER_CHECK_BYTES)),
    )
