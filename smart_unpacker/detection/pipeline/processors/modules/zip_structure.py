import os
import struct
from typing import Any

from smart_unpacker.detection.pipeline.processors.context import FactProcessorContext
from smart_unpacker.detection.pipeline.processors.registry import register_processor


KNOWN_ZIP_COMPRESSION_METHODS = {0, 1, 6, 8, 9, 12, 14, 95, 96, 98, 99}
LOCAL_HEADER_LENGTH = 30


def inspect_zip_local_header(path: str, offset: int) -> dict[str, Any]:
    offset = max(0, int(offset or 0))
    result = {
        "offset": offset,
        "plausible": False,
        "error": "",
    }

    try:
        file_size = os.path.getsize(path)
        with open(path, "rb") as handle:
            handle.seek(offset)
            header = handle.read(LOCAL_HEADER_LENGTH)
    except OSError as exc:
        result["error"] = f"os_error:{exc}"
        return result

    if len(header) < LOCAL_HEADER_LENGTH:
        result["error"] = "short_header"
        return result
    if header[:4] != b"PK\x03\x04":
        result["error"] = "bad_signature"
        return result

    (
        version_needed,
        _flags,
        compression_method,
        _mod_time,
        _mod_date,
        _crc32,
        _compressed_size,
        _uncompressed_size,
        filename_len,
        extra_len,
    ) = struct.unpack("<HHHHHIIIHH", header[4:LOCAL_HEADER_LENGTH])

    if version_needed > 63:
        result["error"] = "unsupported_version"
        return result
    if compression_method not in KNOWN_ZIP_COMPRESSION_METHODS:
        result["error"] = "unknown_compression_method"
        return result
    if filename_len == 0 or filename_len > 4096:
        result["error"] = "invalid_filename_length"
        return result
    if offset + LOCAL_HEADER_LENGTH + filename_len + extra_len > file_size:
        result["error"] = "header_exceeds_file_size"
        return result

    result.update({
        "plausible": True,
        "version_needed": version_needed,
        "compression_method": compression_method,
        "filename_len": filename_len,
        "extra_len": extra_len,
    })
    return result


@register_processor(
    "zip_structure",
    input_facts={"file.path"},
    output_facts={"zip.local_header"},
    schemas={
        "zip.local_header": {
            "type": "dict",
            "description": "ZIP local header plausibility at the beginning of the candidate file.",
        },
    },
)
def process_zip_local_header(context: FactProcessorContext) -> dict[str, Any]:
    return inspect_zip_local_header(context.fact_bag.get("file.path") or "", 0)
