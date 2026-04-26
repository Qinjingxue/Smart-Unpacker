import os
from typing import Any

from smart_unpacker.detection.pipeline.processors.context import FactProcessorContext
from smart_unpacker.detection.pipeline.processors.registry import register_processor


TAR_BLOCK_SIZE = 512
DEFAULT_MAX_TAR_ENTRIES_TO_WALK = 8


def _empty_result(error: str = "") -> dict[str, Any]:
    return {
        "plausible": False,
        "error": error,
        "format": "",
        "stored_checksum": 0,
        "computed_checksum": 0,
        "file_size": 0,
        "member_size": 0,
        "ustar_magic": False,
        "zero_block": False,
        "entries_checked": 0,
        "entry_walk_ok": False,
        "end_zero_blocks": False,
    }


def _parse_octal_field(field: bytes) -> int | None:
    text = field.rstrip(b"\x00 ").strip()
    if not text:
        return 0
    try:
        return int(text.decode("ascii"), 8)
    except (UnicodeDecodeError, ValueError):
        return None


def _checksum(header: bytes) -> int:
    return sum(header[:148]) + (32 * 8) + sum(header[156:])


def _padding_for_size(size: int) -> int:
    remainder = size % TAR_BLOCK_SIZE
    return 0 if remainder == 0 else TAR_BLOCK_SIZE - remainder


def _header_plausible(header: bytes) -> tuple[bool, str, int, bool]:
    if len(header) < TAR_BLOCK_SIZE:
        return False, "short_header", 0, False
    if header == b"\x00" * TAR_BLOCK_SIZE:
        return False, "zero_block", 0, False
    stored_checksum = _parse_octal_field(header[148:156])
    member_size = _parse_octal_field(header[124:136])
    if stored_checksum is None:
        return False, "invalid_checksum_field", 0, False
    if member_size is None:
        return False, "invalid_size_field", 0, False
    if stored_checksum != _checksum(header):
        return False, "checksum_mismatch", member_size, False
    return True, "", member_size, header[257:263] in {b"ustar\x00", b"ustar "}


def _walk_tar_entries(path: str, file_size: int, max_entries: int) -> dict[str, Any]:
    result = {"entries_checked": 0, "entry_walk_ok": False, "end_zero_blocks": False, "error": ""}
    limit = max(0, int(max_entries or 0))
    if limit <= 0:
        return result
    offset = 0
    zero_blocks = 0
    try:
        with open(path, "rb") as handle:
            while result["entries_checked"] < limit and offset + TAR_BLOCK_SIZE <= file_size:
                handle.seek(offset)
                header = handle.read(TAR_BLOCK_SIZE)
                if header == b"\x00" * TAR_BLOCK_SIZE:
                    zero_blocks += 1
                    offset += TAR_BLOCK_SIZE
                    if zero_blocks >= 2:
                        result["end_zero_blocks"] = True
                        result["entry_walk_ok"] = result["entries_checked"] > 0
                        return result
                    continue
                zero_blocks = 0
                ok, error, member_size, _ustar = _header_plausible(header)
                if not ok:
                    result["error"] = error
                    return result
                next_offset = offset + TAR_BLOCK_SIZE + member_size + _padding_for_size(member_size)
                if next_offset > file_size:
                    result["error"] = "member_payload_out_of_range"
                    return result
                result["entries_checked"] += 1
                offset = next_offset
    except OSError as exc:
        result["error"] = f"os_error:{exc}"
        return result

    result["entry_walk_ok"] = result["entries_checked"] > 0
    return result


def inspect_tar_header_structure(path: str, max_entries_to_walk: int = DEFAULT_MAX_TAR_ENTRIES_TO_WALK) -> dict[str, Any]:
    try:
        file_size = os.path.getsize(path)
        if file_size < TAR_BLOCK_SIZE:
            return _empty_result("file_too_small")
        with open(path, "rb") as handle:
            header = handle.read(TAR_BLOCK_SIZE)
    except OSError as exc:
        return _empty_result(f"os_error:{exc}")

    result = _empty_result()
    result["file_size"] = file_size
    if len(header) < TAR_BLOCK_SIZE:
        result["error"] = "short_header"
        return result
    if header == b"\x00" * TAR_BLOCK_SIZE:
        result["error"] = "leading_zero_block"
        result["zero_block"] = True
        return result

    stored_checksum = _parse_octal_field(header[148:156])
    member_size = _parse_octal_field(header[124:136])
    computed_checksum = _checksum(header)
    result.update({
        "stored_checksum": stored_checksum or 0,
        "computed_checksum": computed_checksum,
        "member_size": member_size or 0,
        "ustar_magic": header[257:263] in {b"ustar\x00", b"ustar "},
    })

    if stored_checksum is None:
        result["error"] = "invalid_checksum_field"
        return result
    if member_size is None:
        result["error"] = "invalid_size_field"
        return result
    if stored_checksum != computed_checksum:
        result["error"] = "checksum_mismatch"
        return result

    result["plausible"] = True
    result["format"] = "ustar" if result["ustar_magic"] else "tar"
    walk = _walk_tar_entries(path, file_size, max_entries_to_walk)
    result["entries_checked"] = walk["entries_checked"]
    result["entry_walk_ok"] = walk["entry_walk_ok"]
    result["end_zero_blocks"] = walk["end_zero_blocks"]
    if walk["error"]:
        result["error"] = walk["error"]
        result["plausible"] = False
    return result


@register_processor(
    "tar_header_structure",
    input_facts={"file.path"},
    output_facts={"tar.header_structure"},
    schemas={
        "tar.header_structure": {
            "type": "dict",
            "description": "TAR header checksum and ustar marker structure check derived from the candidate file.",
        },
    },
)
def process_tar_header_structure(context: FactProcessorContext) -> dict[str, Any]:
    return inspect_tar_header_structure(
        context.fact_bag.get("file.path") or "",
        int(context.fact_config.get("max_entries_to_walk", DEFAULT_MAX_TAR_ENTRIES_TO_WALK)),
    )
