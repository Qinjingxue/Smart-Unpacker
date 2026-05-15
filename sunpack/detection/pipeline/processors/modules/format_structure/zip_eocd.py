from typing import Any

from sunpack_native import inspect_zip_eocd_structure as _native_inspect_zip_eocd_structure

from sunpack.detection.pipeline.processors.context import FactProcessorContext
from sunpack.detection.pipeline.processors.identity import file_identity_for_context
from sunpack.detection.pipeline.processors.registry import register_processor
from sunpack.support.global_cache_manager import cached_value, file_identity


DEFAULT_MAX_CD_ENTRIES_TO_WALK = 16


def inspect_zip_eocd_structure(
    path: str,
    max_cd_entries_to_walk: int = DEFAULT_MAX_CD_ENTRIES_TO_WALK,
    identity: tuple[str, int, int] | None = None,
) -> dict[str, Any]:
    key = (identity or file_identity(path), int(max_cd_entries_to_walk))
    return cached_value(
        "format_zip_eocd_structure",
        key,
        lambda: _with_tolerant_eocd_candidate(path, dict(_native_inspect_zip_eocd_structure(path, max_cd_entries_to_walk))),
    )


@register_processor(
    "zip_eocd_structure",
    input_facts={"file.path"},
    output_facts={"zip.eocd_structure"},
    schemas={
        "zip.eocd_structure": {
            "type": "dict",
            "description": "ZIP EOCD and central directory structure check derived from the candidate file.",
        },
    },
)
def process_zip_eocd_structure(context: FactProcessorContext) -> dict[str, Any]:
    path = context.fact_bag.get("file.path") or ""
    return inspect_zip_eocd_structure(
        path,
        int(context.fact_config.get("max_cd_entries_to_walk", DEFAULT_MAX_CD_ENTRIES_TO_WALK)),
        file_identity_for_context(context, path),
    )


def _with_tolerant_eocd_candidate(path: str, payload: dict[str, Any]) -> dict[str, Any]:
    if payload.get("eocd_candidate_found") is not None:
        return payload
    candidate = _tolerant_eocd_candidate(path)
    if not candidate:
        payload.setdefault("eocd_candidate_found", False)
        return payload
    payload.update(candidate)
    payload.setdefault("eocd_candidate_found", True)
    if payload.get("eocd_offset") in (None, "", 0) and int(candidate.get("eocd_candidate_offset") or 0) > 0:
        payload.setdefault("eocd_offset", int(candidate.get("eocd_candidate_offset") or 0))
    if payload.get("declared_total_entries") in (None, ""):
        payload.setdefault("declared_total_entries", int(candidate.get("eocd_candidate_total_entries") or 0))
    if payload.get("declared_central_directory_offset") in (None, ""):
        payload.setdefault("declared_central_directory_offset", int(candidate.get("eocd_candidate_cd_offset") or 0))
    return payload


def _tolerant_eocd_candidate(path: str) -> dict[str, Any]:
    try:
        with open(path, "rb") as handle:
            handle.seek(0, 2)
            file_size = handle.tell()
            read_size = min(file_size, 22 + 65535)
            handle.seek(file_size - read_size)
            tail = handle.read(read_size)
    except OSError:
        return {}
    sig = b"PK\x05\x06"
    index = tail.rfind(sig)
    if index < 0 or index + 22 > len(tail):
        return {"eocd_candidate_found": False}
    offset = file_size - read_size + index
    record = tail[index:index + 22]
    comment_length = int.from_bytes(record[20:22], "little")
    available_comment = max(0, len(tail) - index - 22)
    total_entries = int.from_bytes(record[10:12], "little")
    cd_offset = int.from_bytes(record[16:20], "little")
    cd_size = int.from_bytes(record[12:16], "little")
    return {
        "eocd_candidate_found": True,
        "eocd_candidate_offset": int(offset),
        "eocd_candidate_comment_length": int(comment_length),
        "eocd_candidate_comment_available_delta": int(available_comment - comment_length),
        "eocd_candidate_declared_entry_count_present": total_entries > 0,
        "eocd_candidate_declared_cd_offset_present": cd_offset > 0,
        "eocd_candidate_total_entries": int(total_entries),
        "eocd_candidate_cd_offset": int(cd_offset),
        "eocd_candidate_cd_size": int(cd_size),
    }
