from typing import Any

from sunpack_native import inspect_zip_eocd_structure as _native_inspect_zip_eocd_structure

from sunpack.detection.pipeline.processors.context import FactProcessorContext
from sunpack.detection.pipeline.processors.identity import file_identity_for_context
from sunpack.detection.pipeline.processors.registry import register_processor
from sunpack.detection.pipeline.processors.modules.format_structure.multi_volume import detection_binary_view, find_zip_eocd
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
        lambda: dict(_native_inspect_zip_eocd_structure(path, max_cd_entries_to_walk)),
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
    view = detection_binary_view(context)
    eocd_offset, candidate = find_zip_eocd(view)
    if eocd_offset is None:
        return {"plausible": False, "magic_matched": False, "error": "eocd_not_found", **candidate}
    max_entries = max(1, min(256, int(context.fact_config.get("max_cd_entries_to_walk", DEFAULT_MAX_CD_ENTRIES_TO_WALK))))
    payload = dict(view.probe_zip(
        eocd_offset=eocd_offset,
        max_cd_entries_to_walk=max_entries,
    ) or {})
    payload.update(candidate)
    payload.setdefault("comment_length", int(candidate.get("eocd_candidate_comment_length") or 0))
    payload.setdefault("declared_central_directory_offset", int(candidate.get("eocd_candidate_cd_offset") or 0))
    payload.setdefault("declared_central_directory_size", int(candidate.get("eocd_candidate_cd_size") or 0))
    payload.setdefault("declared_total_entries", int(payload.get("total_entries") or 0))
    payload.setdefault("trailing_bytes_after_eocd", max(0, view.size - int(payload.get("segment_end") or view.size)))
    physical_cd = int(payload.get("central_directory_offset") or 0)
    declared_cd = int(payload.get("declared_central_directory_offset") or 0)
    payload.setdefault("physical_central_directory_offset", physical_cd)
    payload.setdefault("inferred_central_directory_offset", physical_cd)
    payload.setdefault("inferred_central_directory_size", int(payload.get("central_directory_size") or 0))
    payload.setdefault("central_directory_offset_delta", physical_cd - declared_cd)
    payload.setdefault("central_directory_size_delta", 0)
    payload.setdefault("entry_count_delta", 0)
    links = int(payload.get("local_header_links_checked") or 0)
    payload.setdefault("local_header_links_ok_count", links if payload.get("local_header_links_ok") else 0)
    payload.setdefault("local_header_links_error_count", 0 if payload.get("local_header_links_ok") else 1)
    return payload
