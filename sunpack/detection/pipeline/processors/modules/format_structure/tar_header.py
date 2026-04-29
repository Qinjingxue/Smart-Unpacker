from typing import Any

from sunpack_native import inspect_tar_header_structure as _native_inspect_tar_header_structure

from sunpack.detection.pipeline.processors.context import FactProcessorContext
from sunpack.detection.pipeline.processors.identity import file_identity_for_context
from sunpack.detection.pipeline.processors.registry import register_processor
from sunpack.support.global_cache_manager import cached_value, file_identity


DEFAULT_MAX_TAR_ENTRIES_TO_WALK = 8


def inspect_tar_header_structure(
    path: str,
    max_entries_to_walk: int = DEFAULT_MAX_TAR_ENTRIES_TO_WALK,
    identity: tuple[str, int, int] | None = None,
) -> dict[str, Any]:
    key = (identity or file_identity(path), int(max_entries_to_walk))
    return cached_value(
        "format_tar_header_structure",
        key,
        lambda: dict(_native_inspect_tar_header_structure(path, max_entries_to_walk)),
    )


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
    path = context.fact_bag.get("file.path") or ""
    return inspect_tar_header_structure(
        path,
        int(context.fact_config.get("max_entries_to_walk", DEFAULT_MAX_TAR_ENTRIES_TO_WALK)),
        file_identity_for_context(context, path),
    )
