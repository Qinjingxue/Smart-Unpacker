from typing import Any

from smart_unpacker_native import inspect_tar_header_structure as _native_inspect_tar_header_structure

from smart_unpacker.detection.pipeline.processors.context import FactProcessorContext
from smart_unpacker.detection.pipeline.processors.registry import register_processor
from smart_unpacker.support.external_command_cache import cached_value, file_identity


DEFAULT_MAX_TAR_ENTRIES_TO_WALK = 8


def inspect_tar_header_structure(path: str, max_entries_to_walk: int = DEFAULT_MAX_TAR_ENTRIES_TO_WALK) -> dict[str, Any]:
    key = (file_identity(path), int(max_entries_to_walk))
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
    return inspect_tar_header_structure(
        context.fact_bag.get("file.path") or "",
        int(context.fact_config.get("max_entries_to_walk", DEFAULT_MAX_TAR_ENTRIES_TO_WALK)),
    )
