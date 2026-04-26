from typing import Any

from smart_unpacker_native import inspect_zip_eocd_structure as _native_inspect_zip_eocd_structure

from smart_unpacker.detection.pipeline.processors.context import FactProcessorContext
from smart_unpacker.detection.pipeline.processors.registry import register_processor
from smart_unpacker.support.external_command_cache import cached_value, file_identity


DEFAULT_MAX_CD_ENTRIES_TO_WALK = 16


def inspect_zip_eocd_structure(path: str, max_cd_entries_to_walk: int = DEFAULT_MAX_CD_ENTRIES_TO_WALK) -> dict[str, Any]:
    key = (file_identity(path), int(max_cd_entries_to_walk))
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
    return inspect_zip_eocd_structure(
        context.fact_bag.get("file.path") or "",
        int(context.fact_config.get("max_cd_entries_to_walk", DEFAULT_MAX_CD_ENTRIES_TO_WALK)),
    )
