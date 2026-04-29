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
    path = context.fact_bag.get("file.path") or ""
    return inspect_zip_eocd_structure(
        path,
        int(context.fact_config.get("max_cd_entries_to_walk", DEFAULT_MAX_CD_ENTRIES_TO_WALK)),
        file_identity_for_context(context, path),
    )
