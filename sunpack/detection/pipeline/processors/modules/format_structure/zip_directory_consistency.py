from typing import Any

from sunpack_native import inspect_zip_directory_consistency as _native_inspect_zip_directory_consistency

from sunpack.detection.pipeline.processors.context import FactProcessorContext
from sunpack.detection.pipeline.processors.identity import file_identity_for_context
from sunpack.detection.pipeline.processors.registry import register_processor
from sunpack.support.global_cache_manager import cached_value, file_identity


DEFAULT_MAX_ENTRIES = 128


def inspect_zip_directory_consistency(
    path: str,
    max_entries: int = DEFAULT_MAX_ENTRIES,
    identity: tuple[str, int, int] | None = None,
) -> dict[str, Any]:
    key = (identity or file_identity(path), int(max_entries))
    return cached_value(
        "format_zip_directory_consistency",
        key,
        lambda: dict(_native_inspect_zip_directory_consistency(path, max_entries)),
    )


@register_processor(
    "zip_directory_consistency",
    input_facts={"file.path"},
    output_facts={"zip.directory_consistency"},
    schemas={
        "zip.directory_consistency": {
            "type": "dict",
            "description": "ZIP central directory, local header, descriptor, and ZIP64 consistency facts.",
        },
    },
)
def process_zip_directory_consistency(context: FactProcessorContext) -> dict[str, Any]:
    path = context.fact_bag.get("file.path") or ""
    return inspect_zip_directory_consistency(
        path,
        int(context.fact_config.get("max_entries", DEFAULT_MAX_ENTRIES)),
        file_identity_for_context(context, path),
    )
