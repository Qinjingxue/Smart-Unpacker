from typing import Any

from packrelic_native import inspect_archive_container_structure as _native_inspect_archive_container_structure

from packrelic.detection.pipeline.processors.context import FactProcessorContext
from packrelic.detection.pipeline.processors.identity import file_identity_for_context
from packrelic.detection.pipeline.processors.registry import register_processor
from packrelic.support.global_cache_manager import cached_value, file_identity


def inspect_archive_container_structure(path: str, identity: tuple[str, int, int] | None = None) -> dict[str, Any]:
    return cached_value(
        "format_archive_container_structure",
        (identity or file_identity(path),),
        lambda: dict(_native_inspect_archive_container_structure(path)),
    )


@register_processor(
    "archive_container_structure",
    input_facts={"file.path"},
    output_facts={"archive.container_structure"},
    schemas={
        "archive.container_structure": {
            "type": "dict",
            "description": "Lightweight CAB, ARJ, or CPIO container structure check derived from the candidate file.",
        },
    },
)
def process_archive_container_structure(context: FactProcessorContext) -> dict[str, Any]:
    path = context.fact_bag.get("file.path") or ""
    return inspect_archive_container_structure(path, file_identity_for_context(context, path))
