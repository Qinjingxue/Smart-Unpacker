from typing import Any

from sunpack_native import inspect_zip_structure_graph as _native_inspect_zip_structure_graph

from sunpack.detection.pipeline.processors.context import FactProcessorContext
from sunpack.detection.pipeline.processors.identity import file_identity_for_context
from sunpack.detection.pipeline.processors.registry import register_processor
from sunpack.support.global_cache_manager import cached_value, file_identity


DEFAULT_MAX_ENTRIES = 128


def inspect_zip_structure_graph(
    path: str,
    max_entries: int = DEFAULT_MAX_ENTRIES,
    identity: tuple[str, int, int] | None = None,
) -> dict[str, Any]:
    key = (identity or file_identity(path), int(max_entries))
    return cached_value(
        "format_zip_structure_graph",
        key,
        lambda: dict(_native_inspect_zip_structure_graph(path, max_entries)),
    )


@register_processor(
    "zip_structure_graph",
    input_facts={"file.path"},
    output_facts={"zip.structure_graph"},
    schemas={
        "zip.structure_graph": {
            "type": "dict",
            "description": "ZIP structure graph with nodes, edges, violations, explanations, and summary facts.",
        },
    },
)
def process_zip_structure_graph(context: FactProcessorContext) -> dict[str, Any]:
    path = context.fact_bag.get("file.path") or ""
    return inspect_zip_structure_graph(
        path,
        int(context.fact_config.get("max_entries", DEFAULT_MAX_ENTRIES)),
        file_identity_for_context(context, path),
    )
