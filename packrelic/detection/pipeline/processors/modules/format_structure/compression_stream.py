from typing import Any

from packrelic_native import inspect_compression_stream_structure as _native_inspect_compression_stream_structure

from packrelic.detection.pipeline.processors.context import FactProcessorContext
from packrelic.detection.pipeline.processors.identity import file_identity_for_context
from packrelic.detection.pipeline.processors.registry import register_processor
from packrelic.support.global_cache_manager import cached_value, file_identity


def inspect_compression_stream_structure(path: str, identity: tuple[str, int, int] | None = None) -> dict[str, Any]:
    return cached_value(
        "format_compression_stream_structure",
        (identity or file_identity(path),),
        lambda: dict(_native_inspect_compression_stream_structure(path)),
    )


@register_processor(
    "compression_stream_structure",
    input_facts={"file.path"},
    output_facts={"compression.stream_structure"},
    schemas={
        "compression.stream_structure": {
            "type": "dict",
            "description": "Lightweight gzip, bzip2, xz, or zstd stream structure check derived from the candidate file.",
        },
    },
)
def process_compression_stream_structure(context: FactProcessorContext) -> dict[str, Any]:
    path = context.fact_bag.get("file.path") or ""
    return inspect_compression_stream_structure(path, file_identity_for_context(context, path))
