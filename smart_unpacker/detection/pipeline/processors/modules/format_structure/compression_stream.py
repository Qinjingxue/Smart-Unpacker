from typing import Any

from smart_unpacker_native import inspect_compression_stream_structure as _native_inspect_compression_stream_structure

from smart_unpacker.detection.pipeline.processors.context import FactProcessorContext
from smart_unpacker.detection.pipeline.processors.registry import register_processor


def inspect_compression_stream_structure(path: str) -> dict[str, Any]:
    return dict(_native_inspect_compression_stream_structure(path))


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
    return inspect_compression_stream_structure(context.fact_bag.get("file.path") or "")
