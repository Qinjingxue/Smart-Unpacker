from typing import Any

from smart_unpacker_native import inspect_archive_container_structure as _native_inspect_archive_container_structure

from smart_unpacker.detection.pipeline.processors.context import FactProcessorContext
from smart_unpacker.detection.pipeline.processors.registry import register_processor


def inspect_archive_container_structure(path: str) -> dict[str, Any]:
    return dict(_native_inspect_archive_container_structure(path))


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
    return inspect_archive_container_structure(context.fact_bag.get("file.path") or "")
