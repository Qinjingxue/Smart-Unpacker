from typing import Any

from smart_unpacker_native import inspect_pe_overlay_structure as _native_inspect_pe_overlay_structure

from smart_unpacker.detection.pipeline.processors.context import FactProcessorContext
from smart_unpacker.detection.pipeline.processors.registry import register_processor


def inspect_pe_overlay_structure(path: str, file_size: int | None = None, magic_bytes: bytes | None = None) -> dict[str, Any]:
    return dict(_native_inspect_pe_overlay_structure(path, file_size, magic_bytes or b""))


@register_processor(
    "pe_overlay_structure",
    input_facts={"file.path", "file.size", "file.magic_bytes"},
    output_facts={"pe.overlay_structure"},
    schemas={
        "pe.overlay_structure": {
            "type": "dict",
            "description": "PE header, overlay range, and archive-like overlay evidence derived from the candidate file.",
        },
    },
)
def process_pe_overlay_structure(context: FactProcessorContext) -> dict[str, Any]:
    facts = context.fact_bag
    return inspect_pe_overlay_structure(
        facts.get("file.path") or "",
        facts.get("file.size"),
        facts.get("file.magic_bytes") or b"",
    )
