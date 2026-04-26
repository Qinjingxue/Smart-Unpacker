from typing import Any

from smart_unpacker_native import inspect_seven_zip_structure as _native_inspect_seven_zip_structure

from smart_unpacker.detection.pipeline.processors.context import FactProcessorContext
from smart_unpacker.detection.pipeline.processors.registry import register_processor


DEFAULT_MAX_NEXT_HEADER_CHECK_BYTES = 1024 * 1024


def inspect_seven_zip_structure(
    path: str,
    magic_bytes: bytes | None = None,
    max_next_header_check_bytes: int = DEFAULT_MAX_NEXT_HEADER_CHECK_BYTES,
) -> dict[str, Any]:
    return dict(_native_inspect_seven_zip_structure(path, magic_bytes or b"", max_next_header_check_bytes))


@register_processor(
    "seven_zip_structure",
    input_facts={"file.path", "file.magic_bytes"},
    output_facts={"7z.structure"},
    schemas={
        "7z.structure": {
            "type": "dict",
            "description": "7z signature, version, start-header CRC, next-header range, CRC, and first-NID checks.",
        },
    },
)
def process_seven_zip_structure(context: FactProcessorContext) -> dict[str, Any]:
    facts = context.fact_bag
    return inspect_seven_zip_structure(
        facts.get("file.path") or "",
        facts.get("file.magic_bytes") or b"",
        int(context.fact_config.get("max_next_header_check_bytes", DEFAULT_MAX_NEXT_HEADER_CHECK_BYTES)),
    )
