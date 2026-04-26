from typing import Any

from smart_unpacker_native import inspect_zip_local_header as _native_inspect_zip_local_header

from smart_unpacker.detection.pipeline.processors.context import FactProcessorContext
from smart_unpacker.detection.pipeline.processors.registry import register_processor
from smart_unpacker.support.external_command_cache import cached_value, file_identity


def inspect_zip_local_header(path: str, offset: int) -> dict[str, Any]:
    key = (file_identity(path), int(offset))
    return cached_value(
        "format_zip_local_header",
        key,
        lambda: dict(_native_inspect_zip_local_header(path, offset)),
    )


@register_processor(
    "zip_structure",
    input_facts={"file.path"},
    output_facts={"zip.local_header"},
    schemas={
        "zip.local_header": {
            "type": "dict",
            "description": "ZIP local header plausibility at the beginning of the candidate file.",
        },
    },
)
def process_zip_local_header(context: FactProcessorContext) -> dict[str, Any]:
    return inspect_zip_local_header(context.fact_bag.get("file.path") or "", 0)
