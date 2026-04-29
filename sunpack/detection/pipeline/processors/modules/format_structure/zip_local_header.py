from typing import Any

from sunpack_native import inspect_zip_local_header as _native_inspect_zip_local_header

from sunpack.detection.pipeline.processors.context import FactProcessorContext
from sunpack.detection.pipeline.processors.identity import file_identity_for_context
from sunpack.detection.pipeline.processors.registry import register_processor
from sunpack.support.global_cache_manager import cached_value, file_identity


def inspect_zip_local_header(path: str, offset: int, identity: tuple[str, int, int] | None = None) -> dict[str, Any]:
    key = (identity or file_identity(path), int(offset))
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
    path = context.fact_bag.get("file.path") or ""
    return inspect_zip_local_header(path, 0, file_identity_for_context(context, path))
