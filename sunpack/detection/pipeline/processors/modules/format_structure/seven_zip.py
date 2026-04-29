from typing import Any

from sunpack_native import inspect_seven_zip_structure as _native_inspect_seven_zip_structure

from sunpack.detection.pipeline.processors.context import FactProcessorContext
from sunpack.detection.pipeline.processors.identity import file_identity_for_context
from sunpack.detection.pipeline.processors.registry import register_processor
from sunpack.support.global_cache_manager import cached_value, file_identity


DEFAULT_MAX_NEXT_HEADER_CHECK_BYTES = 1024 * 1024


def inspect_seven_zip_structure(
    path: str,
    magic_bytes: bytes | None = None,
    max_next_header_check_bytes: int = DEFAULT_MAX_NEXT_HEADER_CHECK_BYTES,
    identity: tuple[str, int, int] | None = None,
) -> dict[str, Any]:
    effective_magic = magic_bytes or b""
    key = (identity or file_identity(path), effective_magic, int(max_next_header_check_bytes))
    return cached_value(
        "format_seven_zip_structure",
        key,
        lambda: dict(_native_inspect_seven_zip_structure(path, effective_magic, max_next_header_check_bytes)),
    )


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
    path = facts.get("file.path") or ""
    return inspect_seven_zip_structure(
        path,
        facts.get("file.magic_bytes") or b"",
        int(context.fact_config.get("max_next_header_check_bytes", DEFAULT_MAX_NEXT_HEADER_CHECK_BYTES)),
        file_identity_for_context(context, path),
    )
