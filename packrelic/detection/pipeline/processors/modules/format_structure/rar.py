from typing import Any

from packrelic_native import inspect_rar_structure as _native_inspect_rar_structure

from packrelic.detection.pipeline.format_defaults import DEFAULT_RAR_MAX_FIRST_HEADER_CHECK_BYTES
from packrelic.detection.pipeline.processors.context import FactProcessorContext
from packrelic.detection.pipeline.processors.identity import file_identity_for_context
from packrelic.detection.pipeline.processors.registry import register_processor
from packrelic.support.global_cache_manager import cached_value, file_identity


def inspect_rar_structure(
    path: str,
    magic_bytes: bytes | None = None,
    max_first_header_check_bytes: int = DEFAULT_RAR_MAX_FIRST_HEADER_CHECK_BYTES,
    identity: tuple[str, int, int] | None = None,
) -> dict[str, Any]:
    effective_magic = magic_bytes or b""
    key = (identity or file_identity(path), effective_magic, int(max_first_header_check_bytes))
    return cached_value(
        "format_rar_structure",
        key,
        lambda: dict(_native_inspect_rar_structure(path, effective_magic, max_first_header_check_bytes)),
    )


@register_processor(
    "rar_structure",
    input_facts={"file.path", "file.magic_bytes"},
    output_facts={"rar.structure"},
    schemas={
        "rar.structure": {
            "type": "dict",
            "description": "RAR4/RAR5 signature, main-header CRC, and optional second block/header walk checks.",
        },
    },
)
def process_rar_structure(context: FactProcessorContext) -> dict[str, Any]:
    facts = context.fact_bag
    path = facts.get("file.path") or ""
    return inspect_rar_structure(
        path,
        facts.get("file.magic_bytes") or b"",
        int(context.fact_config.get("max_first_header_check_bytes", DEFAULT_RAR_MAX_FIRST_HEADER_CHECK_BYTES)),
        file_identity_for_context(context, path),
    )
