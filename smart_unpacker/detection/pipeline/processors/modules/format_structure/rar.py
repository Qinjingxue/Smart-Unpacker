from typing import Any

from smart_unpacker_native import inspect_rar_structure as _native_inspect_rar_structure

from smart_unpacker.detection.pipeline.processors.context import FactProcessorContext
from smart_unpacker.detection.pipeline.processors.registry import register_processor
from smart_unpacker.support.external_command_cache import cached_value, file_identity


DEFAULT_MAX_FIRST_HEADER_CHECK_BYTES = 1024 * 1024


def inspect_rar_structure(
    path: str,
    magic_bytes: bytes | None = None,
    max_first_header_check_bytes: int = DEFAULT_MAX_FIRST_HEADER_CHECK_BYTES,
) -> dict[str, Any]:
    effective_magic = magic_bytes or b""
    key = (file_identity(path), effective_magic, int(max_first_header_check_bytes))
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
    return inspect_rar_structure(
        facts.get("file.path") or "",
        facts.get("file.magic_bytes") or b"",
        int(context.fact_config.get("max_first_header_check_bytes", DEFAULT_MAX_FIRST_HEADER_CHECK_BYTES)),
    )
