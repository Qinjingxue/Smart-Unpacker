from typing import Dict, Any
from smart_unpacker.detection.pipeline.processors.context import FactProcessorContext
from smart_unpacker.detection.pipeline.processors.registry import register_processor
from smart_unpacker.extraction.internal.native_password_tester import NativePasswordTester

EXECUTABLE_PROBE_TYPES = {"pe", "elf", "macho", "te"}

@register_processor(
    "seven_zip_probe",
    input_facts={"file.path"},
    output_facts={"7z.probe"},
    schemas={
        "7z.probe": {
            "type": "dict",
            "description": "Lightweight 7-Zip probe result with archive/container/encryption/offset fields.",
        },
    },
)
def process_7z_probe(context: FactProcessorContext) -> Dict[str, Any]:
    base_path = context.fact_bag.get("file.path") or ""
    probe = NativePasswordTester().probe_archive(base_path)
    result = {
        "is_archive": probe.is_archive,
        "type": probe.archive_type or None,
        "offset": probe.offset,
        "is_encrypted": probe.is_encrypted,
        "is_broken": probe.is_broken,
        "checksum_error": probe.checksum_error,
        "error_text": probe.message.lower(),
    }
    if result["type"] in EXECUTABLE_PROBE_TYPES:
        result["is_archive"] = False

    return result
