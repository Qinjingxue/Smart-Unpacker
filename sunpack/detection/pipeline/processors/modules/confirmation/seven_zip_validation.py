from typing import Dict, Any
from sunpack.detection.pipeline.processors.context import FactProcessorContext
from sunpack.detection.pipeline.processors.registry import register_processor
from sunpack.support.sevenzip_native import cached_test_archive
from sunpack.rename.scheduler import RenameScheduler

EXECUTABLE_VALIDATION_TYPES = {"pe", "elf", "macho", "te"}


@register_processor(
    "seven_zip_validation",
    input_facts={"file.path"},
    output_facts={"7z.validation"},
    schemas={
        "7z.validation": {
            "type": "dict",
            "description": "7-Zip test result with ok/encrypted/error fields.",
        },
    },
)
def process_7z_validation(context: FactProcessorContext) -> Dict[str, Any]:
    base_path = context.fact_bag.get("file.path") or ""
    member_paths = list(context.fact_bag.get("candidate.member_paths") or [base_path])
    volume_entries = list(context.fact_bag.get("relation.split_volumes") or [])
    normalizer = RenameScheduler()
    staged = normalizer.normalize_archive_paths(base_path, member_paths, volume_entries=volume_entries)
    try:
        test = cached_test_archive(staged.archive, part_paths=staged.run_parts)
    finally:
        normalizer.cleanup_normalized_split_group(staged)
    validation_type = test.archive_type or ""
    checksum_error = test.checksum_error
    is_executable_container = validation_type in EXECUTABLE_VALIDATION_TYPES
    result = {
        "ok": test.ok and not is_executable_container,
        "command_ok": test.command_ok,
        "type": validation_type,
        "is_executable_container": is_executable_container,
        "warnings": [],
        "checksum_error": checksum_error,
        "encrypted": test.encrypted,
        "error_text": test.message.lower(),
    }

    return result
