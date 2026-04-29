from typing import Dict, Any
from sunpack.detection.pipeline.processors.context import FactProcessorContext
from sunpack.detection.pipeline.processors.registry import register_processor
from sunpack.support.sevenzip_native import cached_probe_archive
from sunpack.rename.scheduler import RenameScheduler

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
    member_paths = list(context.fact_bag.get("candidate.member_paths") or [base_path])
    volume_entries = list(context.fact_bag.get("relation.split_volumes") or [])
    normalizer = RenameScheduler()
    staged = normalizer.normalize_archive_paths(base_path, member_paths, volume_entries=volume_entries)
    try:
        probe = cached_probe_archive(staged.archive, part_paths=staged.run_parts)
    finally:
        normalizer.cleanup_normalized_split_group(staged)
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
