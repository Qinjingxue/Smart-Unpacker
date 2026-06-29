from typing import Dict, Any
from sunpack.detection.pipeline.processors.context import FactProcessorContext
from sunpack.detection.pipeline.processors.registry import register_processor
from sunpack.support.sevenzip_bridge import cached_probe_archive
from sunpack.rename.scheduler import RenameScheduler

EXECUTABLE_PROBE_TYPES = {"pe", "elf", "macho", "te"}


def _known_embedded_archive_input(path: str, facts, part_paths: list[str]) -> dict[str, Any] | None:
    if len(part_paths) != 1:
        return None
    try:
        offset = int(facts.get("file.probe_offset") or 0)
    except (TypeError, ValueError):
        return None
    detected_ext = str(facts.get("file.detected_ext") or "").strip().lower()
    if offset <= 0 or not detected_ext:
        return None
    format_hint = detected_ext.lstrip(".")
    return {
        "kind": "archive_input",
        "entry_path": path,
        "open_mode": "file_range",
        "format_hint": format_hint,
        "parts": [{"path": path, "role": "main", "start": offset}],
        "segment": {"start": offset, "source": "detection"},
    }


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
        archive_input = _known_embedded_archive_input(staged.archive, context.fact_bag, staged.run_parts)
        probe = cached_probe_archive(
            staged.archive,
            part_paths=staged.run_parts,
            archive_input=archive_input,
        )
    finally:
        normalizer.cleanup_normalized_split_group(staged)
    probe_offset = int(probe.offset or 0)
    if archive_input is not None:
        probe_offset += int(archive_input["segment"]["start"])
    result = {
        "is_archive": probe.is_archive,
        "type": probe.archive_type or None,
        "offset": probe_offset,
        "is_encrypted": probe.is_encrypted,
        "is_broken": probe.is_broken,
        "checksum_error": probe.checksum_error,
        "error_text": probe.message.lower(),
    }
    if result["type"] in EXECUTABLE_PROBE_TYPES:
        result["is_archive"] = False

    return result
