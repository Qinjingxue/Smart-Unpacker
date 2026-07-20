from __future__ import annotations

import os
from typing import Any

from sunpack.contracts.archive_state import ArchiveState
from sunpack.detection.pipeline.processors.context import FactProcessorContext
from sunpack.detection.pipeline.processors.registry import register_processor
from sunpack.support.sevenzip_bridge_worker import open_archive_metadata


DEFAULT_CANDIDATE_EXTENSIONS = (
    ".zip", ".7z", ".rar", ".001", ".cab", ".arj", ".cpio",
    ".lha", ".lzh", ".iso", ".wim", ".chm", ".rpm", ".deb",
)


@register_processor(
    "archive_metadata_open",
    input_facts={"file.path"},
    output_facts={"archive.metadata_open"},
    schemas={"archive.metadata_open": {"type": "dict", "description": "Isolated metadata-only archive open result."}},
)
def process_archive_metadata_open(context: FactProcessorContext) -> dict[str, Any]:
    facts = context.fact_bag
    path = str(facts.get("file.path") or "")
    extensions = {
        str(item).lower() if str(item).startswith(".") else f".{str(item).lower()}"
        for item in context.fact_config.get("candidate_extensions", DEFAULT_CANDIDATE_EXTENSIONS)
    }
    extension = os.path.splitext(path)[1].lower()
    if extension not in extensions or not facts.get("confirmation.identity_required"):
        return {"confirmed": False, "status": "skipped", "reason": "no_metadata_candidate"}

    descriptor = ArchiveState.from_any(
        facts.get("archive.state"),
        archive_path=path,
        part_paths=list(facts.get("candidate.member_paths") or [path]),
    ).to_archive_input_descriptor()
    if descriptor.open_mode not in {"file", "native_volumes", "sfx_with_volumes"}:
        return {"confirmed": False, "status": "skipped", "reason": "unsupported_open_mode"}
    result = open_archive_metadata(
        descriptor.entry_path,
        part_paths=descriptor.part_paths(),
        format_hint=descriptor.format_hint,
        timeout=float(context.fact_config.get("timeout_seconds", 1.5) or 1.5),
    )
    return {
        "confirmed": bool(result.ok and result.is_archive),
        "status": result.status,
        "type": result.archive_type,
        "item_count": result.item_count,
        "encrypted": result.encrypted,
        "timed_out": result.timed_out,
        "message": result.message,
    }
