from dataclasses import dataclass
import json
from pathlib import Path
from typing import Any

from smart_unpacker.contracts.archive_state import ArchiveState
from smart_unpacker.contracts.tasks import ArchiveTask
from smart_unpacker.extraction.result import ExtractionResult
from smart_unpacker.passwords import PasswordSession


@dataclass(frozen=True)
class VerificationEvidence:
    task: ArchiveTask
    extraction_result: ExtractionResult
    archive_state: ArchiveState
    archive_source: dict[str, Any]
    patch_digest: str
    state_is_patched: bool
    archive_path: str
    output_dir: str
    password: str | None
    fact_bag: Any
    health: dict[str, Any]
    analysis: dict[str, Any]
    selected_codepage: str | None = None
    progress_manifest: dict[str, Any] | None = None


def build_verification_evidence(
    task: ArchiveTask,
    extraction_result: ExtractionResult,
    password_session: PasswordSession | None = None,
) -> VerificationEvidence:
    fact_bag = task.fact_bag
    password = extraction_result.password_used
    if password is None and password_session is not None:
        password = password_session.get_resolved(task.key)
    if password is None:
        password = fact_bag.get("archive.password")
    archive_state = task.archive_state()
    archive_input = archive_state.to_archive_input_descriptor()
    return VerificationEvidence(
        task=task,
        extraction_result=extraction_result,
        archive_state=archive_state,
        archive_source=archive_state.source.to_dict(),
        patch_digest=archive_state.effective_patch_digest(),
        state_is_patched=bool(archive_state.patches),
        archive_path=archive_input.entry_path,
        output_dir=extraction_result.out_dir,
        password=password,
        fact_bag=fact_bag,
        health=dict(fact_bag.get("resource.health") or {}),
        analysis=dict(fact_bag.get("resource.analysis") or {}),
        selected_codepage=extraction_result.selected_codepage,
        progress_manifest=_load_progress_manifest(extraction_result),
    )


def _load_progress_manifest(extraction_result: ExtractionResult) -> dict[str, Any] | None:
    manifest_path = extraction_result.progress_manifest
    if not manifest_path and extraction_result.out_dir:
        candidate = Path(extraction_result.out_dir) / ".sunpack" / "extraction_manifest.json"
        if candidate.exists():
            manifest_path = str(candidate)
    if not manifest_path:
        return None
    try:
        payload = json.loads(Path(manifest_path).read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError, TypeError, ValueError):
        return None
    return payload if isinstance(payload, dict) else None
