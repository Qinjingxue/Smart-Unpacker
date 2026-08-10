from __future__ import annotations

import hashlib
import os
import shutil
from pathlib import Path
from typing import Any

from sunpack.contracts.extraction import ExtractionResult
from sunpack.support.output_cleanup import (
    DEFAULT_OUTPUT_CLEANUP_MANAGER,
    OutputCleanupEvent,
    OutputCleanupResult,
    OutputRole,
)


def shelve_outcome_if_needed(outcome: Any | None, out_dir: str) -> None:
    if outcome is None:
        return
    current = Path(outcome.result.out_dir)
    target = Path(out_dir)
    if os.path.abspath(str(current)) != os.path.abspath(str(target)) or not current.exists():
        return
    attempt_id = str(getattr(outcome, "attempt_id", "") or "")
    suffix = (attempt_id or _outcome_storage_id(outcome))[:12]
    held = target.with_name(f"{target.name}.incumbent_{suffix}")
    cleanup = DEFAULT_OUTPUT_CLEANUP_MANAGER.cleanup_scoped_path(
        str(held),
        event=OutputCleanupEvent.INCUMBENT_REPLACE,
        role=OutputRole.INCUMBENT,
        workspace_root=str(held.parent),
    )
    _require_cleanup_ready(cleanup)
    shutil.move(str(current), str(held))
    retarget_result_output(outcome.result, str(current), str(held))


def promote_recovery_outcome(outcome: Any, out_dir: str) -> None:
    current = Path(outcome.result.out_dir)
    target = Path(out_dir)
    if os.path.abspath(str(current)) == os.path.abspath(str(target)):
        return
    if not current.exists():
        return
    cleanup = DEFAULT_OUTPUT_CLEANUP_MANAGER.cleanup_canonical(
        str(target),
        event=OutputCleanupEvent.PROMOTE_REPLACE_TARGET,
        planned_output_dir=str(target),
    )
    _require_cleanup_ready(cleanup)
    shutil.move(str(current), str(target))
    retarget_result_output(outcome.result, str(current), str(target))


def cleanup_shelved_outcome(outcome: Any | None, *, keep: Any | None = None) -> None:
    if outcome is None or keep is outcome:
        return
    path = Path(outcome.result.out_dir)
    if ".incumbent_" in path.name:
        DEFAULT_OUTPUT_CLEANUP_MANAGER.cleanup_scoped_path(
            str(path),
            event=OutputCleanupEvent.INCUMBENT_DISCARD,
            role=OutputRole.INCUMBENT,
            workspace_root=str(path.parent),
        )


def promote_beam_output(result: ExtractionResult, temp_dir: str, out_dir: str) -> ExtractionResult:
    if os.path.abspath(temp_dir) != os.path.abspath(out_dir):
        if not os.path.exists(temp_dir):
            return result
        cleanup = DEFAULT_OUTPUT_CLEANUP_MANAGER.cleanup_canonical(
            out_dir,
            event=OutputCleanupEvent.PROMOTE_REPLACE_TARGET,
            planned_output_dir=out_dir,
        )
        _require_cleanup_ready(cleanup)
        shutil.move(temp_dir, out_dir)
    result.out_dir = out_dir
    if isinstance(result.output_inventory_payload, dict):
        result.output_inventory_payload = {
            **result.output_inventory_payload,
            "root": os.path.abspath(out_dir),
        }
    manifest = Path(out_dir) / ".sunpack" / "extraction_manifest.json"
    result.progress_manifest = str(manifest) if manifest.exists() else ""
    return result


def cleanup_beam_evaluations(evaluated: dict[str, tuple[Any, ...]], *, keep: str = "") -> None:
    keep_abs = os.path.abspath(keep) if keep else ""
    for value in evaluated.values():
        temp_dir = str(value[-1])
        if keep_abs and os.path.abspath(temp_dir) == keep_abs:
            continue
        DEFAULT_OUTPUT_CLEANUP_MANAGER.cleanup_scoped_path(
            temp_dir,
            event=OutputCleanupEvent.BEAM_CANDIDATE_REJECTED,
            role=OutputRole.BEAM_CANDIDATE,
            workspace_root=str(Path(temp_dir).parent),
        )


def remove_output(
    path: str,
    *,
    event: OutputCleanupEvent = OutputCleanupEvent.VERIFICATION_RETRY,
    planned_output_dir: str | None = None,
) -> OutputCleanupResult:
    return DEFAULT_OUTPUT_CLEANUP_MANAGER.cleanup_canonical(
        path,
        event=event,
        planned_output_dir=planned_output_dir or path,
    )


def retarget_result_output(result: ExtractionResult, old_dir: str, new_dir: str) -> None:
    old = Path(old_dir)
    new = Path(new_dir)
    progress_manifest = result.progress_manifest
    result.out_dir = str(new)
    if not progress_manifest:
        return
    manifest_path = Path(progress_manifest)
    try:
        relative = manifest_path.relative_to(old)
    except ValueError:
        candidate = new / ".sunpack" / "extraction_manifest.json"
        result.progress_manifest = str(candidate) if candidate.exists() else progress_manifest
        return
    result.progress_manifest = str(new / relative)


def _outcome_storage_id(outcome: Any) -> str:
    result = outcome.result
    payload = "|".join((
        str(getattr(outcome, "attempt_source", "") or ""),
        str(getattr(outcome, "round_index", 0) or 0),
        str(getattr(result, "out_dir", "") or ""),
    ))
    return hashlib.sha256(payload.encode("utf-8", errors="replace")).hexdigest()


def _require_cleanup_ready(result: OutputCleanupResult) -> None:
    if result.cleaned or result.already_absent:
        return
    detail = result.error or result.reason
    raise OSError(f"replacement target cleanup refused: {detail}")
