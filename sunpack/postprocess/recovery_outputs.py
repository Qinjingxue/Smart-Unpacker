from __future__ import annotations

import hashlib
import os
import shutil
from pathlib import Path
from typing import Any

from sunpack.contracts.extraction import ExtractionResult


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
    shutil.rmtree(held, ignore_errors=True)
    shutil.move(str(current), str(held))
    retarget_result_output(outcome.result, str(current), str(held))


def promote_recovery_outcome(outcome: Any, out_dir: str) -> None:
    current = Path(outcome.result.out_dir)
    target = Path(out_dir)
    if os.path.abspath(str(current)) == os.path.abspath(str(target)):
        return
    shutil.rmtree(target, ignore_errors=True)
    if current.exists():
        shutil.move(str(current), str(target))
    retarget_result_output(outcome.result, str(current), str(target))


def cleanup_shelved_outcome(outcome: Any | None, *, keep: Any | None = None) -> None:
    if outcome is None or keep is outcome:
        return
    path = Path(outcome.result.out_dir)
    if ".incumbent_" in path.name:
        shutil.rmtree(path, ignore_errors=True)


def promote_beam_output(result: ExtractionResult, temp_dir: str, out_dir: str) -> ExtractionResult:
    if os.path.abspath(temp_dir) != os.path.abspath(out_dir):
        shutil.rmtree(out_dir, ignore_errors=True)
        if os.path.exists(temp_dir):
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
        shutil.rmtree(temp_dir, ignore_errors=True)


def remove_output(path: str) -> None:
    shutil.rmtree(path, ignore_errors=True)


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
