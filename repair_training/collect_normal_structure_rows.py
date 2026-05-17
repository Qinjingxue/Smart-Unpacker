from __future__ import annotations

import argparse
from concurrent.futures import FIRST_COMPLETED, ProcessPoolExecutor, wait
import json
from pathlib import Path
from typing import Any

from repair_training.collect_damage_rows import observe_damage_runtime
from repair_training.core.datasets import sha256_file, write_json, write_jsonl
from repair_training.core.plugin import normalize_format_name
from sunpack.contracts.archive_input import ArchiveInputDescriptor
from sunpack.contracts.archive_state import ArchiveState
from sunpack.detection.pipeline.processors.modules.format_structure.zip_structure_graph import inspect_zip_structure_graph
from sunpack.repair.job import RepairJob


SCHEMA_VERSION = 2


def main(argv: list[str] | None = None) -> int:
    args = _parser().parse_args(argv)
    fmt = normalize_format_name(args.format)
    if fmt != "zip":
        raise SystemExit("collect_normal_structure_rows currently supports --format zip only")
    output = Path(args.output)
    rows = collect_normal_structure_rows(
        material_root=Path(args.material_root),
        limit=max(0, int(args.limit or 0)),
        seed=int(args.seed or 20260516),
        max_entries=max(1, int(args.max_entries or 128)),
        workers=max(1, int(args.workers or 1)),
        workspace=Path(args.workspace),
        runtime_validation=not bool(args.no_runtime_validation),
    )
    write_jsonl(output, rows)
    summary = _summary(rows)
    summary_path = Path(args.summary_output) if args.summary_output else output.with_name("normal_structure_row_summary.json")
    write_json(summary_path, summary)
    print(json.dumps({"output": str(output), "summary": str(summary_path), **summary}, ensure_ascii=False, sort_keys=True))
    return 0


def collect_normal_structure_rows(
    *,
    material_root: str | Path,
    limit: int = 0,
    seed: int = 20260516,
    max_entries: int = 128,
    workers: int = 1,
    workspace: str | Path = "repair_training/tmp/normal_world_collect",
    runtime_validation: bool = True,
) -> list[dict[str, Any]]:
    sources = _zip_sources(Path(material_root))
    if limit:
        sources = sources[:limit]
    if workers <= 1:
        rows = []
        for index, path in enumerate(sources):
            row, _failure = _collect_one(index, path, max_entries=max_entries, workspace=Path(workspace), runtime_validation=runtime_validation)
            if row:
                rows.append(row)
        return rows
    rows_by_index: dict[int, dict[str, Any]] = {}
    with ProcessPoolExecutor(max_workers=max(1, int(workers or 1))) as pool:
        futures = {}
        for index, path in enumerate(sources):
            futures[pool.submit(_collect_one, index, path, max_entries=max_entries, workspace=Path(workspace), runtime_validation=runtime_validation)] = index
        while futures:
            done, _pending = wait(futures, return_when=FIRST_COMPLETED)
            for future in done:
                index = futures.pop(future)
                row, _failure = future.result()
                if row:
                    rows_by_index[index] = row
    return [rows_by_index[index] for index in sorted(rows_by_index)]


def rows_from_graph(
    graph: dict[str, Any],
    *,
    sample_id: str,
    source_identity: dict[str, Any] | None = None,
) -> list[dict[str, Any]]:
    return [{
        "schema_version": SCHEMA_VERSION,
        "row_type": "normal_structure_supervised",
        "sample_id": sample_id,
        "format": "zip",
        "source_identity": dict(source_identity or {}),
        "knowledge_payload": {"format": {"zip": {"structure": {"graph": graph}}}},
    }]


def _zip_sources(material_root: Path) -> list[Path]:
    root = material_root / "zip" if (material_root / "zip").is_dir() else material_root
    return sorted(
        path
        for path in root.rglob("*.zip")
        if path.is_file() and _looks_like_clean_zip(path)
    )


def _summary(rows: list[dict[str, Any]]) -> dict[str, Any]:
    return {
        "schema_version": SCHEMA_VERSION,
        "rows": len(rows),
        "knowledge_rows": len(rows),
        "training_semantics": "masked_archive_knowledge_v1",
    }


def _collect_one(
    index: int,
    path: Path,
    *,
    max_entries: int,
    workspace: Path,
    runtime_validation: bool,
) -> tuple[dict[str, Any] | None, dict[str, Any] | None]:
    try:
        password = _password_for_clean_zip(path)
        graph = inspect_zip_structure_graph(str(path), max_entries=max_entries)
        source_identity = {
            "source_archive_id": path.stem,
            "source_path": str(path),
            "clean_sha256": _sha256(path),
            "selection_reason": _clean_selection_reason(path),
            "password_present": bool(password),
        }
        source_input = {"kind": "path", "format_hint": "zip"}
        if password:
            source_input["password"] = password
        knowledge_payload: dict[str, Any] = {
            "format": {"zip": {"structure": {"graph": graph}}},
            "source": {"input": source_input},
        }
        if password:
            knowledge_payload["archive"] = {
                "password": password,
                "password_present": True,
            }
        observation: dict[str, Any] = {}
        if runtime_validation:
            job = _job_for_path(path, index=index)
            try:
                request_payload, observation = observe_damage_runtime(
                    job,
                    workspace=workspace / f"sample_{index:06d}",
                )
            except Exception as exc:
                observation = {
                    "runtime_error": type(exc).__name__,
                    "runtime_error_message": str(exc),
                    "directory_semantics_kept": True,
                }
            else:
                observation["runtime_complete"] = _runtime_complete(observation)
                observation["directory_semantics_kept"] = True
                knowledge_payload = request_payload.get("knowledge_payload") if isinstance(request_payload.get("knowledge_payload"), dict) else knowledge_payload
        return {
            "schema_version": SCHEMA_VERSION,
            "row_type": "normal_structure_supervised",
            "sample_id": f"clean:{index:06d}",
            "format": "zip",
            "source_identity": source_identity,
            "state_digest": source_identity["clean_sha256"],
            "knowledge_payload": knowledge_payload,
            "runtime_observation": observation,
        }, None
    except Exception as exc:
        return None, {"path": str(path), "reason": type(exc).__name__, "error": str(exc)}


def _job_for_path(path: Path, *, index: int) -> RepairJob:
    password = _password_for_clean_zip(path)
    source_input = {
        "path": str(path),
        "kind": "path",
        "format_hint": "zip",
    }
    if password:
        source_input["password"] = password
    descriptor = ArchiveInputDescriptor.from_any(source_input, archive_path=str(path), format_hint="zip")
    state = ArchiveState.from_archive_input(descriptor)
    knowledge: dict[str, Any] = {"source": {"input": descriptor.to_dict()}}
    if password:
        knowledge["archive"] = {
            "password": password,
            "password_present": True,
        }
    return RepairJob(
        source_input=source_input,
        format="zip",
        confidence=1.0,
        damage_flags=[],
        password=password or None,
        archive_key=f"clean:{index:06d}",
        archive_state=state,
        knowledge=knowledge,
    )


def _runtime_complete(observation: dict[str, Any]) -> bool:
    verification = observation.get("verification") if isinstance(observation.get("verification"), dict) else {}
    summary = verification.get("summary") if isinstance(verification.get("summary"), dict) else verification
    return (
        bool(observation.get("extraction_success"))
        and str(observation.get("verification_status") or summary.get("assessment_status") or "").lower() == "complete"
        and float(summary.get("completeness") or 0.0) >= 1.0
        and str(summary.get("decision_hint") or "").lower() in {"", "accept"}
    )


def _looks_like_clean_zip(path: Path) -> bool:
    if "damaged" in {part.lower() for part in path.parts}:
        return False
    name = path.name.lower()
    stem = path.stem
    if name.startswith("clean-"):
        return True
    parts = stem.split("__")
    return len(parts) >= 5 and parts[4] in {"l0", "l5", "l9"}


def _clean_selection_reason(path: Path) -> str:
    if path.name.lower().startswith("clean-"):
        return "clean_prefix"
    return "base_level_l0_l5_l9"


def _password_for_clean_zip(path: Path) -> str:
    manifest_password = _password_from_material_manifest(path)
    if manifest_password:
        return manifest_password
    if "__encrypted_zipcrypto__" in path.name.lower():
        return "sunpack"
    return ""


def _password_from_material_manifest(path: Path) -> str:
    candidates = [path.parent / "damage_manifest.jsonl"]
    candidates.extend(sorted(path.parent.parent.glob("damage_manifest*.jsonl")) if path.parent.parent.exists() else [])
    names = _candidate_manifest_names(path.name)
    for manifest in candidates:
        if not manifest.is_file():
            continue
        try:
            with manifest.open("r", encoding="utf-8") as handle:
                for line in handle:
                    try:
                        record = json.loads(line)
                    except json.JSONDecodeError:
                        continue
                    for payload in (record.get("source_derivation"), record):
                        if not isinstance(payload, dict):
                            continue
                        output_name = str(payload.get("output_name") or payload.get("path_name") or "")
                        if output_name in names:
                            password = str(payload.get("zip_password") or record.get("password") or "")
                            if password:
                                return password
        except OSError:
            continue
    return ""


def _candidate_manifest_names(name: str) -> set[str]:
    names = {name}
    if name.lower().startswith("clean-"):
        names.add(name[6:])
    return names


def _sha256(path: Path) -> str:
    try:
        return sha256_file(path)
    except Exception:
        return ""


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Collect self-supervised ZIP normal-structure query rows from clean material.")
    parser.add_argument("--format", default="zip")
    parser.add_argument("--material-root", default=str(Path("repair_training") / "material"))
    parser.add_argument("--output", required=True)
    parser.add_argument("--summary-output", default="")
    parser.add_argument("--limit", type=int, default=0)
    parser.add_argument("--seed", type=int, default=20260516)
    parser.add_argument("--max-entries", type=int, default=128)
    parser.add_argument("--workers", type=int, default=1)
    parser.add_argument("--workspace", default=str(Path("repair_training") / "tmp" / "normal_world_collect"))
    parser.add_argument("--no-runtime-validation", action="store_true")
    return parser


if __name__ == "__main__":
    raise SystemExit(main())
