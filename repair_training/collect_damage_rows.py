from __future__ import annotations

import argparse
import json
import random
import time
from collections import Counter
from concurrent.futures import FIRST_COMPLETED, ProcessPoolExecutor, wait
from dataclasses import replace
from pathlib import Path
from typing import Any

from repair_training.core.datasets import read_jsonl, sha256_file, write_json
from repair_training.core.features import damage_labels_for_row
from repair_training.core.material_records import attach_split_volumes
from repair_training.core.plugin import load_training_format_plugin, normalize_format_name
from repair_training.core.run_layout import ensure_run_layout
from repair_training.formats.zip.build_material_impl import (
    DEFAULT_ZIP_V3_DISTRIBUTION,
    _apply_profile_metadata,
    _choose_source_for_profile,
    _distributed_zip_sources,
    _expanded_profile_plan,
    _load_profile_distribution,
    _profile_layer_name,
    build_corpus_corruption_case,
)
from repair_training.taxonomy import normalize_damage_record
from sunpack.contracts.archive_input import ArchiveInputDescriptor
from sunpack.contracts.archive_state import ArchiveState
from sunpack.contracts.detection import FactBag
from sunpack.contracts.tasks import ArchiveTask
from sunpack.coordinator.analysis_stage import ArchiveAnalysisStage
from sunpack.extraction.knowledge import write_extraction_result
from sunpack.extraction.scheduler import ExtractionScheduler
from sunpack.repair.job import RepairJob
from sunpack.repair.policy.training_runtime import build_damage_analysis_request, request_to_dict
from sunpack.verification.knowledge import write_verification_result
from sunpack.verification.scheduler import VerificationScheduler


SCHEMA_VERSION = 1


def main(argv: list[str] | None = None) -> int:
    args = _parser().parse_args(argv)
    fmt = normalize_format_name(args.format)
    if fmt != "zip":
        raise SystemExit("collect_damage_rows currently supports --format zip only")
    output = Path(args.output)
    output.parent.mkdir(parents=True, exist_ok=True)
    run_root = output.parents[1] if output.parent.name == "datasets" else output.parent
    ensure_run_layout(run_root)
    workspace = Path(args.workspace) if args.workspace else run_root / "tmp" / "damage_rows"
    workspace.mkdir(parents=True, exist_ok=True)
    failure_output = Path(args.failure_output) if args.failure_output else output.with_name("damage_row_failures.jsonl")
    summary_output = Path(args.summary_output) if args.summary_output else output.with_name("damage_row_summary.json")
    records = _records_for_args(args, workspace=workspace)
    if args.limit:
        records = records[: max(0, int(args.limit))]
    started = time.perf_counter()
    rows, failures = collect_damage_rows(
        records,
        workspace=workspace,
        workers=max(1, int(args.workers or 1)),
    )
    _write_jsonl(output, rows)
    _write_jsonl(failure_output, failures)
    summary = _summary(rows, failures, elapsed=time.perf_counter() - started)
    write_json(summary_output, summary)
    print(json.dumps({"output": str(output), "failures": str(failure_output), **summary}, ensure_ascii=False, sort_keys=True))
    return 0


def collect_damage_rows(
    records: list[dict[str, Any]],
    *,
    workspace: str | Path,
    workers: int = 1,
    config: dict[str, Any] | None = None,
) -> tuple[list[dict[str, Any]], list[dict[str, Any]]]:
    workspace = Path(workspace)
    if workers <= 1:
        rows: list[dict[str, Any]] = []
        failures: list[dict[str, Any]] = []
        for index, record in enumerate(records):
            try:
                rows.append(collect_damage_row(record, workspace=workspace / f"row_{index:06d}", config=config))
            except Exception as exc:
                failures.append(_failure(record, exc))
        return rows, failures

    rows = []
    failures = []
    with ProcessPoolExecutor(max_workers=workers) as pool:
        futures = {
            pool.submit(_worker_collect_damage_row, index, record, str(workspace), config or {}): index
            for index, record in enumerate(records)
        }
        while futures:
            done, _ = wait(futures, return_when=FIRST_COMPLETED)
            for future in done:
                futures.pop(future, None)
                try:
                    rows.append(future.result())
                except Exception as exc:
                    failures.append({"error": str(exc), "type": type(exc).__name__})
    rows.sort(key=lambda row: str(row.get("sample_id") or row.get("episode_id") or ""))
    return rows, failures


def collect_damage_row(
    record: dict[str, Any],
    *,
    workspace: str | Path,
    config: dict[str, Any] | None = None,
) -> dict[str, Any]:
    workspace = Path(workspace)
    workspace.mkdir(parents=True, exist_ok=True)
    target = normalize_damage_record(record)
    target_payload = _location_target(target.to_dict())
    job = _job_from_record(record, target.format)
    request_payload, observation = observe_damage_runtime(job, workspace=workspace / "runtime", config=config)
    source_input = dict(record.get("damaged_input") or {})
    return {
        "schema_version": SCHEMA_VERSION,
        "row_type": "damage_analysis_supervised",
        "episode_id": str(record.get("query_id") or record.get("sample_id") or ""),
        "sample_id": str(record.get("sample_id") or ""),
        "format": target.format,
        "source_identity": {
            "source_archive_id": record.get("source_archive_id"),
            "source_path": record.get("source_path"),
            "clean_sha256": record.get("clean_sha256"),
            "corrupted_sha256": record.get("corrupted_sha256") or _sha256_path(source_input.get("path")),
        },
        "state_digest": str((request_payload.get("archive_state") or {}).get("patch_digest") or observation.get("state_digest") or ""),
        "round_index": 0,
        "patch_depth": 0,
        "damage_analysis_input": request_payload,
        "damage_analysis_target": target_payload,
        "oracle_damage": [label.to_dict() for label in target.training_labels()],
        "runtime_observation": observation,
        "metadata": {
            "collector": "collect_damage_rows",
            "damage_profile": record.get("damage_profile"),
            "damage_layer": record.get("damage_layer") or record.get("profile_layer") or record.get("actual_damage_layer"),
            "raw_damage_record": record,
        },
    }


def observe_damage_runtime(
    job: RepairJob,
    *,
    workspace: str | Path,
    config: dict[str, Any] | None = None,
) -> tuple[dict[str, Any], dict[str, Any]]:
    config = dict(config or {})
    extraction_config = dict(config.get("extraction") or {})
    extraction_config.setdefault("quiet", True)
    config["extraction"] = extraction_config
    workspace = Path(workspace)
    workspace.mkdir(parents=True, exist_ok=True)
    state = job.archive_state or ArchiveState.from_archive_input(job.archive_input())
    task = _task_for_job(job, state)
    ArchiveAnalysisStage(config).refresh_task_analysis(task)
    extraction_result = None
    verification_result = None
    extractor = ExtractionScheduler(
        process_config=dict(config.get("process") or {}),
        output_config=dict(config.get("output") or {}),
        extraction_config=dict(config.get("extraction") or {}),
    )
    try:
        extraction_result = extractor.extract(task, str(workspace / "extract"))
        write_extraction_result(task, extraction_result)
        verification_result = VerificationScheduler(config).verify(task, extraction_result)
        write_verification_result(task, verification_result)
    finally:
        extractor.close()
    observed_state = task.archive_state()
    knowledge = task.knowledge().to_dict()
    observed_job = replace(
        job,
        archive_state=observed_state,
        knowledge=knowledge,
        extraction_failure=_nested(knowledge, "extraction", "failure") or {},
        extraction_diagnostics=_nested(knowledge, "extraction", "diagnostics") or {},
    )
    request = build_damage_analysis_request(
        observed_job,
        observed_state,
        diagnosis={"format": observed_job.format},
        round_index=0,
    )
    observation = {
        "state_digest": observed_state.effective_patch_digest(),
        "patch_depth": observed_state.patch_depth(),
        "analysis": _nested(knowledge, "analysis") or {},
        "extraction": _nested(knowledge, "extraction") or {},
        "verification": _nested(knowledge, "verification") or {},
        "extraction_success": bool(getattr(extraction_result, "success", False)),
        "verification_status": getattr(verification_result, "assessment_status", ""),
    }
    return request_to_dict(request), observation


def _records_for_args(args: argparse.Namespace, *, workspace: Path) -> list[dict[str, Any]]:
    if args.manifest:
        return [record for record in read_jsonl(args.manifest) if record.get("damaged_input")]
    return _generate_zip_records(
        material_root=Path(args.material_root),
        workspace=workspace / "generated",
        seed=_seed(args.seed),
        per_source=max(1, int(args.per_source or 1)),
        limit=max(0, int(args.limit or 0)),
        distribution_path=Path(args.profile_distribution or DEFAULT_ZIP_V3_DISTRIBUTION),
    )


def _generate_zip_records(
    *,
    material_root: Path,
    workspace: Path,
    seed: int,
    per_source: int,
    limit: int,
    distribution_path: Path,
) -> list[dict[str, Any]]:
    rng = random.Random(seed)
    zip_dir = material_root / "zip"
    distribution, profile_metadata = _load_profile_distribution(str(distribution_path))
    profile_plan = _expanded_profile_plan(distribution, rng) if distribution else []
    sources = _distributed_zip_sources(zip_dir, set())
    if not sources:
        return []
    total = limit or min(len(profile_plan) or len(sources) * per_source, len(sources) * per_source)
    if not profile_plan:
        profile_plan = ["structural_directory"] * total
    records: list[dict[str, Any]] = []
    source_counts: Counter[str] = Counter()
    variant_counts: Counter[str] = Counter()
    for index, profile in enumerate(profile_plan):
        if len(records) >= total:
            break
        source_item = _choose_source_for_profile(sources, profile, source_counts, rng)
        source = Path(source_item["source"])
        source_key = str(source)
        if per_source and source_counts[source_key] >= per_source:
            available = [item for item in sources if source_counts[str(item["source"])] < per_source]
            if not available:
                break
            source_item = _choose_source_for_profile(available, profile, source_counts, rng)
            source = Path(source_item["source"])
            source_key = str(source)
        variant_index = int(variant_counts[source_key])
        variant_counts[source_key] += 1
        source_counts[source_key] += 1
        source_derivation = dict(source_item.get("source_derivation") or {})
        zip_password = str(source_derivation.get("zip_password") or "")
        case_root = workspace / str(source_item.get("source_archive_id") or source.stem) / f"v{variant_index:04d}"
        case = build_corpus_corruption_case(
            case_root,
            source_path=source,
            fmt="zip",
            seed=rng.randrange(1, 2**31 - 1) + index,
            variant_index=variant_index,
            damage_profile=profile,
            source_derivation=source_derivation,
            password=zip_password or None,
        )
        record = case.corpus_manifest_record(
            source_archive_id=str(source_item.get("source_archive_id") or source.stem),
            source_path=str(source),
            damage_profile=profile,
            variant_index=variant_index,
            material_format="zip",
            material_sample_id=str(Path(source_item.get("sample_dir") or "").name),
        )
        if zip_password and not record.get("password"):
            record["password"] = zip_password
        record["source_derivation"] = source_derivation
        record["damage_layer"] = _profile_layer_name(profile)
        record["requested_damage_layer"] = record["damage_layer"]
        record["actual_damage_layer"] = record["damage_layer"]
        record["damage_layer_weight"] = 1.0
        _apply_profile_metadata(record, profile, profile_metadata.get(profile) or {})
        records.append(record)
    return records


def _job_from_record(record: dict[str, Any], fmt: str) -> RepairJob:
    source_input = dict(record.get("damaged_input") or {})
    attach_split_volumes(source_input, record)
    descriptor = ArchiveInputDescriptor.from_any(
        source_input,
        archive_path=str(source_input.get("path") or record.get("damaged_path") or ""),
        format_hint=fmt,
    )
    state = ArchiveState.from_archive_input(descriptor)
    knowledge = {
        "source": {"input": descriptor.to_dict()},
    }
    return RepairJob(
        source_input=source_input,
        format=fmt,
        confidence=1.0,
        password=str(record.get("password") or source_input.get("password") or "") or None,
        damage_flags=[],
        archive_key=str(record.get("sample_id") or record.get("query_id") or ""),
        archive_state=state,
        knowledge=knowledge,
    )


def _task_for_job(job: RepairJob, state: ArchiveState) -> ArchiveTask:
    descriptor = state.to_archive_input_descriptor()
    main_path = descriptor.entry_path or str(job.source_input.get("path") or "")
    parts = descriptor.part_paths() or [main_path]
    bag = FactBag()
    bag.set("archive.input", descriptor.to_dict())
    bag.set("archive.knowledge", dict(job.knowledge or {"source": {"input": descriptor.to_dict()}}))
    task = ArchiveTask(
        fact_bag=bag,
        score=10,
        key=job.archive_key or main_path,
        main_path=main_path,
        all_parts=parts,
        logical_name=state.logical_name or descriptor.logical_name or job.archive_key,
        detected_ext=job.format,
    )
    task.set_archive_state(state)
    return task


def _location_target(raw_target: dict[str, Any]) -> dict[str, Any]:
    plugin = load_training_format_plugin("zip")
    allowed = set(plugin.damage_label_schema().labels if plugin.damage_label_schema else [])
    labels = [
        label
        for label in damage_labels_for_row({"damage_analysis_target": raw_target})
        if label in allowed and label.startswith(("zone:", "field:"))
    ]
    return {
        "schema_version": 2,
        "format": "zip",
        "analysis_target": "location_only",
        "damage_labels": sorted(set(labels)),
        "labels": [
            {"label": label, "zone": {"kind": label.split(":", 1)[0], "path": label.split(":", 1)[1]}}
            for label in sorted(set(labels))
        ],
        "metadata": {
            "taxonomy": raw_target,
            "label_source": "corruptor",
        },
    }


def _summary(rows: list[dict[str, Any]], failures: list[dict[str, Any]], *, elapsed: float) -> dict[str, Any]:
    label_counts: Counter[str] = Counter()
    profile_counts: Counter[str] = Counter()
    for row in rows:
        for label in (row.get("damage_analysis_target") or {}).get("damage_labels") or []:
            label_counts[str(label)] += 1
        profile = str((row.get("metadata") or {}).get("damage_profile") or "")
        if profile:
            profile_counts[profile] += 1
    return {
        "schema_version": SCHEMA_VERSION,
        "rows": len(rows),
        "failures": len(failures),
        "elapsed_seconds": round(float(elapsed), 3),
        "label_counts": dict(sorted(label_counts.items())),
        "profile_counts": dict(sorted(profile_counts.items())),
    }


def _worker_collect_damage_row(index: int, record: dict[str, Any], workspace: str, config: dict[str, Any]) -> dict[str, Any]:
    return collect_damage_row(record, workspace=Path(workspace) / f"row_{index:06d}", config=config)


def _failure(record: dict[str, Any], exc: Exception) -> dict[str, Any]:
    return {
        "sample_id": record.get("sample_id"),
        "damage_profile": record.get("damage_profile"),
        "error": str(exc),
        "type": type(exc).__name__,
    }


def _nested(payload: dict[str, Any], *path: str) -> Any:
    current: Any = payload
    for part in path:
        if not isinstance(current, dict):
            return None
        current = current.get(part)
    return current


def _sha256_path(path: Any) -> str:
    try:
        text = str(path or "")
        return sha256_file(text) if text else ""
    except Exception:
        return ""


def _seed(value: str) -> int:
    if str(value or "").lower() == "random":
        return random.randrange(1, 2**31 - 1)
    return int(value or 20260515)


def _write_jsonl(path: Path, rows: list[dict[str, Any]]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", encoding="utf-8") as handle:
        for row in rows:
            handle.write(json.dumps(row, ensure_ascii=False, sort_keys=True, default=str) + "\n")


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Collect supervised ZIP damage-analysis rows without repair candidates.")
    parser.add_argument("--format", default="zip")
    parser.add_argument("--material-root", default=str(Path("repair_training") / "material"))
    parser.add_argument("--manifest", default="")
    parser.add_argument("--output", required=True)
    parser.add_argument("--failure-output", default="")
    parser.add_argument("--summary-output", default="")
    parser.add_argument("--workspace", default="")
    parser.add_argument("--limit", type=int, default=0)
    parser.add_argument("--workers", type=int, default=1)
    parser.add_argument("--seed", default="20260515")
    parser.add_argument("--per-source", type=int, default=1)
    parser.add_argument("--profile-distribution", default=str(DEFAULT_ZIP_V3_DISTRIBUTION))
    return parser


if __name__ == "__main__":
    raise SystemExit(main())
