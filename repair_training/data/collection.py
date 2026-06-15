from __future__ import annotations

import argparse
import json
import math
import random
import time
from collections import Counter
from concurrent.futures import FIRST_COMPLETED, ProcessPoolExecutor, wait
from dataclasses import replace
from pathlib import Path
from typing import Any

from repair_training.run_store.cleanup import remove_tree_fast
from repair_training.data.io import read_jsonl, sha256_file, write_json
from sunpack.repair.model.diagnosis.features import damage_labels_for_row, damage_location_labels_from_target
from repair_training.data.material import attach_split_volumes
from repair_training.formats.base import load_training_format_plugin, normalize_format_name
from repair_training.run_store.layout import ensure_run_layout
from repair_training.formats.zip.source_material import (
    DEFAULT_ZIP_V3_DISTRIBUTION,
    _apply_profile_metadata,
    _choose_source_for_profile,
    _distributed_zip_sources,
    _expanded_profile_plan,
    _load_profile_distribution,
    _profile_layer_name,
    build_corpus_corruption_case,
)
from repair_training.formats.zip.observability import apply_zip_observability
from repair_training.data.taxonomy import normalize_damage_record
from sunpack.contracts.archive_input import ArchiveInputDescriptor
from sunpack.contracts.archive_state import ArchiveState
from sunpack.contracts.detection import FactBag
from sunpack.contracts.tasks import ArchiveTask
from sunpack.coordinator.analysis_stage import ArchiveAnalysisStage
from sunpack.analysis.knowledge import write_zip_structure_facts
from sunpack.detection.pipeline.processors.modules.format_structure.zip_directory_consistency import (
    inspect_zip_directory_consistency,
)
from sunpack.detection.pipeline.processors.modules.format_structure.zip_eocd import inspect_zip_eocd_structure
from sunpack.detection.pipeline.processors.modules.format_structure.zip_local_header import inspect_zip_local_header
from sunpack.detection.pipeline.processors.modules.format_structure.zip_structure_graph import inspect_zip_structure_graph
from sunpack.extraction.knowledge import write_extraction_result
from sunpack.extraction.scheduler import ExtractionScheduler
from sunpack.repair.job import RepairJob
from sunpack.repair.search.features import build_damage_analysis_request, request_to_dict
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
    cleanup_report: dict[str, Any] = {"enabled": not bool(args.keep_workspace), "removed": []}
    try:
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
        summary["cleanup"] = cleanup_report
        write_json(summary_output, summary)
        print(json.dumps({"output": str(output), "failures": str(failure_output), **summary}, ensure_ascii=False, sort_keys=True))
        return 0
    finally:
        if not args.keep_workspace:
            cleanup_report["removed"].append(_cleanup_workspace(workspace, run_root=run_root))
            try:
                write_json(summary_output.with_name(summary_output.stem + "_cleanup.json"), cleanup_report)
                if summary_output.is_file():
                    summary_payload = json.loads(summary_output.read_text(encoding="utf-8"))
                    if isinstance(summary_payload, dict):
                        summary_payload["cleanup"] = cleanup_report
                        write_json(summary_output, summary_payload)
            except Exception:
                pass


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
    knowledge_payload, observation = observe_damage_runtime(job, workspace=workspace / "runtime", config=config)
    if target.format == "zip":
        target_payload = apply_zip_observability(target_payload, knowledge_payload)
    target_payload = _enforce_single_field_target(record, target_payload)
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
        "state_digest": str(observation.get("state_digest") or ""),
        "round_index": 0,
        "patch_depth": 0,
        "knowledge_payload": knowledge_payload,
        "normal_label": 0,
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
    config = _damage_observation_config(config)
    extraction_config = dict(config.get("extraction") or {})
    extraction_config.setdefault("quiet", True)
    config["extraction"] = extraction_config
    workspace = Path(workspace)
    workspace.mkdir(parents=True, exist_ok=True)
    state = job.archive_state or ArchiveState.from_archive_input(job.archive_input())
    task = _task_for_job(job, state)
    ArchiveAnalysisStage(config).refresh_task_analysis(task)
    _preserve_source_split_metadata(task, job)
    if str(job.format or "").lower() == "zip":
        _ensure_zip_structure_facts(task)
        write_zip_structure_facts(task)
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
        "format_zip_structure": _nested(knowledge, "format", "zip", "structure") or {},
        "extraction": _nested(knowledge, "extraction") or {},
        "verification": _nested(knowledge, "verification") or {},
        "extraction_success": bool(getattr(extraction_result, "success", False)),
        "verification_status": getattr(verification_result, "assessment_status", ""),
    }
    return request_to_dict(request), observation


def _damage_observation_config(config: dict[str, Any] | None) -> dict[str, Any]:
    merged = dict(config or {})
    verification = dict(merged.get("verification") or {})
    if "enabled" not in verification:
        verification["enabled"] = True
    if not verification.get("methods"):
        verification["methods"] = [
            {"name": "extraction_exit_signal", "enabled": True},
            {"name": "output_presence", "enabled": True},
        ]
    merged["verification"] = verification
    return merged


def _ensure_zip_structure_facts(task: ArchiveTask) -> None:
    fact_bag = task.fact_bag
    path = str(fact_bag.get("file.path") or task.main_path or "")
    if not path:
        return
    fact_bag.set("file.path", path)
    if not isinstance(fact_bag.get("zip.eocd_structure"), dict):
        try:
            fact_bag.set("zip.eocd_structure", inspect_zip_eocd_structure(path))
        except Exception as exc:
            fact_bag.set("zip.eocd_structure", {"error": str(exc) or type(exc).__name__})
    if not isinstance(fact_bag.get("zip.directory_consistency"), dict):
        try:
            fact_bag.set("zip.directory_consistency", inspect_zip_directory_consistency(path))
        except Exception as exc:
            fact_bag.set("zip.directory_consistency", {"error": str(exc) or type(exc).__name__})
    if not isinstance(fact_bag.get("zip.structure_graph"), dict):
        try:
            fact_bag.set("zip.structure_graph", inspect_zip_structure_graph(path))
        except Exception as exc:
            fact_bag.set("zip.structure_graph", {"error": str(exc) or type(exc).__name__})
    if not isinstance(fact_bag.get("zip.local_header"), dict):
        try:
            local = inspect_zip_local_header(path, 0)
        except Exception as exc:
            local = {"error": str(exc) or type(exc).__name__}
        fact_bag.set("zip.local_header", local)
        if isinstance(local, dict):
            fact_bag.set("zip.local_header_plausible", bool(local.get("plausible")))
            fact_bag.set("zip.local_header_offset", int(local.get("offset") or 0))
            fact_bag.set("zip.local_header_error", str(local.get("error") or ""))


def _records_for_args(args: argparse.Namespace, *, workspace: Path) -> list[dict[str, Any]]:
    if args.manifest:
        return [record for record in read_jsonl(args.manifest) if record.get("damaged_input")]
    return _generate_zip_records(
        material_root=Path(args.material_root),
        workspace=workspace / "generated",
        seed=_seed(args.seed),
        per_source=max(0, int(args.per_source or 0)),
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
    requested_total = limit or len(profile_plan) or len(sources) * max(1, per_source)
    effective_per_source = max(1, per_source or math.ceil(requested_total / len(sources)))
    if limit:
        effective_per_source = max(effective_per_source, math.ceil(limit / len(sources)))
    total = limit or min(requested_total, len(sources) * effective_per_source)
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
        if effective_per_source and source_counts[source_key] >= effective_per_source:
            available = [item for item in sources if source_counts[str(item["source"])] < effective_per_source]
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
    source_input = _absolute_source_input(source_input)
    descriptor = ArchiveInputDescriptor.from_any(
        source_input,
        archive_path=_absolute_path_str(source_input.get("path") or record.get("damaged_path") or ""),
        format_hint=fmt,
    ).with_path_mapping(_absolute_path_str)
    state = ArchiveState.from_archive_input(descriptor)
    source_payload = descriptor.to_dict()
    for key in ("parts", "ranges", "split_sidecars_available"):
        if source_input.get(key):
            source_payload[key] = source_input.get(key)
    knowledge = {
        "source": {"input": source_payload},
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


def _absolute_source_input(source_input: dict[str, Any]) -> dict[str, Any]:
    output = dict(source_input)
    if output.get("path"):
        output["path"] = _absolute_path_str(output.get("path"))
    if isinstance(output.get("parts"), list):
        parts = []
        for item in output.get("parts") or []:
            if isinstance(item, dict):
                part = dict(item)
                if part.get("path"):
                    part["path"] = _absolute_path_str(part.get("path"))
                if isinstance(part.get("range"), dict):
                    item_range = dict(part["range"])
                    if item_range.get("path"):
                        item_range["path"] = _absolute_path_str(item_range.get("path"))
                    part["range"] = item_range
                parts.append(part)
            else:
                parts.append(item)
        output["parts"] = parts
    if isinstance(output.get("ranges"), list):
        ranges = []
        for item in output.get("ranges") or []:
            if isinstance(item, dict):
                item_range = dict(item)
                if item_range.get("path"):
                    item_range["path"] = _absolute_path_str(item_range.get("path"))
                ranges.append(item_range)
            else:
                ranges.append(item)
        output["ranges"] = ranges
    return output


def _absolute_path_str(value: Any) -> str:
    text = str(value or "")
    if not text:
        return ""
    path = Path(text)
    return str(path if path.is_absolute() else path.resolve())


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
    _preserve_source_split_metadata(task, job)
    return task


def _preserve_source_split_metadata(task: ArchiveTask, job: RepairJob) -> None:
    source_input = ((job.knowledge or {}).get("source") or {}).get("input") if isinstance((job.knowledge or {}).get("source"), dict) else {}
    if isinstance(source_input, dict) and any(source_input.get(key) for key in ("parts", "ranges", "split_sidecars_available")):
        knowledge = task.knowledge()
        merged_source = dict(knowledge.get("source.input") or {})
        for key in ("parts", "ranges", "split_sidecars_available"):
            if source_input.get(key):
                merged_source[key] = source_input.get(key)
        knowledge.set("source.input", merged_source, source_layer="training", source_module="collect_damage_rows")
        task.set_knowledge(knowledge)


def _location_target(raw_target: dict[str, Any]) -> dict[str, Any]:
    plugin = load_training_format_plugin("zip")
    allowed = set(plugin.damage_label_schema().labels if plugin.damage_label_schema else [])
    labels = [
        label
        for label in damage_location_labels_from_target(raw_target)
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


def _enforce_single_field_target(record: dict[str, Any], target_payload: dict[str, Any]) -> dict[str, Any]:
    field = str(record.get("single_field_root") or "")
    if not field:
        return target_payload
    field_label = f"field:{field}"
    zone = _single_field_zone(field)
    zone_label = f"zone:{zone}" if zone else ""
    labels = set(str(item) for item in target_payload.get("damage_labels") or [] if str(item))
    labels.add(field_label)
    if zone_label:
        labels.add(zone_label)
    target_payload = dict(target_payload)
    target_payload["damage_labels"] = sorted(labels)
    target_payload["labels"] = [
        {"label": label, "zone": {"kind": label.split(":", 1)[0], "path": label.split(":", 1)[1]}}
        for label in sorted(labels)
    ]
    metadata = dict(target_payload.get("metadata") or {})
    metadata["single_field_root"] = field
    target_payload["metadata"] = metadata
    return target_payload


def _single_field_zone(field: str) -> str:
    if field.startswith("sfx_prefix."):
        return "sfx_prefix"
    if field.startswith("split_volume."):
        return "split_volume"
    return field.split(".", 1)[0] if "." in field else ""


def _summary(rows: list[dict[str, Any]], failures: list[dict[str, Any]], *, elapsed: float) -> dict[str, Any]:
    label_counts: Counter[str] = Counter()
    profile_counts: Counter[str] = Counter()
    for row in rows:
        for label in damage_labels_for_row(row):
            label_counts[str(label)] += 1
        profile = str((row.get("metadata") or {}).get("damage_profile") or "")
        if profile:
            profile_counts[profile] += 1
    structure_coverage = _structure_coverage(rows)
    return {
        "schema_version": SCHEMA_VERSION,
        "rows": len(rows),
        "failures": len(failures),
        "elapsed_seconds": round(float(elapsed), 3),
        "label_counts": dict(sorted(label_counts.items())),
        "profile_counts": dict(sorted(profile_counts.items())),
        "structure_coverage": structure_coverage,
    }


def _structure_coverage(rows: list[dict[str, Any]]) -> dict[str, Any]:
    counters = Counter()
    for row in rows:
        knowledge = row.get("knowledge_payload") if isinstance(row.get("knowledge_payload"), dict) else {}
        structure = _nested(knowledge, "format", "zip", "structure") or {}
        raw_structure = {}
        observation_structure = (row.get("runtime_observation") or {}).get("format_zip_structure")
        if isinstance(observation_structure, dict) and observation_structure:
            counters["format_zip_structure_present"] += 1
        if structure or raw_structure:
            counters["analysis_native_probe_structure_present"] += 1
        merged = structure or raw_structure or (observation_structure if isinstance(observation_structure, dict) else {})
        graph = merged.get("graph") if isinstance(merged.get("graph"), dict) else {}
        graph_summary = graph.get("summary") if isinstance(graph.get("summary"), dict) else {}
        if graph:
            counters["zip_structure_graph_present"] += 1
        try:
            if float(graph_summary.get("cd_entry_count") or 0.0) > 0:
                counters["zip_graph_cd_entries_present"] += 1
        except (TypeError, ValueError):
            pass
        explanations = graph.get("explanations") if isinstance(graph.get("explanations"), list) else []
        if any(isinstance(item, dict) and item.get("kind") == "sfx_prefix_adjustment" for item in explanations):
            counters["zip_graph_sfx_explanation_present"] += 1
        if any(isinstance(item, dict) and item.get("kind") == "missing_range_adjustment" for item in explanations):
            counters["zip_graph_missing_range_explanation_present"] += 1
        if isinstance(merged.get("eocd"), dict) or any(str(key).startswith("eocd.") for key in merged):
            counters["zip_eocd_structure_present"] += 1
        if isinstance(merged.get("local_header"), dict) or any(str(key).startswith("local_header.") for key in merged):
            counters["zip_local_header_present"] += 1
        if isinstance(merged.get("directory_consistency"), dict) or any(
            str(key).startswith("directory_consistency.") for key in merged
        ):
            counters["zip_directory_consistency_present"] += 1
        if isinstance(merged.get("zip64_consistency"), dict) or any(str(key).startswith("zip64_consistency.") for key in merged):
            counters["zip64_consistency_present"] += 1
        descriptor = _descriptor_structure(merged)
        if descriptor:
            counters["zip_descriptor_facts_present"] += 1
            for field in (
                "wrong_local_header_target_count",
                "compressed_size_ends_inside_descriptor_count",
                "descriptor_span_conflicts_with_cd_size_count",
            ):
                if field in descriptor:
                    counters[f"{field}_present"] += 1
                    try:
                        if float(descriptor.get(field) or 0.0) != 0.0:
                            counters[f"{field}_nonzero"] += 1
                    except (TypeError, ValueError):
                        pass
    total = len(rows)
    return {
        name: {"count": int(counters.get(name, 0)), "ratio": float(counters.get(name, 0) / total) if total else 0.0}
        for name in (
            "zip_eocd_structure_present",
            "zip_local_header_present",
            "zip_directory_consistency_present",
            "zip64_consistency_present",
            "format_zip_structure_present",
            "analysis_native_probe_structure_present",
            "zip_structure_graph_present",
            "zip_graph_cd_entries_present",
            "zip_graph_sfx_explanation_present",
            "zip_graph_missing_range_explanation_present",
            "zip_descriptor_facts_present",
            "wrong_local_header_target_count_present",
            "wrong_local_header_target_count_nonzero",
            "compressed_size_ends_inside_descriptor_count_present",
            "compressed_size_ends_inside_descriptor_count_nonzero",
            "descriptor_span_conflicts_with_cd_size_count_present",
            "descriptor_span_conflicts_with_cd_size_count_nonzero",
        )
    }


def _descriptor_structure(structure: dict[str, Any]) -> dict[str, Any]:
    graph = structure.get("graph") if isinstance(structure.get("graph"), dict) else {}
    summary = graph.get("summary") if isinstance(graph.get("summary"), dict) else {}
    if summary:
        return {
            key: summary.get(key)
            for key in (
                "wrong_local_header_target_count",
                "compressed_size_ends_inside_descriptor_count",
                "descriptor_span_conflicts_with_cd_size_count",
            )
            if key in summary
        }
    directory = structure.get("directory_consistency")
    if isinstance(directory, dict):
        descriptor = directory.get("descriptor")
        if isinstance(descriptor, dict):
            return descriptor
    output: dict[str, Any] = {}
    prefix = "directory_consistency.descriptor."
    for key, value in structure.items():
        key_text = str(key)
        if key_text.startswith(prefix):
            output[key_text[len(prefix):]] = value
    return output


def _cleanup_workspace(workspace: Path, *, run_root: Path) -> dict[str, Any]:
    try:
        resolved_workspace = workspace.resolve()
        resolved_root = run_root.resolve()
        if resolved_workspace == resolved_root or resolved_root not in resolved_workspace.parents:
            return {"path": str(workspace), "ok": False, "reason": "outside_run_root"}
        return {"path": str(workspace), "ok": remove_tree_fast(resolved_workspace, root=resolved_root)}
    except Exception as exc:
        return {"path": str(workspace), "ok": False, "reason": str(exc)}


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
    parser.add_argument("--keep-workspace", action="store_true")
    parser.add_argument("--limit", type=int, default=0, help="Target number of generated damage rows. When set, collection auto-expands per-source variants as needed.")
    parser.add_argument("--workers", type=int, default=1)
    parser.add_argument("--seed", default="20260515")
    parser.add_argument("--per-source", type=int, default=0, help="Target variants per clean source. 0 means auto; --limit is never capped by this value.")
    parser.add_argument("--profile-distribution", default=str(DEFAULT_ZIP_V3_DISTRIBUTION))
    return parser


if __name__ == "__main__":
    raise SystemExit(main())
