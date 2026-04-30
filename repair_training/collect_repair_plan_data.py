from __future__ import annotations

import argparse
import bz2
import gzip
import hashlib
import io
import json
import lzma
import multiprocessing as mp
import pickle
import os
import subprocess
import sys
import tarfile
import tempfile
import time
import zipfile
from dataclasses import replace
from pathlib import Path
from typing import Any

REPO_ROOT = Path(__file__).resolve().parents[1]
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

from sunpack.repair import RepairJob, RepairResult, RepairScheduler
from sunpack.repair.candidate import CandidateSelector, candidate_feature_payload, materialize_candidate


DEFAULT_MANIFEST = Path(".sunpack") / "corpus" / "repair_plan_manifest.jsonl"
DEFAULT_SUCCESS_OUTPUT = Path("repair_training") / "datasets" / "repair_plan_ltr_success.jsonl"
DEFAULT_FAILURE_OUTPUT = Path("repair_training") / "datasets" / "repair_plan_ltr_failure.jsonl"
DEFAULT_MATERIAL_ROOT = Path("repair_training") / "material"


def main(argv: list[str] | None = None) -> int:
    args = _parser().parse_args(argv)
    records = _load_records(args)
    success_output = Path(args.success_output)
    failure_output = Path(args.failure_output)
    success_output.parent.mkdir(parents=True, exist_ok=True)
    failure_output.parent.mkdir(parents=True, exist_ok=True)
    success_pretty_records: list[dict[str, Any]] = []
    failure_pretty_records: list[dict[str, Any]] = []
    summary = {
        "samples": 0,
        "success_rows": 0,
        "failure_rows": 0,
        "timeouts": 0,
        "failed": 0,
        "skipped": 0,
        "label_counts": {},
        "sample_best_label_counts": {},
        "oracle_strength_counts": {},
        "damage_layer_counts": {},
        "state_progress_count": 0,
        "partial_count": 0,
        "success_output": str(success_output),
        "failure_output": str(failure_output),
        "collector_shard": args.collector_shard,
        "collector_workers": args.collector_workers,
        "workspace": args.workspace,
    }
    started_all = time.perf_counter()
    last_progress = started_all
    debug_events = _DebugEvents(Path(args.debug_events) if args.debug_events else None)
    mode = "a" if args.append else "w"
    with success_output.open(mode, encoding="utf-8") as success_handle, failure_output.open(mode, encoding="utf-8") as failure_handle:
        for record_index, record in enumerate(records, start=1):
            total_timeout = float(args.total_timeout_seconds or 0)
            if total_timeout > 0 and time.perf_counter() - started_all > total_timeout:
                debug_events.write("total_timeout", record, record_index=record_index, total_records=len(records), elapsed_seconds=round(time.perf_counter() - started_all, 3))
                summary["failed"] += 1
                break
            idle_timeout = float(args.idle_timeout_seconds or 0)
            if idle_timeout > 0 and time.perf_counter() - last_progress > idle_timeout:
                debug_events.write("idle_timeout", record, record_index=record_index, total_records=len(records), idle_seconds=round(time.perf_counter() - last_progress, 3))
                summary["failed"] += 1
                break
            if record.get("status") == "skipped":
                summary["skipped"] += 1
                continue
            if args.skip_large_stream_samples and _is_large_stream_sample(record, args):
                row = _terminal_row(record, "skipped_budget", "large stream sample skipped by collect budget")
                row["elapsed_sample_seconds"] = 0.0
                _attach_collector_context(row, args)
                _update_summary_counts(summary, record, [row])
                failure_handle.write(json.dumps(row, ensure_ascii=False, sort_keys=True, default=str) + "\n")
                if args.pretty:
                    failure_pretty_records.append(row)
                summary["samples"] += 1
                summary["failure_rows"] += 1
                summary["skipped"] += 1
                debug_events.write("sample_skipped_budget", record, record_index=record_index, total_records=len(records), budget=_sample_budget(record, args))
                continue
            if args.progress:
                print(f"START {record_index}/{len(records)} {record.get('sample_id')} fmt={record.get('material_format') or record.get('format')} source={record.get('source_archive_name')}", flush=True)
            debug_events.write("sample_start", record, record_index=record_index, total_records=len(records))
            started = time.perf_counter()
            status, rows = _collect_sample_with_timeout(record, args, debug_events, record_index, len(records))
            elapsed = round(time.perf_counter() - started, 3)
            last_progress = time.perf_counter()
            for row in rows:
                row["elapsed_sample_seconds"] = elapsed
                _attach_collector_context(row, args)
            _update_summary_counts(summary, record, rows)
            is_success = any(int(row.get("label", 0) or 0) > 0 for row in rows)
            target = success_handle if is_success else failure_handle
            for row in rows:
                target.write(json.dumps(row, ensure_ascii=False, sort_keys=True, default=str) + "\n")
            if args.pretty:
                (success_pretty_records if is_success else failure_pretty_records).extend(rows)
            summary["samples"] += 1
            summary["success_rows" if is_success else "failure_rows"] += len(rows)
            summary["timeouts"] += 1 if status == "timeout" else 0
            summary["failed"] += 1 if status == "failed" else 0
            if args.progress:
                print(f"END {record.get('sample_id')} status={status} rows={len(rows)} elapsed={elapsed}s", flush=True)
            debug_events.write("sample_end", record, record_index=record_index, total_records=len(records), status=status, rows=len(rows), elapsed_seconds=elapsed)
    if args.pretty:
        _pretty_path(success_output).write_text(json.dumps(success_pretty_records, ensure_ascii=False, indent=2, sort_keys=True, default=str), encoding="utf-8")
        _pretty_path(failure_output).write_text(json.dumps(failure_pretty_records, ensure_ascii=False, indent=2, sort_keys=True, default=str), encoding="utf-8")
        summary["success_pretty_output"] = str(_pretty_path(success_output))
        summary["failure_pretty_output"] = str(_pretty_path(failure_output))
    if args.summary_output:
        summary_path = Path(args.summary_output)
        summary_path.parent.mkdir(parents=True, exist_ok=True)
        summary_path.write_text(json.dumps(summary, ensure_ascii=False, indent=2, sort_keys=True, default=str), encoding="utf-8")
    print(json.dumps(summary, ensure_ascii=False, sort_keys=True))
    return 1 if summary["failed"] else 0


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Collect state/action LTR rows from a repair-plan corruption corpus.")
    parser.add_argument("--manifest", default="", help="Repair-plan corpus manifest JSONL. Defaults to scanning --material-root.")
    parser.add_argument("--material-root", default=str(DEFAULT_MATERIAL_ROOT), help="Root containing material damage manifests.")
    parser.add_argument("--formats", default="", help="Optional comma-separated material format filter.")
    parser.add_argument("--sample", action="append", default=[], help="Optional material sample folder name filter. Repeatable.")
    parser.add_argument("--success-output", default=str(DEFAULT_SUCCESS_OUTPUT), help="Rows for samples with useful/complete actions.")
    parser.add_argument("--failure-output", default=str(DEFAULT_FAILURE_OUTPUT), help="Rows for samples without useful actions.")
    parser.add_argument("--summary-output", default="", help="Optional JSON file for the final collector summary.")
    parser.add_argument("--workspace", default=str(Path(".sunpack") / "repair-plan-workspace"), help="Repair workspace used by this collector.")
    parser.add_argument("--collector-shard", type=int, default=-1, help="Collector shard id written into emitted rows.")
    parser.add_argument("--collector-workers", type=int, default=1, help="Total collector worker count written into emitted rows.")
    parser.add_argument("--append", action="store_true", help="Append instead of overwriting output files.")
    parser.set_defaults(pretty=True)
    parser.add_argument("--pretty", action="store_true", help="Also write formatted .pretty.json files. Enabled by default.")
    parser.add_argument("--no-pretty", action="store_false", dest="pretty", help="Only write compact JSONL.")
    parser.add_argument("--limit", type=int, default=0, help="Collect at most N manifest records.")
    parser.add_argument("--max-rounds", type=int, default=3, help="Maximum repair rounds per damaged sample.")
    parser.add_argument("--beam-size", type=int, default=1, help="Reserved interface for beam collection; v1 advances the top current-system path.")
    parser.add_argument("--max-candidates-per-round", type=int, default=10, help="Maximum candidates logged per round.")
    parser.add_argument("--proposal-mode", choices=("lazy", "eager"), default="lazy", help="Use lazy repair plans or eager repair execution while collecting candidates.")
    parser.add_argument("--materialize-top-k-per-round", type=int, default=2, help="Materialize at most K pre-ranked candidates per round in lazy proposal mode.")
    parser.add_argument("--materialize-selected-only", action="store_true", help="In lazy proposal mode, materialize only the pre-ranked top candidate.")
    parser.add_argument("--skip-unmaterialized-labels", action=argparse.BooleanOptionalAction, default=True, help="Do not write proposal-only rows without oracle labels.")
    parser.add_argument("--case-timeout-seconds", type=float, default=45.0, help="Terminate one sample after this timeout. Use 0 to disable.")
    parser.add_argument("--stream-large-size-mb", type=float, default=0.0, help="If >0, apply large-stream budgets to gzip/bzip2/xz/zstd samples at or above this source size.")
    parser.add_argument("--stream-large-case-timeout-seconds", type=float, default=0.0, help="Per-sample timeout for large stream samples. Use 0 to keep --case-timeout-seconds.")
    parser.add_argument("--stream-large-max-candidates-per-round", type=int, default=0, help="Candidate logging cap for large stream samples. Use 0 to keep --max-candidates-per-round.")
    parser.add_argument("--skip-large-stream-samples", action="store_true", help="Skip gzip/bzip2/xz/zstd samples matched by --stream-large-size-mb instead of spending collect time on low-value stream cases.")
    parser.add_argument("--total-timeout-seconds", type=float, default=0.0, help="Stop collection after this wall-clock budget. Use 0 to disable.")
    parser.add_argument("--idle-timeout-seconds", type=float, default=0.0, help="Stop if no sample completes for this many seconds. Use 0 to disable.")
    parser.add_argument("--heartbeat-seconds", type=float, default=5.0, help="While waiting for a sample worker, emit heartbeat progress every N seconds.")
    parser.add_argument("--debug-events", default="", help="Optional JSONL path for collector START/END/TIMEOUT heartbeat events.")
    parser.add_argument("--progress", action="store_true", help="Print sample START/END progress.")
    return parser


def _load_records(args: argparse.Namespace) -> list[dict[str, Any]]:
    if args.manifest:
        return _load_manifest(Path(args.manifest), args.limit)
    manifests = _material_manifests(Path(args.material_root), _csv_filter(args.formats), _sample_filter(args.sample or []))
    records: list[dict[str, Any]] = []
    for manifest in manifests:
        remaining = max(0, int(args.limit or 0) - len(records)) if args.limit else 0
        records.extend(_load_manifest(manifest, remaining))
        if args.limit and len(records) >= args.limit:
            break
    if not records:
        fallback = Path(DEFAULT_MANIFEST)
        if fallback.is_file():
            return _load_manifest(fallback, args.limit)
    return records


def _update_summary_counts(summary: dict[str, Any], record: dict[str, Any], rows: list[dict[str, Any]]) -> None:
    label_counts = summary.setdefault("label_counts", {})
    for row in rows:
        label = str(int(row.get("label", 0) or 0))
        label_counts[label] = int(label_counts.get(label, 0) or 0) + 1
        status = str(row.get("label_status") or "")
        if status == "state_progress":
            summary["state_progress_count"] = int(summary.get("state_progress_count", 0) or 0) + 1
        if status == "partial" or int(row.get("label", 0) or 0) == 1:
            summary["partial_count"] = int(summary.get("partial_count", 0) or 0) + 1
    best = max((int(row.get("label", 0) or 0) for row in rows), default=0)
    best_counts = summary.setdefault("sample_best_label_counts", {})
    best_counts[str(best)] = int(best_counts.get(str(best), 0) or 0) + 1
    oracle = record.get("oracle") if isinstance(record.get("oracle"), dict) else {}
    oracle_strength = str(record.get("oracle_strength") or oracle.get("oracle_strength") or "unknown")
    oracle_counts = summary.setdefault("oracle_strength_counts", {})
    oracle_counts[oracle_strength] = int(oracle_counts.get(oracle_strength, 0) or 0) + 1
    layer = str(record.get("actual_damage_layer") or record.get("damage_layer") or "unknown")
    layer_counts = summary.setdefault("damage_layer_counts", {})
    layer_counts[layer] = int(layer_counts.get(layer, 0) or 0) + 1


def _attach_collector_context(row: dict[str, Any], args: argparse.Namespace) -> None:
    raw_shard = getattr(args, "collector_shard", -1)
    raw_workers = getattr(args, "collector_workers", 1)
    shard = -1 if raw_shard is None else int(raw_shard)
    workers = 1 if raw_workers is None else int(raw_workers)
    if shard >= 0:
        row["collector_shard"] = shard
    row["collector_workers"] = max(1, workers)


def _material_manifests(material_root: Path, formats: set[str], samples: set[str]) -> list[Path]:
    if not material_root.is_dir():
        return []
    output = []
    for manifest in sorted(material_root.glob("*/**/damage_manifest.jsonl")):
        try:
            rel = manifest.relative_to(material_root)
        except ValueError:
            continue
        parts = rel.parts
        if len(parts) < 3:
            continue
        fmt = parts[0]
        sample = parts[1]
        if formats and fmt not in formats:
            continue
        if samples and sample not in samples:
            continue
        output.append(manifest)
    return output


def _load_manifest(path: Path, limit: int) -> list[dict[str, Any]]:
    if not path.is_file():
        raise SystemExit(f"manifest does not exist: {path}")
    records = []
    with path.open(encoding="utf-8") as handle:
        for line in handle:
            if not line.strip():
                continue
            item = json.loads(line)
            if isinstance(item, dict):
                records.append(item)
            if limit and len(records) >= limit:
                break
    return records


def _csv_filter(raw: str) -> set[str]:
    return {item.strip().lower() for item in str(raw or "").split(",") if item.strip()}


def _sample_filter(raw_items: list[str]) -> set[str]:
    output: set[str] = set()
    for raw in raw_items:
        for item in str(raw or "").split(","):
            value = item.strip()
            if value:
                output.add(value)
    return output


def _sample_budget(record: dict[str, Any], args: argparse.Namespace) -> dict[str, Any]:
    return {
        "base_case_timeout_seconds": float(args.case_timeout_seconds or 0),
        "effective_case_timeout_seconds": _effective_case_timeout(record, args),
        "base_max_candidates_per_round": int(args.max_candidates_per_round or 0),
        "effective_max_candidates_per_round": _effective_max_candidates(record, args),
        "is_large_stream_sample": _is_large_stream_sample(record, args),
        "stream_large_size_mb": float(args.stream_large_size_mb or 0),
        "sample_size_mb": round(_record_size_mb(record), 3),
    }


def _effective_case_timeout(record: dict[str, Any], args: argparse.Namespace) -> float:
    timeout = float(args.case_timeout_seconds or 0)
    stream_timeout = float(args.stream_large_case_timeout_seconds or 0)
    if timeout > 0 and stream_timeout > 0 and _is_large_stream_sample(record, args):
        return min(timeout, stream_timeout)
    return timeout


def _effective_max_candidates(record: dict[str, Any], args: argparse.Namespace) -> int:
    base = max(0, int(args.max_candidates_per_round or 0))
    stream_cap = int(args.stream_large_max_candidates_per_round or 0)
    if base > 0 and stream_cap > 0 and _is_large_stream_sample(record, args):
        return max(1, min(base, stream_cap))
    return base


def _is_large_stream_sample(record: dict[str, Any], args: argparse.Namespace) -> bool:
    threshold = float(args.stream_large_size_mb or 0)
    if threshold <= 0:
        return False
    fmt = _normalize_format(str(record.get("material_format") or record.get("format") or ""))
    if fmt not in {"gzip", "bzip2", "xz", "zstd"}:
        return False
    return _record_size_mb(record) >= threshold


def _record_size_mb(record: dict[str, Any]) -> float:
    source_derivation = record.get("source_derivation") if isinstance(record.get("source_derivation"), dict) else {}
    for value in (
        source_derivation.get("size"),
        record.get("source_size"),
        record.get("damaged_size"),
        (record.get("damaged_input") or {}).get("size") if isinstance(record.get("damaged_input"), dict) else None,
    ):
        try:
            if value is not None:
                return float(value) / (1024 * 1024)
        except Exception:
            pass
    for key in ("damaged_path",):
        raw = record.get(key)
        if raw:
            path = Path(str(raw))
            if path.is_file():
                return path.stat().st_size / (1024 * 1024)
    return 0.0


def _collect_sample_with_timeout(record: dict[str, Any], args: argparse.Namespace, debug_events: "_DebugEvents", record_index: int, total_records: int) -> tuple[str, list[dict[str, Any]]]:
    timeout = _effective_case_timeout(record, args)
    if timeout <= 0:
        return _collect_sample(record, args, debug_events)
    with tempfile.TemporaryDirectory(prefix=f"sunpack-plan-worker-{record.get('sample_id', 'sample')}-") as raw_tmp:
        result_path = Path(raw_tmp) / "result.pkl"
        process = mp.Process(target=_collect_worker, args=(record, args, str(result_path)), daemon=True)
        started = time.perf_counter()
        last_heartbeat = started
        process.start()
        while process.is_alive():
            elapsed = time.perf_counter() - started
            if elapsed >= timeout:
                debug_events.write("sample_timeout", record, record_index=record_index, total_records=total_records, pid=process.pid, elapsed_seconds=round(elapsed, 3), timeout_seconds=timeout)
                _kill_process_tree(process.pid)
                process.join(5)
                if process.is_alive():
                    process.kill()
                    process.join(5)
                return "timeout", [_terminal_row(record, "timeout", f"sample exceeded {timeout:.1f}s timeout")]
            heartbeat = float(args.heartbeat_seconds or 0)
            if heartbeat > 0 and time.perf_counter() - last_heartbeat >= heartbeat:
                debug_events.write("sample_heartbeat", record, record_index=record_index, total_records=total_records, pid=process.pid, elapsed_seconds=round(elapsed, 3), timeout_seconds=timeout)
                if args.progress:
                    print(f"WAIT {record_index}/{total_records} {record.get('sample_id')} pid={process.pid} elapsed={elapsed:.1f}s/{timeout:.1f}s", flush=True)
                last_heartbeat = time.perf_counter()
            process.join(0.5)
        if result_path.exists():
            with result_path.open("rb") as handle:
                return pickle.load(handle)
        return "failed", [_terminal_row(record, "failed", f"worker exited without result (exitcode={process.exitcode})")]


def _collect_worker(record: dict[str, Any], args: argparse.Namespace, result_path: str) -> None:
    debug_events = _DebugEvents(Path(args.debug_events) if args.debug_events else None, truncate=False)
    debug_events.write("worker_start", record, pid=os.getpid(), budget=_sample_budget(record, args))
    result = _collect_sample(record, args, debug_events)
    debug_events.write("worker_done", record, pid=os.getpid(), status=result[0], rows=len(result[1]))
    with Path(result_path).open("wb") as handle:
        pickle.dump(result, handle)


def _collect_sample(record: dict[str, Any], args: argparse.Namespace, debug_events: "_DebugEvents | None" = None) -> tuple[str, list[dict[str, Any]]]:
    try:
        return "ok", _collect_sample_rows(record, args, debug_events or _DebugEvents(None, truncate=False))
    except Exception as exc:
        if debug_events is not None:
            debug_events.write("worker_exception", record, error=str(exc))
        return "failed", [_terminal_row(record, "failed", str(exc))]


def _collect_sample_rows(record: dict[str, Any], args: argparse.Namespace, debug_events: "_DebugEvents") -> list[dict[str, Any]]:
    scheduler = _scheduler(args)
    selector = CandidateSelector(scheduler.config)
    source_input = dict(record.get("damaged_input") or {})
    fmt = str(record.get("format") or source_input.get("format_hint") or "")
    damage_flags = list(record.get("damage_flags") or [])
    previous_actions: list[str] = []
    rows: list[dict[str, Any]] = []
    best_completeness = 0.0
    max_candidates_per_round = _effective_max_candidates(record, args)
    debug_events.write("sample_budget", record, budget=_sample_budget(record, args))
    for round_index in range(max(1, int(args.max_rounds or 1))):
        if args.progress:
            print(f"  ROUND {round_index} {record.get('sample_id')} fmt={fmt}", flush=True)
        job = RepairJob(
            source_input=source_input,
            format=fmt,
            confidence=0.82,
            damage_flags=damage_flags,
            archive_key=f"{record.get('sample_id')}:round:{round_index}",
        )
        phase_started = time.perf_counter()
        lazy_mode = str(args.proposal_mode or "lazy") == "lazy"
        batch = scheduler.generate_repair_candidates(job, lazy=lazy_mode)
        debug_events.write(
            "phase",
            record,
            round=round_index,
            phase="generate_candidates",
            elapsed_seconds=round(time.perf_counter() - phase_started, 3),
            candidate_count=len(batch.candidates),
            warning_count=len(batch.warnings or []),
        )
        if args.progress:
            print(f"  CANDIDATES {record.get('sample_id')} round={round_index} count={len(batch.candidates)} warnings={len(batch.warnings or [])}", flush=True)
        phase_started = time.perf_counter()
        before_state = _state_summary(record, source_input, fmt, damage_flags)
        debug_events.write("phase", record, round=round_index, phase="before_state", elapsed_seconds=round(time.perf_counter() - phase_started, 3))
        state_features = _state_features(record, batch, round_index, previous_actions, best_completeness, before_state)
        phase_started = time.perf_counter()
        candidates, materialization_meta = _materialize_for_collection(list(batch.candidates), selector, args, record)
        debug_events.write(
            "phase",
            record,
            round=round_index,
            phase="materialize_candidates",
            elapsed_seconds=round(time.perf_counter() - phase_started, 3),
            candidate_count=len(candidates),
            proposal_count=len(batch.candidates),
            materialization_budget=materialization_meta["budget"],
        )
        phase_started = time.perf_counter()
        validated = [selector._with_native_validation(candidate) for candidate in candidates]  # noqa: SLF001
        debug_events.write("phase", record, round=round_index, phase="native_validation", elapsed_seconds=round(time.perf_counter() - phase_started, 3), candidate_count=len(validated))
        phase_started = time.perf_counter()
        accepted = sorted(
            [(selector.generation_priority(candidate), index, candidate) for index, candidate in enumerate(validated) if selector._accepted(candidate)],  # noqa: SLF001
            key=lambda item: item[0],
            reverse=True,
        )
        accepted_ids = {_candidate_id(candidate) for _, _, candidate in accepted}
        rejected = [
            (None, index, candidate)
            for index, candidate in enumerate(validated)
            if _candidate_id(candidate) not in accepted_ids
        ]
        ranked = [*accepted, *rejected]
        selected_candidate = accepted[0][2] if accepted else None
        selected_id = _candidate_id(selected_candidate)
        debug_events.write("phase", record, round=round_index, phase="rank_candidates", elapsed_seconds=round(time.perf_counter() - phase_started, 3), accepted_count=len(accepted), rejected_count=len(rejected))
        if not validated:
            rows.append(_round_empty_row(record, round_index, state_features, batch))
            break
        logged = 0
        phase_started = time.perf_counter()
        for rank, (_, original_index, candidate) in enumerate(ranked):
            if logged >= max_candidates_per_round:
                break
            materialized_for_label = bool(materialization_meta["materialized_ids"].get(_candidate_id(candidate), True))
            if args.skip_unmaterialized_labels and not materialized_for_label:
                continue
            payload = candidate_feature_payload(candidate)
            after_state = _state_summary(record, candidate.repaired_input if isinstance(candidate.repaired_input, dict) else {}, fmt, list(candidate.damage_flags or damage_flags), payload)
            delta_features = _state_delta(before_state, after_state)
            label_info = _label_candidate(record, candidate, best_completeness, before_state, after_state, delta_features)
            rows.append(_action_row(
                record,
                round_index,
                original_index,
                rank,
                candidate,
                state_features,
                before_state,
                after_state,
                delta_features,
                batch,
                label_info,
                selected=_candidate_id(candidate) == selected_id,
                proposal_only=not materialized_for_label,
                materialized_for_label=materialized_for_label,
                materialization_rank=materialization_meta["ranks"].get(_candidate_id(candidate)),
                materialization_budget=materialization_meta["budget"],
            ))
            logged += 1
        debug_events.write("phase", record, round=round_index, phase="label_candidates", elapsed_seconds=round(time.perf_counter() - phase_started, 3), logged_count=logged)
        if selected_candidate is None:
            break
        phase_started = time.perf_counter()
        selected_result = selected_candidate.to_result(selection={"selected_module": selected_candidate.module_name})
        debug_events.write("phase", record, round=round_index, phase="selected_to_result", elapsed_seconds=round(time.perf_counter() - phase_started, 3), selected_module=selected_candidate.module_name)
        if not selected_result.ok or not selected_result.repaired_input:
            break
        phase_started = time.perf_counter()
        selected_payload = candidate_feature_payload(selected_candidate)
        selected_after_state = _state_summary(record, selected_candidate.repaired_input if isinstance(selected_candidate.repaired_input, dict) else {}, fmt, list(selected_candidate.damage_flags or damage_flags), selected_payload)
        debug_events.write("phase", record, round=round_index, phase="selected_after_state", elapsed_seconds=round(time.perf_counter() - phase_started, 3), selected_module=selected_candidate.module_name)
        phase_started = time.perf_counter()
        selected_delta = _state_delta(before_state, selected_after_state)
        selected_label = _label_candidate(record, selected_candidate, best_completeness, before_state, selected_after_state, selected_delta)
        debug_events.write("phase", record, round=round_index, phase="selected_label", elapsed_seconds=round(time.perf_counter() - phase_started, 3), selected_module=selected_candidate.module_name, selected_label=selected_label.get("label"))
        best_completeness = max(best_completeness, float(selected_label.get("completeness", 0.0) or 0.0))
        previous_actions.extend(str(action) for action in selected_candidate.actions)
        source_input = dict(selected_result.repaired_input)
        damage_flags = list(selected_result.damage_flags or damage_flags)
        if int(selected_label.get("label", 0) or 0) == 3:
            break
    return rows


def _materialize_for_collection(candidates: list[Any], selector: CandidateSelector, args: argparse.Namespace, record: dict[str, Any]) -> tuple[list[Any], dict[str, Any]]:
    if str(args.proposal_mode or "lazy") != "lazy":
        materialized: list[Any] = []
        for candidate in candidates:
            materialized.extend(materialize_candidate(candidate))
        ids = {_candidate_id(candidate): True for candidate in materialized}
        return materialized, {
            "budget": len(candidates),
            "materialized_ids": ids,
            "ranks": {_candidate_id(candidate): index for index, candidate in enumerate(materialized)},
        }

    ranked = sorted(
        [(selector.generation_priority(candidate), index, candidate) for index, candidate in enumerate(candidates)],
        key=lambda item: item[0],
        reverse=True,
    )
    budget = 1 if bool(args.materialize_selected_only) else max(1, int(args.materialize_top_k_per_round or 1))
    budget = min(budget, max(1, _effective_max_candidates(record, args)))
    selected = ranked[:budget]
    materialized = []
    ranks: dict[str, int] = {}
    for materialization_rank, (_, _, candidate) in enumerate(selected):
        produced = materialize_candidate(candidate)
        for item in produced:
            materialized.append(item)
            ranks[_candidate_id(item)] = materialization_rank
    return materialized, {
        "budget": budget,
        "materialized_ids": {_candidate_id(candidate): True for candidate in materialized},
        "ranks": ranks,
        "proposal_count": len(candidates),
    }


def _scheduler(args: argparse.Namespace) -> RepairScheduler:
    return RepairScheduler({
        "repair": {
            "workspace": str(Path(args.workspace)),
            "max_modules_per_job": 64,
            "max_attempts_per_task": 8,
            "stages": {"deep": True},
            "deep": {
                "max_candidates_per_module": 4,
                "verify_candidates": False,
                "max_seconds_per_module": 3.0,
                "max_stream_trim_probe_attempts": 8,
                "max_stream_trim_decode_mb": 32,
            },
        }
    })


def _state_features(record: dict[str, Any], batch, round_index: int, previous_actions: list[str], best_completeness: float, before_state: dict[str, Any] | None = None) -> dict[str, Any]:
    diagnosis = batch.diagnosis if isinstance(batch.diagnosis, dict) else {}
    capability = diagnosis.get("capability_decision") if isinstance(diagnosis.get("capability_decision"), dict) else {}
    source_derivation = record.get("source_derivation") if isinstance(record.get("source_derivation"), dict) else {}
    return {
        "format": record.get("format"),
        "damage_profile": record.get("damage_profile"),
        "damage_flags": list(record.get("damage_flags") or []),
        "source_derivation": _compact_source_derivation(source_derivation),
        "corruption_zones": sorted({item.get("zone") for item in record.get("corruption_plan") or [] if item.get("zone")}),
        "corruption_kinds": sorted({item.get("kind") for item in record.get("corruption_plan") or [] if item.get("kind")}),
        "round": round_index,
        "previous_actions": list(previous_actions),
        "previous_action_count": len(previous_actions),
        "best_completeness": float(best_completeness or 0.0),
        "state_summary": dict(before_state or {}),
        "diagnosis": _compact_diagnosis(diagnosis),
        "capability": {
            "selected_modules": list(capability.get("selected_modules") or []),
            "automatic_unrepairable": bool(capability.get("automatic_unrepairable", False)),
        },
    }


def _action_row(
    record: dict[str, Any],
    round_index: int,
    candidate_index: int,
    rank: int,
    candidate,
    state_features: dict[str, Any],
    before_state: dict[str, Any],
    after_state: dict[str, Any],
    delta_features: dict[str, Any],
    batch,
    label_info: dict[str, Any],
    *,
    selected: bool,
    proposal_only: bool = False,
    materialized_for_label: bool = True,
    materialization_rank: int | None = None,
    materialization_budget: int | None = None,
) -> dict[str, Any]:
    payload = candidate_feature_payload(candidate)
    module_decision = _module_decision(batch, candidate.module_name)
    source_derivation = record.get("source_derivation") if isinstance(record.get("source_derivation"), dict) else {}
    return {
        "schema_version": 1,
        "source": "repair_plan_corpus",
        "query_id": f"{record.get('sample_id')}:{round_index}",
        "sample_id": record.get("sample_id"),
        "source_archive_id": record.get("source_archive_id"),
        "material_format": record.get("material_format"),
        "material_sample_id": record.get("material_sample_id"),
        "source_archive_name": record.get("source_archive_name"),
        "source_derivation": _compact_source_derivation(source_derivation),
        "damaged_file_name": record.get("damaged_file_name"),
        "damaged_path": record.get("damaged_path"),
        "damage_json_path": record.get("damage_json_path"),
        "round": round_index,
        "candidate_index": candidate_index,
        "current_rank": rank,
        "candidate_id": payload.get("candidate_id"),
        "module": candidate.module_name,
        "selected_by_current_system": bool(selected),
        "proposal_only": bool(proposal_only),
        "materialized_for_label": bool(materialized_for_label),
        "materialization_rank": materialization_rank,
        "materialization_budget": materialization_budget,
        "label": int(label_info.get("label", 0) or 0),
        "label_status": label_info.get("status"),
        "label_details": label_info,
        "stable_features": {
            "state": state_features,
            "before_state": before_state,
            "after_state": after_state,
            "delta_features": delta_features,
            "candidate": {
                key: payload.get(key)
                for key in (
                    "module",
                    "format",
                    "stage",
                    "status",
                    "actions",
                    "damage_flags",
                    "patch_cost",
                    "risk_penalty",
                    "cost_penalty",
                    "evidence_score",
                    "benefit_score",
                    "native_validation_score",
                    "native_validation_strength",
                    "predicted_completeness",
                    "validation_count",
                    "requires_native_validation",
                    "has_archive_state_plan",
                    "requires_materialization",
                    "plan_kind",
                    "estimated_cost",
                )
                if key in payload
            },
        },
        "teacher_features": {
            "route_score": module_decision.get("route_score"),
            "fine_score": module_decision.get("fine_score"),
            "module_selected_by_router": module_decision.get("selected"),
            "generation_priority": payload.get("generation_priority"),
            "ranking_raw_score": (payload.get("ltr_features") or {}).get("ranking_raw_score") if isinstance(payload.get("ltr_features"), dict) else None,
            "current_rank": rank,
            "selected_by_current_system": bool(selected),
        },
        "debug_features": {
            "candidate_features": payload,
            "module_decision": module_decision,
        },
    }


def _label_candidate(
    record: dict[str, Any],
    candidate,
    previous_completeness: float,
    before_state: dict[str, Any] | None = None,
    after_state: dict[str, Any] | None = None,
    delta_features: dict[str, Any] | None = None,
) -> dict[str, Any]:
    repaired_input = candidate.repaired_input if isinstance(candidate.repaired_input, dict) else {}
    path = Path(str(repaired_input.get("path") or ""))
    if not path.is_file():
        return {"status": "no_output", "label": 0, "completeness": previous_completeness}
    oracle = record.get("oracle") if isinstance(record.get("oracle"), dict) else {}
    fmt = str(record.get("format") or repaired_input.get("format_hint") or "")
    verified = _verify_output_against_oracle(path, fmt, oracle)
    completeness = float(verified.get("completeness", 0.0) or 0.0)
    verified["before_state"] = before_state or {}
    verified["after_state"] = after_state or {}
    verified["delta_features"] = delta_features or {}
    if int(verified.get("label", 0) or 0) <= 0 and int(verified.get("label", 0) or 0) != -1 and _has_state_progress(delta_features or {}, previous_completeness):
        verified["label"] = 2
        verified["status"] = "state_progress"
        verified["progress_reasons"] = _progress_reasons(delta_features or {}, previous_completeness)
        verified["completeness"] = max(completeness, float((after_state or {}).get("completeness", 0.0) or 0.0))
    return verified


def _state_summary(
    record: dict[str, Any],
    source_input: dict[str, Any],
    fmt: str,
    damage_flags: list[str],
    candidate_payload: dict[str, Any] | None = None,
) -> dict[str, Any]:
    path = Path(str(source_input.get("path") or ""))
    oracle = record.get("oracle") if isinstance(record.get("oracle"), dict) else {}
    payload = candidate_payload if isinstance(candidate_payload, dict) else {}
    summary = {
        "format_detected": bool(fmt or source_input.get("format_hint")),
        "boundary_trusted": not any(flag in set(damage_flags or []) for flag in ("trailing_junk", "boundary_unreliable", "input_truncated", "probably_truncated")),
        "directory_detected": False,
        "entry_count": 0,
        "readable_entry_count": 0,
        "matched_entry_count": 0,
        "wrong_entry_count": 0,
        "completeness": 0.0,
        "damage_flags": list(damage_flags or []),
        "verification_status": "missing_output" if not path.is_file() else "unverified",
        "native_validation_score": payload.get("native_validation_score"),
    }
    if not path.is_file():
        return summary
    verified = _verify_output_against_oracle(path, fmt, oracle)
    summary["verification_status"] = verified.get("status")
    summary["completeness"] = float(verified.get("completeness", 0.0) or 0.0)
    summary["matched_entry_count"] = int(verified.get("matched_files", 0) or 0)
    summary["wrong_entry_count"] = int(verified.get("wrong_files", 0) or 0)
    try:
        recovered = _read_archive_hash_info(path, fmt)
        summary["entry_count"] = len(recovered.get("entries", []))
        summary["readable_entry_count"] = len(recovered.get("hashes", {}))
        summary["directory_detected"] = len(recovered.get("entries", [])) > 0
    except Exception:
        summary["directory_detected"] = False
    original_path = str((record.get("damaged_input") or {}).get("path") or record.get("damaged_path") or "")
    if original_path and str(path) == original_path and any(flag in set(damage_flags or []) for flag in ("central_directory_bad", "central_directory_offset_bad", "central_directory_count_bad")):
        summary["directory_detected"] = False
        summary["entry_count"] = 0
        summary["readable_entry_count"] = 0
    return summary


def _state_delta(before: dict[str, Any], after: dict[str, Any]) -> dict[str, Any]:
    before_score = _as_float(before.get("native_validation_score"))
    after_score = _as_float(after.get("native_validation_score"))
    return {
        "completeness_gain": _as_float(after.get("completeness")) - _as_float(before.get("completeness")),
        "entry_count_gain": int(after.get("entry_count", 0) or 0) - int(before.get("entry_count", 0) or 0),
        "matched_entry_gain": int(after.get("matched_entry_count", 0) or 0) - int(before.get("matched_entry_count", 0) or 0),
        "directory_recovered": bool(after.get("directory_detected")) and not bool(before.get("directory_detected")),
        "boundary_became_trusted": bool(after.get("boundary_trusted")) and not bool(before.get("boundary_trusted")),
        "damage_flag_reduction": max(0, len(before.get("damage_flags") or []) - len(after.get("damage_flags") or [])),
        "verification_score_gain": after_score - before_score,
    }


def _has_state_progress(delta: dict[str, Any], previous_completeness: float) -> bool:
    return bool(_progress_reasons(delta, previous_completeness))


def _progress_reasons(delta: dict[str, Any], previous_completeness: float) -> list[str]:
    reasons: list[str] = []
    if _as_float(delta.get("completeness_gain")) >= 0.15 or (_as_float(delta.get("completeness_gain")) > 0.05 and previous_completeness <= 0.0):
        reasons.append("completeness_gain")
    if int(delta.get("matched_entry_gain", 0) or 0) >= 1:
        reasons.append("matched_entry_gain")
    if bool(delta.get("directory_recovered")):
        reasons.append("directory_recovered")
    if int(delta.get("entry_count_gain", 0) or 0) >= 1:
        reasons.append("entry_count_gain")
    if bool(delta.get("boundary_became_trusted")):
        reasons.append("boundary_became_trusted")
    if _as_float(delta.get("verification_score_gain")) >= 0.20:
        reasons.append("verification_score_gain")
    return reasons


def _as_float(value: Any) -> float:
    try:
        if value is None:
            return 0.0
        return float(value)
    except Exception:
        return 0.0


def _verify_output_against_oracle(path: Path, fmt: str, oracle: dict[str, Any]) -> dict[str, Any]:
    try:
        expected_bytes = oracle.get("expected_bytes") if isinstance(oracle.get("expected_bytes"), dict) else {}
        if expected_bytes:
            digest = _sha256(path.read_bytes())
            complete = digest == expected_bytes.get("sha256")
            return _label_status(3 if complete else -1, "complete" if complete else "hard_negative", 1.0 if complete else 0.0)
        expected_payload = oracle.get("expected_payload") if isinstance(oracle.get("expected_payload"), dict) else {}
        if expected_payload:
            payload = _decompress_payload(path, fmt)
            digest = _sha256(payload)
            complete = digest == expected_payload.get("sha256")
            completeness = len(payload) / max(1, int(expected_payload.get("size") or len(payload) or 1))
            return _label_status(3 if complete else (1 if 0.0 < completeness < 1.0 else -1), "complete" if complete else ("partial" if completeness > 0 else "hard_negative"), completeness)
        expected_files = oracle.get("expected_files") if isinstance(oracle.get("expected_files"), dict) else {}
        if expected_files:
            recovered_info = _read_archive_hash_info(path, fmt)
            recovered = recovered_info.get("hashes", {})
            matched = sum(1 for name, meta in expected_files.items() if recovered.get(name) == meta.get("sha256"))
            wrong_overlap = any(name in expected_files and recovered[name] != expected_files[name].get("sha256") for name in recovered)
            wrong_files = sum(1 for name in recovered if name in expected_files and recovered[name] != expected_files[name].get("sha256"))
            unreadable_files = len([name for name in recovered_info.get("entries", []) if name in expected_files and name not in recovered])
            entry_count = len(recovered_info.get("entries", []))
            completeness = matched / max(1, len(expected_files))
            if completeness >= 0.999:
                return {**_label_status(3, "complete", completeness), "matched_files": matched, "wrong_files": wrong_files, "unreadable_files": unreadable_files, "entry_count": entry_count, "expected_files": len(expected_files)}
            if completeness > 0:
                return {**_label_status(1, "partial", completeness), "matched_files": matched, "wrong_files": wrong_files, "unreadable_files": unreadable_files, "entry_count": entry_count, "expected_files": len(expected_files)}
            status = "hard_negative" if wrong_overlap else ("directory_only" if entry_count else "no_progress")
            return {**_label_status(-1 if wrong_overlap else 0, status, 0.0), "matched_files": matched, "wrong_files": wrong_files, "unreadable_files": unreadable_files, "entry_count": entry_count, "expected_files": len(expected_files)}
    except Exception as exc:
        return {"status": "hard_negative", "label": -1, "completeness": 0.0, "error": str(exc)}
    return _label_status(0, "no_oracle", 0.0)


def _read_archive_hashes(path: Path, fmt: str) -> dict[str, str]:
    return _read_archive_hash_info(path, fmt)["hashes"]


def _read_archive_hash_info(path: Path, fmt: str) -> dict[str, Any]:
    normalized = _normalize_format(fmt)
    if normalized == "zip":
        with zipfile.ZipFile(path) as archive:
            entries = [name for name in archive.namelist() if not name.endswith("/")]
            hashes = {}
            errors = {}
            for name in entries:
                try:
                    hashes[name] = _sha256(archive.read(name))
                except Exception as exc:
                    errors[name] = str(exc)
            return {"entries": entries, "hashes": hashes, "errors": errors}
    if normalized == "tar":
        with tarfile.open(path) as archive:
            return _tar_hash_info_from_archive(archive)
    if normalized in {"tar.gz", "tar.bz2", "tar.xz"}:
        payload = _decompress_payload(path, normalized)
        with tarfile.open(fileobj=io.BytesIO(payload)) as archive:
            return _tar_hash_info_from_archive(archive)
    return {"entries": [], "hashes": {}, "errors": {}}


def _read_tar_hashes(path: Path) -> dict[str, str]:
    with tarfile.open(path) as archive:
        return _tar_hashes_from_archive(archive)


def _tar_hashes_from_archive(archive: tarfile.TarFile) -> dict[str, str]:
    return _tar_hash_info_from_archive(archive)["hashes"]


def _tar_hash_info_from_archive(archive: tarfile.TarFile) -> dict[str, Any]:
    output = {}
    entries = []
    errors = {}
    for item in archive.getmembers():
        if not item.isfile():
            continue
        entries.append(item.name)
        try:
            member = archive.extractfile(item)
            if member is not None:
                output[item.name] = _sha256(member.read())
        except Exception as exc:
            errors[item.name] = str(exc)
    return {"entries": entries, "hashes": output, "errors": errors}


def _decompress_payload(path: Path, fmt: str) -> bytes:
    raw = path.read_bytes()
    normalized = _normalize_format(fmt)
    if normalized in {"gzip", "tar.gz"}:
        return gzip.decompress(raw)
    if normalized in {"bzip2", "tar.bz2"}:
        return bz2.decompress(raw)
    if normalized in {"xz", "tar.xz"}:
        return lzma.decompress(raw)
    return raw


def _normalize_format(fmt: str) -> str:
    value = str(fmt or "").strip().lower().replace("_", ".")
    aliases = {
        "gz": "gzip",
        "bz2": "bzip2",
        "tbz": "tar.bz2",
        "tbz2": "tar.bz2",
        "tgz": "tar.gz",
        "txz": "tar.xz",
    }
    return aliases.get(value, value)


def _label_status(label: int, status: str, completeness: float) -> dict[str, Any]:
    return {
        "label": int(label),
        "status": status,
        "completeness": max(0.0, min(1.0, float(completeness or 0.0))),
    }


def _round_empty_row(record: dict[str, Any], round_index: int, state_features: dict[str, Any], batch) -> dict[str, Any]:
    source_derivation = record.get("source_derivation") if isinstance(record.get("source_derivation"), dict) else {}
    return {
        "schema_version": 1,
        "source": "repair_plan_corpus",
        "query_id": f"{record.get('sample_id')}:{round_index}",
        "sample_id": record.get("sample_id"),
        "material_format": record.get("material_format"),
        "material_sample_id": record.get("material_sample_id"),
        "source_archive_name": record.get("source_archive_name"),
        "source_derivation": _compact_source_derivation(source_derivation),
        "damaged_file_name": record.get("damaged_file_name"),
        "round": round_index,
        "candidate_id": None,
        "module": "",
        "selected_by_current_system": False,
        "label": 0,
        "label_status": "no_candidates",
        "stable_features": {"state": state_features, "candidate": {}},
        "teacher_features": {},
        "debug_features": {"warnings": list(batch.warnings or []), "message": batch.message},
    }


def _terminal_row(record: dict[str, Any], status: str, message: str) -> dict[str, Any]:
    source_derivation = record.get("source_derivation") if isinstance(record.get("source_derivation"), dict) else {}
    return {
        "schema_version": 1,
        "source": "repair_plan_corpus",
        "query_id": f"{record.get('sample_id')}:terminal",
        "sample_id": record.get("sample_id"),
        "material_format": record.get("material_format"),
        "material_sample_id": record.get("material_sample_id"),
        "source_archive_name": record.get("source_archive_name"),
        "source_derivation": _compact_source_derivation(source_derivation),
        "damaged_file_name": record.get("damaged_file_name"),
        "round": None,
        "candidate_id": None,
        "module": "",
        "selected_by_current_system": False,
        "label": 0,
        "label_status": status,
        "stable_features": {"state": {"format": record.get("format"), "damage_profile": record.get("damage_profile"), "source_derivation": _compact_source_derivation(source_derivation)}, "candidate": {}},
        "teacher_features": {},
        "debug_features": {"message": message},
    }


def _module_decision(batch, module_name: str) -> dict[str, Any]:
    diagnosis = batch.diagnosis if isinstance(batch.diagnosis, dict) else {}
    capability = diagnosis.get("capability_decision") if isinstance(diagnosis.get("capability_decision"), dict) else {}
    for item in capability.get("modules") or []:
        if isinstance(item, dict) and item.get("name") == module_name:
            return dict(item)
    return {}


def _compact_diagnosis(diagnosis: dict[str, Any]) -> dict[str, Any]:
    return {
        "status": diagnosis.get("status"),
        "format": diagnosis.get("format"),
        "confidence": diagnosis.get("confidence"),
        "repairable": diagnosis.get("repairable"),
        "categories": list(diagnosis.get("categories") or []),
        "damage_flags": list(diagnosis.get("damage_flags") or []),
    }


def _compact_source_derivation(source_derivation: dict[str, Any]) -> dict[str, Any]:
    return {
        key: source_derivation.get(key)
        for key in (
            "sample_id",
            "source_material_dir",
            "material_format",
            "format",
            "method",
            "level",
            "solid",
            "tool",
            "output_name",
            "sha256",
            "size",
        )
        if key in source_derivation
    }


def _candidate_id(candidate) -> str:
    if candidate is None:
        return ""
    return str(candidate_feature_payload(candidate).get("candidate_id") or "")


def _sha256(data: bytes) -> str:
    import hashlib

    return hashlib.sha256(data).hexdigest()


def _pretty_path(path: Path) -> Path:
    suffix = "".join(path.suffixes)
    if suffix:
        return path.with_name(path.name.removesuffix(suffix) + ".pretty.json")
    return path.with_name(path.name + ".pretty.json")


class _DebugEvents:
    def __init__(self, path: Path | None, *, truncate: bool = True):
        self.path = path
        if self.path is not None:
            self.path.parent.mkdir(parents=True, exist_ok=True)
            if truncate:
                self.path.write_text("", encoding="utf-8")

    def write(self, event: str, record: dict[str, Any], **extra: Any) -> None:
        if self.path is None:
            return
        payload = {
            "event": event,
            "time": time.time(),
            "sample_id": record.get("sample_id"),
            "material_format": record.get("material_format"),
            "format": record.get("format"),
            "source_archive_name": record.get("source_archive_name"),
            "damaged_file_name": record.get("damaged_file_name"),
            **extra,
        }
        with self.path.open("a", encoding="utf-8") as handle:
            handle.write(json.dumps(payload, ensure_ascii=False, sort_keys=True, default=str) + "\n")


def _kill_process_tree(pid: int | None) -> None:
    if not pid:
        return
    if os.name == "nt":
        subprocess.run(["taskkill", "/PID", str(pid), "/T", "/F"], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        return
    try:
        os.kill(pid, 9)
    except OSError:
        pass


if __name__ == "__main__":
    raise SystemExit(main())
