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
from collections import Counter
from pathlib import Path
from typing import Any

REPO_ROOT = Path(__file__).resolve().parents[1]
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

from sunpack.repair import RepairJob, RepairResult, RepairScheduler
from sunpack.repair.candidate import CandidateSelector, candidate_feature_payload, materialize_candidate
from sunpack.contracts.detection import FactBag
from sunpack.contracts.tasks import ArchiveTask
from sunpack.extraction.result import ExtractionResult
from sunpack.verification import VerificationScheduler
from repair_training.runtime_features import FEATURE_CONTRACT_VERSION, RepairPrior, build_runtime_feature_record


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
        "rollout_mode_counts": {},
        "state_count": 0,
        "expanded_state_count": 0,
        "branch_count": 0,
        "future_label_counts": {},
        "terminal_status_counts": {},
        "terminal_success_count": 0,
        "rollout_budget_exhausted": 0,
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
    parser.add_argument("--rollout-mode", choices=("greedy", "greedy_current_selector", "beam", "counterfactual"), default="greedy", help="Repair-state rollout strategy for multi-step training collection.")
    parser.add_argument("--beam-size", type=int, default=1, help="Maximum active next states retained per rollout depth.")
    parser.add_argument("--branch-top-k", type=int, default=2, help="Maximum branch candidates advanced from one state in beam/counterfactual mode.")
    parser.add_argument("--counterfactual-extra", type=int, default=2, help="Additional risky/high-value branches considered in counterfactual mode.")
    parser.add_argument("--max-total-states-per-sample", type=int, default=6, help="Hard cap on states created for one damaged sample, including the root state.")
    parser.add_argument("--future-label-discount", type=float, default=0.8, help="Discount used when backfilling future labels from descendant states.")
    parser.add_argument("--max-candidates-per-round", type=int, default=10, help="Maximum candidates logged per round.")
    parser.add_argument("--proposal-mode", choices=("lazy", "eager"), default="lazy", help="Use lazy repair plans or eager repair execution while collecting candidates.")
    parser.add_argument("--materialize-top-k-per-round", type=int, default=2, help="Materialize at most K pre-ranked candidates per round in lazy proposal mode.")
    parser.add_argument("--materialize-selected-only", action="store_true", help="In lazy proposal mode, materialize only the pre-ranked top candidate.")
    parser.add_argument("--skip-unmaterialized-labels", action=argparse.BooleanOptionalAction, default=True, help="Do not write proposal-only rows without oracle labels.")
    parser.add_argument("--repair-max-modules-per-job", type=int, default=64, help="Repair scheduler module routing cap used during collection.")
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
    seen_states: set[str] = set()
    seen_expanded: set[str] = set()
    seen_branches: set[str] = set()
    terminal_success = False
    budget_exhausted = False
    for row in rows:
        if row.get("row_type") == "terminal":
            terminal_counts = summary.setdefault("terminal_status_counts", {})
            terminal_status = str(row.get("terminal_status") or row.get("label_status") or "unknown")
            terminal_counts[terminal_status] = int(terminal_counts.get(terminal_status, 0) or 0) + 1
            continue
        label = str(int(row.get("label", 0) or 0))
        label_counts[label] = int(label_counts.get(label, 0) or 0) + 1
        mode = str(row.get("rollout_mode") or "greedy")
        mode_counts = summary.setdefault("rollout_mode_counts", {})
        mode_counts[mode] = int(mode_counts.get(mode, 0) or 0) + 1
        state_id = str(row.get("state_id") or "")
        if state_id:
            seen_states.add(state_id)
            seen_expanded.add(state_id)
        parent_action = str(row.get("parent_action_row_id") or "")
        if parent_action:
            seen_branches.add(parent_action)
        status = str(row.get("label_status") or "")
        if status == "state_progress":
            summary["state_progress_count"] = int(summary.get("state_progress_count", 0) or 0) + 1
        if status == "partial" or int(row.get("label", 0) or 0) == 1:
            summary["partial_count"] = int(summary.get("partial_count", 0) or 0) + 1
        details = row.get("label_details") if isinstance(row.get("label_details"), dict) else {}
        future_label = str(int(details.get("future_best_label", row.get("label", 0)) or 0))
        future_counts = summary.setdefault("future_label_counts", {})
        future_counts[future_label] = int(future_counts.get(future_label, 0) or 0) + 1
        terminal_success = terminal_success or bool(details.get("terminal_success")) or int(row.get("label", 0) or 0) == 3
        rollout_summary = row.get("rollout_summary") if isinstance(row.get("rollout_summary"), dict) else {}
        budget_exhausted = budget_exhausted or bool(rollout_summary.get("rollout_budget_exhausted"))
    best = max((int(row.get("label", 0) or 0) for row in rows), default=0)
    best_counts = summary.setdefault("sample_best_label_counts", {})
    best_counts[str(best)] = int(best_counts.get(str(best), 0) or 0) + 1
    summary["state_count"] = int(summary.get("state_count", 0) or 0) + len(seen_states)
    summary["expanded_state_count"] = int(summary.get("expanded_state_count", 0) or 0) + len(seen_expanded)
    summary["branch_count"] = int(summary.get("branch_count", 0) or 0) + len(seen_branches)
    if terminal_success:
        summary["terminal_success_count"] = int(summary.get("terminal_success_count", 0) or 0) + 1
    if budget_exhausted:
        summary["rollout_budget_exhausted"] = int(summary.get("rollout_budget_exhausted", 0) or 0) + 1
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
    rows: list[dict[str, Any]] = []
    max_candidates_per_round = _effective_max_candidates(record, args)
    debug_events.write("sample_budget", record, budget=_sample_budget(record, args))

    rollout_mode = str(getattr(args, "rollout_mode", "greedy") or "greedy")
    root_state = _root_rollout_state(record, fmt, rollout_mode)
    frontier: list[dict[str, Any]] = [root_state]
    next_beam_id = 1
    created_state_count = 1
    expanded_state_count = 0
    branch_count = 0
    budget_exhausted = False
    max_rounds = max(1, int(args.max_rounds or 1))
    max_total_states = max(1, int(getattr(args, "max_total_states_per_sample", 6) or 6))

    for round_index in range(max_rounds):
        if not frontier:
            break
        next_frontier: list[dict[str, Any]] = []
        for state in frontier:
            if expanded_state_count >= max_total_states:
                budget_exhausted = True
                rows.append(_rollout_terminal_row(record, state, "budget_exhausted", "rollout state budget exhausted", None))
                break
            source_input = dict(state.get("source_input") or {})
            damage_flags = list(state.get("damage_flags") or [])
            previous_actions = list(state.get("previous_actions") or [])
            previous_modules = list(state.get("previous_modules") or [])
            best_completeness = float(state.get("best_completeness", 0.0) or 0.0)
            state_round = int(state.get("round", round_index) or round_index)
            query_id = _rollout_query_id(record, state)
            expanded_state_count += 1
            if args.progress:
                print(f"  ROUND {state_round} {record.get('sample_id')} fmt={fmt} query={query_id}", flush=True)
            job = RepairJob(
                source_input=source_input,
                format=fmt,
                confidence=0.82,
                analysis_evidence=_record_analysis_evidence(record, fmt),
                analysis_prepass=_record_analysis_prepass(record, fmt),
                fuzzy_profile=_record_fuzzy_profile(record, fmt),
                extraction_failure=_runtime_extraction_failure(record, state, before_state=None),
                extraction_diagnostics=_runtime_extraction_diagnostics(record, state),
                damage_flags=damage_flags,
                archive_key=f"{record.get('sample_id')}:round:{state_round}:beam:{state.get('beam_id', 0)}",
                attempts=state_round,
            )
            phase_started = time.perf_counter()
            lazy_mode = str(args.proposal_mode or "lazy") == "lazy"
            batch = scheduler.generate_repair_candidates(job, lazy=lazy_mode)
            debug_events.write(
                "phase",
                record,
                round=state_round,
                query_id=query_id,
                phase="generate_candidates",
                elapsed_seconds=round(time.perf_counter() - phase_started, 3),
                candidate_count=len(batch.candidates),
                warning_count=len(batch.warnings or []),
            )
            if args.progress:
                print(f"  CANDIDATES {record.get('sample_id')} round={state_round} count={len(batch.candidates)} warnings={len(batch.warnings or [])}", flush=True)
            phase_started = time.perf_counter()
            before_state = _state_summary(record, source_input, fmt, damage_flags)
            before_state["runtime_verification"] = dict(state.get("runtime_verification") or {}) or _terminal_verification_summary_from_state(record, before_state)
            job = RepairJob(
                source_input=source_input,
                format=fmt,
                confidence=0.82,
                analysis_evidence=_record_analysis_evidence(record, fmt),
                analysis_prepass=_record_analysis_prepass(record, fmt),
                fuzzy_profile=_record_fuzzy_profile(record, fmt),
                extraction_failure=_runtime_extraction_failure(record, state, before_state=before_state),
                extraction_diagnostics=_runtime_extraction_diagnostics(record, state),
                damage_flags=damage_flags,
                archive_key=f"{record.get('sample_id')}:round:{state_round}:beam:{state.get('beam_id', 0)}",
                attempts=state_round,
            )
            debug_events.write("phase", record, round=state_round, query_id=query_id, phase="before_state", elapsed_seconds=round(time.perf_counter() - phase_started, 3))
            state_features = _state_features(record, job, batch, state_round, previous_actions, previous_modules, best_completeness, before_state)
            state_features["previous_modules"] = previous_modules
            state_features["previous_module_count"] = len(previous_modules)
            phase_started = time.perf_counter()
            candidates, materialization_meta = _materialize_for_collection(list(batch.candidates), selector, args, record)
            debug_events.write(
                "phase",
                record,
                round=state_round,
                query_id=query_id,
                phase="materialize_candidates",
                elapsed_seconds=round(time.perf_counter() - phase_started, 3),
                candidate_count=len(candidates),
                proposal_count=len(batch.candidates),
                materialization_budget=materialization_meta["budget"],
            )
            phase_started = time.perf_counter()
            validated = [selector._with_native_validation(candidate) for candidate in candidates]  # noqa: SLF001
            debug_events.write("phase", record, round=state_round, query_id=query_id, phase="native_validation", elapsed_seconds=round(time.perf_counter() - phase_started, 3), candidate_count=len(validated))
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
            selected_candidate = None
            if rollout_mode == "greedy_current_selector":
                selected_candidate, selector_selection = selector.select(list(validated))
                debug_events.write("phase", record, round=state_round, query_id=query_id, phase="selector_select", selected_module=getattr(selected_candidate, "module_name", ""), selection=selector_selection)
            elif accepted:
                selected_candidate = accepted[0][2]
            selected_id = _candidate_id(selected_candidate)
            debug_events.write("phase", record, round=state_round, query_id=query_id, phase="rank_candidates", elapsed_seconds=round(time.perf_counter() - phase_started, 3), accepted_count=len(accepted), rejected_count=len(rejected))
            if not validated:
                empty = _round_empty_row(record, state_round, state_features, batch)
                _attach_rollout_context(empty, state, None, rollout_mode, query_id, "")
                rows.append(empty)
                rows.append(_rollout_terminal_row(record, state, "no_candidates", "no materialized repair candidates", before_state))
                continue
            logged = 0
            phase_started = time.perf_counter()
            row_entries: list[dict[str, Any]] = []
            label_by_id: dict[str, dict[str, Any]] = {}
            after_by_id: dict[str, dict[str, Any]] = {}
            delta_by_id: dict[str, dict[str, Any]] = {}
            rank_by_id: dict[str, int] = {}
            for rank, (_, original_index, candidate) in enumerate(ranked):
                if logged >= max_candidates_per_round:
                    break
                candidate_id = _candidate_id(candidate)
                materialized_for_label = bool(materialization_meta["materialized_ids"].get(candidate_id, True))
                if args.skip_unmaterialized_labels and not materialized_for_label:
                    continue
                payload = candidate_feature_payload(candidate)
                after_state = _state_summary(record, candidate.repaired_input if isinstance(candidate.repaired_input, dict) else {}, fmt, list(candidate.damage_flags or damage_flags), payload)
                delta_features = _state_delta(before_state, after_state)
                label_info = _label_candidate(record, candidate, best_completeness, before_state, after_state, delta_features)
                row = _action_row(
                    record,
                    state_round,
                    original_index,
                    rank,
                    candidate,
                    state_features,
                    before_state,
                    after_state,
                    delta_features,
                    batch,
                    job,
                    label_info,
                    selected=candidate_id == selected_id,
                    proposal_only=not materialized_for_label,
                    materialized_for_label=materialized_for_label,
                    materialization_rank=materialization_meta["ranks"].get(candidate_id),
                    materialization_budget=materialization_meta["budget"],
                )
                action_row_id = _action_row_id(query_id, candidate_id, original_index)
                _attach_rollout_context(row, state, candidate, rollout_mode, query_id, action_row_id)
                rows.append(row)
                row_entries.append({
                    "row": row,
                    "candidate": candidate,
                    "label_info": label_info,
                    "rank": rank,
                    "priority": selector.generation_priority(candidate),
                    "action_row_id": action_row_id,
                })
                label_by_id[candidate_id] = label_info
                after_by_id[candidate_id] = after_state
                delta_by_id[candidate_id] = delta_features
                rank_by_id[candidate_id] = rank
                logged += 1
            debug_events.write("phase", record, round=state_round, query_id=query_id, phase="label_candidates", elapsed_seconds=round(time.perf_counter() - phase_started, 3), logged_count=logged)

            branch_entries = _branch_entries(row_entries, selected_id, rollout_mode, args)
            if state_round + 1 >= max_rounds:
                terminal_entries = branch_entries or row_entries[:1]
                if terminal_entries:
                    for entry in terminal_entries:
                        candidate_id = _candidate_id(entry["candidate"])
                        rows.append(_rollout_terminal_row(
                            record,
                            state,
                            "max_rounds",
                            "maximum repair rounds reached",
                            after_by_id.get(candidate_id, before_state),
                            parent_action_row_id=entry["action_row_id"],
                            parent_candidate_id=candidate_id,
                        ))
                else:
                    rows.append(_rollout_terminal_row(record, state, "max_rounds", "maximum repair rounds reached", before_state))
                continue
            if not branch_entries:
                rows.append(_rollout_terminal_row(record, state, "dead_end", "no branchable repair candidate", before_state))
                continue
            for entry in branch_entries:
                if created_state_count >= max_total_states:
                    budget_exhausted = True
                    rows.append(_rollout_terminal_row(record, state, "budget_exhausted", "rollout state budget exhausted", before_state))
                    break
                candidate = entry["candidate"]
                candidate_id = _candidate_id(candidate)
                selected_result = candidate.to_result(selection={"selected_module": candidate.module_name})
                if not selected_result.ok or not selected_result.repaired_input:
                    rows.append(_rollout_terminal_row(record, state, "dead_end", "selected branch produced no repaired input", after_by_id.get(candidate_id), parent_action_row_id=entry["action_row_id"], parent_candidate_id=candidate_id))
                    continue
                label_info = label_by_id.get(candidate_id, {})
                if int(label_info.get("label", 0) or 0) == 3:
                    rows.append(_rollout_terminal_row(record, state, "complete", "branch reached complete repair", after_by_id.get(candidate_id), parent_action_row_id=entry["action_row_id"], parent_candidate_id=candidate_id, terminal_label=3))
                    continue
                child_runtime_verification = _terminal_verification_summary_from_state(record, after_by_id.get(candidate_id, {}))
                child_state = {
                    "episode_id": state["episode_id"],
                    "state_id": f"{record.get('sample_id')}:r{state_round + 1}:b{next_beam_id}",
                    "round": state_round + 1,
                    "beam_id": next_beam_id,
                    "parent_query_id": query_id,
                    "parent_candidate_id": candidate_id,
                    "parent_action_row_id": entry["action_row_id"],
                    "source_input": dict(selected_result.repaired_input),
                    "damage_flags": _next_state_damage_flags(selected_result, damage_flags, child_runtime_verification),
                    "previous_actions": [*previous_actions, *[str(action) for action in candidate.actions]],
                    "previous_modules": [*previous_modules, str(candidate.module_name)],
                    "best_completeness": max(best_completeness, float(label_info.get("completeness", 0.0) or 0.0)),
                    "path_score": float(state.get("path_score", 0.0) or 0.0) + float(int(label_info.get("label", 0) or 0)),
                    "path_actions": [*list(state.get("path_actions") or []), *[str(action) for action in candidate.actions]],
                    "path_modules": [*list(state.get("path_modules") or []), str(candidate.module_name)],
                    "runtime_verification": child_runtime_verification,
                    "runtime_extraction_diagnostics": _diagnostics_from_runtime_verification(child_runtime_verification),
                    "rollout_mode": rollout_mode,
                }
                next_beam_id += 1
                created_state_count += 1
                branch_count += 1
                next_frontier.append(child_state)
            if budget_exhausted:
                break
        frontier = _trim_frontier(next_frontier, args)
        if budget_exhausted:
            break

    _backfill_future_labels(rows, float(getattr(args, "future_label_discount", 0.8) or 0.8))
    terminal_rows = [row for row in rows if row.get("row_type") == "terminal"]
    terminal_status_counts = Counter(str(item.get("terminal_status") or item.get("label_status") or "unknown") for item in terminal_rows)
    for row in rows:
        row["rollout_summary"] = {
            "state_count": created_state_count,
            "expanded_state_count": expanded_state_count,
            "branch_count": branch_count,
            "rollout_budget_exhausted": bool(budget_exhausted),
            "terminal_count": len(terminal_rows),
            "terminal_status_counts": dict(sorted(terminal_status_counts.items())),
        }
    return rows


def _root_rollout_state(record: dict[str, Any], fmt: str, rollout_mode: str) -> dict[str, Any]:
    sample_id = str(record.get("sample_id") or record.get("source_archive_id") or "sample")
    return {
        "episode_id": sample_id,
        "state_id": f"{sample_id}:r0:b0",
        "round": 0,
        "beam_id": 0,
        "parent_query_id": None,
        "parent_candidate_id": None,
        "parent_action_row_id": None,
        "source_input": dict(record.get("damaged_input") or {"path": record.get("damaged_path"), "format_hint": fmt}),
        "damage_flags": _runtime_initial_damage_flags(record),
        "previous_actions": [],
        "previous_modules": [],
        "best_completeness": 0.0,
        "path_score": 0.0,
        "path_actions": [],
        "path_modules": [],
        "runtime_verification": dict(record.get("runtime_initial_verification") or {}),
        "rollout_mode": rollout_mode,
    }


def _runtime_initial_damage_flags(record: dict[str, Any]) -> list[str]:
    explicit = record.get("runtime_damage_flags")
    if isinstance(explicit, list):
        return [str(item) for item in explicit if str(item)]
    raw = {str(item) for item in (record.get("damage_flags") or [])}
    visible: list[str] = []
    for flag in ("missing_volume", "wrong_password", "truncated", "input_truncated", "probably_truncated", "trailing_junk", "boundary_unreliable", "checksum_error", "crc_error", "damaged"):
        if flag in raw:
            visible.append(flag)
    if raw and "damaged" not in visible:
        visible.append("damaged")
    return visible


def _next_state_damage_flags(result: RepairResult, current_flags: list[str], runtime_verification: dict[str, Any]) -> list[str]:
    if str(runtime_verification.get("assessment_status") or "") == "complete":
        return []
    if str(runtime_verification.get("source_integrity") or "") == "complete":
        return []
    return list(result.damage_flags or current_flags)


def _diagnostics_from_runtime_verification(runtime_verification: dict[str, Any]) -> dict[str, Any]:
    coverage = runtime_verification.get("archive_coverage") if isinstance(runtime_verification.get("archive_coverage"), dict) else {}
    complete = str(runtime_verification.get("assessment_status") or "") == "complete"
    return {
        "failure_stage": "" if complete else "verification",
        "failure_kind": "",
        "result": {
            "status": "success" if complete else "failed",
            "native_status": "success" if complete else "crc_error",
            "files_written": int(coverage.get("complete_files") or runtime_verification.get("complete_files") or 0),
            "bytes_written": int(coverage.get("complete_bytes") or 0),
        },
    }


def _rollout_query_id(record: dict[str, Any], state: dict[str, Any]) -> str:
    sample_id = str(record.get("sample_id") or state.get("episode_id") or "sample")
    if str(state.get("rollout_mode") or "greedy") in {"greedy", "greedy_current_selector"}:
        return f"{sample_id}:{int(state.get('round', 0) or 0)}"
    return f"{sample_id}:r{int(state.get('round', 0) or 0)}:b{int(state.get('beam_id', 0) or 0)}"


def _action_row_id(query_id: str, candidate_id: str, candidate_index: int) -> str:
    return f"{query_id}|{candidate_index}|{candidate_id}"


def _attach_rollout_context(row: dict[str, Any], state: dict[str, Any], candidate: Any, rollout_mode: str, query_id: str, action_row_id: str) -> None:
    row["query_id"] = query_id
    row["episode_id"] = state.get("episode_id")
    row["state_id"] = state.get("state_id")
    row["parent_query_id"] = state.get("parent_query_id")
    row["parent_candidate_id"] = state.get("parent_candidate_id")
    row["parent_action_row_id"] = state.get("parent_action_row_id")
    row["beam_id"] = int(state.get("beam_id", 0) or 0)
    row["path_actions"] = list(state.get("path_actions") or [])
    row["path_modules"] = list(state.get("path_modules") or [])
    row["path_score"] = float(state.get("path_score", 0.0) or 0.0)
    row["rollout_mode"] = rollout_mode
    if action_row_id:
        row["action_row_id"] = action_row_id
    if candidate is not None:
        row["branchable"] = _candidate_has_output(candidate)


def _candidate_has_output(candidate: Any) -> bool:
    repaired_input = candidate.repaired_input if isinstance(getattr(candidate, "repaired_input", None), dict) else {}
    path = str(repaired_input.get("path") or "")
    return bool(path and Path(path).is_file())


def _branch_entries(entries: list[dict[str, Any]], selected_id: str, rollout_mode: str, args: argparse.Namespace) -> list[dict[str, Any]]:
    if not entries:
        return []
    if rollout_mode in {"greedy", "greedy_current_selector"}:
        selected = [entry for entry in entries if _candidate_id(entry["candidate"]) == selected_id]
        return selected[:1]
    by_id: dict[str, dict[str, Any]] = {}

    def add(entry: dict[str, Any]) -> None:
        candidate = entry["candidate"]
        if not _candidate_has_output(candidate):
            return
        by_id.setdefault(_candidate_id(candidate), entry)

    for entry in entries:
        if _candidate_id(entry["candidate"]) == selected_id:
            add(entry)
            break
    for entry in sorted(entries, key=lambda item: float(item.get("priority", 0.0) or 0.0), reverse=True):
        add(entry)
        if len(by_id) >= max(1, int(getattr(args, "branch_top_k", 2) or 2)):
            break
    if rollout_mode == "counterfactual":
        for entry in sorted(entries, key=lambda item: int((item.get("label_info") or {}).get("label", 0) or 0), reverse=True):
            add(entry)
            if len(by_id) >= max(1, int(getattr(args, "branch_top_k", 2) or 2)) + max(0, int(getattr(args, "counterfactual_extra", 2) or 2)):
                break
        risky = [
            entry for entry in entries
            if int((entry.get("label_info") or {}).get("label", 0) or 0) < 0
            or _as_float((candidate_feature_payload(entry["candidate"]).get("risk_penalty"))) > 0.0
        ]
        for entry in sorted(risky, key=lambda item: _as_float(candidate_feature_payload(item["candidate"]).get("risk_penalty")), reverse=True):
            add(entry)
            if len(by_id) >= max(1, int(getattr(args, "branch_top_k", 2) or 2)) + max(0, int(getattr(args, "counterfactual_extra", 2) or 2)):
                break
    limit = max(1, int(getattr(args, "branch_top_k", 2) or 2))
    if rollout_mode == "counterfactual":
        limit += max(0, int(getattr(args, "counterfactual_extra", 2) or 2))
    return list(by_id.values())[:limit]


def _trim_frontier(frontier: list[dict[str, Any]], args: argparse.Namespace) -> list[dict[str, Any]]:
    if not frontier:
        return []
    beam_size = 1 if str(getattr(args, "rollout_mode", "greedy") or "greedy") in {"greedy", "greedy_current_selector"} else max(1, int(getattr(args, "beam_size", 2) or 2))
    return sorted(frontier, key=lambda state: float(state.get("path_score", 0.0) or 0.0), reverse=True)[:beam_size]


def _rollout_terminal_row(
    record: dict[str, Any],
    state: dict[str, Any],
    status: str,
    message: str,
    terminal_state: dict[str, Any] | None,
    *,
    parent_action_row_id: str | None = None,
    parent_candidate_id: str | None = None,
    terminal_label: int | None = None,
) -> dict[str, Any]:
    source_derivation = record.get("source_derivation") if isinstance(record.get("source_derivation"), dict) else {}
    state_round = int(state.get("round", 0) or 0)
    terminal_state = terminal_state if isinstance(terminal_state, dict) else {}
    label = int(terminal_label if terminal_label is not None else _terminal_label_from_state(status, terminal_state))
    terminal_verification = _terminal_verification_summary_from_state(record, terminal_state)
    terminal_coverage = terminal_verification.get("archive_coverage") if isinstance(terminal_verification.get("archive_coverage"), dict) else {}
    terminal_recovery_ratio = _terminal_recovery_ratio(terminal_verification)
    terminal_ratio_source = _terminal_recovery_ratio_source(terminal_verification)
    row = {
        "schema_version": 1,
        "source": "repair_plan_corpus",
        "row_type": "terminal",
        "query_id": f"{state.get('episode_id')}:terminal:{state.get('beam_id', 0)}:{status}",
        "sample_id": record.get("sample_id"),
        "source_archive_id": record.get("source_archive_id"),
        "material_format": record.get("material_format"),
        "material_sample_id": record.get("material_sample_id"),
        "source_archive_name": record.get("source_archive_name"),
        "source_derivation": _compact_source_derivation(source_derivation),
        "damaged_file_name": record.get("damaged_file_name"),
        "damaged_path": record.get("damaged_path"),
        "damage_json_path": record.get("damage_json_path"),
        "round": state_round,
        "candidate_id": None,
        "module": "",
        "selected_by_current_system": False,
        "label": label,
        "label_status": status,
        "episode_id": state.get("episode_id"),
        "state_id": state.get("state_id"),
        "terminal_state_id": state.get("state_id"),
        "parent_query_id": state.get("parent_query_id"),
        "parent_candidate_id": parent_candidate_id or state.get("parent_candidate_id"),
        "parent_action_row_id": parent_action_row_id or state.get("parent_action_row_id"),
        "beam_id": int(state.get("beam_id", 0) or 0),
        "path_actions": list(state.get("path_actions") or []),
        "path_modules": list(state.get("path_modules") or []),
        "path_score": float(state.get("path_score", 0.0) or 0.0),
        "rollout_mode": state.get("rollout_mode") or "greedy",
        "terminal_status": status,
        "terminal_label": label,
        "terminal_state": terminal_state,
        "terminal_verification_summary": terminal_verification,
        "terminal_archive_coverage": terminal_coverage,
        "terminal_recovery_ratio": terminal_recovery_ratio,
        "terminal_recovery_ratio_source": terminal_ratio_source,
        "stable_features": {
            "state": {
                "format": record.get("format"),
                "damage_profile": record.get("damage_profile"),
                "difficulty_tags": list(record.get("difficulty_tags") or []),
                "source_derivation": _compact_source_derivation(source_derivation),
                "terminal_status": status,
                "terminal_state": terminal_state,
            },
            "candidate": {},
        },
        "teacher_features": {},
        "debug_features": {"message": message},
        "label_details": {
            "immediate_label": label,
            "future_best_label": label,
            "terminal_success": label == 3,
            "steps_to_best": 0,
            "subtree_best_label": label,
            "subtree_terminal_success": label == 3,
            "subtree_best_terminal_state_id": state.get("state_id"),
            "selected_path_terminal_label": label,
            "selected_path_terminal_status": status,
            "steps_to_terminal": 0,
        },
        "training_targets": {
            "immediate_gain": label,
            "future_gain": label,
            "discounted_gain": float(label),
            "blended_gain": float(label),
            "strategy_gain": _strategy_gain(label, label, 0, label == 3, status),
            "terminal_recovery_ratio": terminal_recovery_ratio,
            "discounted_terminal_recovery_ratio": terminal_recovery_ratio,
            "strategy_recovery_ratio": _strategy_recovery_ratio(label, terminal_recovery_ratio, 0, label == 3, status),
            "risk_class": _risk_class(label, label, status),
            "hard_negative_weight": _hard_negative_weight(label, label, status),
        },
    }
    return row


def _terminal_label_from_state(status: str, terminal_state: dict[str, Any]) -> int:
    if status == "complete":
        return 3
    verification_status = str(terminal_state.get("verification_status") or "")
    if verification_status == "complete" or _as_float(terminal_state.get("completeness")) >= 0.999:
        return 3
    if verification_status == "partial" or int(terminal_state.get("matched_entry_count", 0) or 0) > 0:
        return 1
    if verification_status == "state_progress" or bool(terminal_state.get("directory_detected")) or _as_float(terminal_state.get("completeness")) >= 0.15:
        return 2
    if verification_status == "hard_negative":
        return -1
    return 0


def _terminal_verification_summary_from_state(record: dict[str, Any], terminal_state: dict[str, Any]) -> dict[str, Any]:
    archive_path = Path(str(terminal_state.get("source_path") or ""))
    source_archive = Path(str(record.get("source_path") or ""))
    if not source_archive.is_file():
        return _verification_result_payload(_failed_terminal_verification("missing_source_archive"))
    try:
        with tempfile.TemporaryDirectory(prefix="sunpack_verify_terminal_") as tmp:
            output_dir = Path(tmp) / "out"
            output_dir.mkdir(parents=True, exist_ok=True)
            if archive_path.is_file():
                extract_status = _extract_archive_for_terminal_verification(archive_path, str(record.get("format") or record.get("material_format") or ""), output_dir)
                result_archive = str(archive_path)
            else:
                extract_status = {"success": False, "failure_kind": "missing_terminal_archive", "error": "terminal archive path is missing", "files_written": 0, "bytes_written": 0}
                result_archive = str(source_archive)
            task_archive = archive_path if archive_path.is_file() else source_archive
            task = _verification_task_from_record(record, task_archive)
            result = ExtractionResult(
                success=extract_status.get("success", False),
                archive=result_archive,
                out_dir=str(output_dir),
                all_parts=[str(archive_path)],
                error=str(extract_status.get("error") or ""),
                diagnostics={
                    "failure_stage": "" if extract_status.get("success") else "terminal_verification_extract",
                    "failure_kind": str(extract_status.get("failure_kind") or ""),
                    "result": {
                        "native_status": "ok" if extract_status.get("success") else "failed",
                        "files_written": int(extract_status.get("files_written", 0) or 0),
                        "bytes_written": int(extract_status.get("bytes_written", 0) or 0),
                    },
                },
                partial_outputs=bool(extract_status.get("files_written", 0)),
            )
            verification = _terminal_verifier().verify(task, result)
            return _verification_result_payload(verification)
    except Exception as exc:
        return _verification_result_payload(_failed_terminal_verification(str(exc)))


def _terminal_recovery_ratio(verification: dict[str, Any]) -> float:
    coverage = verification.get("archive_coverage") if isinstance(verification.get("archive_coverage"), dict) else {}
    if coverage.get("completeness") is not None:
        return max(0.0, min(1.0, _as_float(coverage.get("completeness"))))
    if verification.get("completeness") is not None:
        return max(0.0, min(1.0, _as_float(verification.get("completeness"))))
    expected = int(coverage.get("expected_files", 0) or 0)
    complete = int(coverage.get("complete_files", 0) or 0)
    if expected > 0:
        return max(0.0, min(1.0, complete / expected))
    return 0.0


def _terminal_recovery_ratio_source(verification: dict[str, Any]) -> str:
    coverage = verification.get("archive_coverage") if isinstance(verification.get("archive_coverage"), dict) else {}
    if coverage.get("completeness") is not None:
        return "verification.archive_coverage.completeness"
    if verification.get("completeness") is not None:
        return "verification.completeness"
    return "matched_files/expected_files"


def _terminal_verifier() -> VerificationScheduler:
    return VerificationScheduler({
        "verification": {
            "enabled": True,
            "complete_accept_threshold": 0.999,
            "partial_accept_threshold": 0.2,
            "methods": [
                {"name": "archive_test_crc", "enabled": True, "max_items": 200000},
                {"name": "manifest_size_match", "enabled": True, "max_expected_names": 200000},
                {"name": "output_presence", "enabled": True},
            ],
        }
    })


def _verification_task_from_record(record: dict[str, Any], source_archive: Path) -> ArchiveTask:
    fmt = str(record.get("format") or record.get("material_format") or source_archive.suffix.lstrip("."))
    bag = FactBag()
    bag.set("candidate.entry_path", str(source_archive))
    bag.set("candidate.member_paths", [str(source_archive)])
    bag.set("candidate.logical_name", source_archive.stem)
    bag.set("file.detected_ext", fmt)
    bag.set("archive.format_hint", fmt)
    bag.set("analysis.selected_format", fmt)
    bag.set("analysis.status", "selected")
    bag.set("analysis.confidence", 1.0)
    task = ArchiveTask(
        fact_bag=bag,
        score=10,
        key=str(record.get("source_archive_id") or source_archive.name),
        main_path=str(source_archive),
        all_parts=[str(source_archive)],
        logical_name=str(record.get("source_archive_name") or source_archive.stem),
        detected_ext=fmt,
    )
    task.ensure_archive_state()
    return task


def _extract_archive_for_terminal_verification(archive_path: Path, fmt: str, output_dir: Path) -> dict[str, Any]:
    fmt = _normalize_format(fmt)
    files_written = 0
    bytes_written = 0
    try:
        if fmt == "zip":
            with zipfile.ZipFile(archive_path, "r") as archive:
                for info in archive.infolist():
                    if info.is_dir():
                        continue
                    target = output_dir / info.filename
                    target.parent.mkdir(parents=True, exist_ok=True)
                    data = archive.read(info)
                    target.write_bytes(data)
                    files_written += 1
                    bytes_written += len(data)
        elif fmt == "tar":
            with tarfile.open(archive_path, "r:*") as archive:
                for member in archive.getmembers():
                    if not member.isfile():
                        continue
                    target = output_dir / member.name
                    target.parent.mkdir(parents=True, exist_ok=True)
                    source = archive.extractfile(member)
                    data = source.read() if source is not None else b""
                    target.write_bytes(data)
                    files_written += 1
                    bytes_written += len(data)
        else:
            return {"success": False, "failure_kind": "unsupported_terminal_format", "files_written": 0, "bytes_written": 0}
        return {"success": files_written > 0, "files_written": files_written, "bytes_written": bytes_written}
    except Exception as exc:
        return {"success": files_written > 0, "failure_kind": "extract_error", "error": str(exc), "files_written": files_written, "bytes_written": bytes_written}


def _verification_result_payload(verification: Any) -> dict[str, Any]:
    coverage = getattr(verification, "archive_coverage", None)
    return {
        "assessment_status": getattr(verification, "assessment_status", ""),
        "decision_hint": getattr(verification, "decision_hint", ""),
        "source_integrity": getattr(verification, "source_integrity", ""),
        "completeness": float(getattr(verification, "completeness", 0.0) or 0.0),
        "recoverable_upper_bound": float(getattr(verification, "recoverable_upper_bound", 1.0) or 1.0),
        "complete_files": int(getattr(verification, "complete_files", 0) or 0),
        "partial_files": int(getattr(verification, "partial_files", 0) or 0),
        "failed_files": int(getattr(verification, "failed_files", 0) or 0),
        "missing_files": int(getattr(verification, "missing_files", 0) or 0),
        "unverified_files": int(getattr(verification, "unverified_files", 0) or 0),
        "methods_run": list(getattr(verification, "methods_run", []) or []),
        "repair_hints": dict(getattr(verification, "repair_hints", {}) or {}),
        "archive_coverage": {
            "completeness": float(getattr(coverage, "completeness", 0.0) or 0.0) if coverage is not None else 0.0,
            "file_coverage": float(getattr(coverage, "file_coverage", 0.0) or 0.0) if coverage is not None else 0.0,
            "byte_coverage": float(getattr(coverage, "byte_coverage", 0.0) or 0.0) if coverage is not None else 0.0,
            "complete_bytes": int(getattr(coverage, "complete_bytes", 0) or 0) if coverage is not None else 0,
            "expected_bytes": int(getattr(coverage, "expected_bytes", 0) or 0) if coverage is not None else 0,
            "expected_files": int(getattr(coverage, "expected_files", 0) or 0) if coverage is not None else 0,
            "matched_files": int(getattr(coverage, "matched_files", 0) or 0) if coverage is not None else 0,
            "complete_files": int(getattr(coverage, "complete_files", 0) or 0) if coverage is not None else 0,
            "partial_files": int(getattr(coverage, "partial_files", 0) or 0) if coverage is not None else 0,
            "failed_files": int(getattr(coverage, "failed_files", 0) or 0) if coverage is not None else 0,
            "missing_files": int(getattr(coverage, "missing_files", 0) or 0) if coverage is not None else 0,
            "confidence": float(getattr(coverage, "confidence", 0.0) or 0.0) if coverage is not None else 0.0,
        },
    }


def _failed_terminal_verification(message: str):
    from sunpack.verification.result import (
        ArchiveCoverageSummary,
        DECISION_REPAIR,
        SOURCE_INTEGRITY_DAMAGED,
        ASSESSMENT_UNUSABLE,
        VerificationIssue,
        VerificationResult,
    )

    return VerificationResult(
        methods_run=["terminal_verification"],
        issues=[VerificationIssue(method="terminal_verification", code="fail.terminal_verification", message=message)],
        completeness=0.0,
        recoverable_upper_bound=0.0,
        assessment_status=ASSESSMENT_UNUSABLE,
        source_integrity=SOURCE_INTEGRITY_DAMAGED,
        decision_hint=DECISION_REPAIR,
        archive_coverage=ArchiveCoverageSummary(completeness=0.0, confidence=1.0),
    )


def _label_to_recovery_ratio(label: int) -> float:
    label = int(label or 0)
    if label >= 3:
        return 1.0
    if label == 2:
        return 0.35
    if label == 1:
        return 0.2
    return 0.0


def _strategy_gain(immediate_label: int, terminal_label: int, steps_to_terminal: int, terminal_success: bool, terminal_status: str | None) -> float:
    terminal_label = int(terminal_label or 0)
    immediate_label = int(immediate_label or 0)
    if immediate_label < 0:
        return -1.0
    if terminal_label < 0:
        return -1.0
    steps = max(0, int(steps_to_terminal or 0))
    terminal_component = float(terminal_label) * (0.9 ** steps)
    immediate_component = 0.1 * float(immediate_label)
    success_bonus = 0.5 if terminal_success else 0.0
    status_penalty = 0.0
    if str(terminal_status or "") in {"dead_end", "no_candidates", "budget_exhausted"}:
        status_penalty = 0.25
    return max(-1.0, terminal_component + immediate_component + success_bonus - status_penalty)


def _strategy_recovery_ratio(immediate_label: int, terminal_recovery_ratio: float, steps_to_terminal: int, terminal_success: bool, terminal_status: str | None) -> float:
    if int(immediate_label or 0) < 0 or str(terminal_status or "") == "hard_negative":
        return -1.0
    steps = max(0, int(steps_to_terminal or 0))
    ratio = max(0.0, min(1.0, float(terminal_recovery_ratio or 0.0)))
    value = ratio * (0.9 ** steps)
    if terminal_success:
        value += 0.05
    if str(terminal_status or "") in {"dead_end", "no_candidates", "budget_exhausted"}:
        value -= 0.05
    return max(-1.0, min(1.05, value))


def _backfill_future_labels(rows: list[dict[str, Any]], discount: float) -> None:
    rows_by_id = {str(row.get("action_row_id")): row for row in rows if row.get("action_row_id")}
    children: dict[str, list[dict[str, Any]]] = {}
    terminals: dict[str, list[dict[str, Any]]] = {}
    for row in rows:
        parent_id = str(row.get("parent_action_row_id") or "")
        if parent_id:
            if row.get("row_type") == "terminal":
                terminals.setdefault(parent_id, []).append(row)
            else:
                children.setdefault(parent_id, []).append(row)
    memo: dict[str, dict[str, Any]] = {}

    def best_from(row_id: str) -> dict[str, Any]:
        if row_id in memo:
            return memo[row_id]
        row = rows_by_id.get(row_id, {})
        own_label = int(row.get("label", 0) or 0)
        result = {
            "subtree_best_label": own_label,
            "subtree_best_terminal_recovery_ratio": _label_to_recovery_ratio(own_label),
            "subtree_terminal_success": own_label == 3,
            "subtree_best_terminal_state_id": row.get("state_id"),
            "steps_to_best": 0,
            "selected_path_terminal_label": own_label,
            "selected_path_terminal_status": str(row.get("label_status") or ""),
            "selected_path_terminal_state_id": row.get("state_id"),
            "selected_path_terminal_recovery_ratio": _label_to_recovery_ratio(own_label),
            "steps_to_terminal": 0,
        }
        for terminal in terminals.get(row_id, []):
            terminal_label = int(terminal.get("label", 0) or 0)
            terminal_status = str(terminal.get("label_status") or "")
            terminal_state_id = terminal.get("terminal_state_id") or terminal.get("state_id")
            terminal_ratio = float(terminal.get("terminal_recovery_ratio", _label_to_recovery_ratio(terminal_label)) or 0.0)
            if terminal_ratio > float(result["subtree_best_terminal_recovery_ratio"]) or (terminal_ratio == float(result["subtree_best_terminal_recovery_ratio"]) and terminal_label > int(result["subtree_best_label"])):
                result["subtree_best_label"] = terminal_label
                result["subtree_best_terminal_recovery_ratio"] = terminal_ratio
                result["subtree_best_terminal_state_id"] = terminal_state_id
                result["steps_to_best"] = 1
            result["subtree_terminal_success"] = bool(result["subtree_terminal_success"]) or terminal_label == 3
            if terminal_ratio > float(result["selected_path_terminal_recovery_ratio"]) or (terminal_ratio == float(result["selected_path_terminal_recovery_ratio"]) and terminal_label > int(result["selected_path_terminal_label"])):
                result["selected_path_terminal_label"] = terminal_label
                result["selected_path_terminal_status"] = terminal_status
                result["selected_path_terminal_state_id"] = terminal_state_id
                result["selected_path_terminal_recovery_ratio"] = terminal_ratio
                result["steps_to_terminal"] = 1
        for child in children.get(row_id, []):
            child_id = str(child.get("action_row_id") or "")
            child_result = best_from(child_id) if child_id else {
                "subtree_best_label": int(child.get("label", 0) or 0),
                "subtree_best_terminal_recovery_ratio": _label_to_recovery_ratio(int(child.get("label", 0) or 0)),
                "subtree_terminal_success": int(child.get("label", 0) or 0) == 3,
                "subtree_best_terminal_state_id": child.get("state_id"),
                "steps_to_best": 0,
                "selected_path_terminal_label": int(child.get("label", 0) or 0),
                "selected_path_terminal_status": str(child.get("label_status") or ""),
                "selected_path_terminal_state_id": child.get("state_id"),
                "selected_path_terminal_recovery_ratio": _label_to_recovery_ratio(int(child.get("label", 0) or 0)),
                "steps_to_terminal": 0,
            }
            candidate_steps = int(child_result.get("steps_to_best", 0) or 0) + 1
            child_best = int(child_result.get("subtree_best_label", 0) or 0)
            child_ratio = float(child_result.get("subtree_best_terminal_recovery_ratio", _label_to_recovery_ratio(child_best)) or 0.0)
            result["subtree_terminal_success"] = bool(result["subtree_terminal_success"]) or bool(child_result.get("subtree_terminal_success"))
            if child_ratio > float(result["subtree_best_terminal_recovery_ratio"]) or (child_ratio == float(result["subtree_best_terminal_recovery_ratio"]) and candidate_steps < int(result["steps_to_best"])):
                result["subtree_best_label"] = child_best
                result["subtree_best_terminal_recovery_ratio"] = child_ratio
                result["steps_to_best"] = candidate_steps
                result["subtree_best_terminal_state_id"] = child_result.get("subtree_best_terminal_state_id")
            selected_label = int(child_result.get("selected_path_terminal_label", 0) or 0)
            selected_ratio = float(child_result.get("selected_path_terminal_recovery_ratio", _label_to_recovery_ratio(selected_label)) or 0.0)
            if selected_ratio > float(result["selected_path_terminal_recovery_ratio"]) or (selected_ratio == float(result["selected_path_terminal_recovery_ratio"]) and selected_label > int(result["selected_path_terminal_label"])):
                result["selected_path_terminal_label"] = selected_label
                result["selected_path_terminal_status"] = child_result.get("selected_path_terminal_status")
                result["selected_path_terminal_state_id"] = child_result.get("selected_path_terminal_state_id")
                result["selected_path_terminal_recovery_ratio"] = selected_ratio
                result["steps_to_terminal"] = int(child_result.get("steps_to_terminal", 0) or 0) + 1
        memo[row_id] = result
        return memo[row_id]

    for row in rows:
        if row.get("row_type") == "terminal":
            continue
        row_id = str(row.get("action_row_id") or "")
        immediate_label = int(row.get("label", 0) or 0)
        future = best_from(row_id) if row_id else {
            "subtree_best_label": immediate_label,
            "subtree_best_terminal_recovery_ratio": _label_to_recovery_ratio(immediate_label),
            "subtree_terminal_success": immediate_label == 3,
            "subtree_best_terminal_state_id": row.get("state_id"),
            "steps_to_best": 0,
            "selected_path_terminal_label": immediate_label,
            "selected_path_terminal_status": str(row.get("label_status") or ""),
            "selected_path_terminal_state_id": row.get("state_id"),
            "selected_path_terminal_recovery_ratio": _label_to_recovery_ratio(immediate_label),
            "steps_to_terminal": 0,
        }
        future_label = int(future.get("subtree_best_label", immediate_label) or 0)
        steps_to_best = int(future.get("steps_to_best", 0) or 0)
        terminal_success = bool(future.get("subtree_terminal_success"))
        discounted = float(future_label) * (float(discount) ** int(steps_to_best))
        blended = 0.2 * float(immediate_label) + 0.8 * discounted
        selected_terminal_label = int(future.get("selected_path_terminal_label", immediate_label) or 0)
        selected_terminal_status = str(future.get("selected_path_terminal_status") or "")
        steps_to_terminal = int(future.get("steps_to_terminal", 0) or 0)
        selected_terminal_ratio = float(future.get("selected_path_terminal_recovery_ratio", _label_to_recovery_ratio(selected_terminal_label)) or 0.0)
        best_terminal_ratio = float(future.get("subtree_best_terminal_recovery_ratio", _label_to_recovery_ratio(future_label)) or 0.0)
        strategy_gain = _strategy_gain(immediate_label, selected_terminal_label, steps_to_terminal, bool(terminal_success), selected_terminal_status)
        discounted_terminal_ratio = best_terminal_ratio * (float(discount) ** int(steps_to_best))
        strategy_recovery_ratio = _strategy_recovery_ratio(immediate_label, selected_terminal_ratio, steps_to_terminal, bool(terminal_success), selected_terminal_status)
        details = row.get("label_details") if isinstance(row.get("label_details"), dict) else {}
        details["immediate_label"] = immediate_label
        details["future_best_label"] = future_label
        details["terminal_success"] = bool(terminal_success)
        details["steps_to_best"] = int(steps_to_best)
        details["discounted_future_gain"] = discounted
        details["subtree_best_label"] = future_label
        details["subtree_terminal_success"] = bool(terminal_success)
        details["subtree_best_terminal_state_id"] = future.get("subtree_best_terminal_state_id")
        details["selected_path_terminal_label"] = selected_terminal_label
        details["selected_path_terminal_status"] = selected_terminal_status
        details["selected_path_terminal_state_id"] = future.get("selected_path_terminal_state_id")
        details["steps_to_terminal"] = steps_to_terminal
        details["strategy_gain"] = strategy_gain
        details["terminal_recovery_ratio"] = selected_terminal_ratio
        details["subtree_best_terminal_recovery_ratio"] = best_terminal_ratio
        details["discounted_terminal_recovery_ratio"] = discounted_terminal_ratio
        details["strategy_recovery_ratio"] = strategy_recovery_ratio
        details["risk_class"] = _risk_class(immediate_label, selected_terminal_label, selected_terminal_status)
        details["hard_negative_weight"] = _hard_negative_weight(immediate_label, selected_terminal_label, selected_terminal_status)
        row["label_details"] = details
        row["strategy_outcome"] = {
            "terminal_label": selected_terminal_label,
            "terminal_status": selected_terminal_status,
            "terminal_state_id": future.get("selected_path_terminal_state_id"),
            "subtree_best_label": future_label,
            "subtree_terminal_success": bool(terminal_success),
            "steps_to_terminal": steps_to_terminal,
            "strategy_gain": strategy_gain,
            "terminal_recovery_ratio": selected_terminal_ratio,
            "subtree_best_terminal_recovery_ratio": best_terminal_ratio,
            "discounted_terminal_recovery_ratio": discounted_terminal_ratio,
            "strategy_recovery_ratio": strategy_recovery_ratio,
            "risk_class": details["risk_class"],
            "hard_negative_weight": details["hard_negative_weight"],
        }
        row["terminal_recovery_ratio"] = selected_terminal_ratio
        row["terminal_recovery_ratio_source"] = "verification.archive_coverage.completeness"
        row["training_targets"] = {
            "immediate_gain": immediate_label,
            "future_gain": future_label,
            "discounted_gain": discounted,
            "blended_gain": blended,
            "strategy_gain": strategy_gain,
            "terminal_recovery_ratio": selected_terminal_ratio,
            "subtree_best_terminal_recovery_ratio": best_terminal_ratio,
            "discounted_terminal_recovery_ratio": discounted_terminal_ratio,
            "strategy_recovery_ratio": strategy_recovery_ratio,
            "risk_class": details["risk_class"],
            "hard_negative_weight": details["hard_negative_weight"],
        }


def _risk_class(immediate_label: int, terminal_label: int, terminal_status: str | None) -> str:
    if int(immediate_label or 0) < 0:
        return "hard_negative_immediate"
    if int(terminal_label or 0) < 0 or str(terminal_status or "") == "hard_negative":
        return "hard_negative_terminal"
    if str(terminal_status or "") in {"dead_end", "no_candidates", "budget_exhausted"}:
        return "terminal_failure"
    if int(terminal_label or 0) > 0:
        return "terminal_useful"
    return "neutral"


def _hard_negative_weight(immediate_label: int, terminal_label: int, terminal_status: str | None) -> float:
    risk = _risk_class(immediate_label, terminal_label, terminal_status)
    if risk == "hard_negative_immediate":
        return 2.0
    if risk == "hard_negative_terminal":
        return 1.5
    if risk == "terminal_failure":
        return 0.5
    return 0.0


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
    if _normalize_format(str(record.get("material_format") or record.get("format") or "")) == "zip":
        selected = _balanced_zip_materialization_selection(ranked, budget)
    else:
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


def _is_zip_deceptive_record(record: dict[str, Any]) -> bool:
    if _normalize_format(str(record.get("material_format") or record.get("format") or "")) != "zip":
        return False
    tags = set(str(item) for item in record.get("difficulty_tags") or [])
    profile = str(record.get("damage_profile") or "")
    flags = set(str(item) for item in record.get("damage_flags") or [])
    return bool(
        tags.intersection({"deceptive_structural_success", "hash_mismatch_risk", "two_step_repair"})
        or flags.intersection({"hard_negative_target", "payload_hash_mismatch", "two_step_repair"})
        or profile.startswith("zip_two_step_")
        or profile in {"zip_rebuild_directory_keeps_bad_payload", "zip_wrong_local_offset_extracts_valid_other_entry", "zip_quarantine_keeps_corrupted_entry"}
    )


def _balanced_zip_materialization_selection(ranked: list[tuple[float, int, Any]], budget: int) -> list[tuple[float, int, Any]]:
    selected: list[tuple[float, int, Any]] = []
    seen: set[str] = set()

    def add(entry: tuple[float, int, Any]) -> None:
        if len(selected) >= budget:
            return
        candidate_id = _candidate_id(entry[2])
        if candidate_id in seen:
            return
        seen.add(candidate_id)
        selected.append(entry)

    def category(entry: tuple[float, int, Any]) -> str:
        module = str(getattr(entry[2], "module_name", "") or "")
        actions = " ".join(str(action) for action in getattr(entry[2], "actions", []) or [])
        text = f"{module} {actions}".lower()
        if "quarantine" in text or "partial_recovery" in text or "deep_partial" in text:
            return "deep_partial"
        if "crc" in text or "offset" in text or "comment" in text or "descriptor" in text:
            return "risk"
        if "rebuild" in text or "directory" in text or "eocd" in text or "central_directory" in text:
            return "directory"
        if "trim" in text or "boundary" in text or "trailing" in text:
            return "boundary"
        return "other"

    for entry in ranked[:1]:
        add(entry)
    quotas = (("directory", 2), ("deep_partial", 2), ("risk", 2), ("boundary", 1))
    for wanted, count in quotas:
        added = 0
        for entry in ranked:
            if category(entry) != wanted:
                continue
            before = len(selected)
            add(entry)
            if len(selected) > before:
                added += 1
            if added >= count:
                break
    for entry in ranked:
        add(entry)
        if len(selected) >= budget:
            break
    return selected[:budget]


def _scheduler(args: argparse.Namespace) -> RepairScheduler:
    return RepairScheduler({
        "repair": {
            "workspace": str(Path(args.workspace)),
            "max_modules_per_job": max(1, int(getattr(args, "repair_max_modules_per_job", 64) or 64)),
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


def _state_features(record: dict[str, Any], job: RepairJob, batch, round_index: int, previous_actions: list[str], previous_modules: list[str], best_completeness: float, before_state: dict[str, Any] | None = None) -> dict[str, Any]:
    diagnosis = batch.diagnosis if isinstance(batch.diagnosis, dict) else {}
    capability = diagnosis.get("capability_decision") if isinstance(diagnosis.get("capability_decision"), dict) else {}
    source_derivation = record.get("source_derivation") if isinstance(record.get("source_derivation"), dict) else {}
    runtime_state = _runtime_state_summary(before_state or {})
    runtime_features = build_runtime_feature_record(
        job=job,
        candidate=None,
        previous_actions=list(previous_actions),
        previous_modules=list(previous_modules),
        runtime_state_summary=None,
        repair_prior=None,
    )
    return {
        "feature_contract_version": FEATURE_CONTRACT_VERSION,
        "format": job.format or record.get("format"),
        "source_derivation": _compact_source_derivation(source_derivation),
        "round": round_index,
        "previous_actions": list(previous_actions),
        "previous_action_count": len(previous_actions),
        "previous_modules": list(previous_modules),
        "previous_module_count": len(previous_modules),
        "best_runtime_score": float(runtime_state.get("runtime_score", 0.0) or 0.0),
        "state_summary": runtime_state,
        "runtime_state_summary": runtime_state,
        "runtime_context": runtime_features["runtime_context"],
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
    job: RepairJob,
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
    before_runtime_state = _runtime_state_summary(before_state)
    after_runtime_state = _runtime_state_summary(after_state)
    before_oracle_state = _oracle_state_summary(before_state)
    after_oracle_state = _oracle_state_summary(after_state)
    repair_prior = _repair_prior_from_candidate(payload, module_decision, rank)
    runtime_features = build_runtime_feature_record(
        job=job,
        candidate=candidate,
        previous_actions=list(state_features.get("previous_actions") or []),
        previous_modules=list(state_features.get("previous_modules") or []),
        runtime_state_summary=None,
        repair_prior=repair_prior,
    )
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
            "runtime_context": runtime_features["runtime_context"],
            "candidate_proposal": runtime_features["candidate_proposal"],
            "repair_prior_features": runtime_features["repair_prior_features"],
            "before_state": before_runtime_state,
            "after_state": after_runtime_state,
            "oracle_before_state": before_oracle_state,
            "oracle_after_state": after_oracle_state,
            "delta_features": delta_features,
            "candidate": _runtime_candidate_features(payload),
            "oracle_candidate": _oracle_candidate_features(payload),
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
    if _is_zip_positive_progress_exception(record, candidate, verified, before_state or {}, after_state or {}, delta_features or {}, previous_completeness):
        verified["label"] = 2
        verified["status"] = "state_progress"
        verified["progress_reasons"] = _progress_reasons(delta_features or {}, previous_completeness) or ["zip_structural_progress_on_deceptive_profile"]
        verified["completeness"] = max(completeness, float((after_state or {}).get("completeness", 0.0) or 0.0))
    elif _is_zip_hard_negative(record, candidate, verified):
        verified["label"] = -1
        verified["status"] = "hard_negative"
        verified["hard_negative_reasons"] = _zip_hard_negative_reasons(record, candidate, verified)
        verified["completeness"] = 0.0
    elif int(verified.get("label", 0) or 0) <= 0 and int(verified.get("label", 0) or 0) != -1 and _has_state_progress(delta_features or {}, previous_completeness):
        verified["label"] = 2
        verified["status"] = "state_progress"
        verified["progress_reasons"] = _progress_reasons(delta_features or {}, previous_completeness)
        verified["completeness"] = max(completeness, float((after_state or {}).get("completeness", 0.0) or 0.0))
    elif _is_zip_directory_progress(record, verified, before_state or {}, after_state or {}):
        verified["label"] = 2
        verified["status"] = "state_progress"
        verified["progress_reasons"] = ["zip_directory_visible_without_hash_match"]
        verified["completeness"] = max(completeness, float((after_state or {}).get("completeness", 0.0) or 0.0))
    return verified


def _is_zip_positive_progress_exception(
    record: dict[str, Any],
    candidate,
    verified: dict[str, Any],
    before_state: dict[str, Any],
    after_state: dict[str, Any],
    delta_features: dict[str, Any],
    previous_completeness: float,
) -> bool:
    if _normalize_format(str(record.get("material_format") or record.get("format") or "")) != "zip":
        return False
    if not _record_has_hard_negative_oracle(record):
        return False
    if int(verified.get("label", 0) or 0) >= 3:
        return False
    if str(verified.get("status") or "") == "hard_negative" and int(verified.get("wrong_files", 0) or 0) > 0:
        return False
    module = str(getattr(candidate, "module_name", "") or "").lower()
    actions = " ".join(str(action) for action in getattr(candidate, "actions", []) or []).lower()
    text = f"{module} {actions}"
    if any(token in text for token in ("quarantine", "partial_recovery", "deep_partial", "payload", "crc_repair_masks")):
        return False
    structural = any(token in text for token in ("central_directory", "directory", "eocd", "offset", "comment", "descriptor", "trailing", "trim", "boundary"))
    if not structural:
        return False
    if _progress_reasons(delta_features, previous_completeness):
        return True
    if bool(after_state.get("directory_detected")) and not bool(before_state.get("directory_detected")):
        return True
    if int(after_state.get("entry_count", 0) or 0) > int(before_state.get("entry_count", 0) or 0):
        return True
    if bool(after_state.get("boundary_trusted")) and not bool(before_state.get("boundary_trusted")):
        return True
    return False


def _runtime_state_summary(summary: dict[str, Any]) -> dict[str, Any]:
    entry_count = int(summary.get("entry_count", 0) or 0)
    readable_entry_count = int(summary.get("readable_entry_count", 0) or 0)
    directory_detected = bool(summary.get("directory_detected"))
    boundary_trusted = bool(summary.get("boundary_trusted"))
    format_detected = bool(summary.get("format_detected"))
    runtime_score = 0.0
    if format_detected:
        runtime_score += 0.12
    if boundary_trusted:
        runtime_score += 0.18
    if directory_detected:
        runtime_score += 0.25
    if entry_count > 0:
        runtime_score += min(0.20, entry_count / 50.0)
    if readable_entry_count > 0:
        runtime_score += min(0.20, readable_entry_count / max(1, entry_count) * 0.20)
    runtime_status = "unknown"
    if readable_entry_count > 0:
        runtime_status = "readable_entries"
    elif directory_detected or entry_count > 0:
        runtime_status = "directory_visible"
    elif boundary_trusted:
        runtime_status = "boundary_visible"
    elif format_detected:
        runtime_status = "format_visible"
    return {
        "format_detected": format_detected,
        "boundary_trusted": boundary_trusted,
        "directory_detected": directory_detected,
        "entry_count": entry_count,
        "readable_entry_count": readable_entry_count,
        "damage_flags": list(summary.get("damage_flags") or []),
        "runtime_status": runtime_status,
        "runtime_score": max(0.0, min(1.0, runtime_score)),
    }


def _oracle_state_summary(summary: dict[str, Any]) -> dict[str, Any]:
    return {
        "matched_entry_count": int(summary.get("matched_entry_count", 0) or 0),
        "wrong_entry_count": int(summary.get("wrong_entry_count", 0) or 0),
        "completeness": float(summary.get("completeness", 0.0) or 0.0),
    }


def _runtime_candidate_features(payload: dict[str, Any]) -> dict[str, Any]:
    output = {
        key: payload.get(key)
        for key in (
            "module",
            "format",
            "stage",
            "confidence",
            "score_hint",
            "actions",
            "damage_flags",
            "patch_cost",
            "risk_penalty",
            "cost_penalty",
            "evidence_score",
            "benefit_score",
            "requires_native_validation",
            "has_archive_state_plan",
            "requires_materialization",
            "plan_kind",
            "estimated_cost",
            "input_kind",
        )
        if key in payload
    }
    safe_breakdowns = {
        "benefit_breakdown": {"confidence", "score_hint"},
        "evidence_breakdown": {"patch_quality"},
        "cost_breakdown": {"stage", "lazy_materialization", "native_validation", "patch_complexity"},
        "risk_breakdown": {
            "partial_candidate",
            "content_damage",
            "content_damage_without_native_validation",
            "deep_without_native_validation",
        },
    }
    for group, safe_names in safe_breakdowns.items():
        breakdown = payload.get(group)
        if isinstance(breakdown, dict):
            safe_breakdown = _runtime_breakdown_features(breakdown, safe_names)
            if safe_breakdown:
                output[group] = safe_breakdown
    ltr = payload.get("ltr_features")
    if isinstance(ltr, dict):
        output["ltr_features"] = {
            key: ltr.get(key)
            for key in (
                "module",
                "format",
                "stage",
                "confidence",
                "score_hint",
                "benefit_score",
                "evidence_score",
                "cost_penalty",
                "risk_penalty",
                "module_bias",
                "generation_priority",
                "ranking_raw_score",
                "patch_cost",
                "patch_quality",
                "partial",
                "lazy",
                "requires_native_validation",
                "requires_materialization",
                "plan_kind",
                "estimated_cost",
                "has_archive_state_plan",
                "damage_flag_count",
                "action_count",
                "history_available",
                "history_sample_count",
                "history_score",
            )
            if key in ltr
        }
    history = payload.get("history_features")
    if isinstance(history, dict):
        output["history_features"] = {
            key: history.get(key)
            for key in ("available", "sample_count", "attempts", "accepted", "score", "stage", "format", "module")
            if key in history
        }
    return output


def _runtime_breakdown_features(breakdown: dict[str, Any], safe_names: set[str]) -> dict[str, dict[str, Any]]:
    output: dict[str, dict[str, Any]] = {}
    for key, value in breakdown.items():
        if key not in safe_names or not isinstance(value, dict):
            continue
        output[key] = {
            inner_key: inner_value
            for inner_key, inner_value in dict(value or {}).items()
            if inner_key in {"value", "weight", "contribution"}
        }
    return output


def _repair_prior_from_candidate(payload: dict[str, Any], module_decision: dict[str, Any], rank: int) -> RepairPrior:
    return RepairPrior(
        route_score=_optional_float(module_decision.get("route_score")),
        fine_score=_optional_float(module_decision.get("fine_score")),
        generation_priority=_optional_float(payload.get("generation_priority")),
        current_selector_rank=rank,
        module_selected_by_router=bool(module_decision.get("selected")) if "selected" in module_decision else None,
        proposal_breakdowns={
            group: _runtime_breakdown_features(payload.get(group) if isinstance(payload.get(group), dict) else {}, names)
            for group, names in {
                "benefit_breakdown": {"confidence", "score_hint"},
                "evidence_breakdown": {"patch_quality"},
                "cost_breakdown": {"stage", "lazy_materialization", "native_validation", "patch_complexity"},
                "risk_breakdown": {
                    "partial_candidate",
                    "content_damage",
                    "content_damage_without_native_validation",
                    "deep_without_native_validation",
                },
            }.items()
        },
    )


def _optional_float(value: Any) -> float | None:
    if value is None:
        return None
    try:
        return float(value)
    except Exception:
        return None


def _oracle_candidate_features(payload: dict[str, Any]) -> dict[str, Any]:
    return {
        key: payload.get(key)
        for key in (
            "status",
            "native_validation_score",
            "native_validation_strength",
            "predicted_completeness",
            "validation_count",
            "validations",
            "materialized",
        )
        if key in payload
    }


def _is_zip_hard_negative(record: dict[str, Any], candidate, verified: dict[str, Any]) -> bool:
    if _normalize_format(str(record.get("material_format") or record.get("format") or "")) != "zip":
        return False
    label = int(verified.get("label", 0) or 0)
    if label >= 3:
        return False
    if not _record_has_hard_negative_oracle(record):
        return False
    repaired_input = candidate.repaired_input if isinstance(candidate.repaired_input, dict) else {}
    if not Path(str(repaired_input.get("path") or "")).is_file():
        return False
    candidate_status = str(getattr(candidate, "status", "") or "")
    if candidate_status not in {"repaired", "partial"}:
        return False
    profile = str(record.get("damage_profile") or "")
    if profile in {"zip_all_entry_payload_damage_with_directory", "zip_wrong_offset_content_overlap"}:
        return True
    if int(verified.get("wrong_files", 0) or 0) > 0:
        return True
    if _record_has_any_difficulty_tag(record, {"deceptive_structural_success", "hash_mismatch_risk"}):
        matched = int(verified.get("matched_files", 0) or 0)
        expected = int(verified.get("expected_files", 0) or 0)
        entry_count = int(verified.get("entry_count", 0) or 0)
        status = str(verified.get("status") or "")
        if matched > 0 and expected > matched:
            return True
        if status in {"directory_only", "partial"} and entry_count > 0 and matched <= 0:
            return True
        if status == "partial" and matched > 0:
            return True
    return False


def _zip_hard_negative_reasons(record: dict[str, Any], candidate, verified: dict[str, Any]) -> list[str]:
    reasons = ["zip_payload_hash_mismatch_profile"]
    if int(verified.get("wrong_files", 0) or 0) > 0:
        reasons.append("wrong_entry_hash")
    if str(getattr(candidate, "status", "") or "") in {"repaired", "partial"}:
        reasons.append("candidate_claimed_structural_success")
    profile = str(record.get("damage_profile") or "")
    if profile == "zip_wrong_offset_content_overlap":
        reasons.append("wrong_offset_overlap_profile")
    if _record_has_any_difficulty_tag(record, {"deceptive_structural_success"}):
        reasons.append("deceptive_structural_success_profile")
    if _record_has_any_difficulty_tag(record, {"hash_mismatch_risk"}):
        reasons.append("hash_mismatch_risk_profile")
    matched = int(verified.get("matched_files", 0) or 0)
    expected = int(verified.get("expected_files", 0) or 0)
    if matched > 0 and expected > matched:
        reasons.append("partial_output_from_deceptive_profile")
    if str(verified.get("status") or "") == "directory_only":
        reasons.append("directory_visible_without_trusted_payload")
    return reasons


def _is_zip_directory_progress(record: dict[str, Any], verified: dict[str, Any], before_state: dict[str, Any], after_state: dict[str, Any]) -> bool:
    if _normalize_format(str(record.get("material_format") or record.get("format") or "")) != "zip":
        return False
    if int(verified.get("label", 0) or 0) != 0:
        return False
    if str(verified.get("status") or "") not in {"directory_only", "no_progress"}:
        return False
    candidate_progress_status = str((after_state or {}).get("verification_status") or verified.get("status") or "")
    profile = str(record.get("damage_profile") or "")
    if profile == "zip_directory_only_bad_payload" and candidate_progress_status in {"no_progress", "directory_only"}:
        return True
    if int(verified.get("entry_count", 0) or 0) <= 0 and int((after_state or {}).get("entry_count", 0) or 0) <= 0:
        return False
    if int(verified.get("matched_files", 0) or 0) > 0:
        return False
    profile_capability = str(record.get("profile_capability") or "")
    if profile.startswith("zip_") and ("directory" in profile or "eocd" in profile or profile_capability == "structural_partial"):
        return True
    return bool(after_state.get("directory_detected")) and not bool(before_state.get("directory_detected"))


def _record_has_any_damage_flag(record: dict[str, Any], flags: set[str]) -> bool:
    values: set[str] = set()
    for key in ("damage_flags", "expected_damage_flags"):
        raw = record.get(key)
        if isinstance(raw, list):
            values.update(str(item) for item in raw)
    state = record.get("stable_features") if isinstance(record.get("stable_features"), dict) else {}
    if isinstance(state, dict):
        nested = state.get("state") if isinstance(state.get("state"), dict) else {}
        raw = nested.get("damage_flags")
        if isinstance(raw, list):
            values.update(str(item) for item in raw)
    return bool(values.intersection(flags))


def _record_has_any_difficulty_tag(record: dict[str, Any], tags: set[str]) -> bool:
    values: set[str] = set()
    raw = record.get("difficulty_tags")
    if isinstance(raw, list):
        values.update(str(item) for item in raw)
    state = record.get("stable_features") if isinstance(record.get("stable_features"), dict) else {}
    if isinstance(state, dict):
        nested = state.get("state") if isinstance(state.get("state"), dict) else {}
        nested_tags = nested.get("difficulty_tags")
        if isinstance(nested_tags, list):
            values.update(str(item) for item in nested_tags)
    return bool(values.intersection(tags))


def _record_has_hard_negative_oracle(record: dict[str, Any]) -> bool:
    return (
        _record_has_any_damage_flag(record, {"hard_negative_target", "payload_hash_mismatch", "deceptive_structural_success"})
        or _record_has_any_difficulty_tag(record, {"deceptive_structural_success", "hash_mismatch_risk"})
    )


def _record_analysis_evidence(record: dict[str, Any], fmt: str):
    try:
        from types import SimpleNamespace

        return SimpleNamespace(
            format=fmt or record.get("format") or record.get("material_format") or "",
            confidence=0.82,
            status="selected",
        )
    except Exception:
        return None


def _record_analysis_prepass(record: dict[str, Any], fmt: str) -> dict[str, Any]:
    source_derivation = record.get("source_derivation") if isinstance(record.get("source_derivation"), dict) else {}
    return {
        "status": "selected",
        "format": fmt or record.get("format") or record.get("material_format") or "",
        "selected_format": fmt or record.get("format") or record.get("material_format") or "",
        "confidence": 0.82,
        "source_size": int(record.get("source_size") or source_derivation.get("size") or 0),
    }


def _record_fuzzy_profile(record: dict[str, Any], fmt: str) -> dict[str, Any]:
    return {
        "status": "selected",
        "archive_type": fmt or record.get("format") or record.get("material_format") or "",
        "confidence": 0.82,
    }


def _runtime_extraction_failure(record: dict[str, Any], state: dict[str, Any], before_state: dict[str, Any] | None) -> dict[str, Any]:
    before_state = before_state if isinstance(before_state, dict) else {}
    oracle = _record_terminal_or_current_verification(record, before_state)
    hints = oracle.get("repair_hints") if isinstance(oracle.get("repair_hints"), dict) else _runtime_repair_hints(record, state, before_state)
    return {
        "status": "verification_failed" if before_state else "damaged_input",
        "failure_stage": "verification" if before_state else "analysis",
        "failure_kind": str(oracle.get("failure_kind") or ""),
        "assessment_status": oracle.get("assessment_status"),
        "source_integrity": oracle.get("source_integrity"),
        "decision_hint": oracle.get("decision_hint"),
        "completeness": oracle.get("completeness"),
        "recoverable_upper_bound": oracle.get("recoverable_upper_bound"),
        "complete_files": oracle.get("complete_files"),
        "partial_files": oracle.get("partial_files"),
        "failed_files": oracle.get("failed_files"),
        "missing_files": oracle.get("missing_files"),
        "unverified_files": oracle.get("unverified_files"),
        "archive_coverage": dict(oracle.get("archive_coverage") or {}),
        "repair_hints": hints,
        "error": str(oracle.get("error") or "repair required") if str(oracle.get("assessment_status") or "") not in {"complete", "accepted"} else "",
    }


def _runtime_extraction_diagnostics(record: dict[str, Any], state: dict[str, Any]) -> dict[str, Any]:
    explicit = state.get("runtime_extraction_diagnostics")
    if isinstance(explicit, dict):
        return dict(explicit)
    runtime_verification = state.get("runtime_verification") if isinstance(state.get("runtime_verification"), dict) else {}
    native_status = "success" if str(runtime_verification.get("assessment_status") or "") == "complete" else "crc_error"
    return {
        "failure_stage": "verification",
        "failure_kind": "",
        "result": {
            "native_status": native_status,
            "files_written": 0,
            "bytes_written": 0,
        },
    }


def _record_terminal_or_current_verification(record: dict[str, Any], before_state: dict[str, Any]) -> dict[str, Any]:
    runtime_verification = before_state.get("runtime_verification") if isinstance(before_state.get("runtime_verification"), dict) else {}
    if runtime_verification:
        return dict(runtime_verification)
    completeness = float(before_state.get("completeness", 0.0) or 0.0)
    entry_count = int(before_state.get("entry_count", 0) or 0)
    matched = int(before_state.get("matched_entry_count", 0) or 0)
    wrong = int(before_state.get("wrong_entry_count", 0) or 0)
    expected = _expected_file_count(record)
    failed = max(0, expected - matched)
    status = "complete" if completeness >= 0.999 else ("partial" if matched > 0 else "failed")
    decision = "accept" if status == "complete" else ("accept_partial" if status == "partial" else "repair")
    source_integrity = "payload_damaged" if wrong > 0 else ("damaged" if completeness < 0.999 else "trusted")
    return {
        "assessment_status": status,
        "source_integrity": source_integrity,
        "decision_hint": decision,
        "completeness": completeness,
        "recoverable_upper_bound": 1.0,
        "complete_files": matched,
        "partial_files": max(0, entry_count - matched - wrong),
        "failed_files": failed,
        "missing_files": 0,
        "unverified_files": max(0, entry_count - matched - wrong),
        "archive_coverage": {
            "completeness": completeness,
            "expected_files": expected,
            "complete_files": matched,
            "partial_files": max(0, entry_count - matched - wrong),
            "failed_files": failed,
            "missing_files": 0,
        },
    }


def _expected_file_count(record: dict[str, Any]) -> int:
    oracle = record.get("oracle") if isinstance(record.get("oracle"), dict) else {}
    expected = oracle.get("expected_files")
    if isinstance(expected, list):
        return len(expected)
    if isinstance(expected, dict):
        return len(expected)
    try:
        return int(oracle.get("expected_file_count") or 0)
    except Exception:
        return 0


def _runtime_repair_hints(record: dict[str, Any], state: dict[str, Any], before_state: dict[str, Any]) -> dict[str, Any]:
    flags = set(str(item) for item in (state.get("damage_flags") or record.get("damage_flags") or []))
    fmt = str(record.get("format") or record.get("material_format") or "")
    return {
        "selected_format": fmt,
        "analysis_status": "selected",
        "analysis_confidence": 0.82,
        "source_integrity": "payload_damaged" if "payload_damaged" in flags or "data_error" in flags else "damaged",
        "likely_truncated": bool(flags.intersection({"truncated", "input_truncated", "probably_truncated"})),
        "likely_payload_damage": bool(flags.intersection({"payload_damaged", "data_error", "checksum_error"})),
        "boundary_untrusted": bool(flags.intersection({"trailing_junk", "boundary_unreliable"})) or not bool(before_state.get("boundary_trusted", True)),
    }


def _failure_kind_from_flags(flags: list[str]) -> str:
    values = set(str(item) for item in flags)
    if values.intersection({"truncated", "input_truncated", "probably_truncated"}):
        return "truncated"
    if values.intersection({"payload_damaged", "data_error", "checksum_error"}):
        return "payload_damaged"
    if values.intersection({"trailing_junk", "boundary_unreliable"}):
        return "boundary"
    return "damaged"



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
        "source_path": str(path) if path else "",
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
            if wrong_overlap:
                return {**_label_status(-1, "hard_negative", 0.0), "matched_files": matched, "wrong_files": wrong_files, "unreadable_files": unreadable_files, "entry_count": entry_count, "expected_files": len(expected_files)}
            if completeness > 0:
                return {**_label_status(1, "partial", completeness), "matched_files": matched, "wrong_files": wrong_files, "unreadable_files": unreadable_files, "entry_count": entry_count, "expected_files": len(expected_files)}
            status = "directory_only" if entry_count else "no_progress"
            return {**_label_status(0, status, 0.0), "matched_files": matched, "wrong_files": wrong_files, "unreadable_files": unreadable_files, "entry_count": entry_count, "expected_files": len(expected_files)}
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
    runtime_context = state_features.get("runtime_context") if isinstance(state_features.get("runtime_context"), dict) else {}
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
        "stable_features": {
            "state": state_features,
            "runtime_context": runtime_context,
            "candidate_proposal": {},
            "repair_prior_features": {},
            "candidate": {},
        },
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
        "stable_features": {"state": {"format": record.get("format"), "damage_profile": record.get("damage_profile"), "difficulty_tags": list(record.get("difficulty_tags") or []), "source_derivation": _compact_source_derivation(source_derivation)}, "candidate": {}},
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
        "diagnosis_status": diagnosis.get("status"),
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
