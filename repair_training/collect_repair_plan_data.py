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
from collections import Counter, defaultdict
from pathlib import Path
from typing import Any

REPO_ROOT = Path(__file__).resolve().parents[1]
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

from sunpack.repair import RepairJob, RepairResult, RepairScheduler
from sunpack.repair.candidate import CandidateSelector, candidate_feature_payload, materialize_candidate
from sunpack.repair.context import zip_route_evidence_flags
from sunpack.contracts.archive_state import ArchiveState
from sunpack.contracts.detection import FactBag
from sunpack.contracts.tasks import ArchiveTask
from sunpack.extraction.result import ExtractionResult
from sunpack.support.archive_state_view import archive_state_to_bytes
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
        "no_output_reason_counts": {},
        "route_rejected_by_required_flags": 0,
        "route_rejected_by_can_handle": 0,
        "native_target_mismatch_counts": {},
        "no_output_by_atomic_family": {},
        "route_evidence_flag_counts": {},
        "selected_by_route_evidence": {},
        "residual_flag_counts": {},
        "no_candidates_by_missing_evidence_profile": {},
        "no_output_by_patch_fact": {},
        "native_target_mismatch_by_profile": {},
        "no_candidate_by_native_target": {},
        "validation_failed_by_profile": {},
        "post_crop_no_candidates_by_profile": {},
        "post_crop_residual_fact_counts": {},
        "split_logical_stream_counts": {},
        "split_sidecar_route_counts": {},
        "split_sidecar_complete_candidate_counts": {},
        "extra_field_length_candidate_counts": {},
        "zip64_extra_no_candidate_by_profile": {},
        "descriptor_cd_conflict_diff_buckets": {},
        "legacy_module_seen_count": 0,
        "rollout_budget_exhausted": 0,
        "best_recovery_bucket_counts": {},
        "stop_reason_counts": {},
        "global_stagnation_counts": {},
        "best_partial_returned_count": 0,
        "repair_cache_hits": 0,
        "repair_cache_misses": 0,
        "repair_cache_by_namespace": {},
        "materialize_cache_hits": 0,
        "native_operation_cache_hits": 0,
        "success_output": str(success_output),
        "failure_output": str(failure_output),
        "collector_shard": args.collector_shard,
        "collector_workers": args.collector_workers,
        "sample_execution_mode": args.sample_execution_mode,
        "sample_worker_count": _sample_worker_count(args),
        "workspace": args.workspace,
    }
    started_all = time.perf_counter()
    last_progress = started_all
    debug_events = _DebugEvents(Path(args.debug_events) if args.debug_events else None)
    mode = "a" if args.append else "w"
    with success_output.open(mode, encoding="utf-8") as success_handle, failure_output.open(mode, encoding="utf-8") as failure_handle:
        results = (
            _collect_records_worker_pool(records, args, debug_events, started_all)
            if str(args.sample_execution_mode or "") == "worker_pool"
            else _collect_records_serial(records, args, debug_events, started_all)
        )
        for result in sorted(results, key=lambda item: int(item.get("record_index", 0) or 0)):
            record = result["record"]
            rows = list(result.get("rows") or [])
            status = str(result.get("status") or "")
            if status == "skipped" and not rows:
                summary["skipped"] += 1
                continue
            elapsed = float(result.get("elapsed_seconds", 0.0) or 0.0)
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
            summary["skipped"] += 1 if status.startswith("skipped") else 0
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
    parser.add_argument("--sample-execution-mode", choices=("process_per_sample", "worker_pool", "inprocess"), default="worker_pool", help="How samples are executed. worker_pool reuses long-lived worker processes; process_per_sample preserves the old isolated timeout model.")
    parser.add_argument("--sample-worker-count", type=int, default=0, help="Worker processes used by --sample-execution-mode worker_pool. 0 chooses a conservative default from collector settings.")
    parser.add_argument("--append", action="store_true", help="Append instead of overwriting output files.")
    parser.set_defaults(pretty=True)
    parser.add_argument("--pretty", action="store_true", help="Also write formatted .pretty.json files. Enabled by default.")
    parser.add_argument("--no-pretty", action="store_false", dest="pretty", help="Only write compact JSONL.")
    parser.add_argument("--limit", type=int, default=0, help="Collect at most N manifest records.")
    parser.add_argument("--max-rounds", type=int, default=8, help="Maximum repair rounds per damaged sample.")
    parser.add_argument("--rollout-mode", choices=("greedy", "greedy_current_selector", "beam", "counterfactual"), default="beam", help="Repair-state rollout strategy for multi-step training collection.")
    parser.add_argument("--beam-size", type=int, default=8, help="Maximum active next states retained per rollout depth.")
    parser.add_argument("--branch-top-k", type=int, default=5, help="Maximum branch candidates advanced from one state in beam/counterfactual mode.")
    parser.add_argument("--counterfactual-extra", type=int, default=2, help="Additional risky/high-value branches considered in counterfactual mode.")
    parser.add_argument("--max-total-states-per-sample", type=int, default=80, help="Hard cap on states created for one damaged sample, including the root state.")
    parser.add_argument("--rollout-min-improvement", type=float, default=0.01, help="Minimum global recovery improvement needed to reset rollout stagnation patience.")
    parser.add_argument("--rollout-stagnation-patience", type=int, default=3, help="Stop a sample after this many rollout rounds without global best recovery improvement. Use 0 to disable.")
    parser.add_argument("--future-label-discount", type=float, default=0.8, help="Discount used when backfilling future labels from descendant states.")
    parser.add_argument("--rl-discount", type=float, default=0.95, help="Discount used for offline RL future_return backfill.")
    parser.add_argument("--rl-step-cost", type=float, default=0.01, help="Per-action cost subtracted from offline RL rewards.")
    parser.add_argument("--rl-no-output-penalty", type=float, default=0.05, help="Penalty applied to no-output/dead-end actions for offline RL evaluation.")
    parser.add_argument("--rl-hard-negative-penalty", type=float, default=0.10, help="Penalty applied to hard-negative actions for offline RL evaluation.")
    parser.add_argument("--max-candidates-per-round", type=int, default=10, help="Maximum candidates logged per round.")
    parser.add_argument("--proposal-mode", choices=("lazy", "eager"), default="lazy", help="Use lazy repair plans or eager repair execution while collecting candidates.")
    parser.add_argument("--materialize-top-k-per-round", type=int, default=10, help="Materialize at most K pre-ranked candidates per round in lazy proposal mode.")
    parser.add_argument("--max-expensive-materializations-per-round", type=int, default=3, help="For ZIP lazy collection, materialize at most this many high-cost full-rewrite candidates per round. Use 0 to disable the cap.")
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
    parser.add_argument("--disable-repair-cache", action="store_true", help="Disable per-worker repair materialization/native operation cache.")
    parser.add_argument("--profile-materialization-candidates", action="store_true", help="Emit one debug event per materialized candidate for hotspot profiling.")
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
        module_name = str(row.get("module") or row.get("module_name") or "")
        if module_name in _LEGACY_ZIP_MODULE_NAMES:
            summary["legacy_module_seen_count"] = int(summary.get("legacy_module_seen_count", 0) or 0) + 1
        if row.get("row_type") == "terminal":
            terminal_counts = summary.setdefault("terminal_status_counts", {})
            terminal_status = str(row.get("terminal_status") or row.get("label_status") or "unknown")
            terminal_counts[terminal_status] = int(terminal_counts.get(terminal_status, 0) or 0) + 1
            stop_counts = summary.setdefault("stop_reason_counts", {})
            stop_counts[terminal_status] = int(stop_counts.get(terminal_status, 0) or 0) + 1
            bucket = _recovery_bucket(float(row.get("best_recovery_ratio", row.get("terminal_recovery_ratio", 0.0)) or 0.0))
            bucket_counts = summary.setdefault("best_recovery_bucket_counts", {})
            bucket_counts[bucket] = int(bucket_counts.get(bucket, 0) or 0) + 1
            if terminal_status == "global_recovery_stagnation":
                key = str(row.get("rounds_without_improvement") or 0)
                stagnation_counts = summary.setdefault("global_stagnation_counts", {})
                stagnation_counts[key] = int(stagnation_counts.get(key, 0) or 0) + 1
            if terminal_status != "complete" and float(row.get("best_recovery_ratio", 0.0) or 0.0) > 0.0:
                summary["best_partial_returned_count"] = int(summary.get("best_partial_returned_count", 0) or 0) + 1
            if terminal_status == "no_candidates":
                profile = _record_damage_profile(record)
                counts = summary.setdefault("no_candidates_by_missing_evidence_profile", {})
                counts[profile] = int(counts.get(profile, 0) or 0) + 1
                if "after_archive_carrier_crop" in set(row.get("repair_history_flags") or row.get("path_actions") or []):
                    counts = summary.setdefault("post_crop_no_candidates_by_profile", {})
                    counts[profile] = int(counts.get(profile, 0) or 0) + 1
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
        if status == "no_output":
            details = row.get("label_details") if isinstance(row.get("label_details"), dict) else {}
            reason = str(row.get("no_output_reason") or details.get("no_output_reason") or "unknown")
            reason_counts = summary.setdefault("no_output_reason_counts", {})
            reason_counts[reason] = int(reason_counts.get(reason, 0) or 0) + 1
            module = str(row.get("module") or row.get("module_name") or "unknown")
            module_counts = summary.setdefault("no_output_by_module", {})
            module_counts[module] = int(module_counts.get(module, 0) or 0) + 1
            family = str(row.get("route_family") or (row.get("stable_features", {}).get("candidate", {}) if isinstance(row.get("stable_features"), dict) else {}).get("route_family") or module or "unknown")
            family_counts = summary.setdefault("no_output_by_atomic_family", {})
            family_counts[family] = int(family_counts.get(family, 0) or 0) + 1
            profile = _record_damage_profile(record)
            profile_counts = summary.setdefault("no_output_by_damage_profile", {})
            profile_counts[profile] = int(profile_counts.get(profile, 0) or 0) + 1
            native_target = str(row.get("native_target") or "unknown")
            target_counts = summary.setdefault("no_candidate_by_native_target", {})
            target_counts[native_target] = int(target_counts.get(native_target, 0) or 0) + 1
        candidate_payload = row.get("debug_features", {}).get("candidate_features", {}) if isinstance(row.get("debug_features"), dict) else {}
        if bool(row.get("native_target_mismatch") or candidate_payload.get("native_target_mismatch")):
            key = str(row.get("module") or row.get("module_name") or "unknown")
            mismatch_counts = summary.setdefault("native_target_mismatch_counts", {})
            mismatch_counts[key] = int(mismatch_counts.get(key, 0) or 0) + 1
            profile = _record_damage_profile(record)
            profile_counts = summary.setdefault("native_target_mismatch_by_profile", {})
            profile_counts[profile] = int(profile_counts.get(profile, 0) or 0) + 1
        patch_facts = [str(item) for item in row.get("patch_facts") or candidate_payload.get("patch_facts") or []]
        if status == "no_output":
            for fact in patch_facts or ["none"]:
                counts = summary.setdefault("no_output_by_patch_fact", {})
                counts[fact] = int(counts.get(fact, 0) or 0) + 1
        candidate_status = str(row.get("candidate_status") or candidate_payload.get("candidate_status") or "")
        if candidate_status == "validation_failed":
            profile = _record_damage_profile(record)
            counts = summary.setdefault("validation_failed_by_profile", {})
            counts[profile] = int(counts.get(profile, 0) or 0) + 1
        residual_facts = [str(item) for item in row.get("residual_facts") or candidate_payload.get("residual_facts") or []]
        if "after_archive_carrier_crop" in set(patch_facts):
            for fact in residual_facts or ["none"]:
                counts = summary.setdefault("post_crop_residual_fact_counts", {})
                counts[fact] = int(counts.get(fact, 0) or 0) + 1
        if bool(row.get("split_sidecars_available") or candidate_payload.get("split_sidecars_available")) and int(row.get("label", 0) or 0) == 3:
            key = str(row.get("module") or row.get("module_name") or "unknown")
            counts = summary.setdefault("split_sidecar_complete_candidate_counts", {})
            counts[key] = int(counts.get(key, 0) or 0) + 1
        if bool(row.get("split_sidecars_available") or candidate_payload.get("split_sidecars_available")):
            key = "logical_stream_built" if bool(row.get("logical_stream_built") or candidate_payload.get("logical_stream_built")) else "logical_stream_missing"
            counts = summary.setdefault("split_logical_stream_counts", {})
            counts[key] = int(counts.get(key, 0) or 0) + 1
            module_key = str(row.get("module") or row.get("module_name") or "unknown")
            route_counts = summary.setdefault("split_sidecar_route_counts", {})
            route_counts[module_key] = int(route_counts.get(module_key, 0) or 0) + 1
        if str(row.get("module") or row.get("module_name") or "") == "zip_fix_extra_field_length":
            key = str(row.get("label_status") or row.get("terminal_status") or status or "unknown")
            counts = summary.setdefault("extra_field_length_candidate_counts", {})
            counts[key] = int(counts.get(key, 0) or 0) + 1
        if str(row.get("module") or row.get("module_name") or "") == "zip_fix_zip64_extra_size" and status == "no_output":
            profile = _record_damage_profile(record)
            counts = summary.setdefault("zip64_extra_no_candidate_by_profile", {})
            counts[profile] = int(counts.get(profile, 0) or 0) + 1
        route_evidence = [str(item) for item in row.get("route_evidence_flags") or []]
        route_evidence_lower = {item.lower() for item in route_evidence}
        for flag in route_evidence:
            counts = summary.setdefault("route_evidence_flag_counts", {})
            counts[flag] = int(counts.get(flag, 0) or 0) + 1
        residual_flags = [str(item) for item in row.get("residual_damage_flags") or []]
        for flag in residual_flags:
            counts = summary.setdefault("residual_flag_counts", {})
            counts[flag] = int(counts.get(flag, 0) or 0) + 1
        matched_route_flags = {str(item).lower() for item in row.get("route_required_flags_matched") or []}
        if route_evidence_lower & matched_route_flags:
            key = str(row.get("module") or row.get("module_name") or "unknown")
            counts = summary.setdefault("selected_by_route_evidence", {})
            counts[key] = int(counts.get(key, 0) or 0) + 1
        decision = row.get("debug_features", {}).get("module_decision", {}) if isinstance(row.get("debug_features"), dict) else {}
        decision_reasons = set(decision.get("reasons") or []) if isinstance(decision, dict) else set()
        if "route_required_flags_unmet" in decision_reasons:
            summary["route_rejected_by_required_flags"] = int(summary.get("route_rejected_by_required_flags", 0) or 0) + 1
        if "can_handle_rejected" in decision_reasons:
            summary["route_rejected_by_can_handle"] = int(summary.get("route_rejected_by_can_handle", 0) or 0) + 1
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
    rollout_summary = next((row.get("rollout_summary") for row in rows if isinstance(row.get("rollout_summary"), dict)), {})
    _merge_repair_cache_summary(summary, rollout_summary.get("repair_cache") if isinstance(rollout_summary, dict) else {})
    _merge_materialization_summary(summary, rollout_summary.get("materialization") if isinstance(rollout_summary, dict) else {})
    oracle = record.get("oracle") if isinstance(record.get("oracle"), dict) else {}
    oracle_strength = str(record.get("oracle_strength") or oracle.get("oracle_strength") or "unknown")
    oracle_counts = summary.setdefault("oracle_strength_counts", {})
    oracle_counts[oracle_strength] = int(oracle_counts.get(oracle_strength, 0) or 0) + 1
    layer = str(record.get("actual_damage_layer") or record.get("damage_layer") or "unknown")
    layer_counts = summary.setdefault("damage_layer_counts", {})
    layer_counts[layer] = int(layer_counts.get(layer, 0) or 0) + 1


def _merge_repair_cache_summary(summary: dict[str, Any], cache_stats: Any) -> None:
    if not isinstance(cache_stats, dict):
        return
    hits = int(cache_stats.get("hits", 0) or 0)
    misses = int(cache_stats.get("misses", 0) or 0)
    summary["repair_cache_hits"] = int(summary.get("repair_cache_hits", 0) or 0) + hits
    summary["repair_cache_misses"] = int(summary.get("repair_cache_misses", 0) or 0) + misses
    by_namespace = summary.setdefault("repair_cache_by_namespace", {})
    for namespace, counts in (cache_stats.get("by_namespace") or {}).items():
        if not isinstance(counts, dict):
            continue
        target = by_namespace.setdefault(str(namespace), {"hits": 0, "misses": 0})
        target["hits"] = int(target.get("hits", 0) or 0) + int(counts.get("hits", 0) or 0)
        target["misses"] = int(target.get("misses", 0) or 0) + int(counts.get("misses", 0) or 0)
        if str(namespace) == "materialize_candidate":
            summary["materialize_cache_hits"] = int(summary.get("materialize_cache_hits", 0) or 0) + int(counts.get("hits", 0) or 0)
        elif str(namespace) == "zip_scan_artifact":
            summary["zip_scan_artifact_hits"] = int(summary.get("zip_scan_artifact_hits", 0) or 0) + int(counts.get("hits", 0) or 0)
            summary["zip_scan_artifact_misses"] = int(summary.get("zip_scan_artifact_misses", 0) or 0) + int(counts.get("misses", 0) or 0)
        elif str(namespace).startswith("native_"):
            summary["native_operation_cache_hits"] = int(summary.get("native_operation_cache_hits", 0) or 0) + int(counts.get("hits", 0) or 0)


def _merge_materialization_summary(summary: dict[str, Any], materialization: Any) -> None:
    if not isinstance(materialization, dict):
        return
    summary["expensive_materialization_skipped_count"] = int(summary.get("expensive_materialization_skipped_count", 0) or 0) + int(materialization.get("expensive_materialization_skipped_count", 0) or 0)
    summary["materialize_worker_seconds_saved_estimate"] = round(
        float(summary.get("materialize_worker_seconds_saved_estimate", 0.0) or 0.0)
        + float(materialization.get("materialize_worker_seconds_saved_estimate", 0.0) or 0.0),
        3,
    )
    target = summary.setdefault("materialize_cost_bucket_counts", {})
    for bucket, count in (materialization.get("materialize_cost_bucket_counts") or {}).items():
        target[str(bucket)] = int(target.get(str(bucket), 0) or 0) + int(count or 0)


_LEGACY_ZIP_MODULE_NAMES = {
    "zip_fix_boundary",
    "zip_fix_pointers",
    "zip_fix_zip64",
    "zip_rebuild",
    "zip_salvage",
    "zip_resolve_conflicts",
}


def _recovery_bucket(value: float) -> str:
    ratio = max(0.0, min(1.0, float(value or 0.0)))
    if ratio >= 0.999:
        return "1.00"
    if ratio <= 0.0:
        return "0.00"
    if ratio < 0.25:
        return "0.00-0.25"
    if ratio < 0.50:
        return "0.25-0.50"
    if ratio < 0.75:
        return "0.50-0.75"
    return "0.75-1.00"


def _record_damage_profile(record: dict[str, Any]) -> str:
    profile = str(record.get("damage_profile") or "").strip()
    if profile:
        return profile
    sample_id = str(record.get("sample_id") or "")
    tail = sample_id.rsplit("__", 1)[-1] if "__" in sample_id else sample_id
    if tail:
        parts = tail.rsplit("_", 1)
        if len(parts) == 2 and parts[1].isdigit():
            return parts[0]
        return tail
    return "unknown"


def _is_zip_partial_first_record(record: dict[str, Any]) -> bool:
    profile = _record_damage_profile(record)
    flags = {str(item) for item in record.get("damage_flags") or []}
    if profile.endswith("zip_split_tail_volume_truncated") or profile == "zip_split_tail_volume_truncated":
        return True
    if _normalize_format(str(record.get("material_format") or record.get("format") or "")) != "zip":
        return False
    return bool(flags & {"missing_volume", "input_truncated", "unexpected_end", "stream_truncated"})


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


def _sample_worker_count(args: argparse.Namespace) -> int:
    explicit = int(getattr(args, "sample_worker_count", 0) or 0)
    if explicit > 0:
        return explicit
    if int(getattr(args, "collector_shard", -1) or -1) >= 0:
        return 1
    return max(1, int(getattr(args, "collector_workers", 1) or 1))


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
    if _is_zip_high_recovery_competition_record(record):
        return max(base, 8)
    return base


def _is_zip_high_recovery_competition_record(record: dict[str, Any]) -> bool:
    if _normalize_format(str(record.get("material_format") or record.get("format") or "")) != "zip":
        return False
    profile = str(record.get("damage_profile") or "")
    return profile in {
        "zip_wrong_local_offset_extracts_valid_other_entry",
        "zip_eocd_cd_half_damaged",
        "zip_quarantine_keeps_corrupted_entry",
        "zip_drop_central_directory_keep_local_headers",
        "zip_rebuild_directory_keeps_bad_payload",
        "zip_partial_recovery_wrong_hash_same_name",
        "zip_single_entry_payload_damage",
        "zip_local_header_crc_wrong_cd_correct",
        "zip_partial_cd_rebuild_then_payload_mismatch",
        "zip_drop_central_directory_keep_local_headers",
        "zip_sfx_cd_damage",
        "zip_sfx_payload_damage",
        "zip_sfx_split_missing_volume",
        "zip_split_missing_middle_volume",
        "zip_zip64_extra_size_mismatch",
    }


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


def _attach_split_volumes(source_input: dict[str, Any], record: dict[str, Any]) -> None:
    tags = record.get("zip_container_tags") or []
    profile_text = " ".join(str(record.get(key) or "") for key in ("damage_profile", "sample_id", "source_archive_id", "zip_variant")).lower()
    split_hint = bool(
        (isinstance(tags, list) and ("split" in tags or "multi_volume" in tags or "split_archive" in tags))
        or "split" in profile_text
        or isinstance(record.get("zip_split"), dict)
    )
    if not split_hint:
        return
    volumes: list[dict[str, Any]] = []
    split_payload = record.get("zip_split")
    if isinstance(split_payload, dict):
        for item in split_payload.get("volumes") or []:
            if isinstance(item, dict) and item.get("path"):
                volumes.append(dict(item))
    # .volumes/ dir is next to the SOURCE archive, not the damaged file copy
    source_path = record.get("source_path") or ""
    source_name = record.get("source_archive_name") or ""
    if source_path:
        source_archive = Path(source_path)
    elif source_name:
        # Reconstruct: material/zip/<sample>/<source_archive_name>
        material_sample = record.get("material_sample_id") or ""
        material_format = record.get("material_format") or "zip"
        source_archive = Path("repair_training") / "material" / material_format / material_sample / source_name
    else:
        source_archive = None
    volumes_dir = source_archive.parent / (source_archive.name + ".volumes") if source_archive is not None else None
    if volumes_dir is not None and volumes_dir.is_dir():
        for vol in sorted(volumes_dir.iterdir()):
            if not vol.is_file():
                continue
            volumes.append({"path": str(vol.resolve()), "role": "volume"})
    if not volumes:
        return
    source_input["parts"] = source_input.get("parts") or []
    source_input["ranges"] = source_input.get("ranges") or []
    source_input["use_parts_only"] = True
    existing = {str(p.get("path", "")) for p in source_input.get("parts", []) if isinstance(p, dict)}
    def volume_sort_key(item: dict[str, Any]) -> tuple[int, str]:
        try:
            return (int(item.get("index") or item.get("volume_number") or 0), str(item.get("path") or ""))
        except Exception:
            return (0, str(item.get("path") or ""))
    for vol in sorted(volumes, key=volume_sort_key):
        vol_path = str(Path(str(vol.get("path") or "")).resolve())
        if vol_path not in existing:
            source_input["parts"].append({"path": vol_path, "role": "volume"})
            source_input["ranges"].append({"path": vol_path, "start": 0, "end": None})


def _collect_records_serial(records: list[dict[str, Any]], args: argparse.Namespace, debug_events: "_DebugEvents", started_all: float) -> list[dict[str, Any]]:
    results: list[dict[str, Any]] = []
    last_progress = started_all
    total_records = len(records)
    for record_index, record in enumerate(records, start=1):
        total_timeout = float(args.total_timeout_seconds or 0)
        if total_timeout > 0 and time.perf_counter() - started_all > total_timeout:
            debug_events.write("total_timeout", record, record_index=record_index, total_records=total_records, elapsed_seconds=round(time.perf_counter() - started_all, 3))
            break
        idle_timeout = float(args.idle_timeout_seconds or 0)
        if idle_timeout > 0 and time.perf_counter() - last_progress > idle_timeout:
            debug_events.write("idle_timeout", record, record_index=record_index, total_records=total_records, idle_seconds=round(time.perf_counter() - last_progress, 3))
            break
        skipped = _skipped_sample_result(record, args, debug_events, record_index, total_records)
        if skipped is not None:
            results.append(skipped)
            last_progress = time.perf_counter()
            continue
        if args.progress:
            print(f"START {record_index}/{total_records} {record.get('sample_id')} fmt={record.get('material_format') or record.get('format')} source={record.get('source_archive_name')}", flush=True)
        debug_events.write("sample_start", record, record_index=record_index, total_records=total_records)
        started = time.perf_counter()
        status, rows = (
            _collect_sample(record, args, debug_events)
            if str(args.sample_execution_mode or "") == "inprocess"
            else _collect_sample_with_timeout(record, args, debug_events, record_index, total_records)
        )
        elapsed = round(time.perf_counter() - started, 3)
        last_progress = time.perf_counter()
        if args.progress:
            print(f"END {record.get('sample_id')} status={status} rows={len(rows)} elapsed={elapsed}s", flush=True)
        debug_events.write("sample_end", record, record_index=record_index, total_records=total_records, status=status, rows=len(rows), elapsed_seconds=elapsed)
        results.append({"record_index": record_index, "record": record, "status": status, "rows": rows, "elapsed_seconds": elapsed})
    return results


def _skipped_sample_result(record: dict[str, Any], args: argparse.Namespace, debug_events: "_DebugEvents", record_index: int, total_records: int) -> dict[str, Any] | None:
    if record.get("status") == "skipped":
        return {"record_index": record_index, "record": record, "status": "skipped", "rows": [], "elapsed_seconds": 0.0}
    if args.skip_large_stream_samples and _is_large_stream_sample(record, args):
        row = _terminal_row(record, "skipped_budget", "large stream sample skipped by collect budget")
        debug_events.write("sample_skipped_budget", record, record_index=record_index, total_records=total_records, budget=_sample_budget(record, args))
        return {"record_index": record_index, "record": record, "status": "skipped_budget", "rows": [row], "elapsed_seconds": 0.0}
    return None


def _collect_records_worker_pool(records: list[dict[str, Any]], args: argparse.Namespace, debug_events: "_DebugEvents", started_all: float) -> list[dict[str, Any]]:
    total_records = len(records)
    worker_count = min(max(1, _sample_worker_count(args)), max(1, total_records))
    if worker_count <= 1 and float(args.case_timeout_seconds or 0) <= 0:
        pool_args = argparse.Namespace(**vars(args))
        pool_args.sample_execution_mode = "inprocess"
        return _collect_records_serial(records, pool_args, debug_events, started_all)

    results: list[dict[str, Any]] = []
    pending: list[tuple[int, dict[str, Any]]] = []
    for record_index, record in enumerate(records, start=1):
        skipped = _skipped_sample_result(record, args, debug_events, record_index, total_records)
        if skipped is not None:
            results.append(skipped)
        else:
            pending.append((record_index, record))
    if not pending:
        return results

    ctx = mp.get_context("spawn")
    result_queue = ctx.Queue()
    workers: dict[int, dict[str, Any]] = {}
    free_workers: list[int] = []

    def start_worker(worker_id: int) -> None:
        task_queue = ctx.Queue(maxsize=1)
        process = ctx.Process(target=_collect_pool_worker, args=(worker_id, args, task_queue, result_queue), daemon=True)
        process.start()
        workers[worker_id] = {"process": process, "queue": task_queue, "current": None}
        free_workers.append(worker_id)

    for worker_id in range(worker_count):
        start_worker(worker_id)

    next_task = 0
    completed = 0
    last_progress = started_all
    heartbeat_last: dict[int, float] = {}
    try:
        while completed < len(pending):
            now = time.perf_counter()
            total_timeout = float(args.total_timeout_seconds or 0)
            if total_timeout > 0 and now - started_all > total_timeout:
                record = pending[next_task][1] if next_task < len(pending) else pending[-1][1]
                debug_events.write("total_timeout", record, total_records=total_records, elapsed_seconds=round(now - started_all, 3))
                break
            idle_timeout = float(args.idle_timeout_seconds or 0)
            if idle_timeout > 0 and now - last_progress > idle_timeout:
                record = pending[next_task][1] if next_task < len(pending) else pending[-1][1]
                debug_events.write("idle_timeout", record, total_records=total_records, idle_seconds=round(now - last_progress, 3))
                break
            while free_workers and next_task < len(pending):
                worker_id = free_workers.pop(0)
                entry = workers.get(worker_id)
                if not entry or not entry["process"].is_alive():
                    start_worker(worker_id)
                    entry = workers[worker_id]
                    free_workers.remove(worker_id)
                record_index, record = pending[next_task]
                next_task += 1
                if args.progress:
                    print(f"START {record_index}/{total_records} {record.get('sample_id')} worker={worker_id} fmt={record.get('material_format') or record.get('format')} source={record.get('source_archive_name')}", flush=True)
                debug_events.write("sample_start", record, record_index=record_index, total_records=total_records, worker_id=worker_id)
                entry["current"] = {"record_index": record_index, "record": record, "started": time.perf_counter()}
                heartbeat_last[worker_id] = time.perf_counter()
                entry["queue"].put({"record_index": record_index, "total_records": total_records, "record": record})

            try:
                message = result_queue.get(timeout=0.05)
            except Exception:
                message = None
            if isinstance(message, dict):
                if message.get("message_type") == "debug_event":
                    payload = message.get("payload")
                    if isinstance(payload, dict):
                        debug_events.write_payload(payload)
                    continue
                worker_id = int(message.get("worker_id", -1))
                entry = workers.get(worker_id)
                current = entry.get("current") if entry else None
                record = message.get("record") or (current or {}).get("record") or {}
                record_index = int(message.get("record_index") or (current or {}).get("record_index") or 0)
                rows = list(message.get("rows") or [])
                status = str(message.get("status") or "failed")
                elapsed = round(float(message.get("elapsed_seconds") or 0.0), 3)
                results.append({"record_index": record_index, "record": record, "status": status, "rows": rows, "elapsed_seconds": elapsed})
                debug_events.write("sample_end", record, record_index=record_index, total_records=total_records, worker_id=worker_id, status=status, rows=len(rows), elapsed_seconds=elapsed)
                if args.progress:
                    print(f"END {record.get('sample_id')} worker={worker_id} status={status} rows={len(rows)} elapsed={elapsed}s", flush=True)
                if entry:
                    entry["current"] = None
                    free_workers.append(worker_id)
                completed += 1
                last_progress = time.perf_counter()

            for worker_id, entry in list(workers.items()):
                current = entry.get("current")
                if not current:
                    continue
                record = current["record"]
                timeout = _effective_case_timeout(record, args)
                elapsed = time.perf_counter() - float(current["started"])
                heartbeat = float(args.heartbeat_seconds or 0)
                if heartbeat > 0 and time.perf_counter() - heartbeat_last.get(worker_id, current["started"]) >= heartbeat:
                    debug_events.write("sample_heartbeat", record, record_index=current["record_index"], total_records=total_records, worker_id=worker_id, pid=entry["process"].pid, elapsed_seconds=round(elapsed, 3), timeout_seconds=timeout)
                    heartbeat_last[worker_id] = time.perf_counter()
                if timeout > 0 and elapsed >= timeout:
                    debug_events.write("sample_timeout", record, record_index=current["record_index"], total_records=total_records, worker_id=worker_id, pid=entry["process"].pid, elapsed_seconds=round(elapsed, 3), timeout_seconds=timeout)
                    _kill_process_tree(entry["process"].pid)
                    entry["process"].join(5)
                    if entry["process"].is_alive():
                        entry["process"].kill()
                        entry["process"].join(5)
                    rows = [_terminal_row(record, "timeout", f"sample exceeded {timeout:.1f}s timeout")]
                    results.append({"record_index": current["record_index"], "record": record, "status": "timeout", "rows": rows, "elapsed_seconds": round(elapsed, 3)})
                    debug_events.write("sample_end", record, record_index=current["record_index"], total_records=total_records, worker_id=worker_id, status="timeout", rows=len(rows), elapsed_seconds=round(elapsed, 3))
                    completed += 1
                    last_progress = time.perf_counter()
                    workers.pop(worker_id, None)
                    try:
                        free_workers.remove(worker_id)
                    except ValueError:
                        pass
                    start_worker(worker_id)
    finally:
        for entry in workers.values():
            queue = entry.get("queue")
            process = entry.get("process")
            try:
                queue.put(None)
            except Exception:
                pass
            if process is not None:
                process.join(2)
                if process.is_alive():
                    _kill_process_tree(process.pid)
                    process.join(2)
                    if process.is_alive():
                        process.kill()
    return results


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


def _collect_pool_worker(worker_id: int, args: argparse.Namespace, task_queue: Any, result_queue: Any) -> None:
    debug_events = _QueueDebugEvents(result_queue) if getattr(args, "debug_events", None) else _DebugEvents(None, truncate=False)
    while True:
        task = task_queue.get()
        if task is None:
            return
        record = dict(task.get("record") or {})
        record_index = int(task.get("record_index", 0) or 0)
        started = time.perf_counter()
        debug_events.write("worker_start", record, worker_id=worker_id, pid=os.getpid(), record_index=record_index, total_records=task.get("total_records"), budget=_sample_budget(record, args))
        try:
            status, rows = _collect_sample(record, args, debug_events)
        except Exception as exc:
            status, rows = "failed", [_terminal_row(record, "failed", str(exc))]
            debug_events.write("sample_exception", record, worker_id=worker_id, pid=os.getpid(), record_index=record_index, error=str(exc))
        elapsed = round(time.perf_counter() - started, 3)
        debug_events.write("worker_done", record, worker_id=worker_id, pid=os.getpid(), record_index=record_index, status=status, rows=len(rows), elapsed_seconds=elapsed)
        result_queue.put({
            "message_type": "result",
            "worker_id": worker_id,
            "record_index": record_index,
            "record": record,
            "status": status,
            "rows": rows,
            "elapsed_seconds": elapsed,
        })


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
    _attach_split_volumes(source_input, record)
    if source_input.get("parts"):
        damaged = record.get("damaged_input")
        if isinstance(damaged, dict):
            damaged["parts"] = source_input["parts"]
            damaged["use_parts_only"] = bool(source_input.get("use_parts_only"))
        record["split_sidecars_available"] = True
        # Remove missing_volume flag since volumes are now available
        flags = record.get("damage_flags")
        if isinstance(flags, list) and "missing_volume" in flags:
            record["damage_flags"] = [f for f in flags if f != "missing_volume"]
            record["runtime_damage_flags"] = record["damage_flags"]
    # Merge zip_container_tags into damage_flags for SFX/carrier detection
    container_tags = record.get("zip_container_tags") or []
    if isinstance(container_tags, list):
        tag_flags = {t for t in container_tags if t in {"sfx", "carrier_prefix", "carrier_archive", "embedded_archive"}}
        if tag_flags:
            existing = set(record.get("damage_flags") or [])
            record["damage_flags"] = list(existing | tag_flags)
            record["runtime_damage_flags"] = record["damage_flags"]
    route_evidence = zip_route_evidence_flags(record)
    if route_evidence:
        record["route_evidence_flags"] = _dedupe_str([*list(record.get("route_evidence_flags") or []), *route_evidence])
        record["damage_flags"] = _dedupe_str([*list(record.get("damage_flags") or []), *route_evidence])
        record["runtime_damage_flags"] = _dedupe_str([*list(record.get("runtime_damage_flags") or record.get("damage_flags") or []), *route_evidence])
    if record.get("split_sidecars_available") and "missing_volume_unavailable" not in set(record.get("damage_flags") or []) and "tail_volume_truncated" not in set(record.get("damage_flags") or []):
        for key in ("damage_flags", "runtime_damage_flags", "route_evidence_flags"):
            if isinstance(record.get(key), list):
                record[key] = [flag for flag in record[key] if flag not in {"missing_volume", "input_truncated", "unexpected_end", "stream_truncated"}]
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
    rollout_min_improvement = max(0.0, float(getattr(args, "rollout_min_improvement", 0.01) or 0.0))
    rollout_patience = max(0, int(getattr(args, "rollout_stagnation_patience", 3) or 0))
    global_best_recovery = 0.0
    best_state_id = str(root_state.get("state_id") or "")
    rounds_without_improvement = 0
    complete_found = False
    materialization_summary: dict[str, Any] = {
        "materialize_cost_bucket_counts": {},
        "expensive_materialization_skipped_count": 0,
        "materialize_worker_seconds_saved_estimate": 0.0,
    }

    for round_index in range(max_rounds):
        if complete_found:
            break
        if not frontier:
            break
        next_frontier: list[dict[str, Any]] = []
        round_best_recovery = global_best_recovery
        for state in frontier:
            if complete_found:
                break
            if expanded_state_count >= max_total_states:
                budget_exhausted = True
                rows.append(_rollout_terminal_row(record, state, "budget_exhausted", "rollout state budget exhausted", None))
                break
            source_input = dict(state.get("source_input") or {})
            archive_state = _archive_state_from_rollout_state(record, state, fmt)
            damage_flags = list(state.get("damage_flags") or [])
            route_evidence_flags = list(state.get("route_evidence_flags") or [])
            repair_history_flags = list(state.get("repair_history_flags") or [])
            residual_damage_flags = list(state.get("residual_damage_flags") or [])
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
                password=record.get("password"),
                archive_state=archive_state,
                repair_history=_repair_history_payload(record, state, route_evidence_flags, repair_history_flags, residual_damage_flags),
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
                password=record.get("password"),
                archive_state=archive_state,
                repair_history=_repair_history_payload(record, state, route_evidence_flags, repair_history_flags, residual_damage_flags),
            )
            debug_events.write("phase", record, round=state_round, query_id=query_id, phase="before_state", elapsed_seconds=round(time.perf_counter() - phase_started, 3))
            state_features = _state_features(record, job, batch, state_round, previous_actions, previous_modules, best_completeness, before_state)
            state_features["previous_modules"] = previous_modules
            state_features["previous_module_count"] = len(previous_modules)
            phase_started = time.perf_counter()
            candidates, materialization_meta = _materialize_for_collection(list(batch.candidates), selector, args, record, debug_events, state_round, query_id)
            _merge_materialization_round_summary(materialization_summary, materialization_meta)
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
                expensive_materialization_skipped_count=materialization_meta.get("expensive_materialization_skipped_count", 0),
                materialize_worker_seconds_saved_estimate=round(float(materialization_meta.get("materialize_worker_seconds_saved_estimate", 0.0) or 0.0), 3),
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
                candidate_view = _training_candidate_view(record, candidate, fmt)
                after_state = _state_summary(record, candidate_view.get("source_input") or {}, fmt, list(candidate.damage_flags or damage_flags), payload)
                delta_features = _state_delta(before_state, after_state)
                label_info = _label_candidate(record, candidate, best_completeness, before_state, after_state, delta_features, candidate_view=candidate_view)
                round_best_recovery = max(round_best_recovery, float(label_info.get("completeness", 0.0) or 0.0))
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
                candidate_view = _training_candidate_view(record, candidate, fmt)
                next_source_input = candidate_view.get("source_input_for_next_round") if isinstance(candidate_view.get("source_input_for_next_round"), dict) else dict(selected_result.repaired_input or {})
                if not selected_result.ok or not next_source_input:
                    rows.append(_rollout_terminal_row(record, state, "dead_end", "selected branch produced no repaired input", after_by_id.get(candidate_id), parent_action_row_id=entry["action_row_id"], parent_candidate_id=candidate_id))
                    continue
                label_info = label_by_id.get(candidate_id, {})
                if int(label_info.get("label", 0) or 0) == 3 and rollout_mode != "greedy_current_selector":
                    rows.append(_rollout_terminal_row(record, state, "complete", "branch reached complete repair", after_by_id.get(candidate_id), parent_action_row_id=entry["action_row_id"], parent_candidate_id=candidate_id, terminal_label=3))
                    complete_found = True
                    best_state_id = str(state.get("state_id") or best_state_id)
                    continue
                child_runtime_verification = _terminal_verification_summary_from_state(record, after_by_id.get(candidate_id, {}))
                child_repair_history_flags = _child_repair_history_flags(
                    [*previous_modules, str(candidate.module_name)],
                    [*previous_actions, *[str(action) for action in candidate.actions]],
                )
                payload = candidate_feature_payload(candidate)
                patch_facts = [str(item) for item in payload.get("patch_facts") or []]
                if "after_archive_carrier_crop" in patch_facts and "after_archive_carrier_crop" not in child_repair_history_flags:
                    child_repair_history_flags.append("after_archive_carrier_crop")
                child_residual_flags = _residual_damage_flags_from_label(label_info, after_by_id.get(candidate_id, {}), child_runtime_verification)
                child_state = {
                    "episode_id": state["episode_id"],
                    "state_id": f"{record.get('sample_id')}:r{state_round + 1}:b{next_beam_id}",
                    "round": state_round + 1,
                    "beam_id": next_beam_id,
                    "parent_query_id": query_id,
                    "parent_candidate_id": candidate_id,
                    "parent_action_row_id": entry["action_row_id"],
                    "source_input": dict(next_source_input),
                    "archive_state": candidate_view.get("archive_state"),
                    "damage_flags": _next_state_damage_flags(
                        selected_result,
                        damage_flags,
                        child_runtime_verification,
                        label_info,
                        route_evidence_flags=route_evidence_flags,
                        repair_history_flags=child_repair_history_flags,
                        residual_damage_flags=child_residual_flags,
                    ),
                    "route_evidence_flags": list(route_evidence_flags),
                    "repair_history_flags": child_repair_history_flags,
                    "residual_damage_flags": child_residual_flags,
                    "applied_patch_facts": _dedupe_str([*list(state.get("applied_patch_facts") or []), *patch_facts]),
                    "previous_actions": [*previous_actions, *[str(action) for action in candidate.actions]],
                    "previous_modules": [*previous_modules, str(candidate.module_name)],
                    "best_completeness": max(best_completeness, float(label_info.get("completeness", 0.0) or 0.0)),
                    "global_best_recovery_ratio": max(global_best_recovery, float(label_info.get("completeness", 0.0) or 0.0)),
                    "rounds_without_improvement": rounds_without_improvement,
                    "best_state_id": best_state_id,
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
            if complete_found:
                break
        frontier = _trim_frontier(next_frontier, args)
        if round_best_recovery >= global_best_recovery + rollout_min_improvement:
            global_best_recovery = round_best_recovery
            rounds_without_improvement = 0
            if frontier:
                best_state_id = str(frontier[0].get("state_id") or best_state_id)
        elif frontier:
            rounds_without_improvement += 1
        for item in frontier:
            item["global_best_recovery_ratio"] = global_best_recovery
            item["rounds_without_improvement"] = rounds_without_improvement
            item["best_state_id"] = best_state_id
        if rollout_patience > 0 and frontier and rounds_without_improvement >= rollout_patience:
            for state in frontier:
                rows.append(_rollout_terminal_row(record, state, "global_recovery_stagnation", "global best recovery did not improve within rollout patience", _state_summary(record, dict(state.get("source_input") or {}), fmt, list(state.get("damage_flags") or []))))
            frontier = []
            break
        if budget_exhausted:
            break

    _backfill_future_labels(rows, float(getattr(args, "future_label_discount", 0.8) or 0.8))
    _backfill_rl_transitions(rows, args)
    terminal_rows = [row for row in rows if row.get("row_type") == "terminal"]
    terminal_status_counts = Counter(str(item.get("terminal_status") or item.get("label_status") or "unknown") for item in terminal_rows)
    repair_cache_stats = scheduler.repair_cache.stats() if hasattr(scheduler, "repair_cache") else {}
    debug_events.write("repair_cache_stats", record, stats=repair_cache_stats)
    for row in rows:
        row["rollout_summary"] = {
            "state_count": created_state_count,
            "expanded_state_count": expanded_state_count,
            "branch_count": branch_count,
            "rollout_budget_exhausted": bool(budget_exhausted),
            "terminal_count": len(terminal_rows),
            "terminal_status_counts": dict(sorted(terminal_status_counts.items())),
            "repair_cache": repair_cache_stats,
            "materialization": materialization_summary,
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
        "route_evidence_flags": _dedupe_str(list(record.get("route_evidence_flags") or zip_route_evidence_flags(record))),
        "repair_history_flags": [],
        "residual_damage_flags": [],
        "previous_actions": [],
        "previous_modules": [],
        "best_completeness": 0.0,
        "global_best_recovery_ratio": 0.0,
        "rounds_without_improvement": 0,
        "best_state_id": f"{sample_id}:r0:b0",
        "path_score": 0.0,
        "path_actions": [],
        "path_modules": [],
        "runtime_verification": dict(record.get("runtime_initial_verification") or {}),
        "rollout_mode": rollout_mode,
    }


def _runtime_initial_damage_flags(record: dict[str, Any]) -> list[str]:
    explicit = record.get("runtime_damage_flags")
    if isinstance(explicit, list):
        return _dedupe_str([str(item) for item in explicit if str(item)])
    raw = {str(item) for item in (record.get("damage_flags") or [])}
    visible: list[str] = []
    evidence = set(zip_route_evidence_flags(record))
    raw.update(evidence)
    for flag in (
        "missing_volume", "wrong_password", "truncated", "input_truncated", "probably_truncated", "trailing_junk", "boundary_unreliable",
        "checksum_error", "crc_error", "damaged", "duplicate_entries", "has_duplicate_entries", "filename_encoding_bad", "raw_filename_bytes",
        "has_filename_encoding_risk", "long_comment_present", "zip_comment_length_bad", "comment_length_bad", "eocd_bad", "zip64",
        "zip64_extra_present", "zip64_extra_bad", "zip64_extra_size_bad", "zip64_locator_bad", "zip64_eocd_bad", "sfx", "carrier_prefix",
        "carrier_archive", "embedded_archive", "data_descriptor", "compressed_size_bad", "bit3_data_descriptor", "local_header_conflict",
        "central_directory_bad", "central_directory_offset_bad", "central_directory_count_bad", "local_header_bad", "local_header_recovery",
        "extra_field_bad", "extra_field_length_bad", "extra_length_bad",
        "split_archive", "split_sidecars_available", "tail_volume_truncated", "middle_volume_missing", "missing_volume_unavailable",
        "spurious_data_descriptor_candidate", "descriptor_record_in_payload_gap", "descriptor_delete_would_align_next_header",
    ):
        if flag in raw:
            visible.append(flag)
    if raw and "damaged" not in visible:
        visible.append("damaged")
    return _dedupe_str(visible)


def _next_state_damage_flags(
    result: RepairResult,
    current_flags: list[str],
    runtime_verification: dict[str, Any],
    label_info: dict[str, Any] | None = None,
    *,
    route_evidence_flags: list[str] | None = None,
    repair_history_flags: list[str] | None = None,
    residual_damage_flags: list[str] | None = None,
) -> list[str]:
    label_info = label_info if isinstance(label_info, dict) else {}
    complete_by_oracle = int(label_info.get("label", 0) or 0) == 3 or (
        str(label_info.get("status") or "") == "complete" and float(label_info.get("completeness", 0.0) or 0.0) >= 0.999
    )
    if complete_by_oracle:
        return []
    flags = _dedupe_str([
        *list(result.damage_flags or current_flags),
        *list(route_evidence_flags or []),
        *list(repair_history_flags or []),
        *list(residual_damage_flags or []),
    ])
    if "after_archive_carrier_crop" in set(flags):
        flags = [flag for flag in flags if flag not in {"sfx", "carrier_archive", "carrier_prefix", "embedded_archive"}]
    if flags:
        return flags
    if str(runtime_verification.get("assessment_status") or "") == "complete" or str(runtime_verification.get("source_integrity") or "") == "complete":
        return ["exact_match_failed", "content_integrity_bad_or_unknown"]
    return list(current_flags)


def _dedupe_str(values: list[Any]) -> list[str]:
    result: list[str] = []
    seen: set[str] = set()
    for value in values:
        text = str(value or "").strip()
        if not text or text in seen:
            continue
        seen.add(text)
        result.append(text)
    return result


def _child_repair_history_flags(modules: list[str], actions: list[str]) -> list[str]:
    flags: list[str] = []
    for module in modules:
        module = str(module or "")
        if not module:
            continue
        flags.append(f"already_tried:{module}")
        if module == "archive_carrier_crop_deep_recovery" or module.endswith("_carrier_crop_deep_recovery"):
            flags.append("after_archive_carrier_crop")
        if module in {"zip_fix_eocd_comment_length", "zip_fix_eocd_record"}:
            flags.append("after_eocd_repair")
        if module in {"zip_rebuild_cd_from_local_headers", "zip_rebuild_cd_preserve_raw_names", "zip_rebuild_cd_from_data_descriptors"}:
            flags.append("after_cd_rebuild")
        if module in {"zip_fix_local_header_fields", "zip_local_header_partial_scan"}:
            flags.append("after_local_header_repair")
    for action in actions:
        action = str(action or "")
        if "carrier" in action and "crop" in action:
            flags.append("after_archive_carrier_crop")
        if "eocd" in action:
            flags.append("after_eocd_repair")
        if "central_directory" in action or "rebuild_cd" in action:
            flags.append("after_cd_rebuild")
        if "local_header" in action:
            flags.append("after_local_header_repair")
    return _dedupe_str(flags)


def _residual_damage_flags_from_label(label_info: dict[str, Any], after_state: dict[str, Any] | None, runtime_verification: dict[str, Any]) -> list[str]:
    label_info = label_info if isinstance(label_info, dict) else {}
    after_state = after_state if isinstance(after_state, dict) else {}
    if int(label_info.get("label", 0) or 0) == 3 or (
        str(label_info.get("status") or "") == "complete" and float(label_info.get("completeness", 0.0) or 0.0) >= 0.999
    ):
        return []
    flags = ["exact_match_failed"]
    reasons = {str(item) for item in label_info.get("hard_negative_reasons") or []}
    if reasons & {"payload_hash_mismatch", "wrong_payload_for_expected_name", "wrong_entries_without_oracle_match"}:
        flags.extend(["payload_hash_mismatch", "content_integrity_bad_or_unknown"])
    expected = int(label_info.get("expected_files", 0) or 0)
    matched = int(label_info.get("matched_files", 0) or 0)
    unreadable = int(label_info.get("unreadable_files", 0) or 0)
    entry_count = int(label_info.get("entry_count", after_state.get("entry_count", 0)) or 0)
    readable = int(after_state.get("readable_entry_count", runtime_verification.get("complete_files", 0)) or 0)
    if expected and matched < expected:
        flags.append("partial_entries_remaining")
    if unreadable > 0 or (entry_count and readable < entry_count):
        flags.extend(["directory_visible_payload_unreadable", "content_integrity_bad_or_unknown"])
    if str(runtime_verification.get("assessment_status") or "") == "complete" and float(label_info.get("completeness", 0.0) or 0.0) < 0.999:
        flags.extend(["payload_hash_mismatch", "content_integrity_bad_or_unknown"])
    status = str(label_info.get("status") or "")
    if status in {"partial", "directory_only", "state_progress"}:
        flags.append("partial_entries_remaining")
    return _dedupe_str(flags)


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
    if path and Path(path).is_file():
        return True
    return _candidate_archive_state_payload(candidate) is not None


def _archive_state_from_rollout_state(record: dict[str, Any], state: dict[str, Any], fmt: str) -> ArchiveState | None:
    raw = state.get("archive_state")
    source_input = state.get("source_input") if isinstance(state.get("source_input"), dict) else {}
    if not isinstance(raw, dict):
        raw = source_input.get("archive_state") if isinstance(source_input.get("archive_state"), dict) else None
    if not isinstance(raw, dict):
        return None
    return _archive_state_from_payload(record, raw, fmt)


def _candidate_archive_state_payload(candidate: Any) -> dict[str, Any] | None:
    plan = getattr(candidate, "plan", None)
    if isinstance(plan, dict) and isinstance(plan.get("archive_state"), dict):
        return dict(plan["archive_state"])
    try:
        result = candidate.to_result()
    except Exception:
        return None
    repaired_state = getattr(result, "repaired_state", None)
    if repaired_state is not None:
        try:
            return repaired_state.to_dict()
        except Exception:
            return None
    return None


def _archive_state_from_payload(record: dict[str, Any], raw: dict[str, Any], fmt: str) -> ArchiveState | None:
    try:
        fallback = str((record.get("damaged_input") or {}).get("path") or record.get("damaged_path") or record.get("source_path") or "")
        parts = [
            str(item.get("path") or "")
            for item in ((record.get("damaged_input") or {}).get("parts") or [])
            if isinstance(item, dict) and item.get("path")
        ]
        return ArchiveState.from_any(
            raw,
            archive_path=fallback,
            part_paths=parts or None,
            format_hint=str(record.get("format") or record.get("material_format") or fmt or ""),
            logical_name=str(record.get("source_archive_name") or record.get("sample_id") or ""),
        )
    except Exception:
        return None


def _training_candidate_view(record: dict[str, Any], candidate: Any, fmt: str) -> dict[str, Any]:
    repaired_input = candidate.repaired_input if isinstance(getattr(candidate, "repaired_input", None), dict) else {}
    path = Path(str(repaired_input.get("path") or ""))
    if path.is_file():
        return {
            "source_kind": str(repaired_input.get("kind") or "file"),
            "source_input": dict(repaired_input),
            "source_input_for_next_round": dict(repaired_input),
            "materialized_path": str(path),
        }
    raw_state = _candidate_archive_state_payload(candidate)
    if not isinstance(raw_state, dict):
        return {
            "source_kind": str(repaired_input.get("kind") or "missing"),
            "source_input": dict(repaired_input),
            "source_input_for_next_round": dict(repaired_input),
            "no_output_reason": _candidate_no_output_reason(candidate, archive_state_present=False),
        }
    state = _archive_state_from_payload(record, raw_state, fmt)
    if state is None:
        return {
            "source_kind": "archive_state",
            "archive_state": raw_state,
            "source_input": {},
            "source_input_for_next_round": {},
            "no_output_reason": "patch_materialization_failed",
            "materialization_error": "archive_state payload could not be parsed",
        }
    try:
        materialized_path = _materialize_training_archive_state(state, fmt)
    except Exception as exc:
        return {
            "source_kind": "archive_state",
            "archive_state": raw_state,
            "patch_digest": state.effective_patch_digest(),
            "source_input": {},
            "source_input_for_next_round": {},
            "no_output_reason": "patch_materialization_failed",
            "materialization_error": str(exc),
        }
    summary_input = {"kind": "file", "source_kind": "archive_state", "path": materialized_path, "format_hint": state.format_hint or state.source.format_hint or fmt, "patch_digest": state.effective_patch_digest()}
    return {
        "source_kind": "archive_state",
        "archive_state": state.to_dict(),
        "patch_digest": state.effective_patch_digest(),
        "materialized_path": materialized_path,
        "source_input": summary_input,
        "source_input_for_next_round": _archive_state_source_input(state.to_dict(), state.format_hint or state.source.format_hint or fmt),
    }


def _materialize_training_archive_state(state: ArchiveState, fmt: str) -> str:
    digest = _sha256(json.dumps(state.to_dict(), sort_keys=True).encode("utf-8"))
    suffix = "." + (_normalize_format(fmt or state.format_hint or state.source.format_hint or "zip").split(".")[-1] or "zip")
    root = Path(".sunpack") / "repair-plan-workspace" / "training_archive_state"
    root.mkdir(parents=True, exist_ok=True)
    path = root / f"state_{digest[:24]}{suffix}"
    if not path.is_file():
        path.write_bytes(archive_state_to_bytes(state))
    return str(path)


def _archive_state_source_input(raw_state: dict[str, Any], fmt: str) -> dict[str, Any]:
    return {
        "kind": "archive_state",
        "format_hint": str(raw_state.get("format_hint") or fmt or ""),
        "patch_digest": str(raw_state.get("patch_digest") or ""),
        "archive_state": dict(raw_state),
    }


def _candidate_no_output_reason(candidate: Any, *, archive_state_present: bool) -> str:
    if archive_state_present:
        return "patch_materialization_failed"
    for validation in list(getattr(candidate, "validations", []) or []):
        warnings = [str(item) for item in getattr(validation, "warnings", []) or []]
        if any("repair plan produced no candidate" in warning for warning in warnings):
            return "lazy_plan_produced_no_candidate"
    return "missing_repaired_input"


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
    best_recovery_ratio = max(terminal_recovery_ratio, float(state.get("global_best_recovery_ratio", state.get("best_completeness", 0.0)) or 0.0))
    best_state_id = str(state.get("best_state_id") or state.get("state_id") or "")
    rounds_without_improvement = int(state.get("rounds_without_improvement", 0) or 0)
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
        "damage_profile": _record_damage_profile(record),
        "partial_first_target": _is_zip_partial_first_record(record),
        "zip_variant": record.get("zip_variant") or source_derivation.get("zip_variant"),
        "zip_container_tags": record.get("zip_container_tags") or source_derivation.get("zip_container_tags"),
        "zip_structure_features": record.get("zip_structure_features") or source_derivation.get("zip_structure_features"),
        "structure_targeted_profile": bool(record.get("structure_targeted_profile", False)),
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
        "route_evidence_flags": list(state.get("route_evidence_flags") or []),
        "repair_history_flags": list(state.get("repair_history_flags") or []),
        "residual_damage_flags": list(state.get("residual_damage_flags") or []),
        "path_score": float(state.get("path_score", 0.0) or 0.0),
        "rollout_mode": state.get("rollout_mode") or "greedy",
        "terminal_status": status,
        "terminal_label": label,
        "terminal_state": terminal_state,
        "terminal_verification_summary": terminal_verification,
        "terminal_archive_coverage": terminal_coverage,
        "terminal_recovery_ratio": terminal_recovery_ratio,
        "terminal_recovery_ratio_source": terminal_ratio_source,
        "best_recovery_ratio": best_recovery_ratio,
        "best_state_id": best_state_id,
        "rounds_without_improvement": rounds_without_improvement,
        "frontier_exhausted": status in {"frontier_exhausted", "dead_end", "no_candidates"},
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
            "best_recovery_ratio": best_recovery_ratio,
            "best_state_id": best_state_id,
            "rounds_without_improvement": rounds_without_improvement,
        },
        "training_targets": {
            "immediate_gain": label,
            "future_gain": label,
            "discounted_gain": float(label),
            "blended_gain": float(label),
            "terminal_recovery_ratio": terminal_recovery_ratio,
            "best_recovery_ratio": best_recovery_ratio,
            "discounted_terminal_recovery_ratio": terminal_recovery_ratio,
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
        discounted_terminal_ratio = best_terminal_ratio * (float(discount) ** int(steps_to_best))
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
        details["terminal_recovery_ratio"] = selected_terminal_ratio
        details["subtree_best_terminal_recovery_ratio"] = best_terminal_ratio
        details["discounted_terminal_recovery_ratio"] = discounted_terminal_ratio
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
            "terminal_recovery_ratio": selected_terminal_ratio,
            "subtree_best_terminal_recovery_ratio": best_terminal_ratio,
            "discounted_terminal_recovery_ratio": discounted_terminal_ratio,
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
            "terminal_recovery_ratio": selected_terminal_ratio,
            "subtree_best_terminal_recovery_ratio": best_terminal_ratio,
            "discounted_terminal_recovery_ratio": discounted_terminal_ratio,
            "risk_class": details["risk_class"],
            "hard_negative_weight": details["hard_negative_weight"],
        }


def _backfill_rl_transitions(rows: list[dict[str, Any]], args: argparse.Namespace) -> None:
    gamma = float(getattr(args, "rl_discount", 0.95) or 0.95)
    step_cost = float(getattr(args, "rl_step_cost", 0.01) or 0.01)
    no_output_penalty = float(getattr(args, "rl_no_output_penalty", 0.05) or 0.05)
    hard_negative_penalty = float(getattr(args, "rl_hard_negative_penalty", 0.10) or 0.10)

    action_rows = [row for row in rows if row.get("row_type") != "terminal" and row.get("action_row_id")]
    terminal_rows = [row for row in rows if row.get("row_type") == "terminal"]
    children_by_parent: dict[str, list[dict[str, Any]]] = defaultdict(list)
    terminals_by_parent: dict[str, list[dict[str, Any]]] = defaultdict(list)
    state_rows: dict[str, dict[str, Any]] = {}
    actions_by_state: dict[str, list[dict[str, Any]]] = defaultdict(list)

    for row in action_rows:
        state_id = str(row.get("state_id") or "")
        if state_id:
            state_rows.setdefault(state_id, row)
            actions_by_state[state_id].append(row)
        parent = str(row.get("parent_action_row_id") or "")
        if parent:
            children_by_parent[parent].append(row)
    for terminal in terminal_rows:
        parent = str(terminal.get("parent_action_row_id") or "")
        if parent:
            terminals_by_parent[parent].append(terminal)
        terminal["rl"] = _terminal_rl_payload(terminal, gamma, step_cost, no_output_penalty, hard_negative_penalty)

    for row in action_rows:
        row_id = str(row.get("action_row_id") or "")
        current_ratio = _runtime_recovery_ratio_from_action_row(row)
        child = _first_child_state_row(children_by_parent.get(row_id, []))
        terminal = _best_terminal_row(terminals_by_parent.get(row_id, []))
        if child is not None:
            next_state_id = str(child.get("state_id") or "")
            next_summary = _rl_runtime_state_summary_from_action_row(child)
            next_ratio = _runtime_recovery_ratio_from_action_row(child)
            done = False
            terminal_status = ""
            terminal_ratio = None
            terminal_state_id = None
        elif terminal is not None:
            next_state_id = str(terminal.get("terminal_state_id") or terminal.get("state_id") or "")
            next_summary = _rl_runtime_state_summary_from_terminal_row(terminal)
            next_ratio = _terminal_row_recovery_ratio(terminal)
            done = True
            terminal_status = str(terminal.get("terminal_status") or terminal.get("label_status") or "")
            terminal_ratio = next_ratio
            terminal_state_id = next_state_id
        else:
            next_state_id = None
            next_summary = {}
            done = True
            terminal_status = _rl_terminal_status_for_unobserved_action(row)
            next_ratio = 0.0 if terminal_status in {"no_output", "dead_end", "no_candidates"} else current_ratio
            terminal_ratio = next_ratio
            terminal_state_id = None

        immediate_reward = float(next_ratio - current_ratio - step_cost)
        action_penalty = _rl_action_penalty(row, terminal_status, no_output_penalty, hard_negative_penalty)
        row["rl"] = {
            "schema_version": 1,
            "state_id": row.get("state_id"),
            "action_id": row_id,
            "next_state_id": next_state_id,
            "done": bool(done),
            "observed_transition": bool(child is not None or terminal is not None or done),
            "state_features": _rl_state_features(row),
            "action_features": _rl_action_features(row),
            "current_state_recovery_ratio": current_ratio,
            "next_state_recovery_ratio": next_ratio,
            "next_state_summary": next_summary,
            "immediate_reward": immediate_reward,
            "action_penalty": action_penalty,
            "reward": immediate_reward - action_penalty,
            "future_return": immediate_reward - action_penalty,
            "terminal_reward": terminal_ratio,
            "terminal_status": terminal_status,
            "terminal_state_id": terminal_state_id,
            "discount": gamma,
            "step_cost": step_cost,
            "no_output_penalty": no_output_penalty,
            "hard_negative_penalty": hard_negative_penalty,
        }

    memo: dict[str, float] = {}
    visiting: set[str] = set()

    def future_return_for_action(row: dict[str, Any]) -> float:
        row_id = str(row.get("action_row_id") or "")
        if not row_id:
            return 0.0
        if row_id in memo:
            return memo[row_id]
        if row_id in visiting:
            return float(_nested(row, "rl", "reward") or 0.0)
        visiting.add(row_id)
        rl = row.get("rl") if isinstance(row.get("rl"), dict) else {}
        reward = float(rl.get("reward", 0.0) or 0.0)
        value = reward
        if not bool(rl.get("done")):
            next_state_id = str(rl.get("next_state_id") or "")
            child_actions = actions_by_state.get(next_state_id, [])
            if child_actions:
                value += gamma * max(future_return_for_action(child) for child in child_actions)
        visiting.discard(row_id)
        memo[row_id] = value
        return value

    for row in action_rows:
        rl = row.get("rl") if isinstance(row.get("rl"), dict) else {}
        future_return = future_return_for_action(row)
        rl["future_return"] = future_return
        rl["episode_return"] = future_return
        row["rl"] = rl


def _terminal_rl_payload(row: dict[str, Any], gamma: float, step_cost: float, no_output_penalty: float, hard_negative_penalty: float) -> dict[str, Any]:
    terminal_ratio = _terminal_row_recovery_ratio(row)
    return {
        "schema_version": 1,
        "state_id": row.get("state_id"),
        "action_id": None,
        "next_state_id": None,
        "done": True,
        "observed_transition": True,
        "state_features": {},
        "action_features": {},
        "current_state_recovery_ratio": terminal_ratio,
        "next_state_recovery_ratio": terminal_ratio,
        "next_state_summary": _rl_runtime_state_summary_from_terminal_row(row),
        "immediate_reward": 0.0,
        "action_penalty": 0.0,
        "reward": 0.0,
        "future_return": terminal_ratio,
        "episode_return": terminal_ratio,
        "terminal_reward": terminal_ratio,
        "terminal_status": str(row.get("terminal_status") or row.get("label_status") or ""),
        "terminal_state_id": row.get("terminal_state_id") or row.get("state_id"),
        "discount": gamma,
        "step_cost": step_cost,
        "no_output_penalty": no_output_penalty,
        "hard_negative_penalty": hard_negative_penalty,
    }


def _first_child_state_row(children: list[dict[str, Any]]) -> dict[str, Any] | None:
    if not children:
        return None
    return sorted(children, key=lambda row: (int(row.get("round", 0) or 0), int(row.get("beam_id", 0) or 0), str(row.get("action_row_id") or "")))[0]


def _best_terminal_row(terminals: list[dict[str, Any]]) -> dict[str, Any] | None:
    if not terminals:
        return None
    return sorted(terminals, key=lambda row: (_terminal_row_recovery_ratio(row), int(row.get("label", 0) or 0)), reverse=True)[0]


def _runtime_recovery_ratio_from_action_row(row: dict[str, Any]) -> float:
    runtime = _nested(row, "stable_features", "runtime_context", "verification_summary")
    if not isinstance(runtime, dict):
        runtime = _nested(row, "stable_features", "state", "runtime_context", "verification_summary")
    if isinstance(runtime, dict):
        return _terminal_recovery_ratio(runtime)
    return 0.0


def _terminal_row_recovery_ratio(row: dict[str, Any]) -> float:
    if row.get("terminal_recovery_ratio") is not None:
        return max(0.0, min(1.0, _as_float(row.get("terminal_recovery_ratio"))))
    terminal_verification = row.get("terminal_verification_summary") if isinstance(row.get("terminal_verification_summary"), dict) else {}
    if terminal_verification:
        return _terminal_recovery_ratio(terminal_verification)
    return max(0.0, min(1.0, _as_float(row.get("terminal_reward"))))


def _rl_runtime_state_summary_from_action_row(row: dict[str, Any]) -> dict[str, Any]:
    stable = row.get("stable_features") if isinstance(row.get("stable_features"), dict) else {}
    before_state = stable.get("before_state") if isinstance(stable.get("before_state"), dict) else {}
    return dict(before_state)


def _rl_runtime_state_summary_from_terminal_row(row: dict[str, Any]) -> dict[str, Any]:
    terminal_state = row.get("terminal_state") if isinstance(row.get("terminal_state"), dict) else {}
    return _runtime_state_summary(terminal_state)


def _rl_state_features(row: dict[str, Any]) -> dict[str, Any]:
    stable = row.get("stable_features") if isinstance(row.get("stable_features"), dict) else {}
    runtime_context = stable.get("runtime_context") if isinstance(stable.get("runtime_context"), dict) else {}
    return {
        "feature_contract_version": FEATURE_CONTRACT_VERSION,
        "runtime_context": runtime_context,
    }


def _rl_action_features(row: dict[str, Any]) -> dict[str, Any]:
    stable = row.get("stable_features") if isinstance(row.get("stable_features"), dict) else {}
    return {
        "candidate_proposal": stable.get("candidate_proposal") if isinstance(stable.get("candidate_proposal"), dict) else {},
        "repair_prior_features": stable.get("repair_prior_features") if isinstance(stable.get("repair_prior_features"), dict) else {},
    }


def _rl_terminal_status_for_unobserved_action(row: dict[str, Any]) -> str:
    status = str(row.get("label_status") or "")
    if status:
        return status
    if not bool(row.get("branchable")):
        return "no_output"
    return "unobserved_action"


def _rl_action_penalty(row: dict[str, Any], terminal_status: str, no_output_penalty: float, hard_negative_penalty: float) -> float:
    status = str(row.get("label_status") or terminal_status or "")
    penalty = 0.0
    if status in {"no_output", "dead_end", "no_candidates"}:
        penalty += no_output_penalty
    if status == "no_output" and str(row.get("no_output_reason") or _nested(row, "label_details", "no_output_reason") or "") == "lazy_plan_produced_no_candidate":
        penalty += no_output_penalty
    if status == "hard_negative" or int(row.get("label", 0) or 0) < 0:
        penalty += hard_negative_penalty
    return penalty


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


def _materialize_for_collection(
    candidates: list[Any],
    selector: CandidateSelector,
    args: argparse.Namespace,
    record: dict[str, Any],
    debug_events: "_DebugEvents | None" = None,
    state_round: int | None = None,
    query_id: str = "",
) -> tuple[list[Any], dict[str, Any]]:
    if str(args.proposal_mode or "lazy") != "lazy":
        materialized: list[Any] = []
        for candidate in candidates:
            materialized.extend(_profiled_materialize_candidate(candidate, args, record, debug_events, state_round, query_id, None))
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
        selected, selection_stats = _balanced_zip_materialization_selection(ranked, budget, record, args, debug_events, state_round, query_id)
    else:
        selected = ranked[:budget]
        selection_stats = _materialization_selection_stats(ranked, selected, [], record)
    materialized = []
    ranks: dict[str, int] = {}
    for materialization_rank, (_, _, candidate) in enumerate(selected):
        produced = _profiled_materialize_candidate(candidate, args, record, debug_events, state_round, query_id, materialization_rank)
        for item in produced:
            materialized.append(item)
            ranks[_candidate_id(item)] = materialization_rank
    return materialized, {
        "budget": budget,
        "materialized_ids": {_candidate_id(candidate): True for candidate in materialized},
        "ranks": ranks,
        "proposal_count": len(candidates),
        **selection_stats,
    }


def _merge_materialization_round_summary(summary: dict[str, Any], meta: dict[str, Any]) -> None:
    summary["expensive_materialization_skipped_count"] = int(summary.get("expensive_materialization_skipped_count", 0) or 0) + int(meta.get("expensive_materialization_skipped_count", 0) or 0)
    summary["materialize_worker_seconds_saved_estimate"] = float(summary.get("materialize_worker_seconds_saved_estimate", 0.0) or 0.0) + float(meta.get("materialize_worker_seconds_saved_estimate", 0.0) or 0.0)
    buckets = summary.setdefault("materialize_cost_bucket_counts", {})
    for key, value in (meta.get("materialize_cost_bucket_counts") or {}).items():
        buckets[str(key)] = int(buckets.get(str(key), 0) or 0) + int(value or 0)


def _profiled_materialize_candidate(
    candidate: Any,
    args: argparse.Namespace,
    record: dict[str, Any],
    debug_events: "_DebugEvents | None",
    state_round: int | None,
    query_id: str,
    materialization_rank: int | None,
) -> list[Any]:
    if not bool(getattr(args, "profile_materialization_candidates", False)):
        return materialize_candidate(candidate)
    started = time.perf_counter()
    produced = materialize_candidate(candidate)
    elapsed = time.perf_counter() - started
    if debug_events is not None:
        debug_events.write(
            "materialize_candidate",
            record,
            round=state_round,
            query_id=query_id,
            elapsed_seconds=round(elapsed, 3),
            materialization_rank=materialization_rank,
            module_name=str(getattr(candidate, "module_name", "") or ""),
            candidate_id=_candidate_id(candidate),
            produced_count=len(produced),
            produced_modules=[str(getattr(item, "module_name", "") or "") for item in produced],
            produced_label_statuses=[
                str((getattr(item, "diagnosis", {}) or {}).get("candidate_status") or (getattr(item, "diagnosis", {}) or {}).get("label_status") or "")
                for item in produced
            ],
        )
    return produced


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


_ZIP_FULL_REWRITE_MODULES = {
    "zip_rebuild_cd_from_local_headers",
    "zip_rebuild_cd_preserve_raw_names",
    "zip_rebuild_cd_from_data_descriptors",
    "zip_reconcile_cd_local_headers",
    "zip_reconcile_cd_data_descriptor_conflict",
    "zip_quarantine_failed_entries",
    "zip_salvage_verified_entries",
    "zip_partial_salvage_missing_volume",
    "zip_local_header_partial_scan",
    "zip_resolve_duplicate_entries",
    "zip_resolve_overlapping_entries",
    "archive_carrier_crop_deep_recovery",
}


_ZIP_LOW_COST_PATCH_MODULES = {
    "zip_remove_spurious_data_descriptor",
    "zip_normalize_data_descriptor_flags",
    "zip_reconcile_cd_entry_names_from_local_headers",
    "zip_fix_cd_offset",
    "zip_fix_cd_entry_count",
    "zip_fix_eocd_comment_length",
    "zip_fix_eocd_record",
    "zip_fix_local_header_fields",
    "zip_fix_extra_field_length",
    "zip_fix_zip64_locator",
    "zip_fix_zip64_eocd",
    "zip_fix_zip64_extra_size",
    "zip_trim_trailing_junk",
}


def _balanced_zip_materialization_selection(
    ranked: list[tuple[float, int, Any]],
    budget: int,
    record: dict[str, Any],
    args: argparse.Namespace,
    debug_events: "_DebugEvents | None" = None,
    state_round: int | None = None,
    query_id: str = "",
) -> tuple[list[tuple[float, int, Any]], dict[str, Any]]:
    selected: list[tuple[float, int, Any]] = []
    seen: set[str] = set()
    skipped: list[tuple[tuple[float, int, Any], str]] = []
    expensive_selected = 0
    max_expensive = int(getattr(args, "max_expensive_materializations_per_round", 2) or 0)
    high_recovery = _is_zip_high_recovery_competition_record(record)
    if high_recovery and max_expensive > 0:
        max_expensive = max(max_expensive, 4)
    if _zip_materialization_cost_cap_exempt(record):
        max_expensive = 0
    flags = {str(item) for item in record.get("damage_flags") or []}
    route_flags = {str(item) for item in record.get("route_evidence_flags") or []}
    evidence = flags | route_flags

    def module(entry: tuple[float, int, Any]) -> str:
        return str(getattr(entry[2], "module_name", "") or "")

    def expensive(entry: tuple[float, int, Any]) -> bool:
        name = module(entry)
        if name in _ZIP_LOW_COST_PATCH_MODULES:
            return False
        return name in _ZIP_FULL_REWRITE_MODULES or _estimated_materialize_cost_ms(entry[2], record) >= 450.0

    def family(entry: tuple[float, int, Any]) -> str:
        name = module(entry)
        if name in {"zip_rebuild_cd_from_local_headers", "zip_rebuild_cd_preserve_raw_names", "zip_rebuild_cd_from_data_descriptors", "zip_reconcile_cd_local_headers", "zip_reconcile_cd_data_descriptor_conflict"}:
            return "directory_rewrite"
        if name in {"zip_quarantine_failed_entries", "zip_salvage_verified_entries", "zip_local_header_partial_scan", "zip_partial_salvage_missing_volume"}:
            return "salvage_rewrite"
        if name in {"zip_resolve_duplicate_entries", "zip_resolve_overlapping_entries"}:
            return "conflict_rewrite"
        return name

    selected_expensive_families: set[str] = set()

    def add(entry: tuple[float, int, Any]) -> None:
        nonlocal expensive_selected
        if len(selected) >= budget:
            return
        candidate_id = _candidate_id(entry[2])
        if candidate_id in seen:
            return
        if expensive(entry) and max_expensive > 0:
            name = module(entry)
            if name == "zip_rebuild_cd_preserve_raw_names" and not (evidence & {"raw_filename_bytes", "filename_encoding_bad", "non_utf8_filename", "after_descriptor_flag_normalize", "exact_match_failed"}):
                skipped.append((entry, "raw_name_without_name_evidence"))
                return
            fam = family(entry)
            if not high_recovery and fam == "directory_rewrite" and fam in selected_expensive_families:
                skipped.append((entry, "expensive_duplicate_family"))
                return
            if expensive_selected >= max_expensive:
                skipped.append((entry, "expensive_round_cap"))
                return
            expensive_selected += 1
            selected_expensive_families.add(fam)
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
    if high_recovery:
        quotas = (("directory", 2), ("deep_partial", 2), ("boundary", 1), ("risk", 2))
    else:
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
    selected = selected[:budget]
    if debug_events is not None:
        for entry, reason in skipped:
            candidate = entry[2]
            debug_events.write(
                "materialization_skip",
                record,
                round=state_round,
                query_id=query_id,
                module_name=module(entry),
                candidate_id=_candidate_id(candidate),
                estimated_materialize_cost_ms=round(_estimated_materialize_cost_ms(candidate, record), 1),
                skip_reason=reason,
            )
    return selected, _materialization_selection_stats(ranked, selected, skipped, record)


def _materialization_selection_stats(
    ranked: list[tuple[float, int, Any]],
    selected: list[tuple[float, int, Any]],
    skipped: list[tuple[tuple[float, int, Any], str]],
    record: dict[str, Any],
) -> dict[str, Any]:
    selected_ids = {_candidate_id(entry[2]) for entry in selected}
    buckets: dict[str, int] = {}
    for _, _, candidate in selected:
        bucket = _materialize_cost_bucket(_estimated_materialize_cost_ms(candidate, record))
        buckets[bucket] = int(buckets.get(bucket, 0) or 0) + 1
    skipped_cost = sum(_estimated_materialize_cost_ms(entry[2], record) for entry, _ in skipped if _candidate_id(entry[2]) not in selected_ids)
    return {
        "materialize_cost_bucket_counts": buckets,
        "expensive_materialization_skipped_count": len(skipped),
        "materialize_worker_seconds_saved_estimate": round(skipped_cost / 1000.0, 3),
    }


def _materialize_cost_bucket(cost_ms: float) -> str:
    if cost_ms < 100:
        return "<100ms"
    if cost_ms < 400:
        return "100-400ms"
    if cost_ms < 1000:
        return "400ms-1s"
    if cost_ms < 3000:
        return "1-3s"
    return ">=3s"


def _estimated_materialize_cost_ms(candidate: Any, record: dict[str, Any]) -> float:
    module = str(getattr(candidate, "module_name", "") or "")
    size_mb = _record_size_mb(record) if record else 0.0
    base = {
        "zip_rebuild_cd_preserve_raw_names": 850.0,
        "zip_rebuild_cd_from_local_headers": 800.0,
        "zip_reconcile_cd_local_headers": 950.0,
        "zip_rebuild_cd_from_data_descriptors": 450.0,
        "zip_reconcile_cd_data_descriptor_conflict": 500.0,
        "zip_resolve_duplicate_entries": 650.0,
        "zip_quarantine_failed_entries": 450.0,
        "zip_salvage_verified_entries": 450.0,
        "zip_local_header_partial_scan": 450.0,
        "zip_partial_salvage_missing_volume": 550.0,
        "archive_carrier_crop_deep_recovery": 650.0,
        "zip_remove_spurious_data_descriptor": 90.0,
        "zip_normalize_data_descriptor_flags": 90.0,
        "zip_reconcile_cd_entry_names_from_local_headers": 120.0,
        "zip_fix_cd_offset": 120.0,
        "zip_fix_cd_entry_count": 80.0,
        "zip_fix_extra_field_length": 90.0,
        "zip_trim_trailing_junk": 80.0,
    }.get(module, 180.0)
    size_factor = min(5.0, max(0.0, size_mb) / 24.0)
    if module in _ZIP_FULL_REWRITE_MODULES:
        base += size_factor * 550.0
    elif module in _ZIP_LOW_COST_PATCH_MODULES:
        base += size_factor * 40.0
    if "sfx_split" in str(record.get("zip_variant") or "") or "split_zip" in str(record.get("zip_variant") or ""):
        base *= 1.25
    return float(base)


def _zip_materialization_cost_cap_exempt(record: dict[str, Any]) -> bool:
    profile = str(record.get("damage_profile") or "")
    if profile.startswith("zip_two_step_"):
        return True
    if profile in {
        "zip_sfx_cd_damage",
        "zip_sfx_payload_damage",
        "zip_sfx_split_missing_volume",
        "zip_zip64_extra_size_mismatch",
        "zip_single_entry_payload_damage",
        "zip_local_header_crc_wrong_cd_correct",
        "zip_partial_cd_rebuild_then_payload_mismatch",
        "zip_drop_central_directory_keep_local_headers",
        "zip_rebuild_directory_keeps_bad_payload",
        "zip_partial_recovery_wrong_hash_same_name",
    }:
        return True
    tags = {str(item) for item in record.get("zip_container_tags") or []}
    flags = {str(item) for item in record.get("damage_flags") or []}
    return bool(tags & {"sfx", "carrier_archive", "carrier_prefix"} or flags & {"sfx", "carrier_archive", "carrier_prefix", "zip64_extra_bad", "zip64_extra_size_bad"})


def _scheduler(args: argparse.Namespace) -> RepairScheduler:
    return RepairScheduler({
        "repair": {
            "workspace": str(Path(args.workspace)),
            "max_attempts_per_task": 8,
            "runtime_cache": {
                "enabled": not bool(getattr(args, "disable_repair_cache", False)),
                "max_entries": 512,
            },
            "module_limits": {
                "max_candidates_per_module": 6,
                "verify_candidates": False,
                "max_seconds_per_module": 8.0,
                "max_stream_trim_probe_attempts": 8,
                "max_stream_trim_decode_mb": 32,
            },
            "modules": [
                {"name": "archive_carrier_crop_deep_recovery", "enabled": True},
                {"name": "zip_trim_trailing_junk", "enabled": True},
                {"name": "zip_fix_eocd_comment_length", "enabled": True},
                {"name": "zip_fix_eocd_record", "enabled": True},
                {"name": "zip_fix_cd_offset", "enabled": True},
                {"name": "zip_fix_cd_entry_count", "enabled": True},
                {"name": "zip_fix_local_header_fields", "enabled": True},
                {"name": "zip_fix_extra_field_length", "enabled": True},
                {"name": "zip_fix_zip64_locator", "enabled": True},
                {"name": "zip_fix_zip64_eocd", "enabled": True},
                {"name": "zip_fix_zip64_extra_size", "enabled": True},
                {"name": "zip_rebuild_cd_from_local_headers", "enabled": True},
                {"name": "zip_rebuild_cd_preserve_raw_names", "enabled": True},
                {"name": "zip_rebuild_cd_from_data_descriptors", "enabled": True},
                {"name": "zip_remove_spurious_data_descriptor", "enabled": True},
                {"name": "zip_normalize_data_descriptor_flags", "enabled": True},
                {"name": "zip_reconcile_cd_entry_names_from_local_headers", "enabled": True},
                {"name": "zip_reconcile_cd_local_headers", "enabled": True},
                {"name": "zip_quarantine_failed_entries", "enabled": True},
                {"name": "zip_salvage_verified_entries", "enabled": True},
                {"name": "zip_partial_salvage_missing_volume", "enabled": True},
                {"name": "zip_local_header_partial_scan", "enabled": True},
                {"name": "zip_resolve_duplicate_entries", "enabled": True},
                {"name": "zip_resolve_overlapping_entries", "enabled": True},
                {"name": "zip_reconcile_cd_data_descriptor_conflict", "enabled": True},
            ],
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
        "route_evidence_flags": list(getattr(job, "repair_history", {}).get("route_evidence_flags") or []),
        "repair_history_flags": list(getattr(job, "repair_history", {}).get("repair_history_flags") or []),
        "residual_damage_flags": list(getattr(job, "repair_history", {}).get("residual_damage_flags") or []),
        "damage_flags": list(job.damage_flags or []),
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
        "zip_variant": record.get("zip_variant") or source_derivation.get("zip_variant"),
        "zip_container_tags": record.get("zip_container_tags") or source_derivation.get("zip_container_tags"),
        "zip_structure_features": record.get("zip_structure_features") or source_derivation.get("zip_structure_features"),
        "structure_targeted_profile": bool(record.get("structure_targeted_profile", False)),
        "damaged_file_name": record.get("damaged_file_name"),
        "damaged_path": record.get("damaged_path"),
        "damage_json_path": record.get("damage_json_path"),
        "round": round_index,
        "candidate_index": candidate_index,
        "current_rank": rank,
        "candidate_id": payload.get("candidate_id"),
        "module": candidate.module_name,
        "module_name": candidate.module_name,
        "repair_name": payload.get("repair_name") or candidate.module_name,
        "atomic_action_group": payload.get("atomic_action_group") or payload.get("repair_name") or candidate.module_name,
        "native_key": payload.get("native_key") or "",
        "native_target": payload.get("native_target") or "",
        "candidate_status": payload.get("candidate_status") or "",
        "route_family": payload.get("route_family") or payload.get("atomic_action_group") or payload.get("repair_name") or candidate.module_name,
        "route_required_flags_matched": list(payload.get("route_required_flags_matched") or []),
        "route_reject_reason": payload.get("route_reject_reason") or "",
        "patch_facts": list(payload.get("patch_facts") or []),
        "residual_facts": list(payload.get("residual_facts") or []),
        "validation_details": dict(payload.get("validation_details") or {}),
        "raw_name_bytes_preserved": bool(payload.get("raw_name_bytes_preserved")),
        "raw_name_source": payload.get("raw_name_source") or "",
        "split_sidecars_available": bool(payload.get("split_sidecars_available")),
        "logical_stream_built": bool(payload.get("logical_stream_built")),
        "after_archive_carrier_crop": bool(payload.get("after_archive_carrier_crop")),
        "route_evidence_flags": list(state_features.get("route_evidence_flags") or []),
        "repair_history_flags": list(state_features.get("repair_history_flags") or []),
        "residual_damage_flags": list(state_features.get("residual_damage_flags") or []),
        "native_target_mismatch": bool(payload.get("native_target_mismatch")),
        "selected_by_current_system": bool(selected),
        "proposal_only": bool(proposal_only),
        "materialized_for_label": bool(materialized_for_label),
        "materialization_rank": materialization_rank,
        "materialization_budget": materialization_budget,
        "label": int(label_info.get("label", 0) or 0),
        "label_status": label_info.get("status"),
        "no_output_reason": label_info.get("no_output_reason") if str(label_info.get("status") or "") == "no_output" else "",
        "source_kind": label_info.get("source_kind") or "",
        "context_mismatch_penalty": float(payload.get("context_mismatch_penalty", 0.0) or 0.0),
        "lazy_no_output_risk": float(payload.get("lazy_no_output_risk", 0.0) or 0.0),
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
            "context_mismatch_penalty": payload.get("context_mismatch_penalty"),
            "lazy_no_output_risk": payload.get("lazy_no_output_risk"),
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
    candidate_view: dict[str, Any] | None = None,
) -> dict[str, Any]:
    view = candidate_view if isinstance(candidate_view, dict) else _training_candidate_view(record, candidate, str(record.get("format") or record.get("material_format") or ""))
    repaired_input = view.get("source_input") if isinstance(view.get("source_input"), dict) else (candidate.repaired_input if isinstance(candidate.repaired_input, dict) else {})
    path = Path(str(repaired_input.get("path") or ""))
    if not path.is_file():
        reason = str(view.get("no_output_reason") or _candidate_no_output_reason(candidate, archive_state_present=bool(view.get("archive_state"))))
        return {
            "status": "no_output",
            "label": 0,
            "completeness": previous_completeness,
            "no_output_reason": reason,
            "materialization_error": str(view.get("materialization_error") or ""),
            "source_kind": str(view.get("source_kind") or repaired_input.get("kind") or "missing"),
            "patch_digest": str(view.get("patch_digest") or ""),
        }
    oracle = record.get("oracle") if isinstance(record.get("oracle"), dict) else {}
    fmt = str(record.get("format") or repaired_input.get("format_hint") or "")
    verified = _verify_output_against_oracle(path, fmt, oracle)
    if view.get("source_kind"):
        verified["source_kind"] = view.get("source_kind")
    if view.get("patch_digest"):
        verified["patch_digest"] = view.get("patch_digest")
    if view.get("materialized_path"):
        verified["training_materialized_path"] = view.get("materialized_path")
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
            "repair_name",
            "atomic_action_group",
            "native_key",
            "route_family",
            "route_required_flags_matched",
            "route_reject_reason",
            "native_target_mismatch",
            "format",
            "confidence",
            "score_hint",
            "actions",
            "damage_flags",
            "patch_cost",
            "risk_penalty",
            "context_mismatch_penalty",
            "lazy_no_output_risk",
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
        "cost_breakdown": {"lazy_materialization", "native_validation", "patch_complexity"},
        "risk_breakdown": {
            "partial_candidate",
            "content_damage",
            "content_damage_without_native_validation",
        },
        "context_mismatch_breakdown": {
            "conflict_without_conflict",
            "conflict_on_descriptor_without_cd_conflict",
            "zip64_without_zip64",
            "pointer_on_sfx_or_split",
            "boundary_on_payload_descriptor",
            "descriptor_rebuild_without_descriptor",
            "descriptor_reconcile_without_descriptor",
        },
        "lazy_no_output_breakdown": {
            "lazy_candidate",
            "materialization_failed",
            "conflict_without_conflict",
            "zip64_without_zip64",
            "split_tail_non_salvage",
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
                "confidence",
                "score_hint",
                "benefit_score",
                "evidence_score",
                "cost_penalty",
                "risk_penalty",
                "context_mismatch_penalty",
                "lazy_no_output_risk",
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
            for key in ("available", "sample_count", "attempts", "accepted", "score", "format", "module")
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
                "cost_breakdown": {"lazy_materialization", "native_validation", "patch_complexity"},
                "risk_breakdown": {
                    "partial_candidate",
                    "content_damage",
                    "content_damage_without_native_validation",
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
        source_derivation = record.get("source_derivation") if isinstance(record.get("source_derivation"), dict) else {}

        return SimpleNamespace(
            format=fmt or record.get("format") or record.get("material_format") or "",
            confidence=0.82,
            status="selected",
            details={
                "zip_structure_features": record.get("zip_structure_features") or source_derivation.get("zip_structure_features") or {},
                "zip_container_tags": record.get("zip_container_tags") or source_derivation.get("zip_container_tags") or [],
                "damage_profile": _record_damage_profile(record),
            },
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
        "zip_structure_features": record.get("zip_structure_features") or source_derivation.get("zip_structure_features") or {},
        "zip_container_tags": record.get("zip_container_tags") or source_derivation.get("zip_container_tags") or [],
        "damage_profile": _record_damage_profile(record),
    }


def _repair_history_payload(
    record: dict[str, Any],
    state: dict[str, Any],
    route_evidence_flags: list[str],
    repair_history_flags: list[str],
    residual_damage_flags: list[str],
) -> dict[str, Any]:
    source_derivation = record.get("source_derivation") if isinstance(record.get("source_derivation"), dict) else {}
    return {
        "previous_modules": list(state.get("previous_modules") or []),
        "previous_actions": list(state.get("previous_actions") or []),
        "path_modules": list(state.get("path_modules") or []),
        "path_actions": list(state.get("path_actions") or []),
        "applied_patch_facts": list(state.get("applied_patch_facts") or []),
        "route_evidence_flags": list(route_evidence_flags or []),
        "repair_history_flags": list(repair_history_flags or []),
        "residual_damage_flags": list(residual_damage_flags or []),
        "damage_profile": _record_damage_profile(record),
        "zip_structure_features": record.get("zip_structure_features") or source_derivation.get("zip_structure_features") or {},
        "zip_container_tags": record.get("zip_container_tags") or source_derivation.get("zip_container_tags") or [],
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
        "residual_damage_flags": list(state.get("residual_damage_flags") or []),
        "route_evidence_flags": list(state.get("route_evidence_flags") or []),
        "repair_history_flags": list(state.get("repair_history_flags") or []),
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
    source_kind = str(source_input.get("source_kind") or source_input.get("kind") or "file")
    patch_digest = str(source_input.get("patch_digest") or "")
    materialization_error = ""
    if source_kind == "archive_state" and isinstance(source_input.get("archive_state"), dict):
        raw_state = dict(source_input["archive_state"])
        patch_digest = str(raw_state.get("patch_digest") or "")
        state = _archive_state_from_payload(record, raw_state, fmt)
        if state is not None:
            patch_digest = state.effective_patch_digest()
            try:
                source_input = {"kind": "file", "path": _materialize_training_archive_state(state, fmt), "format_hint": state.format_hint or state.source.format_hint or fmt}
            except Exception as exc:
                materialization_error = str(exc)
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
        "source_kind": source_kind,
        "patch_digest": patch_digest,
        "materialization_error": materialization_error,
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


def _nested(value: Any, *keys: str) -> Any:
    current = value
    for key in keys:
        if not isinstance(current, dict):
            return None
        current = current.get(key)
    return current


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
            info = _read_archive_entry_infos(path, fmt)
            recovered_sizes = info.get("sizes", {})
            recovered_crcs = info.get("crcs", {})
            entry_count = len(info.get("entries", []))
            matched_files = 0
            matched_bytes = 0
            expected_bytes = 0
            wrong_files = 0
            unreadable_files = 0
            for name, meta in expected_files.items():
                if not isinstance(meta, dict):
                    continue
                expected_size = int(meta.get("size", 0) or 0)
                expected_bytes += max(0, expected_size)
                if name not in recovered_sizes:
                    unreadable_files += 1
                    continue
                actual_size = int(recovered_sizes.get(name, 0) or 0)
                actual_crc = int(recovered_crcs.get(name, 0) or 0)
                expected_crc = int(meta.get("crc32", 0) or 0)
                size_ok = (expected_size > 0 and actual_size >= expected_size) or (expected_size == 0 and actual_size > 0)
                crc_ok = (expected_crc != 0 and actual_crc != 0 and expected_crc == actual_crc) or (expected_crc == 0)
                if size_ok:
                    matched_files += 1
                    matched_bytes += min(actual_size, max(1, expected_size))
                else:
                    if crc_ok:
                        matched_files += 1
                        matched_bytes += min(actual_size, max(1, expected_size))
                    else:
                        wrong_files += 1
            max_expected = max(1, len(expected_files))
            file_coverage = matched_files / max_expected
            byte_coverage = matched_bytes / max(1, expected_bytes) if expected_bytes > 0 else file_coverage
            completeness = min(1.0, max(0.0, (file_coverage + byte_coverage) / 2.0))
            if completeness >= 0.999:
                return {**_label_status(3, "complete", completeness), "matched_files": matched_files, "wrong_files": wrong_files, "unreadable_files": unreadable_files, "entry_count": entry_count, "expected_files": len(expected_files)}
            if wrong_files > 0 and matched_files == 0:
                return {**_label_status(-1, "hard_negative", 0.0), "matched_files": matched_files, "wrong_files": wrong_files, "unreadable_files": unreadable_files, "entry_count": entry_count, "expected_files": len(expected_files)}
            if completeness > 0:
                return {**_label_status(1, "partial", completeness), "matched_files": matched_files, "wrong_files": wrong_files, "unreadable_files": unreadable_files, "entry_count": entry_count, "expected_files": len(expected_files)}
            status = "directory_only" if entry_count else "no_progress"
            return {**_label_status(0, status, 0.0), "matched_files": matched_files, "wrong_files": wrong_files, "unreadable_files": unreadable_files, "entry_count": entry_count, "expected_files": len(expected_files)}
    except Exception as exc:
        return {"status": "hard_negative", "label": -1, "completeness": 0.0, "error": str(exc)}
    return _label_status(0, "no_oracle", 0.0)


def _read_archive_hashes(path: Path, fmt: str) -> dict[str, str]:
    return _read_archive_hash_info(path, fmt)["hashes"]


def _read_archive_entry_infos(path: Path, fmt: str) -> dict[str, Any]:
    """Extract per-entry size+crc32 from repaired output, matching production verification."""
    normalized = _normalize_format(fmt)
    if normalized == "zip":
        try:
            with zipfile.ZipFile(path) as archive:
                entries = [name for name in archive.namelist() if not name.endswith("/")]
                sizes = {}
                crcs = {}
                for info in archive.infolist():
                    if info.is_dir():
                        continue
                    sizes[info.filename] = int(info.file_size)
                    crcs[info.filename] = int(info.CRC) & 0xFFFFFFFF
            return {"entries": entries, "sizes": sizes, "crcs": crcs}
        except Exception:
            return {"entries": [], "sizes": {}, "crcs": {}}
    if normalized == "tar":
        try:
            with tarfile.open(path) as archive:
                entries = [m.name for m in archive.getmembers() if m.isfile()]
                sizes = {m.name: int(m.size) for m in archive.getmembers() if m.isfile()}
            return {"entries": entries, "sizes": sizes, "crcs": {}}
        except Exception:
            return {"entries": [], "sizes": {}, "crcs": {}}
    return {"entries": [], "sizes": {}, "crcs": {}}


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
        "zip_variant": record.get("zip_variant") or source_derivation.get("zip_variant"),
        "zip_container_tags": record.get("zip_container_tags") or source_derivation.get("zip_container_tags"),
        "zip_structure_features": record.get("zip_structure_features") or source_derivation.get("zip_structure_features"),
        "structure_targeted_profile": bool(record.get("structure_targeted_profile", False)),
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
            "zip_variant",
            "zip_container_tags",
            "zip_tool",
            "zip_method",
            "zip_level",
            "zip_structure_features",
            "zip_split",
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
        self.write_payload(_debug_event_payload(event, record, extra))

    def write_payload(self, payload: dict[str, Any]) -> None:
        if self.path is None:
            return
        with self.path.open("a", encoding="utf-8") as handle:
            handle.write(json.dumps(payload, ensure_ascii=False, sort_keys=True, default=str) + "\n")


class _QueueDebugEvents(_DebugEvents):
    def __init__(self, queue: Any):
        super().__init__(None, truncate=False)
        self.queue = queue

    def write(self, event: str, record: dict[str, Any], **extra: Any) -> None:
        self.queue.put({"message_type": "debug_event", "payload": _debug_event_payload(event, record, extra)})


def _debug_event_payload(event: str, record: dict[str, Any], extra: dict[str, Any]) -> dict[str, Any]:
    return {
        "event": event,
        "time": time.time(),
        "sample_id": record.get("sample_id"),
        "material_format": record.get("material_format"),
        "format": record.get("format"),
        "source_archive_name": record.get("source_archive_name"),
        "damaged_file_name": record.get("damaged_file_name"),
        **extra,
    }


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
