from __future__ import annotations

import argparse
import json
import shutil
import subprocess
import sys
import time
from collections import Counter, defaultdict
from datetime import datetime
from pathlib import Path
from types import SimpleNamespace
from typing import Any, Iterable


ROOT = Path(__file__).resolve().parents[2]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from sunpack.support import repair_trace  # noqa: E402

import importlib.util  # noqa: E402
from repair_training.core.run_layout import create_evaluation_run_dir, latest_training_dataset, update_run_manifest  # noqa: E402


AB_SCRIPT = ROOT / "repair_training" / "evaluation" / "runtime_policy_ab.py"
DEFAULT_DATASET = latest_training_dataset()


def _load_ab_module():
    spec = importlib.util.spec_from_file_location("evaluate_runtime_policy_ab", AB_SCRIPT)
    if spec is None or spec.loader is None:
        raise RuntimeError(f"cannot load runtime AB script: {AB_SCRIPT}")
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


ab = _load_ab_module()


def main() -> int:
    parser = argparse.ArgumentParser(description="Compare production-aligned training rows against real runtime ZIP model policy probe rows.")
    parser.add_argument("--dataset", default=str(DEFAULT_DATASET))
    parser.add_argument("--sample-count", type=int, default=12)
    parser.add_argument("--profiles", default="")
    parser.add_argument("--seed", type=int, default=37)
    parser.add_argument("--case-timeout-seconds", type=float, default=30.0)
    parser.add_argument("--run-timeout-seconds", type=float, default=0.0)
    parser.add_argument("--collector-timeout-seconds", type=float, default=0.0)
    parser.add_argument("--max-rounds", type=int, default=6)
    parser.add_argument("--workers", type=int, default=2)
    parser.add_argument("--run-dir", default="", help="Evaluation run directory.")
    parser.add_argument("--run-name", default="policy_env_compare")
    parser.add_argument("--keep-temp", action="store_true", help="Keep tmp workspace after the report is written.")
    parser.add_argument("--workspace", default="")
    parser.add_argument("--output-json", default="")
    parser.add_argument("--output-jsonl", default="")
    parser.add_argument("--skip-collector", action="store_true", help="Use existing --training-jsonl instead of running collect_repair_plan_data.py.")
    parser.add_argument("--training-jsonl", default="")
    parser.add_argument("--collector-materialize-all", action=argparse.BooleanOptionalAction, default=True, help="Collect all runtime-visible candidates for strict environment alignment.")
    parser.add_argument("--collector-branch-top-k", type=int, default=0)
    parser.add_argument("--collector-materialize-top-k", type=int, default=0)
    parser.add_argument("--progress", action="store_true")
    args = parser.parse_args()

    started = time.perf_counter()
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    run_dir = create_evaluation_run_dir(args.run_dir or None, run_name=args.run_name)
    report_dir = run_dir / "reports"
    output_json = Path(args.output_json) if args.output_json else report_dir / f"policy_env_compare_{timestamp}.json"
    output_jsonl = Path(args.output_jsonl) if args.output_jsonl else report_dir / f"policy_env_compare_{timestamp}.jsonl"
    output_json.parent.mkdir(parents=True, exist_ok=True)
    output_jsonl.parent.mkdir(parents=True, exist_ok=True)
    if not args.workspace:
        args.workspace = str(run_dir / "tmp" / "policy_env_compare_workspace")
    workspace = Path(args.workspace)
    workspace.mkdir(parents=True, exist_ok=True)

    profile_filters = [item.strip() for item in str(args.profiles or "").split(",") if item.strip()]
    _progress(args, "select_samples:start", dataset=str(Path(args.dataset)), sample_count=args.sample_count, profiles=profile_filters)
    records = ab.sample_records(
        Path(args.dataset),
        sample_count=max(1, int(args.sample_count or 1)),
        seed=int(args.seed or 0),
        profile_filters=profile_filters,
    )
    _progress(args, "select_samples:done", selected=len(records))
    manifest = workspace / f"selected_samples_{timestamp}.jsonl"
    _write_jsonl(manifest, records)

    runtime_jsonl = workspace / f"runtime_model_rows_{timestamp}.jsonl"
    _progress(args, "runtime_probe:start", output=str(runtime_jsonl), workers=args.workers)
    runtime_rows = run_runtime_probe(args, records, runtime_jsonl)
    _progress(args, "runtime_probe:done", rows=len(runtime_rows))
    probe_events = read_probe_events(runtime_rows)
    path_filter_json = workspace / f"runtime_selected_paths_{timestamp}.json"
    runtime_selected_paths = _runtime_sample_selected_paths(probe_events)
    for row in runtime_rows:
        sample_id = str(row.get("sample_id") or "")
        if sample_id:
            runtime_selected_paths.setdefault(sample_id, [])
    path_filter_json.write_text(
        json.dumps(runtime_selected_paths, ensure_ascii=False, indent=2, sort_keys=True),
        encoding="utf-8",
    )
    args.path_filter_json = str(path_filter_json)

    if args.skip_collector:
        training_jsonl = Path(args.training_jsonl)
        if not training_jsonl.is_file():
            raise SystemExit("--skip-collector requires --training-jsonl")
        training_summary: dict[str, Any] = {"skipped_collector": True, "training_jsonl": str(training_jsonl)}
    else:
        _progress(args, "collector:start", manifest=str(manifest), materialize_all=bool(args.collector_materialize_all))
        training_jsonl, training_summary = run_training_collector(args, manifest, workspace, timestamp)
        _progress(args, "collector:done", training_jsonl=str(training_jsonl), success_rows=training_summary.get("success_rows"))

    _progress(args, "read_training:start", training_jsonl=str(training_jsonl))
    training_rows = read_jsonl(training_jsonl)
    _progress(args, "read_training:done", rows=len(training_rows))
    _progress(args, "compare:start", probe_events=len(probe_events))
    comparison_rows = compare_training_runtime(training_rows, probe_events)
    _write_jsonl(output_jsonl, comparison_rows)

    summary = summarize_comparison(comparison_rows, runtime_rows, training_summary)
    summary.update({
        "run_dir": str(run_dir),
        "dataset": str(Path(args.dataset)),
        "sample_count": len(records),
        "profiles": profile_filters,
        "seed": int(args.seed or 0),
        "selected_manifest": str(manifest),
        "training_jsonl": str(training_jsonl),
        "runtime_jsonl": str(runtime_jsonl),
        "comparison_jsonl": str(output_jsonl),
        "wall_seconds": round(time.perf_counter() - started, 3),
    })
    output_json.write_text(json.dumps(summary, ensure_ascii=False, indent=2, sort_keys=True), encoding="utf-8")
    update_run_manifest(
        run_dir,
        kind="policy_env_compare",
        dataset=str(Path(args.dataset)),
        reports={"summary": str(output_json), "rows": str(output_jsonl)},
        parameters={
            "sample_count": args.sample_count,
            "seed": args.seed,
            "profiles": profile_filters,
            "max_rounds": args.max_rounds,
            "workers": args.workers,
        },
        ended_at=datetime.now().isoformat(timespec="seconds"),
    )
    if not args.keep_temp:
        shutil.rmtree(run_dir / "tmp", ignore_errors=True)
    print(json.dumps(summary, ensure_ascii=False, indent=2, sort_keys=True))
    return 0


def run_training_collector(args: argparse.Namespace, manifest: Path, workspace: Path, timestamp: str) -> tuple[Path, dict[str, Any]]:
    success = workspace / f"training_success_{timestamp}.jsonl"
    failure = workspace / f"training_failure_{timestamp}.jsonl"
    summary = workspace / f"training_summary_{timestamp}.json"
    cmd = [
        sys.executable,
        str(ROOT / "repair_training" / "collect_runtime_repair_graph.py"),
        "--manifest",
        str(manifest),
        "--formats",
        "zip",
        "--success-output",
        str(success),
        "--failure-output",
        str(failure),
        "--summary-output",
        str(summary),
        "--workspace",
        str(workspace / "collector_workspace"),
        "--workers",
        str(max(1, int(args.workers or 1))),
        "--max-rounds",
        str(max(1, int(args.max_rounds or 1))),
        "--max-states",
        str(max(1, int(args.max_rounds or 1)) * (16 if bool(getattr(args, "collector_materialize_all", True)) else 4)),
        "--branch-top-k",
        str(max(1, int(args.collector_branch_top_k or (8 if bool(getattr(args, "collector_materialize_all", True)) else 2)))),
        "--case-timeout-seconds",
        str(max(1.0, float(args.case_timeout_seconds or 30.0))),
        "--no-pretty",
    ]
    if bool(getattr(args, "collector_materialize_all", True)):
        cmd.extend([
            "--materialize-top-k",
            str(max(1, int(args.collector_materialize_top_k or 128))),
        ])
    else:
        cmd.extend([
            "--materialize-top-k",
            str(max(1, int(args.collector_materialize_top_k or 8))),
        ])
    path_filter_json = str(getattr(args, "path_filter_json", "") or "")
    if path_filter_json:
        cmd.extend(["--path-filter-json", path_filter_json])
    if args.progress:
        cmd.append("--progress")
    timeout = _collector_timeout_seconds(args)
    started = time.perf_counter()
    try:
        completed = subprocess.run(cmd, cwd=str(ROOT), text=True, capture_output=True, timeout=timeout if timeout > 0 else None)
    except subprocess.TimeoutExpired as exc:
        raise SystemExit(
            "collector timed out\n"
            f"timeout_seconds: {timeout}\n"
            f"elapsed_seconds: {round(time.perf_counter() - started, 3)}\n"
            f"command: {' '.join(cmd)}\n"
            f"stdout:\n{exc.stdout or ''}\n"
            f"stderr:\n{exc.stderr or ''}"
        )
    if completed.returncode != 0:
        raise SystemExit(
            "collector failed\n"
            f"command: {' '.join(cmd)}\n"
            f"stdout:\n{completed.stdout}\n"
            f"stderr:\n{completed.stderr}"
        )
    payload = json.loads(summary.read_text(encoding="utf-8")) if summary.is_file() else {}
    return success, payload


def run_runtime_probe(args: argparse.Namespace, records: list[dict[str, Any]], output_jsonl: Path) -> list[dict[str, Any]]:
    runtime_args = SimpleNamespace(
        dataset=str(Path(args.dataset)),
        sample_count=len(records),
        profiles=str(args.profiles or ""),
        seed=int(args.seed or 0),
        case_timeout_seconds=float(args.case_timeout_seconds or 30.0),
        run_timeout_seconds=float(args.run_timeout_seconds or 0.0),
        max_rounds=int(args.max_rounds or 6),
        workers=int(args.workers or 1),
        parallel_mode="worker_pool",
        workspace=str(Path(args.workspace) / "runtime_workspace"),
        output_json="",
        output_jsonl=str(output_jsonl),
        disable_repair_cache=False,
        progress=bool(args.progress),
        enable_policy_probe=True,
    )
    rows: list[dict[str, Any]] = []
    jobs = [(index, record, ab.RUN_MODES[1]) for index, record in enumerate(records)]
    output_jsonl.parent.mkdir(parents=True, exist_ok=True)
    with output_jsonl.open("w", encoding="utf-8") as handle:
        for row in ab.run_jobs(jobs, runtime_args):
            rows.append(row)
            handle.write(json.dumps(row, ensure_ascii=False, sort_keys=True) + "\n")
            _progress(args, "runtime_probe:row", sample_id=row.get("sample_id"), status=row.get("terminal_status"), wall=row.get("wall_seconds"), probe_events=row.get("probe_event_count"))
    return rows


def _collector_timeout_seconds(args: argparse.Namespace) -> float:
    configured = float(getattr(args, "collector_timeout_seconds", 0.0) or 0.0)
    if configured > 0:
        return configured
    sample_count = max(1, int(getattr(args, "sample_count", 1) or 1))
    case_timeout = max(1.0, float(getattr(args, "case_timeout_seconds", 30.0) or 30.0))
    multiplier = 3.0 if bool(getattr(args, "collector_materialize_all", True)) else 1.5
    return max(60.0, sample_count * case_timeout * multiplier)


def _progress(args: argparse.Namespace, event: str, **payload: Any) -> None:
    if not bool(getattr(args, "progress", False)):
        return
    record = {"event": event, "time": round(time.time(), 3), **payload}
    print(json.dumps(record, ensure_ascii=False, sort_keys=True), flush=True)


def compare_training_runtime(training_rows: list[dict[str, Any]], probe_events: list[dict[str, Any]]) -> list[dict[str, Any]]:
    training_by_query = _training_queries(training_rows)
    runtime_requests = [event for event in probe_events if event.get("event") == "policy_probe_request"]
    decisions = _decisions_by_query(probe_events)
    runtime_paths = _runtime_paths_by_query(runtime_requests, decisions)
    rows: list[dict[str, Any]] = []
    for request in runtime_requests:
        sample_id = _sample_id_from_run_id(str(request.get("run_id") or ""))
        round_index = int(request.get("round", 0) or 0)
        runtime_path = runtime_paths.get(str(request.get("query_id") or ""), ())
        key = (sample_id, round_index, runtime_path)
        training = training_by_query.get(key, {})
        runtime_candidates = request.get("candidate_payloads") if isinstance(request.get("candidate_payloads"), list) else []
        training_candidates = training.get("candidates") if isinstance(training.get("candidates"), list) else []
        runtime_keys = {_candidate_signature(candidate) for candidate in runtime_candidates if isinstance(candidate, dict)}
        training_keys = {_candidate_signature(candidate) for candidate in training_candidates if isinstance(candidate, dict)}
        decision = decisions.get(str(request.get("query_id") or ""), {})
        selected = decision.get("selected_candidate") if isinstance(decision.get("selected_candidate"), dict) else {}
        best = training.get("best_candidate") if isinstance(training.get("best_candidate"), dict) else {}
        rows.append({
            "sample_id": sample_id,
            "round": round_index,
            "runtime_path_signatures": list(runtime_path),
            "training_path_signatures": list(training.get("path_signatures") or []),
            "runtime_query_id": request.get("query_id"),
            "training_query_id": training.get("query_id", ""),
            "runtime_candidate_count": len(runtime_candidates),
            "training_candidate_count": len(training_candidates),
            "training_all_candidate_count": int(training.get("all_candidate_count") or len(training_candidates)),
            "training_excluded_no_output_count": int(training.get("excluded_no_output_count") or 0),
            "candidate_overlap_count": len(runtime_keys & training_keys),
            "candidate_missing_in_runtime": sorted(training_keys - runtime_keys),
            "candidate_extra_in_runtime": sorted(runtime_keys - training_keys),
            "candidate_set_hash_runtime": request.get("candidate_set_hash") or repair_trace.canonical_hash(sorted(runtime_keys)),
            "candidate_set_hash_training": repair_trace.canonical_hash(sorted(training_keys)),
            "runtime_context_hash": request.get("runtime_context_hash") or "",
            "training_runtime_context_hashes": sorted(set(training.get("runtime_context_hashes") or [])),
            "runtime_selected_signature": _candidate_signature(selected),
            "training_best_signature": _candidate_signature(best),
            "selection_matches_training_best": bool(selected and best and _candidate_signature(selected) == _candidate_signature(best)),
            "feature_missing_sections": _feature_missing_sections(runtime_candidates),
            "feature_key_diff": _feature_key_diff(training_candidates, runtime_candidates),
            "policy_decision_status": (decision.get("policy") or {}).get("decision_status") if isinstance(decision.get("policy"), dict) else "",
            "policy_fallback_reason": (decision.get("policy") or {}).get("fallback_reason") if isinstance(decision.get("policy"), dict) else "",
        })
    return rows


def _training_queries(rows: list[dict[str, Any]]) -> dict[tuple[str, int, tuple[str, ...]], dict[str, Any]]:
    action_by_row_id = {
        str(row.get("action_row_id") or ""): row
        for row in rows
        if row.get("row_type") != "terminal" and row.get("action_row_id")
    }
    path_cache: dict[str, tuple[str, ...]] = {}
    grouped: dict[tuple[str, int, tuple[str, ...]], list[dict[str, Any]]] = defaultdict(list)
    for row in rows:
        if row.get("row_type") == "terminal":
            continue
        sample_id = str(row.get("sample_id") or "")
        if not sample_id:
            continue
        path = _training_state_path(row, action_by_row_id, path_cache)
        grouped[(sample_id, int(row.get("round", 0) or 0), path)].append(row)
    output: dict[tuple[str, int, tuple[str, ...]], dict[str, Any]] = {}
    for key, items in grouped.items():
        model_items = [row for row in items if _training_row_is_runtime_branchable(row)]
        candidates = [_training_candidate_payload(row) for row in model_items]
        best_pool = model_items or items
        best_row = max(best_pool, key=_training_return_value) if best_pool else {}
        output[key] = {
            "query_id": str(items[0].get("query_id") or "") if items else "",
            "candidates": candidates,
            "all_candidate_count": len(items),
            "excluded_no_output_count": max(0, len(items) - len(model_items)),
            "best_candidate": _training_candidate_payload(best_row) if best_row else {},
            "path_signatures": list(key[2]),
            "runtime_context_hashes": [
                repair_trace.canonical_hash((row.get("stable_features") or {}).get("runtime_context") or {})
                for row in model_items
                if isinstance(row.get("stable_features"), dict)
            ],
        }
    return output


def _training_state_path(
    row: dict[str, Any],
    action_by_row_id: dict[str, dict[str, Any]],
    cache: dict[str, tuple[str, ...]],
) -> tuple[str, ...]:
    state_id = str(row.get("state_id") or "")
    if state_id in cache:
        return cache[state_id]
    chain: list[str] = []
    seen: set[str] = set()
    parent_id = str(row.get("parent_action_row_id") or "")
    while parent_id and parent_id not in seen:
        seen.add(parent_id)
        parent = action_by_row_id.get(parent_id)
        if not parent:
            break
        chain.append(_candidate_signature(_training_candidate_payload(parent)))
        parent_id = str(parent.get("parent_action_row_id") or "")
    path = tuple(reversed([item for item in chain if item]))
    cache[state_id] = path
    return path


def _runtime_paths_by_query(
    requests: list[dict[str, Any]],
    decisions: dict[str, dict[str, Any]],
) -> dict[str, tuple[str, ...]]:
    by_run: dict[str, list[dict[str, Any]]] = defaultdict(list)
    for request in requests:
        by_run[str(request.get("run_id") or "")].append(request)
    output: dict[str, tuple[str, ...]] = {}
    for run_id, run_requests in by_run.items():
        path: list[str] = []
        for request in sorted(run_requests, key=lambda item: int(item.get("round", 0) or 0)):
            query_id = str(request.get("query_id") or "")
            output[query_id] = tuple(path)
            decision = decisions.get(query_id, {})
            selected = decision.get("selected_candidate") if isinstance(decision.get("selected_candidate"), dict) else {}
            signature = _candidate_signature(selected)
            if signature:
                path.append(signature)
    return output


def _runtime_sample_selected_paths(events: list[dict[str, Any]]) -> dict[str, list[str]]:
    requests = [event for event in events if event.get("event") == "policy_probe_request"]
    decisions = _decisions_by_query(events)
    by_run: dict[str, list[dict[str, Any]]] = defaultdict(list)
    for request in requests:
        by_run[str(request.get("run_id") or "")].append(request)
    output: dict[str, list[str]] = {}
    for run_id, run_requests in by_run.items():
        sample_id = _sample_id_from_run_id(run_id)
        path: list[str] = []
        for request in sorted(run_requests, key=lambda item: int(item.get("round", 0) or 0)):
            decision = decisions.get(str(request.get("query_id") or ""), {})
            selected = decision.get("selected_candidate") if isinstance(decision.get("selected_candidate"), dict) else {}
            signature = _candidate_signature(selected)
            if signature:
                path.append(signature)
        if sample_id:
            output[sample_id] = path
    return output


def _training_row_is_runtime_branchable(row: dict[str, Any]) -> bool:
    if row.get("no_output_reason") or str(row.get("label_status") or "") == "no_output":
        return False
    if row.get("branchable") is False:
        return False
    return True


def _training_candidate_payload(row: dict[str, Any]) -> dict[str, Any]:
    stable = row.get("stable_features") if isinstance(row.get("stable_features"), dict) else {}
    return {
        "candidate_id": row.get("candidate_id"),
        "module_name": row.get("module_name") or row.get("module"),
        "repair_name": row.get("repair_name"),
        "native_key": row.get("native_key"),
        "native_target": row.get("native_target"),
        "candidate_status": row.get("candidate_status"),
        "patch_facts": row.get("patch_facts"),
        "validation_details": row.get("validation_details"),
        "runtime_context": stable.get("runtime_context") if isinstance(stable.get("runtime_context"), dict) else {},
        "candidate_proposal": stable.get("candidate_proposal") if isinstance(stable.get("candidate_proposal"), dict) else {},
    }


def _training_return_value(row: dict[str, Any]) -> float:
    rl = row.get("rl") if isinstance(row.get("rl"), dict) else {}
    for key in ("single_path_robust_return", "future_return", "terminal_reward"):
        try:
            return float(rl.get(key))
        except (TypeError, ValueError):
            pass
    try:
        return float(row.get("label", 0) or 0)
    except (TypeError, ValueError):
        return 0.0


def _decisions_by_query(events: list[dict[str, Any]]) -> dict[str, dict[str, Any]]:
    output = {}
    for event in events:
        if event.get("event") == "policy_probe_decision":
            output[str(event.get("query_id") or "")] = event
    return output


def _candidate_signature(candidate: dict[str, Any]) -> str:
    if not isinstance(candidate, dict) or not candidate:
        return ""
    proposal = candidate.get("candidate_proposal") if isinstance(candidate.get("candidate_proposal"), dict) else {}
    validation = proposal.get("validation_details") if isinstance(proposal.get("validation_details"), dict) else candidate.get("validation_details")
    policy = validation.get("policy") if isinstance(validation, dict) else ""
    facts = proposal.get("patch_facts") or candidate.get("patch_facts") or []
    return "|".join([
        str(candidate.get("module_name") or candidate.get("module") or ""),
        str(candidate.get("repair_name") or ""),
        str(candidate.get("native_target") or ""),
        str(policy or ""),
        ",".join(str(item) for item in facts or []),
    ])


def _feature_missing_sections(candidates: list[Any]) -> list[str]:
    missing: set[str] = set()
    for candidate in candidates:
        if not isinstance(candidate, dict):
            continue
        for section in ("runtime_context", "candidate_proposal"):
            if not isinstance(candidate.get(section), dict):
                missing.add(section)
    return sorted(missing)


def _feature_key_diff(training_candidates: list[Any], runtime_candidates: list[Any]) -> dict[str, Any]:
    training_context_keys = _nested_key_union(candidate.get("runtime_context") for candidate in training_candidates if isinstance(candidate, dict))
    runtime_context_keys = _nested_key_union(candidate.get("runtime_context") for candidate in runtime_candidates if isinstance(candidate, dict))
    training_candidate_keys = _nested_key_union(candidate.get("candidate_proposal") for candidate in training_candidates if isinstance(candidate, dict))
    runtime_candidate_keys = _nested_key_union(candidate.get("candidate_proposal") for candidate in runtime_candidates if isinstance(candidate, dict))
    return {
        "runtime_context_missing_in_runtime": sorted(training_context_keys - runtime_context_keys)[:80],
        "runtime_context_extra_in_runtime": sorted(runtime_context_keys - training_context_keys)[:80],
        "candidate_proposal_missing_in_runtime": sorted(training_candidate_keys - runtime_candidate_keys)[:80],
        "candidate_proposal_extra_in_runtime": sorted(runtime_candidate_keys - training_candidate_keys)[:80],
    }


def _nested_key_union(values: Iterable[Any]) -> set[str]:
    keys: set[str] = set()
    for value in values:
        keys.update(_nested_keys(value))
    return keys


def _nested_keys(value: Any, prefix: str = "") -> set[str]:
    if not isinstance(value, dict):
        return set()
    output: set[str] = set()
    for key, item in value.items():
        name = f"{prefix}.{key}" if prefix else str(key)
        output.add(name)
        if isinstance(item, dict):
            output.update(_nested_keys(item, name))
    return output


def summarize_comparison(rows: list[dict[str, Any]], runtime_rows: list[dict[str, Any]], training_summary: dict[str, Any]) -> dict[str, Any]:
    missing_sections = Counter(section for row in rows for section in row.get("feature_missing_sections") or [])
    candidate_mismatch = [row for row in rows if row.get("candidate_missing_in_runtime") or row.get("candidate_extra_in_runtime")]
    selection_mismatch = [row for row in rows if row.get("training_best_signature") and not row.get("selection_matches_training_best")]
    mode_summary = ab.summarize_mode(runtime_rows)
    profile_summary = _profile_alignment_summary(rows)
    return {
        "training_summary": training_summary,
        "runtime_model_summary": mode_summary,
        "runtime_query_count": len(rows),
        "candidate_set_mismatch_count": len(candidate_mismatch),
        "selection_mismatch_count": len(selection_mismatch),
        "feature_missing_sections": dict(missing_sections),
        "missing_module_by_profile": profile_summary["missing_module_by_profile"],
        "extra_module_by_profile": profile_summary["extra_module_by_profile"],
        "candidate_overlap_by_profile": profile_summary["candidate_overlap_by_profile"],
        "runtime_missing_route_flag_by_profile": profile_summary["runtime_missing_route_flag_by_profile"],
        "avg_candidate_overlap_ratio": _avg(
            float(row.get("candidate_overlap_count", 0) or 0) / max(1.0, float(row.get("training_candidate_count", 0) or 0))
            for row in rows
        ),
        "top_candidate_mismatch_samples": candidate_mismatch[:20],
        "top_selection_mismatch_samples": selection_mismatch[:20],
    }


def _profile_alignment_summary(rows: list[dict[str, Any]]) -> dict[str, Any]:
    missing: dict[str, Counter] = defaultdict(Counter)
    extra: dict[str, Counter] = defaultdict(Counter)
    overlaps: dict[str, list[float]] = defaultdict(list)
    missing_flags: dict[str, Counter] = defaultdict(Counter)
    for row in rows:
        profile = _profile_from_sample_id(str(row.get("sample_id") or ""))
        for signature in row.get("candidate_missing_in_runtime") or []:
            missing[profile][str(signature).split("|", 1)[0]] += 1
        for signature in row.get("candidate_extra_in_runtime") or []:
            extra[profile][str(signature).split("|", 1)[0]] += 1
        overlaps[profile].append(float(row.get("candidate_overlap_count", 0) or 0) / max(1.0, float(row.get("training_candidate_count", 0) or 0)))
        diff = row.get("feature_key_diff") if isinstance(row.get("feature_key_diff"), dict) else {}
        for key in diff.get("runtime_context_missing_in_runtime") or []:
            text = str(key)
            marker = "analysis_native_probe.route_evidence_"
            if text.startswith(marker):
                missing_flags[profile][text[len(marker):]] += 1
    return {
        "missing_module_by_profile": {profile: dict(counter.most_common(20)) for profile, counter in missing.items()},
        "extra_module_by_profile": {profile: dict(counter.most_common(20)) for profile, counter in extra.items()},
        "candidate_overlap_by_profile": {profile: round(sum(values) / len(values), 6) for profile, values in overlaps.items() if values},
        "runtime_missing_route_flag_by_profile": {profile: dict(counter.most_common(30)) for profile, counter in missing_flags.items()},
    }


def _profile_from_sample_id(sample_id: str) -> str:
    marker = "_zip_"
    if marker in sample_id:
        tail = "zip_" + sample_id.split(marker, 1)[1]
        parts = tail.split("_")
        if len(parts) > 1 and parts[-1].isdigit():
            return "_".join(parts[:-1])
        return tail
    return "unknown"


def read_probe_events(runtime_rows: list[dict[str, Any]]) -> list[dict[str, Any]]:
    events: list[dict[str, Any]] = []
    for row in runtime_rows:
        path = Path(str(row.get("probe_path") or ""))
        events.extend(read_jsonl(path))
    return events


def read_jsonl(path: Path) -> list[dict[str, Any]]:
    if not path.is_file():
        return []
    rows = []
    with path.open("r", encoding="utf-8") as handle:
        for line in handle:
            if not line.strip():
                continue
            try:
                item = json.loads(line)
            except json.JSONDecodeError:
                continue
            if isinstance(item, dict):
                rows.append(item)
    return rows


def _write_jsonl(path: Path, rows: Iterable[dict[str, Any]]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", encoding="utf-8") as handle:
        for row in rows:
            handle.write(json.dumps(row, ensure_ascii=False, sort_keys=True, default=str))
            handle.write("\n")


def _sample_id_from_run_id(value: str) -> str:
    suffix = ":zip_model_policy"
    if value.endswith(suffix):
        return value[: -len(suffix)]
    return value.split(":", 1)[0]


def _avg(values: Iterable[float]) -> float:
    items = list(values)
    return round(sum(items) / len(items), 6) if items else 0.0


if __name__ == "__main__":
    raise SystemExit(main())
