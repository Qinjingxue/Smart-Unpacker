from __future__ import annotations

import argparse
import json
import os
import time
from collections import Counter, defaultdict
from dataclasses import replace
from pathlib import Path
from typing import Any

from repair_training.build_policy_transition_rows import _job_from_row
from repair_training.core.datasets import read_jsonl, write_json, write_jsonl
from sunpack.repair.scheduler import RepairScheduler


def main(argv: list[str] | None = None) -> int:
    args = _parse_args(argv)
    if args.diagnosis_model_dir:
        os.environ["SUNPACK_DIAGNOSIS_GNN_MODEL_DIR"] = str(Path(args.diagnosis_model_dir).resolve())
    if args.policy_model_dir:
        os.environ["SUNPACK_POLICY_TRANSFORMER_MODEL_DIR"] = str(Path(args.policy_model_dir).resolve())
    if args.device:
        os.environ["SUNPACK_MODEL_DEVICE"] = args.device
    rows = list(read_jsonl(args.input))[: max(0, int(args.limit or 0)) or None]
    if args.shard_count > 1:
        rows = [row for index, row in enumerate(rows) if index % args.shard_count == args.shard_index]
    output = Path(args.output)
    output.mkdir(parents=True, exist_ok=True)
    paths_file = output / f"paths_shard_{args.shard_index}.jsonl"
    if args.no_resume and paths_file.exists():
        paths_file.unlink()
    completed = set()
    if paths_file.exists():
        for row in read_jsonl(paths_file):
            completed.add(str(row.get("sample_id") or ""))
    scheduler = RepairScheduler(_scheduler_config(args))
    started = time.time()
    with paths_file.open("a", encoding="utf-8") as handle:
        for local_index, row in enumerate(rows):
            sample_id = str(row.get("sample_id") or row.get("id") or f"sample_{local_index}")
            if sample_id in completed:
                continue
            result = _evaluate_row(
                row,
                row_index=local_index,
                scheduler=scheduler,
                workspace=Path(args.workspace) / f"shard_{args.shard_index}" / str(local_index),
                max_rounds=args.max_rounds,
                max_sample_seconds=args.max_sample_seconds,
            )
            handle.write(json.dumps(result, ensure_ascii=False, sort_keys=True) + "\n")
            handle.flush()
            print(
                f"shard={args.shard_index} done={local_index + 1}/{len(rows)} "
                f"rounds={result['rounds']} unique={result['unique_modules']} "
                f"stop={result['stopped']} elapsed={time.time() - started:.1f}s",
                flush=True,
            )
    return 0


def aggregate(output: str | Path) -> dict[str, Any]:
    output = Path(output)
    results: list[dict[str, Any]] = []
    for path in sorted(output.glob("paths_shard_*.jsonl")):
        results.extend(read_jsonl(path))
    write_jsonl(output / "paths.jsonl", results)
    by_profile: dict[str, list[dict[str, Any]]] = defaultdict(list)
    for row in results:
        by_profile[str(row.get("profile") or "unknown")].append(row)
    profile_summary = []
    for profile, items in sorted(by_profile.items()):
        action_counts = Counter(action for row in items for action in row.get("actions") or [])
        module_counts = Counter(module for row in items for module in row.get("modules") or [])
        n = max(1, len(items))
        mean_rounds = sum(float(row.get("rounds") or 0) for row in items) / n
        mean_unique = sum(float(row.get("unique_modules") or 0) for row in items) / n
        stop_rate = sum(1 for row in items if row.get("stopped")) / n
        timeout_rate = sum(1 for row in items if "sample_timeout" in (row.get("errors") or [])) / n
        # Runtime repair currently relies on graph exploration convergence more than a trusted
        # per-round oracle score, so "not fixed" here means no complete/accept signal appeared.
        fixed_rate = sum(1 for row in items if row.get("complete")) / n
        converged_not_fixed = mean_rounds >= 20 and mean_unique >= 8 and fixed_rate < 0.5
        profile_summary.append(
            {
                "profile": profile,
                "samples": len(items),
                "runtime_errors": sum(1 for row in items if row.get("errors") and not row.get("actions")),
                "mean_rounds": round(mean_rounds, 3),
                "mean_unique_modules": round(mean_unique, 3),
                "stopped_rate": round(stop_rate, 6),
                "timeout_rate": round(timeout_rate, 6),
                "complete_rate": round(fixed_rate, 6),
                "converged_not_fixed": converged_not_fixed,
                "action_counts": dict(action_counts.most_common()),
                "top_modules": dict(module_counts.most_common(10)),
                "examples": [
                    str(row.get("sample_id") or "")
                    for row in sorted(items, key=lambda item: (-int(item.get("rounds") or 0), -int(item.get("unique_modules") or 0)))[:3]
                ],
            }
        )
    profile_summary = sorted(profile_summary, key=lambda item: (not item["converged_not_fixed"], -item["mean_rounds"], -item["mean_unique_modules"]))
    write_json(output / "profile_summary.json", profile_summary)
    summary = {
        "samples": len(results),
        "valid_with_actions": sum(1 for row in results if row.get("actions")),
        "runtime_errors": sum(1 for row in results if row.get("errors") and not row.get("actions")),
        "mean_rounds": round(sum(float(row.get("rounds") or 0) for row in results) / max(1, len(results)), 3),
        "mean_unique_modules": round(sum(float(row.get("unique_modules") or 0) for row in results) / max(1, len(results)), 3),
        "stopped_rate": round(sum(1 for row in results if row.get("stopped")) / max(1, len(results)), 6),
        "complete_rate": round(sum(1 for row in results if row.get("complete")) / max(1, len(results)), 6),
        "action_counts": dict(Counter(action for row in results for action in row.get("actions") or []).most_common()),
        "top_modules": dict(Counter(module for row in results for module in row.get("modules") or []).most_common(20)),
        "converged_not_fixed_profiles": [row for row in profile_summary if row.get("converged_not_fixed")],
    }
    write_json(output / "summary.json", summary)
    return summary


def _evaluate_row(
    row: dict[str, Any],
    *,
    row_index: int,
    scheduler: RepairScheduler,
    workspace: Path,
    max_rounds: int,
    max_sample_seconds: float,
) -> dict[str, Any]:
    sample_id = str(row.get("sample_id") or row.get("id") or f"sample_{row_index}")
    started = time.time()
    actions: list[str] = []
    modules: list[str] = []
    errors: list[str] = []
    stopped = False
    terminal_action = ""
    stop_reason = ""
    try:
        job = _job_from_row(row, row_index=row_index, format_name=str(row.get("format") or "zip"), workspace=workspace)
        if job is None:
            raise RuntimeError("job_from_row_returned_none")
        history: dict[str, Any] = {"items": []}
        for round_index in range(max_rounds):
            if max_sample_seconds > 0 and time.time() - started > max_sample_seconds:
                errors.append("sample_timeout")
                break
            result = scheduler.repair(job)
            diagnosis = result.diagnosis if isinstance(result.diagnosis, dict) else {}
            loop = diagnosis.get("policy_loop") if isinstance(diagnosis.get("policy_loop"), dict) else {}
            action = _latest_action(loop)
            action_type = str(action.get("action_type") or "")
            module_name = str(action.get("module_name") or "")
            if action_type:
                actions.append(action_type)
            if module_name:
                modules.append(module_name)
            terminal_action = str(loop.get("terminal_action") or terminal_action or "")
            stop_reason = str(loop.get("stop_reason") or stop_reason or "")
            history["items"].append({"diagnosis": diagnosis})
            knowledge = dict(job.knowledge or {})
            knowledge["repair"] = {"history": history}
            job = replace(job, repair_history=history, knowledge=knowledge, attempts=round_index + 1)
            if result.repaired_state is not None:
                job = replace(job, archive_state=result.repaired_state)
            if action_type == "stop" or terminal_action == "stop":
                stopped = True
                break
    except Exception as exc:
        errors.append(type(exc).__name__ + ": " + str(exc)[:240])
    return {
        "sample_id": sample_id,
        "profile": _profile(row),
        "rounds": len(actions),
        "actions": actions,
        "modules": modules,
        "unique_modules": len(set(modules)),
        "stopped": stopped,
        "terminal_action": terminal_action,
        "stop_reason": stop_reason,
        "complete": False,
        "errors": errors,
        "elapsed_seconds": round(time.time() - started, 3),
    }


def _latest_action(loop: dict[str, Any]) -> dict[str, Any]:
    rounds = loop.get("rounds") if isinstance(loop.get("rounds"), list) else []
    for row in reversed(rounds):
        if isinstance(row, dict) and isinstance(row.get("graph_action"), dict):
            return dict(row["graph_action"])
    if isinstance(loop.get("graph_action"), dict):
        return dict(loop["graph_action"])
    return {}


def _profile(row: dict[str, Any]) -> str:
    metadata = row.get("metadata") if isinstance(row.get("metadata"), dict) else {}
    raw = metadata.get("raw_damage_record") if isinstance(metadata.get("raw_damage_record"), dict) else {}
    source = row.get("source_identity") if isinstance(row.get("source_identity"), dict) else {}
    source_id = str(source.get("source_archive_id") or "")
    roots = []
    for label in row.get("oracle_damage") or []:
        if isinstance(label, dict):
            text = str(label.get("label") or "")
            if text.startswith("field:"):
                roots.append(text[6:])
    root_key = "+".join(sorted(set(roots))) if roots else str(metadata.get("damage_profile") or raw.get("damage_profile") or "unknown_roots")
    return f"{source_id}|{root_key}" if source_id else root_key


def _scheduler_config(args: argparse.Namespace) -> dict[str, Any]:
    return {
        "policy": {
            "enabled": True,
            "provider_package": "sunpack_repair_models",
            "strict_provider_errors": False,
            "graph_stop_stale_patience": int(args.stale_patience),
            "min_best_recovery_improvement": 0.0,
        },
        "max_repair_rounds_per_task": int(args.max_rounds),
        "max_repair_seconds_per_task": int(args.max_sample_seconds),
    }


def _parse_args(argv: list[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Run policy runtime eval and aggregate profiles.")
    parser.add_argument("--input", required=True)
    parser.add_argument("--output", required=True)
    parser.add_argument("--workspace", required=True)
    parser.add_argument("--diagnosis-model-dir", default="")
    parser.add_argument("--policy-model-dir", default="")
    parser.add_argument("--device", default="cuda")
    parser.add_argument("--limit", type=int, default=200)
    parser.add_argument("--max-rounds", type=int, default=30)
    parser.add_argument("--max-sample-seconds", type=float, default=90.0)
    parser.add_argument("--stale-patience", type=int, default=20)
    parser.add_argument("--shard-index", type=int, default=0)
    parser.add_argument("--shard-count", type=int, default=1)
    parser.add_argument("--no-resume", action="store_true")
    parser.add_argument("--aggregate-only", action="store_true")
    args = parser.parse_args(argv)
    if args.aggregate_only:
        summary = aggregate(args.output)
        print(json.dumps(summary, ensure_ascii=False, indent=2))
        raise SystemExit(0)
    return args


if __name__ == "__main__":
    raise SystemExit(main())
