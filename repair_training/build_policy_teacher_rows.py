from __future__ import annotations

import argparse
from concurrent.futures import FIRST_COMPLETED, ProcessPoolExecutor, wait
from pathlib import Path
from typing import Any

from repair_training.core.datasets import read_jsonl, write_json, write_jsonl
from repair_training.core.repair_policy_transformer.teacher import DEFAULT_TEACHER_BUDGET, build_policy_teacher_samples


def main(argv: list[str] | None = None) -> int:
    args = _parser().parse_args(argv)
    budget = {
        "max_expansions": args.max_expansions,
        "max_depth": args.max_depth,
        "module_branch_k": args.module_branch_k,
        "rollout_depth": args.rollout_depth,
        "epsilon": args.epsilon,
        "teacher_stale_patience": args.teacher_stale_patience,
        "stop_margin": args.stop_margin,
        "teacher_exploration_rate": args.teacher_exploration_rate,
        "teacher_second_best_rate": args.teacher_second_best_rate,
        "teacher_bad_branch_rate": args.teacher_bad_branch_rate,
        "teacher_undo_probe_rate": args.teacher_undo_probe_rate,
        "teacher_force_undo_after_stale": args.teacher_force_undo_after_stale,
        "teacher_undo_margin": args.teacher_undo_margin,
        "teacher_bad_branch_depth_min": args.teacher_bad_branch_depth_min,
        "teacher_bad_branch_depth_max": args.teacher_bad_branch_depth_max,
        "undo_positive_target_ratio": args.undo_positive_target_ratio,
        "best_tie_margin": args.best_tie_margin,
        "runtime_action_top_n": args.runtime_action_top_n,
        "teacher_deep_eval_top_n": args.teacher_deep_eval_top_n,
        "teacher_shallow_eval_top_n": args.teacher_shallow_eval_top_n,
    }
    input_rows = read_jsonl(args.input)
    rows = _build_rows_parallel(
        input_rows,
        format_name=args.format,
        budget=budget,
        workspace=args.workspace or None,
        recovery_mode=args.recovery_mode,
        runtime_rollout=not args.no_runtime_rollout,
        workers=max(1, int(args.workers or 1)),
    )
    output = Path(args.output)
    write_jsonl(output, [row.to_dict() for row in rows])
    action_count = sum(len(row.actions) for row in rows)
    promising = sum(1 for row in rows if row.has_promising_future)
    row_dicts = [row.to_dict() for row in rows]
    undo_high = sum(1 for row in row_dicts if _undo_is_best(row))
    undo_top2 = sum(1 for row in row_dicts if _undo_is_top_k(row, 2))
    bad_branch = sum(1 for row in row_dicts if row.get("branch_bad"))
    consecutive_undo = _consecutive_undo_rows(row_dicts)
    write_json(Path(args.summary_output) if args.summary_output else output.with_name("policy_teacher_rows_summary.json"), {
        "rows": len(rows),
        "actions": action_count,
        "promising_future_rows": promising,
        "undo_best_rows": undo_high,
        "undo_top2_rows": undo_top2,
        "bad_branch_rows": bad_branch,
        "consecutive_undo_rows": consecutive_undo,
        "module_family_counts": _module_family_counts(row_dicts),
        "q_tie_group_counts": _q_tie_group_counts(row_dicts),
        "budget": budget,
        "workers": max(1, int(args.workers or 1)),
        "formats": sorted({row.format for row in rows}),
    })
    return 0


def _build_rows_parallel(
    input_rows: list[dict[str, Any]],
    *,
    format_name: str,
    budget: dict[str, Any],
    workspace: str,
    recovery_mode: str,
    runtime_rollout: bool,
    workers: int,
) -> list[Any]:
    if workers <= 1:
        return build_policy_teacher_samples(
            input_rows,
            format_name=format_name,
            budget=budget,
            workspace=workspace or None,
            recovery_mode=recovery_mode,
            runtime_rollout=runtime_rollout,
        )
    root = Path(workspace or "repair_training_policy_teacher_workspace")
    root.mkdir(parents=True, exist_ok=True)
    completed: dict[int, list[dict[str, Any]]] = {}
    with ProcessPoolExecutor(max_workers=workers) as pool:
        pending = {
            pool.submit(_worker_build_policy_teacher_rows, index, row, format_name, budget, str(root / f"worker_{index % workers}"), recovery_mode, runtime_rollout): index
            for index, row in enumerate(input_rows)
        }
        while pending:
            done, _ = wait(pending, return_when=FIRST_COMPLETED)
            for future in done:
                index = pending.pop(future)
                completed[index] = future.result()
    from repair_training.core.repair_policy_transformer.schema import sample_from_dict

    output = []
    for index in sorted(completed):
        output.extend(sample_from_dict(row) for row in completed[index])
    return output


def _worker_build_policy_teacher_rows(
    index: int,
    row: dict[str, Any],
    format_name: str,
    budget: dict[str, Any],
    workspace: str,
    recovery_mode: str,
    runtime_rollout: bool,
) -> list[dict[str, Any]]:
    samples = build_policy_teacher_samples(
        [row],
        format_name=format_name,
        budget={**dict(budget), "seed": int((budget or {}).get("seed", 13) or 13) + index},
        workspace=workspace,
        recovery_mode=recovery_mode,
        runtime_rollout=runtime_rollout,
    )
    return [sample.to_dict() for sample in samples]


def _undo_is_best(row: dict[str, Any]) -> bool:
    actions = row.get("actions") if isinstance(row.get("actions"), list) else []
    if not actions:
        return False
    if any(str(item.get("action_type") or "") == "undo" and item.get("best_action_set_member") for item in actions if isinstance(item, dict)):
        return True
    best = max(actions, key=lambda item: float(item.get("action_q_value") or 0.0))
    return str(best.get("action_type") or "") == "undo"


def _undo_is_top_k(row: dict[str, Any], k: int) -> bool:
    actions = row.get("actions") if isinstance(row.get("actions"), list) else []
    if any(str(item.get("action_type") or "") == "undo" and item.get("best_action_set_member") for item in actions if isinstance(item, dict)):
        return True
    ranked = sorted(actions, key=lambda item: float(item.get("action_q_value") or 0.0), reverse=True)
    return any(str(item.get("action_type") or "") == "undo" for item in ranked[:k])


def _consecutive_undo_rows(rows: list[dict[str, Any]]) -> int:
    count = 0
    previous_base = ""
    previous_undo = False
    for row in rows:
        base = str(row.get("sample_id") or "").split(":step:")[0]
        undo = _undo_is_best(row)
        if undo and previous_undo and base == previous_base:
            count += 1
        previous_base = base
        previous_undo = undo
    return count


def _module_family_counts(rows: list[dict[str, Any]]) -> dict[str, int]:
    counts: dict[str, int] = {}
    for row in rows:
        for action in row.get("actions") or []:
            if not isinstance(action, dict) or action.get("action_type") != "module":
                continue
            features = action.get("features") if isinstance(action.get("features"), dict) else {}
            family = str(features.get("module_family") or features.get("route_family") or action.get("module_name") or "")
            counts[family] = counts.get(family, 0) + 1
    return dict(sorted(counts.items(), key=lambda item: (-item[1], item[0])))


def _q_tie_group_counts(rows: list[dict[str, Any]]) -> dict[str, int]:
    counts: dict[str, int] = {}
    for row in rows:
        tie_count = sum(1 for action in row.get("actions") or [] if isinstance(action, dict) and action.get("best_action_set_member"))
        key = str(tie_count)
        counts[key] = counts.get(key, 0) + 1
    return dict(sorted(counts.items(), key=lambda item: int(item[0]) if item[0].isdigit() else 0))


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Build Q-labelled RepairGraph policy teacher rows.")
    parser.add_argument("--format", default="zip")
    parser.add_argument("--input", required=True)
    parser.add_argument("--output", required=True)
    parser.add_argument("--summary-output", default="")
    parser.add_argument("--max-expansions", type=int, default=int(DEFAULT_TEACHER_BUDGET["max_expansions"]))
    parser.add_argument("--max-depth", type=int, default=int(DEFAULT_TEACHER_BUDGET["max_depth"]))
    parser.add_argument("--module-branch-k", type=int, default=int(DEFAULT_TEACHER_BUDGET["module_branch_k"]))
    parser.add_argument("--rollout-depth", type=int, default=int(DEFAULT_TEACHER_BUDGET["rollout_depth"]))
    parser.add_argument("--epsilon", type=float, default=float(DEFAULT_TEACHER_BUDGET["epsilon"]))
    parser.add_argument("--teacher-stale-patience", type=int, default=int(DEFAULT_TEACHER_BUDGET["teacher_stale_patience"]))
    parser.add_argument("--stop-margin", type=float, default=float(DEFAULT_TEACHER_BUDGET["stop_margin"]))
    parser.add_argument("--teacher-exploration-rate", type=float, default=float(DEFAULT_TEACHER_BUDGET["teacher_exploration_rate"]))
    parser.add_argument("--teacher-second-best-rate", type=float, default=float(DEFAULT_TEACHER_BUDGET["teacher_second_best_rate"]))
    parser.add_argument("--teacher-bad-branch-rate", type=float, default=float(DEFAULT_TEACHER_BUDGET["teacher_bad_branch_rate"]))
    parser.add_argument("--teacher-undo-probe-rate", type=float, default=float(DEFAULT_TEACHER_BUDGET["teacher_undo_probe_rate"]))
    parser.add_argument("--teacher-force-undo-after-stale", type=int, default=int(DEFAULT_TEACHER_BUDGET["teacher_force_undo_after_stale"]))
    parser.add_argument("--teacher-undo-margin", type=float, default=float(DEFAULT_TEACHER_BUDGET["teacher_undo_margin"]))
    parser.add_argument("--teacher-bad-branch-depth-min", type=int, default=int(DEFAULT_TEACHER_BUDGET["teacher_bad_branch_depth_min"]))
    parser.add_argument("--teacher-bad-branch-depth-max", type=int, default=int(DEFAULT_TEACHER_BUDGET["teacher_bad_branch_depth_max"]))
    parser.add_argument("--undo-positive-target-ratio", type=float, default=float(DEFAULT_TEACHER_BUDGET["undo_positive_target_ratio"]))
    parser.add_argument("--best-tie-margin", type=float, default=float(DEFAULT_TEACHER_BUDGET["best_tie_margin"]))
    parser.add_argument("--runtime-action-top-n", type=int, default=int(DEFAULT_TEACHER_BUDGET["runtime_action_top_n"]))
    parser.add_argument("--teacher-deep-eval-top-n", type=int, default=int(DEFAULT_TEACHER_BUDGET["teacher_deep_eval_top_n"]))
    parser.add_argument("--teacher-shallow-eval-top-n", type=int, default=int(DEFAULT_TEACHER_BUDGET["teacher_shallow_eval_top_n"]))
    parser.add_argument("--workspace", default="")
    parser.add_argument("--recovery-mode", choices=["policy_light", "policy_full", "training_oracle"], default="policy_full")
    parser.add_argument("--workers", type=int, default=1)
    parser.add_argument("--no-runtime-rollout", action="store_true")
    return parser


if __name__ == "__main__":
    raise SystemExit(main())
