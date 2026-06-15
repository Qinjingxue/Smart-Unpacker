from __future__ import annotations

import argparse
import json
from collections import Counter, defaultdict
from pathlib import Path
from typing import Any

from repair_training.core.datasets import read_jsonl, write_json, write_jsonl
from repair_training.core.diagnosis_gnn.actionable_roots import (
    ACTIONABLE_ROOT_SEMANTICS,
    ROOT_HYPOTHESIS_TRAINING_OBJECTIVE,
    modules_for_root,
)
from sunpack.model_runtime.diagnosis.root_cases import ROOT_CASES, canonical_root_case


SCHEMA = "hgt_guidance_hard_negative_v1"


def main(argv: list[str] | None = None) -> int:
    args = _parser().parse_args(argv)
    reports = read_jsonl(args.guidance_paths)
    probe_rows, hard_rows, summary = build_hard_negative_rows(
        reports,
        strategy=str(args.strategy or ""),
        root_top_n=int(args.root_top_n),
        hard_rank_cutoff=int(args.hard_rank_cutoff),
        hard_score_min=float(args.hard_score_min),
        min_improvement=float(args.min_improvement),
    )
    output = Path(args.output)
    output.mkdir(parents=True, exist_ok=True)
    write_jsonl(output / "hgt_guidance_probe_rows.jsonl", probe_rows)
    write_jsonl(output / "hgt_guidance_hard_negatives.jsonl", hard_rows)
    write_json(output / "hgt_guidance_hard_negative_summary.json", summary)
    print(json.dumps({"output": str(output), **summary}, ensure_ascii=False, sort_keys=True))
    return 0


def build_hard_negative_rows(
    reports: list[dict[str, Any]],
    *,
    strategy: str = "",
    root_top_n: int = 10,
    hard_rank_cutoff: int = 3,
    hard_score_min: float = 0.50,
    min_improvement: float = 0.01,
) -> tuple[list[dict[str, Any]], list[dict[str, Any]], dict[str, Any]]:
    probe_rows: list[dict[str, Any]] = []
    hard_rows: list[dict[str, Any]] = []
    root_counts: Counter[str] = Counter()
    hard_root_counts: Counter[str] = Counter()
    module_counts: Counter[str] = Counter()
    module_positive_counts: Counter[str] = Counter()
    module_failed_counts: Counter[str] = Counter()
    state_count = 0
    positive_state_count = 0

    for report in reports:
        selected_strategy = _select_strategy(report, strategy)
        if not selected_strategy:
            continue
        sample_id = str(report.get("sample_id") or "")
        initial_recovery = _float(selected_strategy.get("initial_recovery"))
        for step in selected_strategy.get("history") or []:
            if not isinstance(step, dict):
                continue
            state_count += 1
            recovery_before = _float((step.get("recovery") or {}).get("score"))
            module_results = _module_results(step, recovery_before=recovery_before)
            root_results = _root_results(step, module_results, root_top_n=root_top_n)
            best_delta = max([row["recovery_delta"] for row in root_results] or [0.0])
            if best_delta > min_improvement:
                positive_state_count += 1
            graph_sample_id = _graph_sample_id(sample_id, step)
            for result in root_results:
                root = result["candidate_root"]
                root_counts[root] += 1
                for module in result.get("attempted_modules") or []:
                    module_counts[module] += 1
                    if result["recovery_delta"] > min_improvement:
                        module_positive_counts[module] += 1
                    if result.get("materialization_failed_count"):
                        module_failed_counts[module] += 1
                hard_negative = (
                    int(result.get("root_rank") or 999) <= hard_rank_cutoff
                    and float(result.get("hgt_score") or 0.0) >= hard_score_min
                    and result["recovery_delta"] <= min_improvement
                    and best_delta > min_improvement
                )
                probe = {
                    "schema_version": SCHEMA,
                    "graph_sample_id": graph_sample_id,
                    "source_sample_id": sample_id,
                    "state_digest": str(step.get("state_digest") or ""),
                    "round": int(step.get("round") or 0),
                    "strategy_topk": int(selected_strategy.get("topk") or 0),
                    "candidate_root": root,
                    "root_rank": int(result.get("root_rank") or 0),
                    "hgt_score": float(result.get("hgt_score") or 0.0),
                    "probe_action": "hgt_guided_module_family",
                    "probe_action_modules": list(result.get("attempted_modules") or []),
                    "best_module": str(result.get("best_module") or ""),
                    "recovery_before": recovery_before,
                    "recovery_after": float(result.get("recovery_after") or recovery_before),
                    "recovery_delta": float(result.get("recovery_delta") or 0.0),
                    "ak_consistency_delta": float(result.get("recovery_delta") or 0.0),
                    "evidence_delta": float(result.get("recovery_delta") or 0.0),
                    "materialization_failed_count": int(result.get("materialization_failed_count") or 0),
                    "patch_state_count": int(result.get("patch_state_count") or 0),
                    "hard_negative": hard_negative,
                    "diagnosis_semantics": ACTIONABLE_ROOT_SEMANTICS,
                    "training_objective": ROOT_HYPOTHESIS_TRAINING_OBJECTIVE,
                }
                probe_rows.append(probe)
                if hard_negative:
                    hard_root_counts[root] += 1
                    hard_rows.append({
                        **probe,
                        "truth_labels": list(report.get("truth_labels") or []),
                        "hgt_top_roots": list(step.get("hgt_top_roots") or [])[:10],
                        "allowed_modules": list(step.get("allowed_modules") or [])[:20],
                        "best_available_delta": best_delta,
                    })

    summary = {
        "schema_version": SCHEMA,
        "reports": len(reports),
        "states": state_count,
        "positive_states": positive_state_count,
        "probe_rows": len(probe_rows),
        "hard_negative_rows": len(hard_rows),
        "hard_negative_rate": len(hard_rows) / max(1, len(probe_rows)),
        "root_counts": dict(sorted(root_counts.items())),
        "hard_root_counts": dict(hard_root_counts.most_common()),
        "top_modules": dict(module_counts.most_common(30)),
        "positive_modules": dict(module_positive_counts.most_common(30)),
        "failed_modules": dict(module_failed_counts.most_common(30)),
    }
    return probe_rows, hard_rows, summary


def _select_strategy(report: dict[str, Any], strategy: str) -> dict[str, Any]:
    strategies = report.get("strategies") if isinstance(report.get("strategies"), dict) else {}
    if strategy and isinstance(strategies.get(strategy), dict):
        return strategies[strategy]
    numeric = sorted(
        (int(key), value)
        for key, value in strategies.items()
        if str(key).isdigit() and isinstance(value, dict)
    )
    return numeric[-1][1] if numeric else {}


def _module_results(step: dict[str, Any], *, recovery_before: float) -> dict[str, dict[str, Any]]:
    output: dict[str, dict[str, Any]] = {}
    for item in step.get("tried_modules") or []:
        if not isinstance(item, dict):
            continue
        module = str(item.get("module_name") or "")
        if not module:
            continue
        best_after = recovery_before
        patch_state_count = 0
        materialization_failed_count = 0
        for candidate in item.get("candidates") or []:
            if not isinstance(candidate, dict):
                continue
            if candidate.get("has_repaired_state"):
                patch_state_count += 1
                best_after = max(best_after, _float((candidate.get("recovery") or {}).get("score"), default=recovery_before))
            elif candidate.get("status") == "materialization_failed":
                materialization_failed_count += 1
        output[module] = {
            "module_name": module,
            "recovery_after": best_after,
            "recovery_delta": best_after - recovery_before,
            "patch_state_count": patch_state_count,
            "materialization_failed_count": materialization_failed_count,
        }
    return output


def _root_results(step: dict[str, Any], module_results: dict[str, dict[str, Any]], *, root_top_n: int) -> list[dict[str, Any]]:
    rows: list[dict[str, Any]] = []
    for rank, item in enumerate(step.get("hgt_top_roots") or [], start=1):
        if rank > root_top_n or not isinstance(item, dict):
            break
        root = canonical_root_case(str(item.get("root_case") or ""))
        if not root:
            continue
        modules = [module for module in modules_for_root(root) if module in module_results]
        if not modules:
            modules = []
        best = None
        for module in modules:
            result = module_results[module]
            if best is None or result["recovery_delta"] > best["recovery_delta"]:
                best = result
        if best is None:
            best = {"module_name": "", "recovery_after": 0.0, "recovery_delta": 0.0, "patch_state_count": 0, "materialization_failed_count": 0}
        rows.append({
            "candidate_root": root,
            "root_rank": rank,
            "hgt_score": _float(item.get("score")),
            "attempted_modules": modules,
            "best_module": best["module_name"],
            "recovery_after": _float(best.get("recovery_after")),
            "recovery_delta": _float(best.get("recovery_delta")),
            "patch_state_count": sum(int(module_results[module].get("patch_state_count") or 0) for module in modules),
            "materialization_failed_count": sum(int(module_results[module].get("materialization_failed_count") or 0) for module in modules),
        })
    return rows


def _graph_sample_id(sample_id: str, step: dict[str, Any]) -> str:
    round_index = int(step.get("round") or 0)
    if round_index <= 1:
        return sample_id
    digest = str(step.get("state_digest") or "")[:12]
    return f"{sample_id}::round:{round_index}::state:{digest}"


def _float(value: Any, default: float = 0.0) -> float:
    try:
        return float(value)
    except (TypeError, ValueError):
        return float(default)


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Build hard-negative root probe rows from real HGT-guided repair rollouts.")
    parser.add_argument("--guidance-paths", required=True, help="hgt_repair_guidance_paths.jsonl")
    parser.add_argument("--output", required=True)
    parser.add_argument("--strategy", default="", help="Top-k strategy to analyze; default uses largest available top-k.")
    parser.add_argument("--root-top-n", type=int, default=len(ROOT_CASES))
    parser.add_argument("--hard-rank-cutoff", type=int, default=3)
    parser.add_argument("--hard-score-min", type=float, default=0.50)
    parser.add_argument("--min-improvement", type=float, default=0.01)
    return parser


if __name__ == "__main__":
    raise SystemExit(main())
