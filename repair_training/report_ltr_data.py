from __future__ import annotations

import argparse
import json
import math
import statistics
from collections import Counter, defaultdict
from pathlib import Path
from typing import Any


DEFAULT_DATASET_DIR = Path("repair_training") / "datasets"
DEFAULT_MODEL_ROOT = Path("repair_training") / "models"
DEFAULT_OUTPUT = DEFAULT_DATASET_DIR / "ltr_data_quality_report.json"
DEFAULT_POLICY_REPORT = DEFAULT_DATASET_DIR / "offline_policy_evaluation.json"


def main(argv: list[str] | None = None) -> int:
    args = _parser().parse_args(argv)
    rows = _load_rows(_input_paths(args.input, Path(args.dataset_dir)))
    report = _build_report(rows, Path(args.model_root), _policy_report_paths(args.policy_report))
    output = Path(args.output)
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_text(json.dumps(report, ensure_ascii=False, indent=2, sort_keys=True, default=str), encoding="utf-8")
    if args.markdown:
        _markdown_path(output).write_text(_markdown_report(report), encoding="utf-8")
    print(json.dumps(report, ensure_ascii=False, sort_keys=True, default=str))
    return 0


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Summarize repair-plan LTR dataset quality.")
    parser.add_argument("--dataset-dir", default=str(DEFAULT_DATASET_DIR), help="Directory containing LTR JSONL datasets.")
    parser.add_argument("--input", action="append", default=[], help="Input JSONL file. Repeatable; defaults to --dataset-dir/*.jsonl.")
    parser.add_argument("--model-root", default=str(DEFAULT_MODEL_ROOT), help="Root containing trained LTR model summaries.")
    parser.add_argument("--output", default=str(DEFAULT_OUTPUT), help="JSON report output path.")
    parser.add_argument("--policy-report", action="append", default=[], help="Optional offline policy evaluator JSON output. Repeatable; defaults to repair_training/datasets/offline_policy_evaluation.json if present.")
    parser.add_argument("--markdown", action="store_true", help="Also write a compact Markdown report next to --output.")
    return parser


def _policy_report_paths(values: list[str]) -> list[Path]:
    paths = [Path(value) for value in values if value] if values else [DEFAULT_POLICY_REPORT]
    return [path for path in paths if path.is_file()]


def _input_paths(inputs: list[str], dataset_dir: Path) -> list[Path]:
    paths = [Path(item) for item in inputs] if inputs else sorted(dataset_dir.glob("*.jsonl"))
    output = []
    for path in paths:
        name = path.name.lower()
        if not path.is_file():
            continue
        if name.startswith("repair_plan_collect_events") or name.endswith(".pretty.json"):
            continue
        if name.startswith("predictions"):
            continue
        output.append(path)
    return output


def _load_rows(paths: list[Path]) -> list[dict[str, Any]]:
    rows: list[dict[str, Any]] = []
    for path in paths:
        with path.open("r", encoding="utf-8") as handle:
            for line in handle:
                line = line.strip()
                if not line:
                    continue
                try:
                    row = json.loads(line)
                except json.JSONDecodeError:
                    continue
                if isinstance(row, dict) and ("query_id" in row or "sample_id" in row):
                    row["_source_file"] = str(path)
                    rows.append(row)
    return rows


def _build_report(rows: list[dict[str, Any]], model_root: Path, policy_report_paths: list[Path] | None = None) -> dict[str, Any]:
    terminal_rows = [row for row in rows if row.get("row_type") == "terminal"]
    rows = [row for row in rows if row.get("row_type") != "terminal"]
    query_groups: dict[str, list[dict[str, Any]]] = defaultdict(list)
    for row in rows:
        query_groups[str(row.get("query_id") or row.get("sample_id") or "")].append(row)
    label_counts = Counter(str(int(row.get("label", 0) or 0)) for row in rows)
    status_counts = Counter(str(row.get("label_status") or "unknown") for row in rows)
    format_counts = Counter(_row_format(row) for row in rows)
    module_counts = Counter(str(row.get("module") or "<none>") for row in rows)
    source_counts = Counter(str(row.get("_source_file") or "") for row in rows)
    query_sizes = [len(items) for items in query_groups.values()]
    best_labels = [max((int(row.get("label", 0) or 0) for row in items), default=0) for items in query_groups.values()]
    no_candidate_rows = sum(1 for row in rows if str(row.get("label_status") or "") == "no_candidates")
    failed_rows = sum(1 for row in rows if str(row.get("label_status") or "") in {"failed", "timeout"})
    timeout_rows = sum(1 for row in rows if str(row.get("label_status") or "") == "timeout")
    partial_rows = sum(1 for row in rows if int(row.get("label", 0) or 0) == 1 or str(row.get("label_status") or "") == "partial")
    state_progress_rows = sum(1 for row in rows if int(row.get("label", 0) or 0) == 2 or str(row.get("label_status") or "") == "state_progress")
    total = max(1, len(rows))
    model_metrics = _model_metrics(model_root, source_counts, len(rows), format_counts)
    rollout = _rollout_report(rows, query_groups)
    difficulty = _difficulty_report(rows, query_groups)
    recovery = _recovery_ratio_report(rows, query_groups)
    report = {
        "dataset": {
            "row_count": len(rows),
            "terminal_row_count": len(terminal_rows),
            "query_count": len(query_groups),
            "source_files": dict(sorted(source_counts.items())),
        },
        "terminal_status_distribution": dict(sorted(Counter(str(row.get("terminal_status") or row.get("label_status") or "unknown") for row in terminal_rows).items())),
        "label_distribution": dict(sorted(label_counts.items(), key=lambda item: int(item[0]))),
        "sample_best_label_distribution": dict(sorted(Counter(str(label) for label in best_labels).items(), key=lambda item: int(item[0]))),
        "label_status_distribution": dict(sorted(status_counts.items())),
        "format_distribution": dict(sorted(format_counts.items())),
        "module_distribution_top20": dict(module_counts.most_common(20)),
        "query_candidate_count": _series_summary(query_sizes),
        "query_candidate_count_distribution": dict(sorted(Counter(str(size) for size in query_sizes).items(), key=lambda item: int(item[0]))),
        "quality_ratios": {
            "partial_row_ratio": partial_rows / total,
            "state_progress_row_ratio": state_progress_rows / total,
            "no_candidate_row_ratio": no_candidate_rows / total,
            "timeout_or_failed_row_ratio": failed_rows / total,
        },
        "failure_signal_counts": {
            "no_candidate_rows": no_candidate_rows,
            "timeout_rows": timeout_rows,
            "failed_or_timeout_rows": failed_rows,
        },
        "format_detection_quality": _format_detection_quality(rows),
        "rollout": rollout,
        "rl_dataset": _rl_dataset_report(rows, terminal_rows),
        "difficulty": difficulty,
        "terminal_recovery": recovery,
        "zip_structure": _zip_structure_report(rows),
        "per_format": _per_format_report(rows, model_metrics),
        "model_metric_comparison": model_metrics,
        "model_top3_comparison": _model_top3_comparison(model_metrics),
        "policy_comparison": _policy_comparison(policy_report_paths or []),
        "repair_prior_dependency": _repair_prior_dependency(model_metrics),
    }
    report["warnings"] = _quality_warnings(report)
    return report


def _row_format(row: dict[str, Any]) -> str:
    if row.get("material_format"):
        return str(row["material_format"])
    stable = row.get("stable_features") if isinstance(row.get("stable_features"), dict) else {}
    state = stable.get("state") if isinstance(stable.get("state"), dict) else {}
    return str(row.get("format") or state.get("format") or "unknown")


def _per_format_report(rows: list[dict[str, Any]], model_metrics: dict[str, Any]) -> dict[str, Any]:
    by_format: dict[str, list[dict[str, Any]]] = defaultdict(list)
    for row in rows:
        by_format[_row_format(row)].append(row)
    output: dict[str, Any] = {}
    for fmt, items in sorted(by_format.items()):
        groups: dict[str, list[dict[str, Any]]] = defaultdict(list)
        for row in items:
            groups[str(row.get("query_id") or row.get("sample_id") or "")].append(row)
        query_sizes = [len(values) for values in groups.values()]
        labels = Counter(str(int(row.get("label", 0) or 0)) for row in items)
        statuses = Counter(str(row.get("label_status") or "unknown") for row in items)
        modules = Counter(str(row.get("module") or "<none>") for row in items)
        output[fmt] = {
            "row_count": len(items),
            "query_count": len(groups),
            "label_distribution": dict(sorted(labels.items(), key=lambda item: int(item[0]))),
            "label_status_distribution": dict(sorted(statuses.items())),
            "query_candidate_count": _series_summary(query_sizes),
            "query_candidate_count_distribution": dict(sorted(Counter(str(size) for size in query_sizes).items(), key=lambda item: int(item[0]))),
            "quality_ratios": _quality_ratios(items),
            "rollout": _rollout_report(items, groups),
            "difficulty": _difficulty_report(items, groups),
            "terminal_recovery": _recovery_ratio_report(items, groups),
            "module_distribution_top10": dict(modules.most_common(10)),
            "trainability": _format_trainability(items, groups),
            "model_metrics": _metrics_for_format(model_metrics, fmt),
        }
    return output


def _quality_ratios(rows: list[dict[str, Any]]) -> dict[str, float]:
    total = max(1, len(rows))
    return {
        "partial_row_ratio": sum(1 for row in rows if int(row.get("label", 0) or 0) == 1 or str(row.get("label_status") or "") == "partial") / total,
        "state_progress_row_ratio": sum(1 for row in rows if int(row.get("label", 0) or 0) == 2 or str(row.get("label_status") or "") == "state_progress") / total,
        "complete_row_ratio": sum(1 for row in rows if int(row.get("label", 0) or 0) == 3 or str(row.get("label_status") or "") == "complete") / total,
        "hard_negative_row_ratio": sum(1 for row in rows if int(row.get("label", 0) or 0) == -1 or str(row.get("label_status") or "") == "hard_negative") / total,
    }


def _rollout_report(rows: list[dict[str, Any]], query_groups: dict[str, list[dict[str, Any]]]) -> dict[str, Any]:
    episodes: dict[str, set[str]] = defaultdict(set)
    future_labels = Counter()
    immediate_future_disagreements = 0
    selected_rows = []
    selected_future_hits = 0
    label2_rows = 0
    label2_terminal_recovery_success = 0
    hard_negative_rows = 0
    hard_negative_future_failure = 0
    for row in rows:
        episode_id = str(row.get("episode_id") or row.get("sample_id") or "")
        state_id = str(row.get("state_id") or row.get("query_id") or "")
        if episode_id and state_id:
            episodes[episode_id].add(state_id)
        details = row.get("label_details") if isinstance(row.get("label_details"), dict) else {}
        immediate = int(details.get("immediate_label", row.get("label", 0)) or 0)
        future = int(details.get("future_best_label", immediate) or 0)
        future_labels[str(future)] += 1
        if immediate != future:
            immediate_future_disagreements += 1
        if bool(row.get("selected_by_current_system")):
            selected_rows.append(row)
        if immediate == 2:
            label2_rows += 1
            if _row_best_terminal_recovery_ratio(row) >= 0.999:
                label2_terminal_recovery_success += 1
        if immediate == -1:
            hard_negative_rows += 1
            if future <= 0:
                hard_negative_future_failure += 1
    for query, items in query_groups.items():
        if not items:
            continue
        best_future = max(int(((row.get("label_details") if isinstance(row.get("label_details"), dict) else {}) or {}).get("future_best_label", row.get("label", 0)) or 0) for row in items)
        selected = [row for row in items if bool(row.get("selected_by_current_system"))]
        if selected and int(((selected[0].get("label_details") if isinstance(selected[0].get("label_details"), dict) else {}) or {}).get("future_best_label", selected[0].get("label", 0)) or 0) == best_future:
            selected_future_hits += 1
    state_counts = [len(states) for states in episodes.values()]
    multi_round_queries = sum(1 for query in query_groups if ":r" in query and ":b" in query)
    return {
        "episode_count": len(episodes),
        "states_per_episode": _series_summary(state_counts),
        "multi_round_query_ratio": multi_round_queries / max(1, len(query_groups)),
        "future_best_label_distribution": dict(sorted(future_labels.items(), key=lambda item: int(item[0]))),
        "immediate_future_disagreement_ratio": immediate_future_disagreements / max(1, len(rows)),
        "selected_path_future_best_hit_rate": selected_future_hits / max(1, len(query_groups)),
        "state_progress_terminal_recovery_success_rate": label2_terminal_recovery_success / max(1, label2_rows),
        "hard_negative_future_failure_rate": hard_negative_future_failure / max(1, hard_negative_rows),
    }


def _rl_dataset_report(rows: list[dict[str, Any]], terminal_rows: list[dict[str, Any]]) -> dict[str, Any]:
    rl_rows = [row for row in rows if isinstance(row.get("rl"), dict)]
    if not rl_rows and not any(isinstance(row.get("rl"), dict) for row in terminal_rows):
        return {
            "available": False,
            "episode_count": 0,
            "transition_count": 0,
        }
    episodes = {str(row.get("episode_id") or row.get("sample_id") or "") for row in rl_rows if row.get("episode_id") or row.get("sample_id")}
    states = {str(_nested(row, "rl", "state_id") or row.get("state_id") or "") for row in rl_rows if _nested(row, "rl", "state_id") or row.get("state_id")}
    next_states = {str(_nested(row, "rl", "next_state_id") or "") for row in rl_rows if _nested(row, "rl", "next_state_id")}
    done_count = sum(1 for row in rl_rows if bool(_nested(row, "rl", "done")))
    observed_count = sum(1 for row in rl_rows if bool(_nested(row, "rl", "observed_transition")))
    terminal_ratios = [_as_float(_nested(row, "rl", "terminal_reward")) for row in rl_rows if _nested(row, "rl", "terminal_reward") is not None]
    immediate_rewards = [_as_float(_nested(row, "rl", "immediate_reward")) for row in rl_rows]
    rewards = [_as_float(_nested(row, "rl", "reward")) for row in rl_rows]
    future_returns = [_as_float(_nested(row, "rl", "future_return")) for row in rl_rows]
    return {
        "available": True,
        "episode_count": len(episodes),
        "state_count": len(states),
        "transition_count": len(rl_rows),
        "terminal_row_count": len(terminal_rows),
        "done_ratio": done_count / max(1, len(rl_rows)),
        "observed_transition_ratio": observed_count / max(1, len(rl_rows)),
        "observed_next_state_count": len(next_states),
        "immediate_reward": _series_summary_float(immediate_rewards),
        "reward": _series_summary_float(rewards),
        "future_return": _series_summary_float(future_returns),
        "terminal_recovery_ratio": _series_summary_float(terminal_ratios),
    }


def _policy_comparison(paths: list[Path]) -> dict[str, Any]:
    output: dict[str, Any] = {}
    for path in paths:
        try:
            payload = json.loads(path.read_text(encoding="utf-8"))
        except Exception:
            continue
        key = str(payload.get("name") or path.stem)
        output[key] = payload
    return output


def _recovery_ratio_report(rows: list[dict[str, Any]], query_groups: dict[str, list[dict[str, Any]]]) -> dict[str, Any]:
    ratios = [_row_recovery_ratio(row) for row in rows]
    best_ratios: list[float] = []
    top1_ratios: list[float] = []
    regrets: list[float] = []
    spreads: list[float] = []
    variable_queries = 0
    profile_counts: Counter[str] = Counter()
    best_module_counts: Counter[str] = Counter()
    worst_module_counts: Counter[str] = Counter()
    profile_module_regret: dict[tuple[str, str], list[float]] = defaultdict(list)
    profile_regret: dict[str, list[float]] = defaultdict(list)
    for items in query_groups.values():
        if not items:
            continue
        ranked = sorted(items, key=_row_recovery_ratio, reverse=True)
        best_row = ranked[0]
        worst_row = ranked[-1]
        best = _row_recovery_ratio(best_row)
        worst = _row_recovery_ratio(worst_row)
        spread = max(0.0, best - worst)
        selected = [row for row in items if bool(row.get("selected_by_current_system"))]
        top = selected[0] if selected else items[0]
        top_ratio = _row_recovery_ratio(top)
        regret = max(0.0, best - top_ratio)
        best_ratios.append(best)
        top1_ratios.append(top_ratio)
        regrets.append(regret)
        spreads.append(spread)
        if spread > 1e-9:
            variable_queries += 1
            profile = _damage_profile(best_row) or _damage_profile(worst_row) or "unknown"
            profile_counts[profile] += 1
            best_module_counts[_row_module(best_row)] += 1
            worst_module_counts[_row_module(worst_row)] += 1
            profile_regret[profile].append(regret)
            profile_module_regret[(profile, _row_module(top))].append(regret)
    return {
        "row_terminal_recovery_ratio": _series_summary_float(ratios),
        "query_best_recovery_ratio": _series_summary_float(best_ratios),
        "query_top1_recovery_ratio": _series_summary_float(top1_ratios),
        "query_top1_regret": _series_summary_float(regrets),
        "query_terminal_recovery_regret": _series_summary_float(regrets),
        "query_terminal_recovery_spread": _series_summary_float(spreads),
        "variable_terminal_recovery_query_count": variable_queries,
        "variable_terminal_recovery_query_ratio": variable_queries / max(1, len(query_groups)),
        "terminal_recovery_spread_distribution": _spread_distribution(spreads),
        "query_best_terminal_recovery_mean": statistics.mean(best_ratios) if best_ratios else 0.0,
        "query_top1_terminal_recovery_mean": statistics.mean(top1_ratios) if top1_ratios else 0.0,
        "query_terminal_recovery_regret_mean": statistics.mean(regrets) if regrets else 0.0,
        "query_terminal_recovery_regret_p90": _percentile_float(sorted(regrets), 0.90) if regrets else 0.0,
        "variable_recovery_profiles_top20": dict(profile_counts.most_common(20)),
        "best_recovery_modules_top20": dict(best_module_counts.most_common(20)),
        "worst_recovery_modules_top20": dict(worst_module_counts.most_common(20)),
        "profile_regret_top20": _regret_items(profile_regret),
        "profile_module_regret_top20": _regret_items(profile_module_regret),
        "positive_recovery_row_ratio": sum(1 for value in ratios if value > 0.0) / max(1, len(ratios)),
    }


def _row_recovery_ratio(row: dict[str, Any]) -> float:
    targets = row.get("training_targets") if isinstance(row.get("training_targets"), dict) else {}
    for key in ("terminal_recovery_ratio", "subtree_best_terminal_recovery_ratio"):
        if targets.get(key) is not None:
            return _clamp01(_as_float(targets.get(key)))
    if row.get("terminal_recovery_ratio") is not None:
        return _clamp01(_as_float(row.get("terminal_recovery_ratio")))
    details = row.get("label_details") if isinstance(row.get("label_details"), dict) else {}
    for key in ("terminal_recovery_ratio", "subtree_best_terminal_recovery_ratio"):
        if details.get(key) is not None:
            return _clamp01(_as_float(details.get(key)))
    label = int(row.get("label", 0) or 0)
    if label >= 3:
        return 1.0
    if label == 2:
        return 0.35
    if label == 1:
        return 0.2
    return 0.0


def _row_module(row: dict[str, Any]) -> str:
    return str(row.get("module") or _nested(row, "stable_features", "candidate", "module") or "<none>")


def _spread_distribution(values: list[float]) -> dict[str, int]:
    buckets = Counter()
    for value in values:
        if value >= 0.999:
            buckets[">=1.0"] += 1
        elif value >= 0.5:
            buckets[">=0.5"] += 1
        elif value >= 0.2:
            buckets[">=0.2"] += 1
        elif value > 0:
            buckets[">0"] += 1
        else:
            buckets["0"] += 1
    return dict(buckets)


def _regret_items(groups: dict[Any, list[float]]) -> list[dict[str, Any]]:
    items: list[dict[str, Any]] = []
    for key, values in groups.items():
        if not values:
            continue
        if isinstance(key, tuple):
            name = "|".join(str(part) for part in key)
        else:
            name = str(key)
        items.append({
            "key": name,
            "count": len(values),
            "mean_regret": statistics.mean(values),
            "p90_regret": _percentile_float(sorted(values), 0.90),
        })
    return sorted(items, key=lambda item: (float(item["mean_regret"]), int(item["count"])), reverse=True)[:20]


def _repair_prior_dependency(model_metrics: dict[str, Any]) -> dict[str, Any]:
    grouped: dict[str, dict[str, Any]] = defaultdict(dict)
    for key, metrics in model_metrics.items():
        if not isinstance(metrics, dict):
            continue
        view = str(metrics.get("feature_view") or Path(str(key)).name)
        scope = str(key).rsplit("/", 1)[0] if "/" in str(key) else str(metrics.get("format_scope") or "all")
        grouped[scope][view] = metrics
    output: dict[str, Any] = {}
    for scope, views in grouped.items():
        runtime = _model_ndcg_for_view(views, "runtime_only")
        prior = _model_ndcg_for_view(views, "runtime_plus_repair_prior")
        if runtime is None and prior is None:
            continue
        diff = None if runtime is None or prior is None else prior - runtime
        output[scope] = {
            "runtime_only_ndcg@1": runtime,
            "runtime_plus_repair_prior_ndcg@1": prior,
            "prior_minus_runtime_ndcg@1": diff,
            "prior_dependency_warning": bool(diff is not None and diff > 0.15),
        }
    return output


def _zip_structure_report(rows: list[dict[str, Any]]) -> dict[str, Any]:
    zip_rows = [row for row in rows if _row_format(row) == "zip" or _row_zip_variant(row)]
    if not zip_rows:
        return {
            "available": False,
            "zip_variant_distribution": {},
            "zip_variant_label_distribution": {},
            "zip_variant_terminal_recovery": {},
            "zip_variant_oracle_zero_count": {},
            "profile_by_zip_variant": {},
        }
    variant_counts: Counter[str] = Counter()
    label_by_variant: dict[str, Counter[str]] = defaultdict(Counter)
    recovery_by_variant: dict[str, list[float]] = defaultdict(list)
    zero_by_variant: Counter[str] = Counter()
    profile_by_variant: dict[str, Counter[str]] = defaultdict(Counter)
    targeted_by_variant: dict[str, Counter[str]] = defaultdict(Counter)
    for row in zip_rows:
        variant = _row_zip_variant(row)
        variant_counts[variant] += 1
        label_by_variant[variant][str(int(row.get("label", 0) or 0))] += 1
        ratio = _row_recovery_ratio(row)
        recovery_by_variant[variant].append(ratio)
        if ratio <= 0.0:
            zero_by_variant[variant] += 1
        profile = _damage_profile(row) or "unknown"
        profile_by_variant[variant][profile] += 1
        targeted_by_variant[variant][str(bool(row.get("structure_targeted_profile"))).lower()] += 1
    return {
        "available": True,
        "zip_variant_distribution": dict(variant_counts.most_common()),
        "zip_variant_label_distribution": {
            variant: dict(sorted(counts.items(), key=lambda item: int(item[0])))
            for variant, counts in sorted(label_by_variant.items())
        },
        "zip_variant_terminal_recovery": {
            variant: _series_summary_float(values)
            for variant, values in sorted(recovery_by_variant.items())
        },
        "zip_variant_oracle_zero_count": dict(sorted(zero_by_variant.items())),
        "profile_by_zip_variant": {
            variant: dict(counts.most_common(20))
            for variant, counts in sorted(profile_by_variant.items())
        },
        "structure_targeted_profile_by_variant": {
            variant: dict(sorted(counts.items()))
            for variant, counts in sorted(targeted_by_variant.items())
        },
    }


def _row_zip_variant(row: dict[str, Any]) -> str:
    for value in (
        row.get("zip_variant"),
        _nested(row, "source_derivation", "zip_variant"),
        _nested(row, "stable_features", "state", "source_derivation", "zip_variant"),
        _nested(row, "debug_context", "source_derivation", "zip_variant"),
    ):
        if value:
            return str(value)
    return "unknown"


def _model_ndcg_for_view(metrics: dict[str, Any], view: str) -> float | None:
    item = metrics.get(view) if isinstance(metrics.get(view), dict) else {}
    if not item:
        return None
    metric = item.get("metrics") if isinstance(item.get("metrics"), dict) else item
    if not isinstance(metric, dict):
        return None
    value = metric.get("ndcg@1")
    try:
        return None if value is None else float(value)
    except Exception:
        return None


def _as_float(value: Any) -> float:
    try:
        if value is None:
            return 0.0
        return float(value)
    except Exception:
        return 0.0


def _clamp01(value: float) -> float:
    return max(0.0, min(1.0, float(value or 0.0)))


def _difficulty_report(rows: list[dict[str, Any]], query_groups: dict[str, list[dict[str, Any]]]) -> dict[str, Any]:
    entropies: list[float] = []
    target_unique_counts: list[int] = []
    mixed_target_queries = 0
    hard_positive_queries = 0
    hard_partial_queries = 0
    teacher_wrong_future_best = 0
    teacher_considered = 0
    selected_future_hits = 0
    selected_considered = 0
    label2_rows = 0
    label2_terminal_recovery_complete = 0
    two_step_rows = 0
    two_step_success_rows = 0
    two_step_success_by_recovery_rows = 0
    deceptive_hard_negative_rows = 0
    profile_module_labels: dict[tuple[str, str], Counter[str]] = defaultdict(Counter)
    for row in rows:
        target = _terminal_target_label(row)
        tags = _difficulty_tags(row)
        details = row.get("label_details") if isinstance(row.get("label_details"), dict) else {}
        profile = _damage_profile(row)
        module = str(row.get("module") or _nested(row, "stable_features", "candidate", "module") or "")
        profile_module_labels[(profile, module)][str(int(row.get("label", 0) or 0))] += 1
        if int(row.get("label", 0) or 0) == 2:
            label2_rows += 1
            if _row_best_terminal_recovery_ratio(row) >= 0.999:
                label2_terminal_recovery_complete += 1
        if "two_step_repair" in tags or "two_step" in profile:
            two_step_rows += 1
            if int(details.get("future_best_label", row.get("label", 0)) or 0) >= 3:
                two_step_success_rows += 1
            if _row_best_terminal_recovery_ratio(row) >= 0.999:
                two_step_success_by_recovery_rows += 1
        if "deceptive_structural_success" in tags or "hash_mismatch_risk" in tags or int(row.get("label", 0) or 0) < 0:
            if target <= 0 or int(row.get("label", 0) or 0) < 0:
                deceptive_hard_negative_rows += 1
    for query, items in query_groups.items():
        if not items:
            continue
        targets = [_terminal_target_label(row) for row in items]
        unique = set(targets)
        target_unique_counts.append(len(unique))
        if len(unique) >= 2:
            mixed_target_queries += 1
        entropies.append(_entropy(targets))
        has_hard = any(_is_hard_negative(row) for row in items)
        has_positive = any(_terminal_target_label(row) > 1 for row in items)
        has_partial = any(int(row.get("label", 0) or 0) == 1 or str(row.get("label_status") or "") == "partial" for row in items)
        if has_hard and has_positive:
            hard_positive_queries += 1
        if has_hard and has_partial:
            hard_partial_queries += 1
        best_future = max(_future_value(row) for row in items)
        teacher_row = _teacher_top_row(items)
        if teacher_row is not None:
            teacher_considered += 1
            if _future_value(teacher_row) < best_future:
                teacher_wrong_future_best += 1
        selected = [row for row in items if bool(row.get("selected_by_current_system"))]
        if selected:
            selected_considered += 1
            if _future_value(selected[0]) >= best_future:
                selected_future_hits += 1
    purities: list[float] = []
    for labels in profile_module_labels.values():
        total = sum(labels.values())
        if total:
            purities.append(max(labels.values()) / total)
    query_count = max(1, len(query_groups))
    return {
        "query_target_entropy": _series_summary_float(entropies),
        "candidate_target_unique_count_distribution": dict(sorted(Counter(str(value) for value in target_unique_counts).items(), key=lambda item: int(item[0]))),
        "mixed_target_query_ratio": mixed_target_queries / query_count,
        "hard_negative_vs_positive_same_query_count": hard_positive_queries,
        "hard_negative_vs_positive_same_query_ratio": hard_positive_queries / query_count,
        "hard_negative_vs_partial_same_query_count": hard_partial_queries,
        "hard_negative_vs_partial_same_query_ratio": hard_partial_queries / query_count,
        "state_progress_terminal_recovery_complete_count": label2_terminal_recovery_complete,
        "state_progress_terminal_recovery_complete_rate": label2_terminal_recovery_complete / max(1, label2_rows),
        "teacher_top1_wrong_but_future_best_exists_count": teacher_wrong_future_best,
        "teacher_top1_wrong_but_future_best_exists_ratio": teacher_wrong_future_best / max(1, teacher_considered),
        "selected_path_future_best_hit_rate": selected_future_hits / max(1, selected_considered),
        "two_step_row_count": two_step_rows,
        "two_step_success_row_count": two_step_success_rows,
        "two_step_success_by_recovery_row_count": two_step_success_by_recovery_rows,
        "deceptive_hard_negative_row_count": deceptive_hard_negative_rows,
        "profile_module_label_purity": _series_summary_float(purities),
    }


def _difficulty_tags(row: dict[str, Any]) -> list[str]:
    state = _nested(row, "stable_features", "state")
    candidate = _nested(row, "stable_features", "candidate")
    values: list[Any] = []
    if isinstance(state, dict):
        values.extend(state.get("difficulty_tags") or [])
        values.append(state.get("damage_profile"))
    if isinstance(candidate, dict):
        values.extend(candidate.get("difficulty_tags") or [])
    values.extend(row.get("difficulty_tags") or [])
    profile = _damage_profile(row)
    if "two_step" in profile:
        values.append("two_step_repair")
    return [str(value) for value in values if value]


def _damage_profile(row: dict[str, Any]) -> str:
    explicit = str(_nested(row, "stable_features", "state", "damage_profile") or row.get("damage_profile") or "")
    if explicit:
        return explicit
    sample = str(row.get("sample_id") or row.get("episode_id") or "")
    known = (
        "zip_two_step_boundary_then_cd_rebuild",
        "zip_two_step_comment_fix_then_eocd_repair",
        "zip_two_step_local_header_then_cd_offset",
        "zip_two_step_drop_cd_with_eocd_noise",
        "zip_drop_central_directory_keep_local_headers",
        "zip_cd_offset_near_valid_wrong_entry",
        "zip_eocd_counts_wrong_but_cd_readable",
        "zip_local_header_crc_wrong_cd_correct",
        "zip_cd_crc_wrong_local_payload_correct",
        "zip_comment_overlap_eocd_shifted",
        "zip_duplicate_entries_conflicting_crc",
        "zip_data_descriptor_conflict",
        "zip_partial_cd_rebuild_then_payload_mismatch",
        "structural_boundary",
        "structural_header_tail",
        "structural_footer_tail",
        "zip_directory_only_bad_payload",
        "zip_rebuild_directory_keeps_bad_payload",
        "zip_quarantine_keeps_corrupted_entry",
        "zip_wrong_local_offset_extracts_valid_other_entry",
        "zip_crc_repair_masks_payload_mismatch",
        "zip_partial_recovery_wrong_hash_same_name",
        "zip_all_entry_payload_damage_with_directory",
        "zip_wrong_offset_content_overlap",
        "zip_eocd_cd_half_damaged",
        "zip_sfx_cd_damage",
        "zip_sfx_payload_damage",
        "zip_sfx_split_missing_volume",
        "zip_split_missing_middle_volume",
        "zip_split_tail_volume_truncated",
        "zip_data_descriptor_cd_conflict",
        "zip_data_descriptor_payload_bad",
        "zip_zip64_eocd_locator_bad",
        "zip_zip64_extra_size_mismatch",
        "zip_duplicate_entry_crc_conflict",
        "zip_non_utf8_filename_directory_rebuild",
        "zip_extra_field_length_bad",
        "zip_mixed_method_one_entry_bad",
    )
    for item in known:
        if item in sample:
            return item
    return ""


def _row_best_terminal_recovery_ratio(row: dict[str, Any]) -> float:
    details = row.get("label_details") if isinstance(row.get("label_details"), dict) else {}
    targets = row.get("training_targets") if isinstance(row.get("training_targets"), dict) else {}
    for key in ("subtree_best_terminal_recovery_ratio", "terminal_recovery_ratio"):
        if details.get(key) is not None:
            return _as_float(details.get(key))
    for key in ("subtree_best_terminal_recovery_ratio", "terminal_recovery_ratio"):
        if targets.get(key) is not None:
            return _as_float(targets.get(key))
    return _as_float(row.get("terminal_recovery_ratio"))


def _is_hard_negative(row: dict[str, Any]) -> bool:
    targets = row.get("training_targets") if isinstance(row.get("training_targets"), dict) else {}
    return int(row.get("label", 0) or 0) < 0 or str(targets.get("risk_class") or "").startswith("hard_negative")


def _terminal_target_label(row: dict[str, Any]) -> int:
    ratio = _row_recovery_ratio(row)
    if ratio >= 0.999:
        return 4
    if ratio >= 0.67:
        return 3
    if ratio >= 0.34:
        return 2
    if ratio > 0:
        return 1
    return 0


def _future_value(row: dict[str, Any]) -> int:
    details = row.get("label_details") if isinstance(row.get("label_details"), dict) else {}
    targets = row.get("training_targets") if isinstance(row.get("training_targets"), dict) else {}
    raw = targets.get("future_gain", details.get("future_best_label", row.get("label", 0)))
    try:
        return int(raw or 0)
    except Exception:
        return int(row.get("label", 0) or 0)


def _teacher_top_row(items: list[dict[str, Any]]) -> dict[str, Any] | None:
    if not items:
        return None
    ranked: list[tuple[float, dict[str, Any]]] = []
    for row in items:
        teacher = row.get("teacher_features") if isinstance(row.get("teacher_features"), dict) else {}
        score = teacher.get("generation_priority")
        if score is None:
            score = teacher.get("ranking_raw_score")
        if score is None:
            score = 1.0 if bool(row.get("selected_by_current_system")) else 0.0
        try:
            ranked.append((float(score), row))
        except Exception:
            ranked.append((0.0, row))
    return sorted(ranked, key=lambda item: item[0], reverse=True)[0][1]


def _entropy(values: list[int]) -> float:
    if not values:
        return 0.0
    counts = Counter(values)
    total = float(sum(counts.values()) or 1)
    result = 0.0
    for count in counts.values():
        probability = float(count) / total
        if probability > 0:
            result -= probability * math.log2(probability)
    return result


def _format_trainability(rows: list[dict[str, Any]], groups: dict[str, list[dict[str, Any]]]) -> dict[str, Any]:
    candidate_groups = {query: items for query, items in groups.items() if len(items) >= 2}
    gains = {_label_gain(row.get("label")) for row in rows}
    reasons = []
    if len(candidate_groups) < 30:
        reasons.append("too_few_queries")
    if len(gains) < 2:
        reasons.append("label_single_class")
    if not candidate_groups:
        reasons.append("candidate_competition_too_low")
    return {
        "trainable": not reasons,
        "reasons": reasons,
        "candidate_query_count": len(candidate_groups),
        "label_gain_count": len(gains),
    }


def _label_gain(label: Any) -> int:
    try:
        raw = int(label or 0)
    except Exception:
        raw = 0
    return {-1: 0, 0: 0, 1: 1, 2: 2, 3: 4}.get(raw, 0)


def _metrics_for_format(model_metrics: dict[str, Any], fmt: str) -> dict[str, Any]:
    prefix = f"{fmt}/"
    output = {}
    for key, value in model_metrics.items():
        if key.startswith(prefix):
            output[key[len(prefix):]] = value
    return output


def _format_detection_quality(rows: list[dict[str, Any]]) -> dict[str, Any]:
    mismatches = []
    compared_top = 0
    matched_top = 0
    compared_state = 0
    matched_state = 0
    for row in rows:
        material = _normalize_format_name(row.get("material_format"))
        if not material:
            continue
        top = _normalize_format_name(row.get("format"))
        state = _normalize_format_name(_nested(row, "stable_features", "state", "format"))
        if top:
            compared_top += 1
            matched_top += 1 if top == material else 0
        if state:
            compared_state += 1
            matched_state += 1 if state == material else 0
        if (top and top != material) or (state and state != material):
            mismatches.append({
                "query_id": row.get("query_id"),
                "sample_id": row.get("sample_id"),
                "material_format": row.get("material_format"),
                "top_format": row.get("format"),
                "state_format": _nested(row, "stable_features", "state", "format"),
            })
    return {
        "top_format_compared": compared_top,
        "top_format_match_ratio": matched_top / max(1, compared_top),
        "state_format_compared": compared_state,
        "state_format_match_ratio": matched_state / max(1, compared_state),
        "mismatch_count": len(mismatches),
        "mismatches_sample": mismatches[:50],
    }


def _normalize_format_name(value: Any) -> str:
    normalized = str(value or "").strip().lower().replace(".", "_").replace("-", "_")
    aliases = {
        "tgz": "tar_gz",
        "tar_gzip": "tar_gz",
        "tbz": "tar_bz2",
        "tbz2": "tar_bz2",
        "tar_bzip2": "tar_bz2",
        "txz": "tar_xz",
        "seven_zip": "7z",
    }
    return aliases.get(normalized, normalized)


def _nested(row: dict[str, Any], *keys: str) -> Any:
    current: Any = row
    for key in keys:
        if not isinstance(current, dict):
            return None
        current = current.get(key)
    return current


def _series_summary(values: list[int]) -> dict[str, Any]:
    if not values:
        return {"count": 0, "min": 0, "p50": 0, "p90": 0, "max": 0, "mean": 0.0}
    ordered = sorted(values)
    return {
        "count": len(values),
        "min": ordered[0],
        "p50": _percentile(ordered, 0.50),
        "p90": _percentile(ordered, 0.90),
        "max": ordered[-1],
        "mean": statistics.mean(ordered),
    }


def _series_summary_float(values: list[float]) -> dict[str, Any]:
    if not values:
        return {"count": 0, "min": 0.0, "p50": 0.0, "p90": 0.0, "max": 0.0, "mean": 0.0}
    ordered = sorted(float(value) for value in values)
    return {
        "count": len(values),
        "min": ordered[0],
        "p50": _percentile_float(ordered, 0.50),
        "p90": _percentile_float(ordered, 0.90),
        "max": ordered[-1],
        "mean": statistics.mean(ordered),
    }


def _mean(values: list[float | int]) -> float:
    return float(statistics.mean(values)) if values else 0.0


def _percentile(ordered: list[int], ratio: float) -> float:
    if not ordered:
        return 0.0
    index = min(len(ordered) - 1, max(0, int(math.ceil(len(ordered) * ratio) - 1)))
    return float(ordered[index])


def _percentile_float(ordered: list[float], ratio: float) -> float:
    if not ordered:
        return 0.0
    index = min(len(ordered) - 1, max(0, int(math.ceil(len(ordered) * ratio) - 1)))
    return float(ordered[index])


def _model_metrics(model_root: Path, source_counts: Counter[str], row_count: int, format_counts: Counter[str] | None = None) -> dict[str, Any]:
    output: dict[str, Any] = {}
    if not model_root.is_dir():
        return output
    current_sources = {_normalize_path(path) for path in source_counts if path}
    for summary_path in sorted(model_root.rglob("training_summary.json")):
        try:
            summary = json.loads(summary_path.read_text(encoding="utf-8"))
        except Exception:
            continue
        view = str(summary.get("feature_view") or summary_path.parent.name)
        key = str(summary_path.parent.relative_to(model_root)).replace("\\", "/")
        summary_sources = {_normalize_path(path) for path in summary.get("input_files", []) if path}
        summary_row_count = int(summary.get("row_count") or 0)
        format_scope = str(summary.get("format_scope") or "all")
        stale_reasons = []
        if current_sources and summary_sources and current_sources != summary_sources:
            stale_reasons.append("input_files_differ")
        if format_scope == "all" and row_count and summary_row_count and row_count != summary_row_count:
            stale_reasons.append("row_count_differs")
        if format_scope != "all" and format_counts:
            expected_rows = int(format_counts.get(format_scope, 0) or 0)
            if expected_rows and summary_row_count and expected_rows != summary_row_count:
                stale_reasons.append("format_row_count_differs")
        output[key] = {
            "feature_view": view,
            "format_scope": format_scope,
            "row_count": summary.get("row_count"),
            "query_count": summary.get("query_count"),
            "feature_count": summary.get("feature_count"),
            "metrics": summary.get("metrics", {}),
            "top3_metrics": _prediction_top3_metrics(summary_path.parent / "predictions.jsonl"),
            "matches_current_dataset": not stale_reasons,
            "stale_reasons": stale_reasons,
        }
    for summary_path in sorted(model_root.rglob("skip_summary.json")):
        try:
            summary = json.loads(summary_path.read_text(encoding="utf-8"))
        except Exception:
            continue
        view = str(summary.get("feature_view") or summary_path.parent.name)
        key = str(summary_path.parent.relative_to(model_root)).replace("\\", "/")
        summary_sources = {_normalize_path(path) for path in summary.get("input_files", []) if path}
        stale_reasons = []
        if current_sources and summary_sources and current_sources != summary_sources:
            stale_reasons.append("input_files_differ")
        output[key] = {
            "feature_view": view,
            "format_scope": str(summary.get("format_scope") or "all"),
            "status": "skipped",
            "skip_reason": summary.get("skip_reason"),
            "row_count": summary.get("row_count"),
            "query_count": summary.get("query_count"),
            "feature_count": 0,
            "metrics": {},
            "matches_current_dataset": not stale_reasons,
            "stale_reasons": stale_reasons,
        }
    return output


def _prediction_top3_metrics(path: Path) -> dict[str, Any]:
    if not path.is_file():
        return {}
    groups: dict[str, list[dict[str, Any]]] = defaultdict(list)
    row_count = 0
    with path.open("r", encoding="utf-8") as handle:
        for line in handle:
            line = line.strip()
            if not line:
                continue
            try:
                row = json.loads(line)
            except json.JSONDecodeError:
                continue
            if not isinstance(row, dict):
                continue
            groups[str(row.get("query_id") or "")].append(row)
            row_count += 1
    if not groups:
        return {"query_count": 0, "prediction_row_count": row_count}
    top3_means: list[float] = []
    top3_best_values: list[float] = []
    contains_hard_negative = 0
    wasted_slot_ratios: list[float] = []
    oracle_best_covered = 0
    no_output_wasted_by_module: Counter[str] = Counter()
    no_output_wasted_by_profile: Counter[str] = Counter()
    no_output_wasted_by_profile_module: Counter[str] = Counter()
    wasted_by_module: Counter[str] = Counter()
    wasted_by_profile: Counter[str] = Counter()
    for items in groups.values():
        ranked = sorted(items, key=lambda item: _as_float(item.get("score")), reverse=True)
        top3 = ranked[:3]
        if not top3:
            continue
        all_recoveries = [_prediction_recovery_ratio(item) for item in ranked]
        top3_recoveries = [_prediction_recovery_ratio(item) for item in top3]
        oracle_best = max(all_recoveries, default=0.0)
        top3_best = max(top3_recoveries, default=0.0)
        top3_means.append(statistics.mean(top3_recoveries))
        top3_best_values.append(top3_best)
        if any(_prediction_is_hard_negative(item) for item in top3):
            contains_hard_negative += 1
        wasted_slot_ratios.append(sum(1 for item in top3 if _prediction_is_wasted_slot(item)) / max(1, len(top3)))
        for item in top3:
            if not _prediction_is_wasted_slot(item):
                continue
            module = _prediction_module(item)
            profile = _prediction_profile(item)
            wasted_by_module[module] += 1
            wasted_by_profile[profile] += 1
            if str(item.get("label_status") or "") == "no_output":
                no_output_wasted_by_module[module] += 1
                no_output_wasted_by_profile[profile] += 1
                no_output_wasted_by_profile_module[f"{profile}|{module}"] += 1
        if top3_best >= oracle_best - 1e-9:
            oracle_best_covered += 1
    query_count = max(1, len(groups))
    return {
        "query_count": len(groups),
        "prediction_row_count": row_count,
        "top3_terminal_recovery_mean": _mean(top3_means),
        "top3_best_terminal_recovery_mean": _mean(top3_best_values),
        "top3_contains_hard_negative_ratio": contains_hard_negative / query_count,
        "top3_wasted_slot_ratio": _mean(wasted_slot_ratios),
        "top3_oracle_best_covered_ratio": oracle_best_covered / query_count,
        "top3_wasted_by_module_top20": dict(wasted_by_module.most_common(20)),
        "top3_wasted_by_profile_top20": dict(wasted_by_profile.most_common(20)),
        "top3_no_output_wasted_by_module_top20": dict(no_output_wasted_by_module.most_common(20)),
        "top3_no_output_wasted_by_profile_top20": dict(no_output_wasted_by_profile.most_common(20)),
        "top3_no_output_wasted_by_profile_module_top20": dict(no_output_wasted_by_profile_module.most_common(20)),
    }


def _prediction_recovery_ratio(row: dict[str, Any]) -> float:
    if row.get("terminal_recovery_ratio") is not None:
        return _clamp01(_as_float(row.get("terminal_recovery_ratio")))
    gain = int(_as_float(row.get("target_gain")))
    if gain >= 4:
        return 1.0
    if gain == 3:
        return 0.67
    if gain == 2:
        return 0.34
    if gain == 1:
        return 0.20
    return 0.0


def _prediction_is_hard_negative(row: dict[str, Any]) -> bool:
    return bool(row.get("is_hard_negative") or str(row.get("label_status") or "") == "hard_negative" or int(_as_float(row.get("label"))) < 0)


def _prediction_is_wasted_slot(row: dict[str, Any]) -> bool:
    status = str(row.get("label_status") or "")
    return bool(_prediction_recovery_ratio(row) <= 0.0 or status in {"hard_negative", "no_candidates", "no_progress", "no_output"})


def _prediction_module(row: dict[str, Any]) -> str:
    return str(row.get("module") or "<none>")


def _prediction_profile(row: dict[str, Any]) -> str:
    return str(row.get("damage_profile") or "unknown")


def _model_top3_comparison(model_metrics: dict[str, Any]) -> dict[str, Any]:
    output: dict[str, Any] = {}
    grouped: dict[str, dict[str, Any]] = defaultdict(dict)
    for key, item in model_metrics.items():
        if not isinstance(item, dict):
            continue
        view = str(item.get("feature_view") or Path(str(key)).name)
        scope = str(key).rsplit("/", 1)[0] if "/" in str(key) else str(item.get("format_scope") or "all")
        grouped[scope][view] = item.get("top3_metrics", {})
    for scope, views in grouped.items():
        if not views:
            continue
        teacher = views.get("teacher_only_baseline") if isinstance(views.get("teacher_only_baseline"), dict) else {}
        scope_output: dict[str, Any] = {}
        for view, metrics in views.items():
            if not isinstance(metrics, dict) or not metrics:
                continue
            entry = dict(metrics)
            if teacher:
                entry["model_top3_vs_teacher_top3_recovery_delta"] = (
                    float(metrics.get("top3_terminal_recovery_mean", 0.0) or 0.0)
                    - float(teacher.get("top3_terminal_recovery_mean", 0.0) or 0.0)
                )
            scope_output[view] = entry
        if scope_output:
            output[scope] = scope_output
    return output


def _normalize_path(value: str) -> str:
    try:
        return str(Path(value).resolve()).replace("\\", "/").lower()
    except Exception:
        return str(value).replace("\\", "/").lower()


def _quality_warnings(report: dict[str, Any]) -> list[str]:
    warnings: list[str] = []
    row_count = max(1, int(report.get("dataset", {}).get("row_count", 0) or 0))
    formats = report.get("format_distribution", {}) if isinstance(report.get("format_distribution"), dict) else {}
    zip_ratio = int(formats.get("zip", 0) or 0) / row_count
    if zip_ratio > 0.5:
        warnings.append("zip_dominates_dataset")
    for fmt, count in formats.items():
        if int(count or 0) / row_count < 0.05:
            warnings.append(f"format_underrepresented:{fmt}")
    stream_rows = sum(int(formats.get(fmt, 0) or 0) for fmt in ("gzip", "bzip2", "xz", "zstd"))
    labels = report.get("label_distribution", {}) if isinstance(report.get("label_distribution"), dict) else {}
    positive_rows = sum(int(labels.get(str(label), 0) or 0) for label in (1, 2, 3))
    if stream_rows / row_count > 0.3 and positive_rows == 0:
        warnings.append("stream_rows_no_positive_labels")
    negative_ratio = (int(labels.get("-1", 0) or 0) + int(labels.get("0", 0) or 0)) / row_count
    if negative_ratio < 0.15:
        warnings.append("negative_labels_too_sparse")
    candidate_distribution = report.get("query_candidate_count_distribution", {}) if isinstance(report.get("query_candidate_count_distribution"), dict) else {}
    query_count = max(1, int(report.get("dataset", {}).get("query_count", 0) or 0))
    single_ratio = int(candidate_distribution.get("1", 0) or 0) / query_count
    if single_ratio > 0.1:
        warnings.append("too_many_single_candidate_queries")
    candidate_summary = report.get("query_candidate_count", {}) if isinstance(report.get("query_candidate_count"), dict) else {}
    if float(candidate_summary.get("p90", 0.0) or 0.0) <= 2.0:
        warnings.append("low_candidate_competition")
    ratios = report.get("quality_ratios", {}) if isinstance(report.get("quality_ratios"), dict) else {}
    if float(ratios.get("timeout_or_failed_row_ratio", 0.0) or 0.0) > 0.02:
        warnings.append("timeouts_present")
    metrics = report.get("model_metric_comparison", {}) if isinstance(report.get("model_metric_comparison"), dict) else {}
    if any(isinstance(item, dict) and not item.get("matches_current_dataset", True) for item in metrics.values()):
        warnings.append("model_metrics_stale")
    stable = _model_ndcg(metrics, "stable_only")
    proposal = _model_ndcg(metrics, "proposal_only")
    teacher = _model_ndcg(metrics, "teacher_only_baseline")
    if stable is not None and teacher is not None and stable > 0.95 and abs(stable - teacher) < 0.05:
        warnings.append("dataset_may_be_too_easy")
    difficulty = report.get("difficulty", {}) if isinstance(report.get("difficulty"), dict) else {}
    entropy = difficulty.get("query_target_entropy") if isinstance(difficulty.get("query_target_entropy"), dict) else {}
    if float(entropy.get("mean", 0.0) or 0.0) < 0.35:
        warnings.append("dataset_too_easy_target_entropy_low")
    if float(difficulty.get("state_progress_terminal_recovery_complete_rate", 0.0) or 0.0) < 0.05 or int(difficulty.get("state_progress_terminal_recovery_complete_count", 0) or 0) <= 0:
        warnings.append("too_few_two_step_success_cases")
    if int(difficulty.get("deceptive_hard_negative_row_count", 0) or 0) <= 0:
        warnings.append("too_few_deceptive_hard_negatives")
    if float(difficulty.get("teacher_top1_wrong_but_future_best_exists_ratio", 0.0) or 0.0) < 0.20:
        warnings.append("teacher_top1_too_aligned")
    profile_purity = difficulty.get("profile_module_label_purity") if isinstance(difficulty.get("profile_module_label_purity"), dict) else {}
    if float(profile_purity.get("mean", 0.0) or 0.0) > 0.75:
        warnings.append("profile_module_label_purity_too_high")
    recovery = report.get("terminal_recovery", {}) if isinstance(report.get("terminal_recovery"), dict) else {}
    if float(recovery.get("variable_terminal_recovery_query_ratio", 0.0) or 0.0) < 0.40:
        warnings.append("terminal_recovery_competition_too_low")
    if float(difficulty.get("hard_negative_vs_positive_same_query_ratio", 0.0) or 0.0) < 0.10 and int(labels.get("-1", 0) or 0) > 0 and positive_rows > 0:
        warnings.append("too_few_hard_negative_positive_competition")
    if proposal is not None and teacher is not None and proposal >= 0.999 and teacher >= 0.999:
        warnings.append("dataset_still_too_deterministic")
    if int(formats.get("zip", 0) or 0) > 0:
        warnings.append("source_split_recommended")
    dependency = report.get("repair_prior_dependency", {}) if isinstance(report.get("repair_prior_dependency"), dict) else {}
    if any(isinstance(item, dict) and item.get("prior_dependency_warning") for item in dependency.values()):
        warnings.append("repair_prior_dependency_high")
    per_format = report.get("per_format", {}) if isinstance(report.get("per_format"), dict) else {}
    for fmt, item in per_format.items():
        if not isinstance(item, dict):
            continue
        trainability = item.get("trainability") if isinstance(item.get("trainability"), dict) else {}
        for reason in trainability.get("reasons", []) or []:
            if reason == "too_few_queries":
                warnings.append(f"format_too_few_queries:{fmt}")
            elif reason == "label_single_class":
                warnings.append(f"format_label_single_class:{fmt}")
            elif reason == "candidate_competition_too_low":
                warnings.append(f"format_low_candidate_competition:{fmt}")
        if not trainability.get("trainable", False):
            warnings.append(f"format_not_trainable:{fmt}")
    return warnings


def _model_ndcg(metrics: dict[str, Any], view: str) -> float | None:
    for item in metrics.values():
        if not isinstance(item, dict) or item.get("feature_view") != view:
            continue
        if not item.get("matches_current_dataset", True):
            continue
        inner = item.get("metrics") if isinstance(item.get("metrics"), dict) else {}
        try:
            return float(inner.get("ndcg@1"))
        except Exception:
            return None
    return None


def _markdown_path(path: Path) -> Path:
    return path.with_suffix(".md")


def _markdown_report(report: dict[str, Any]) -> str:
    lines = [
        "# LTR Data Quality Report",
        "",
        f"- Rows: {report['dataset']['row_count']}",
        f"- Queries: {report['dataset']['query_count']}",
        f"- Labels: `{json.dumps(report['label_distribution'], ensure_ascii=False, sort_keys=True)}`",
        f"- Best labels: `{json.dumps(report['sample_best_label_distribution'], ensure_ascii=False, sort_keys=True)}`",
        f"- Formats: `{json.dumps(report['format_distribution'], ensure_ascii=False, sort_keys=True)}`",
        f"- Candidate count: `{json.dumps(report['query_candidate_count'], ensure_ascii=False, sort_keys=True)}`",
        f"- Quality ratios: `{json.dumps(report['quality_ratios'], ensure_ascii=False, sort_keys=True)}`",
        f"- Rollout: `{json.dumps(report.get('rollout', {}), ensure_ascii=False, sort_keys=True)}`",
        f"- RL dataset: `{json.dumps(report.get('rl_dataset', {}), ensure_ascii=False, sort_keys=True)}`",
        f"- Difficulty: `{json.dumps(report.get('difficulty', {}), ensure_ascii=False, sort_keys=True)}`",
        f"- Terminal recovery: `{json.dumps(report.get('terminal_recovery', {}), ensure_ascii=False, sort_keys=True)}`",
        f"- Model top3: `{json.dumps(report.get('model_top3_comparison', {}), ensure_ascii=False, sort_keys=True)}`",
        f"- Policy comparison: `{json.dumps(report.get('policy_comparison', {}), ensure_ascii=False, sort_keys=True)}`",
        f"- Format detection: `{json.dumps(report.get('format_detection_quality', {}), ensure_ascii=False, sort_keys=True)}`",
        f"- Warnings: `{json.dumps(report.get('warnings', []), ensure_ascii=False, sort_keys=True)}`",
        "",
        "## Per Format",
    ]
    for fmt, item in report.get("per_format", {}).items():
        lines.append(f"- `{fmt}`: rows={item.get('row_count')} queries={item.get('query_count')} labels=`{json.dumps(item.get('label_distribution', {}), ensure_ascii=False, sort_keys=True)}` rollout=`{json.dumps(item.get('rollout', {}), ensure_ascii=False, sort_keys=True)}` trainable=`{json.dumps(item.get('trainability', {}), ensure_ascii=False, sort_keys=True)}`")
    lines.extend([
        "",
        "## Model Metrics",
    ])
    for name, item in report.get("model_metric_comparison", {}).items():
        lines.append(f"- `{name}`: metrics=`{json.dumps(item.get('metrics', {}), ensure_ascii=False, sort_keys=True)}` top3=`{json.dumps(item.get('top3_metrics', {}), ensure_ascii=False, sort_keys=True)}`")
    lines.append("")
    return "\n".join(lines)


if __name__ == "__main__":
    raise SystemExit(main())
