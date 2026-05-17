from __future__ import annotations

import argparse
import json
from collections import Counter, defaultdict
from pathlib import Path
from typing import Any

import numpy as np

from repair_training.core.datasets import action_query_id, read_jsonl, sort_for_groups, write_json
from repair_training.core.features import transform_rows
from repair_training.core.plugin import load_training_format_plugin, normalize_format_name


def main(argv: list[str] | None = None) -> int:
    args = _parser().parse_args(argv)
    fmt = normalize_format_name(args.format)
    plugin = load_training_format_plugin(fmt)
    model_dir = Path(args.model_dir).resolve()
    rows_path = Path(args.action_policy_rows).resolve()
    output_path = Path(args.output).resolve()
    rows = sort_for_groups(read_jsonl(rows_path))
    if args.limit and args.limit > 0:
        rows = _limit_groups(rows, args.limit)
    schema = _read_json(model_dir / "feature_schema.json")
    x, y = transform_rows(rows, schema=schema, plugin=plugin, model_type="step_action")
    scores = _predict(model_dir, x)
    report = evaluate_ranked_actions(rows, scores, y)
    report["format"] = fmt
    report["model_dir"] = str(model_dir)
    report["action_policy_rows"] = str(rows_path)
    report["rows"] = len(rows)
    write_json(output_path, report)
    print(json.dumps(report, ensure_ascii=False, sort_keys=True))
    return 0


def evaluate_ranked_actions(rows: list[dict[str, Any]], scores: np.ndarray, labels: np.ndarray) -> dict[str, Any]:
    groups: dict[str, list[int]] = defaultdict(list)
    for index, row in enumerate(rows):
        groups[action_query_id(row)].append(index)
    correct = 0
    close_correct = 0
    regrets: list[float] = []
    selected_counter: Counter[str] = Counter()
    best_counter: Counter[str] = Counter()
    profile_stats: dict[str, dict[str, Any]] = {}
    hard_cases: list[dict[str, Any]] = []
    for group_id, indexes in groups.items():
        group_scores = np.array([float(scores[index]) for index in indexes], dtype=np.float32)
        group_labels = np.array([float(labels[index]) for index in indexes], dtype=np.float32)
        selected_pos = int(np.argmax(group_scores))
        best_pos = int(np.argmax(group_labels))
        selected_index = indexes[selected_pos]
        best_index = indexes[best_pos]
        selected_row = rows[selected_index]
        best_row = rows[best_index]
        selected_action = _action_name(selected_row)
        best_action = _action_name(best_row)
        selected_counter[selected_action] += 1
        best_counter[best_action] += 1
        regret = float(group_labels[best_pos] - group_labels[selected_pos])
        regrets.append(regret)
        hit = selected_pos == best_pos
        close_hit = regret <= 1e-6
        correct += 1 if hit else 0
        close_correct += 1 if close_hit else 0
        profile = _profile(best_row)
        stats = profile_stats.setdefault(profile, {"groups": 0, "correct": 0, "close_correct": 0, "regrets": [], "best": Counter(), "selected": Counter()})
        stats["groups"] += 1
        stats["correct"] += 1 if hit else 0
        stats["close_correct"] += 1 if close_hit else 0
        stats["regrets"].append(regret)
        stats["best"][best_action] += 1
        stats["selected"][selected_action] += 1
        if not close_hit:
            hard_cases.append({
                "group_id": group_id,
                "episode_id": best_row.get("episode_id"),
                "round_index": best_row.get("round_index"),
                "state_digest": best_row.get("state_digest"),
                "damage_profile": profile,
                "selected_action": selected_action,
                "best_action": best_action,
                "selected_score": float(group_scores[selected_pos]),
                "best_score": float(group_scores[best_pos]),
                "selected_label": float(group_labels[selected_pos]),
                "best_label": float(group_labels[best_pos]),
                "regret": regret,
                "current_recovery": _score(best_row.get("current_recovery")),
                "selected_step_action": selected_row.get("step_action"),
                "best_step_action": best_row.get("step_action"),
            })
    group_count = max(1, len(groups))
    profile_report = {
        profile: {
            "groups": int(values["groups"]),
            "accuracy": float(values["correct"] / max(1, values["groups"])),
            "tie_aware_accuracy": float(values["close_correct"] / max(1, values["groups"])),
            "mean_regret": float(np.mean(values["regrets"])) if values["regrets"] else 0.0,
            "best_actions": dict(values["best"]),
            "selected_actions": dict(values["selected"]),
        }
        for profile, values in sorted(profile_stats.items())
    }
    weakest_profiles = sorted(
        (
            {"damage_profile": profile, **payload}
            for profile, payload in profile_report.items()
            if payload["groups"] >= 3
        ),
        key=lambda item: (item["tie_aware_accuracy"], -item["mean_regret"], item["damage_profile"]),
    )[:20]
    return {
        "groups": len(groups),
        "best_action_accuracy": float(correct / group_count),
        "tie_aware_accuracy": float(close_correct / group_count),
        "mean_regret": float(np.mean(regrets)) if regrets else 0.0,
        "p95_regret": float(np.percentile(regrets, 95)) if regrets else 0.0,
        "selected_action_distribution": dict(selected_counter),
        "oracle_best_action_distribution": dict(best_counter),
        "profiles": profile_report,
        "weakest_profiles": weakest_profiles,
        "hard_cases": sorted(hard_cases, key=lambda item: item["regret"], reverse=True)[:200],
    }


def _predict(model_dir: Path, x: np.ndarray) -> np.ndarray:
    model_path = model_dir / "model.txt"
    if not model_path.is_file():
        raise SystemExit(f"missing repair action model: {model_path}")
    try:
        import lightgbm as lgb
    except Exception as exc:  # pragma: no cover
        raise SystemExit("LightGBM is required for action model evaluation.") from exc
    booster = lgb.Booster(model_file=str(model_path))
    scores = booster.predict(x) if len(x) else np.array([], dtype=np.float32)
    return np.asarray(scores, dtype=np.float32)


def _limit_groups(rows: list[dict[str, Any]], limit: int) -> list[dict[str, Any]]:
    selected: list[dict[str, Any]] = []
    seen: set[str] = set()
    for row in rows:
        key = action_query_id(row)
        if key not in seen:
            if len(seen) >= limit:
                break
            seen.add(key)
        selected.append(row)
    return selected


def _action_name(row: dict[str, Any]) -> str:
    action_type = str(row.get("action_type") or "")
    if action_type == "module":
        candidate = row.get("candidate_snapshot") if isinstance(row.get("candidate_snapshot"), dict) else {}
        metadata = candidate.get("metadata") if isinstance(candidate.get("metadata"), dict) else {}
        module = candidate.get("module_name") or metadata.get("last_patch_module")
        return f"module:{module or row.get('candidate_id') or 'unknown'}"
    return action_type or "unknown"


def _profile(row: dict[str, Any]) -> str:
    target = row.get("damage_analysis_target") if isinstance(row.get("damage_analysis_target"), dict) else {}
    metadata = target.get("metadata") if isinstance(target.get("metadata"), dict) else {}
    return str(metadata.get("damage_profile") or row.get("damage_profile") or "unknown")


def _score(value: Any) -> float:
    if isinstance(value, dict):
        try:
            return float(value.get("score") or 0.0)
        except Exception:
            return 0.0
    return 0.0


def _read_json(path: Path) -> dict[str, Any]:
    return json.loads(path.read_text(encoding="utf-8")) if path.is_file() else {}


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Evaluate a trained RepairAction LightGBM ranker on action_policy_rows.jsonl.")
    parser.add_argument("--format", default="zip")
    parser.add_argument("--model-dir", required=True)
    parser.add_argument("--action-policy-rows", required=True)
    parser.add_argument("--output", required=True)
    parser.add_argument("--limit", type=int, default=0, help="Optional maximum number of state groups to evaluate.")
    return parser


if __name__ == "__main__":
    raise SystemExit(main())

