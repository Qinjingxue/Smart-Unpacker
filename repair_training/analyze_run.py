from __future__ import annotations

import argparse
import json
from collections import Counter
from pathlib import Path
from typing import Any

from repair_training.core.datasets import read_jsonl, write_json


def main(argv: list[str] | None = None) -> int:
    args = _parser().parse_args(argv)
    run_dir = Path(args.run_dir)
    report = analyze_run(run_dir)
    output = Path(args.output) if args.output else run_dir / "datasets" / "quality_report.json"
    write_json(output, report)
    print(json.dumps(report, ensure_ascii=False, sort_keys=True))
    return 0


def analyze_run(run_dir: str | Path) -> dict[str, Any]:
    run_dir = Path(run_dir)
    datasets = run_dir / "datasets"
    episodes = read_jsonl(datasets / "episodes.jsonl")
    timings = read_jsonl(datasets / "collection_timings.jsonl")
    failures = read_jsonl(datasets / "episode_failures.jsonl")
    damage_rows = read_jsonl(datasets / "damage_rows.jsonl")
    action_rows = read_jsonl(datasets / "action_values.jsonl")
    collection_summary = _read_json(datasets / "collection_summary.json")
    feature_summary = _read_json(run_dir / "features" / "damage_analysis" / "feature_summary.json")

    episode_ids: list[str] = []
    transitions = 0
    candidate_total = 0
    no_candidate_episodes = 0
    zero_candidate_states = 0
    state_count = 0
    candidate_digest_total = 0
    candidate_digest_unique = 0
    duplicate_candidate_states = 0
    label_counts: Counter[str] = Counter()
    family_counts: Counter[str] = Counter()
    selected_actions: Counter[str] = Counter()
    terminal_actions: Counter[str] = Counter()
    candidate_modules: Counter[str] = Counter()
    scores_before: list[float] = []
    scores_after: list[float] = []

    for episode in episodes:
        episode_ids.append(str(episode.get("episode_id") or ""))
        episode_candidate_count = 0
        for label in episode.get("oracle_damage") or []:
            if not isinstance(label, dict):
                continue
            name = str(label.get("label") or "")
            label_counts[name] += 1
            family = str((label.get("metadata") or {}).get("family") or name.split("/")[0])
            family_counts[family] += 1
        for transition in episode.get("transitions") or []:
            transitions += 1
            state_count += 1
            candidates = transition.get("candidate_snapshots") or []
            candidate_total += len(candidates)
            episode_candidate_count += len(candidates)
            if not candidates:
                zero_candidate_states += 1
            digests = [
                str(candidate.get("patch_digest") or "")
                for candidate in candidates
                if isinstance(candidate, dict) and candidate.get("patch_digest")
            ]
            candidate_digest_total += len(digests)
            candidate_digest_unique += len(set(digests))
            if len(set(digests)) < len(digests):
                duplicate_candidate_states += 1
            for candidate in candidates:
                if isinstance(candidate, dict):
                    candidate_modules[str(candidate.get("module_name") or candidate.get("module") or "")] += 1
            action = str((transition.get("selected_action") or {}).get("action_type") or "")
            selected_actions[action] += 1
            if transition.get("terminal"):
                terminal_actions[action] += 1
            scores_before.append(float((transition.get("verification_before") or {}).get("score") or 0.0))
            scores_after.append(float((transition.get("verification_after") or {}).get("score") or 0.0))
        if episode_candidate_count == 0:
            no_candidate_episodes += 1

    action_counts: Counter[str] = Counter()
    best_action_counts: Counter[str] = Counter()
    for row in action_rows:
        action = row.get("action") if isinstance(row.get("action"), dict) else {}
        action_type = str(action.get("action_type") or "")
        action_counts[action_type] += 1
        if row.get("is_best_action"):
            best_action_counts[action_type] += 1

    damage_label_rows: Counter[str] = Counter()
    for row in damage_rows:
        target = row.get("damage_analysis_target") if isinstance(row.get("damage_analysis_target"), dict) else {}
        for label in target.get("damage_labels") or []:
            damage_label_rows[str(label)] += 1

    timing_values = [float(row.get("elapsed_seconds") or 0.0) for row in timings if row.get("status") == "ok"]
    timing_status = Counter(str(row.get("status") or "") for row in timings)
    unique_episode_ids = len(set(episode_ids))
    report = {
        "run_dir": str(run_dir),
        "collection_summary": collection_summary,
        "feature_summary": feature_summary,
        "counts": {
            "episodes": len(episodes),
            "unique_episode_ids": unique_episode_ids,
            "duplicate_episode_ids": len(episode_ids) - unique_episode_ids,
            "timing_rows": len(timings),
            "failure_rows": len(failures),
            "transitions": transitions,
            "damage_rows": len(damage_rows),
            "action_values": len(action_rows),
            "candidate_snapshots": candidate_total,
        },
        "performance": {
            "timing_status": dict(timing_status),
            "collection_timing_seconds": _stats(timing_values),
            "estimated_samples_per_second": _rate(len(timing_values), float(collection_summary.get("wall_seconds") or 0.0)),
        },
        "quality": {
            "avg_transitions_per_episode": _ratio(transitions, len(episodes)),
            "avg_candidate_snapshots_per_transition": _ratio(candidate_total, transitions),
            "episodes_with_no_candidates": no_candidate_episodes,
            "episodes_with_no_candidates_ratio": _ratio(no_candidate_episodes, len(episodes)),
            "states_with_zero_candidates": zero_candidate_states,
            "states_with_zero_candidates_ratio": _ratio(zero_candidate_states, state_count),
            "candidate_digest_duplicate_ratio": round(1.0 - candidate_digest_unique / max(1, candidate_digest_total), 6),
            "states_with_duplicate_candidate_digests": duplicate_candidate_states,
            "score_before": _stats(scores_before),
            "score_after": _stats(scores_after),
            "oracle_label_unique": len(label_counts),
            "damage_row_label_unique": len(damage_label_rows),
        },
        "actions": {
            "selected_transition_actions": dict(selected_actions),
            "terminal_transition_actions": dict(terminal_actions),
            "action_value_rows_by_action": dict(action_counts),
            "best_action_rows_by_action": dict(best_action_counts),
        },
        "top": {
            "oracle_family_counts": family_counts.most_common(25),
            "oracle_label_counts": label_counts.most_common(40),
            "damage_row_label_counts": damage_label_rows.most_common(40),
            "candidate_modules": candidate_modules.most_common(40),
            "slowest_samples": sorted(timings, key=lambda row: float(row.get("elapsed_seconds") or 0.0), reverse=True)[:25],
        },
    }
    return report


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Analyze episode collection performance and training data quality.")
    parser.add_argument("--run-dir", required=True)
    parser.add_argument("--output", default="")
    return parser


def _read_json(path: Path) -> dict[str, Any]:
    if not path.is_file():
        return {}
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except json.JSONDecodeError:
        return {}
    return data if isinstance(data, dict) else {}


def _stats(values: list[float]) -> dict[str, float]:
    values = sorted(float(value or 0.0) for value in values)
    if not values:
        return {"count": 0, "min": 0.0, "p50": 0.0, "p90": 0.0, "p99": 0.0, "max": 0.0, "avg": 0.0}
    return {
        "count": len(values),
        "min": round(values[0], 6),
        "p50": round(values[len(values) // 2], 6),
        "p90": round(values[int((len(values) - 1) * 0.9)], 6),
        "p99": round(values[int((len(values) - 1) * 0.99)], 6),
        "max": round(values[-1], 6),
        "avg": round(sum(values) / len(values), 6),
    }


def _ratio(numerator: int | float, denominator: int | float) -> float:
    return round(float(numerator or 0.0) / max(1.0, float(denominator or 0.0)), 6)


def _rate(count: int, seconds: float) -> float:
    return round(float(count or 0) / seconds, 6) if seconds > 0 else 0.0


if __name__ == "__main__":
    raise SystemExit(main())
