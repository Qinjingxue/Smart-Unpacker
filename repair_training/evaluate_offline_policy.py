from __future__ import annotations

import argparse
import json
import random
import statistics
from collections import Counter, defaultdict
from pathlib import Path
from typing import Any


DEFAULT_DATASET_DIR = Path("repair_training") / "datasets"
DEFAULT_OUTPUT = DEFAULT_DATASET_DIR / "offline_policy_evaluation.json"


def main(argv: list[str] | None = None) -> int:
    args = _parser().parse_args(argv)
    rows = _load_rows(_input_paths(args.input, Path(args.dataset_dir)))
    predictions = _load_prediction_scores(args.policy)
    policies = _policy_specs(args.policy)
    if not policies:
        policies = ["current_selector", "random", "oracle_upper_bound"]
    graph = _build_graph(rows)
    payload = {
        "name": args.name,
        "input_files": [str(path) for path in _input_paths(args.input, Path(args.dataset_dir))],
        "dataset": {
            "row_count": len(rows),
            "episode_count": len(graph["roots"]),
            "state_count": len(graph["states"]),
            "transition_count": len(graph["actions"]),
        },
        "policies": {},
    }
    oracle_cache: dict[str, dict[str, Any]] = {}
    for policy in policies:
        result = _evaluate_policy(policy, graph, predictions, args, oracle_cache)
        payload["policies"][policy] = result
    _attach_regret_against_oracle(payload)
    output = Path(args.output)
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_text(json.dumps(payload, ensure_ascii=False, indent=2, sort_keys=True), encoding="utf-8")
    print(json.dumps(payload, ensure_ascii=False, sort_keys=True))
    return 0


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Evaluate offline repair policies on observed RL rollout graphs.")
    parser.add_argument("--dataset-dir", default=str(DEFAULT_DATASET_DIR), help="Directory containing repair-plan JSONL datasets.")
    parser.add_argument("--input", action="append", default=[], help="Input JSONL file. Repeatable; defaults to terminal recovery JSONLs when present.")
    parser.add_argument("--policy", action="append", default=[], help="Policy spec: current_selector, random, oracle_upper_bound, or ltr:<predictions.jsonl>.")
    parser.add_argument("--output", default=str(DEFAULT_OUTPUT), help="Evaluation JSON output path.")
    parser.add_argument("--name", default="offline_policy_evaluation", help="Report name stored in the output JSON.")
    parser.add_argument("--seed", type=int, default=2026, help="Seed for random policy.")
    parser.add_argument("--max-steps", type=int, default=20, help="Maximum transitions followed per episode.")
    return parser


def _input_paths(inputs: list[str], dataset_dir: Path) -> list[Path]:
    if inputs:
        return [Path(item) for item in inputs if Path(item).is_file()]
    preferred = [
        dataset_dir / "repair_plan_ltr_success_zip_terminal_recovery.jsonl",
        dataset_dir / "repair_plan_ltr_failure_zip_terminal_recovery.jsonl",
    ]
    if all(path.is_file() for path in preferred):
        return preferred
    return [
        path for path in sorted(dataset_dir.glob("*.jsonl"))
        if path.is_file()
        and not path.name.lower().startswith(("repair_plan_collect_events", "predictions", "collect_profile"))
    ]


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
                if isinstance(row, dict) and (row.get("action_row_id") or row.get("row_type") == "terminal"):
                    rows.append(row)
    return rows


def _policy_specs(values: list[str]) -> list[str]:
    output = []
    for value in values:
        value = str(value or "").strip()
        if not value:
            continue
        if value.startswith("ltr:"):
            path = value[4:]
            name = Path(path).parent.name or Path(path).stem
            output.append(f"ltr:{name}")
        else:
            output.append(value)
    return output


def _load_prediction_scores(values: list[str]) -> dict[str, dict[tuple[str, str], float]]:
    output: dict[str, dict[tuple[str, str], float]] = {}
    for value in values:
        value = str(value or "")
        if not value.startswith("ltr:"):
            continue
        path = Path(value[4:])
        name = path.parent.name or path.stem
        scores: dict[tuple[str, str], float] = {}
        if not path.is_file():
            output[name] = scores
            continue
        with path.open("r", encoding="utf-8") as handle:
            for line in handle:
                line = line.strip()
                if not line:
                    continue
                try:
                    row = json.loads(line)
                except json.JSONDecodeError:
                    continue
                key = (str(row.get("query_id") or ""), str(row.get("candidate_id") or ""))
                scores[key] = _as_float(row.get("score"))
        output[name] = scores
    return output


def _build_graph(rows: list[dict[str, Any]]) -> dict[str, Any]:
    actions_by_state: dict[str, list[dict[str, Any]]] = defaultdict(list)
    states: set[str] = set()
    roots: dict[str, str] = {}
    actions: dict[str, dict[str, Any]] = {}
    for row in rows:
        if row.get("row_type") == "terminal":
            continue
        rl = row.get("rl") if isinstance(row.get("rl"), dict) else {}
        state_id = str(rl.get("state_id") or row.get("state_id") or row.get("query_id") or "")
        action_id = str(rl.get("action_id") or row.get("action_row_id") or "")
        if not state_id or not action_id:
            continue
        states.add(state_id)
        next_state = str(rl.get("next_state_id") or "")
        if next_state and not bool(rl.get("done")):
            states.add(next_state)
        actions_by_state[state_id].append(row)
        actions[action_id] = row
        episode = str(row.get("episode_id") or row.get("sample_id") or "")
        if episode and (int(row.get("round", 0) or 0) == 0 or not row.get("parent_action_row_id")):
            roots.setdefault(episode, state_id)
    return {
        "actions_by_state": dict(actions_by_state),
        "states": states,
        "roots": roots,
        "actions": actions,
    }


def _evaluate_policy(policy: str, graph: dict[str, Any], predictions: dict[str, dict[tuple[str, str], float]], args: argparse.Namespace, oracle_cache: dict[str, dict[str, Any]]) -> dict[str, Any]:
    rng = random.Random(int(args.seed))
    episodes = []
    skipped = 0
    unobserved = 0
    fallback = 0
    profile_regret: dict[str, list[float]] = defaultdict(list)
    module_regret: dict[str, list[float]] = defaultdict(list)
    oracle_policy = "oracle_upper_bound"
    for episode, root_state in sorted((graph.get("roots") or {}).items()):
        result = _follow_policy(policy, root_state, graph, predictions, rng, int(args.max_steps))
        if result.get("skipped"):
            skipped += 1
            if result.get("reason") == "unobserved_action":
                unobserved += 1
            continue
        oracle = oracle_cache.get(episode)
        if oracle is None:
            oracle = _follow_policy(oracle_policy, root_state, graph, predictions, rng, int(args.max_steps))
            oracle_cache[episode] = oracle
        regret = max(0.0, _as_float(oracle.get("terminal_recovery_ratio")) - _as_float(result.get("terminal_recovery_ratio")))
        result["oracle_terminal_recovery_ratio"] = _as_float(oracle.get("terminal_recovery_ratio"))
        result["terminal_recovery_regret"] = regret
        episodes.append(result)
        profile_regret[str(result.get("damage_profile") or "unknown")].append(regret)
        module_regret[str(result.get("first_module") or "<none>")].append(regret)
        fallback += int(result.get("fallback_count", 0) or 0)
    return {
        "episode_count": len(episodes),
        "skipped_episode_count": skipped,
        "unobserved_action_count": unobserved,
        "fallback_count": fallback,
        "mean_terminal_recovery": _mean([_as_float(item.get("terminal_recovery_ratio")) for item in episodes]),
        "mean_episode_return": _mean([_as_float(item.get("episode_return")) for item in episodes]),
        "mean_steps": _mean([_as_float(item.get("steps")) for item in episodes]),
        "no_output_rate": _mean([_as_float(item.get("no_output_count")) / max(1.0, _as_float(item.get("steps"))) for item in episodes]),
        "hard_negative_rate": _mean([_as_float(item.get("hard_negative_count")) / max(1.0, _as_float(item.get("steps"))) for item in episodes]),
        "mean_regret_vs_oracle": _mean([_as_float(item.get("terminal_recovery_regret")) for item in episodes]),
        "p90_regret_vs_oracle": _percentile(sorted(_as_float(item.get("terminal_recovery_regret")) for item in episodes), 0.90),
        "terminal_recovery_distribution": _series([_as_float(item.get("terminal_recovery_ratio")) for item in episodes]),
        "profile_regret_top20": _regret_items(profile_regret),
        "module_regret_top20": _regret_items(module_regret),
    }


def _follow_policy(policy: str, state_id: str, graph: dict[str, Any], predictions: dict[str, dict[tuple[str, str], float]], rng: random.Random, max_steps: int) -> dict[str, Any]:
    episode_return = 0.0
    terminal_recovery = 0.0
    steps = 0
    no_output_count = 0
    hard_negative_count = 0
    fallback_count = 0
    first_module = ""
    damage_profile = ""
    visited: set[str] = set()
    current = state_id
    discount = 1.0
    for _ in range(max_steps):
        if current in visited:
            return {"skipped": True, "reason": "cycle"}
        visited.add(current)
        actions = list((graph.get("actions_by_state") or {}).get(current, []))
        if not actions:
            break
        action, used_fallback = _choose_action(policy, actions, predictions, rng)
        fallback_count += int(used_fallback)
        if action is None:
            return {"skipped": True, "reason": "no_action"}
        rl = action.get("rl") if isinstance(action.get("rl"), dict) else {}
        if not first_module:
            first_module = str(action.get("module") or "<none>")
            damage_profile = _damage_profile(action)
        reward = _as_float(rl.get("reward"))
        episode_return += discount * reward
        discount *= _as_float(rl.get("discount")) or 0.95
        steps += 1
        status = str(action.get("label_status") or rl.get("terminal_status") or "")
        if status == "no_output":
            no_output_count += 1
        if status == "hard_negative" or int(action.get("label", 0) or 0) < 0:
            hard_negative_count += 1
        if bool(rl.get("done")):
            terminal_recovery = _as_float(rl.get("terminal_reward"))
            if rl.get("terminal_reward") is None:
                terminal_recovery = _as_float(rl.get("next_state_recovery_ratio"))
            break
        next_state = str(rl.get("next_state_id") or "")
        if not next_state:
            return {"skipped": True, "reason": "unobserved_action"}
        current = next_state
    return {
        "skipped": False,
        "terminal_recovery_ratio": terminal_recovery,
        "episode_return": episode_return,
        "steps": steps,
        "no_output_count": no_output_count,
        "hard_negative_count": hard_negative_count,
        "fallback_count": fallback_count,
        "first_module": first_module,
        "damage_profile": damage_profile,
    }


def _choose_action(policy: str, actions: list[dict[str, Any]], predictions: dict[str, dict[tuple[str, str], float]], rng: random.Random) -> tuple[dict[str, Any] | None, bool]:
    if not actions:
        return None, False
    if policy == "current_selector":
        selected = [row for row in actions if bool(row.get("selected_by_current_system"))]
        if selected:
            return selected[0], False
        return _best_generation_priority(actions), True
    if policy == "random":
        return rng.choice(actions), False
    if policy == "oracle_upper_bound":
        return max(actions, key=lambda row: _as_float(_nested(row, "rl", "future_return"))), False
    if policy.startswith("ltr:"):
        name = policy.split(":", 1)[1]
        scores = predictions.get(name, {})
        ranked = []
        for row in actions:
            key = (str(row.get("query_id") or ""), str(row.get("candidate_id") or ""))
            ranked.append((scores.get(key), row))
        known = [(score, row) for score, row in ranked if score is not None]
        if known:
            return max(known, key=lambda item: float(item[0]))[1], False
        return _best_generation_priority(actions), True
    return _best_generation_priority(actions), True


def _best_generation_priority(actions: list[dict[str, Any]]) -> dict[str, Any]:
    return max(actions, key=lambda row: _as_float(_nested(row, "teacher_features", "generation_priority")))


def _damage_profile(row: dict[str, Any]) -> str:
    explicit = _nested(row, "stable_features", "state", "damage_profile") or row.get("damage_profile")
    if explicit:
        return str(explicit)
    sample = str(row.get("sample_id") or row.get("episode_id") or "")
    marker = "_zip_"
    if marker in sample:
        return sample.split(marker, 1)[1].rsplit("_", 1)[0]
    return "unknown"


def _attach_regret_against_oracle(payload: dict[str, Any]) -> None:
    policies = payload.get("policies") if isinstance(payload.get("policies"), dict) else {}
    oracle = policies.get("oracle_upper_bound") if isinstance(policies.get("oracle_upper_bound"), dict) else {}
    oracle_mean = _as_float(oracle.get("mean_terminal_recovery"))
    for name, item in policies.items():
        if not isinstance(item, dict):
            continue
        item["mean_terminal_recovery_regret_vs_oracle_mean"] = max(0.0, oracle_mean - _as_float(item.get("mean_terminal_recovery")))


def _regret_items(groups: dict[str, list[float]]) -> list[dict[str, Any]]:
    rows = []
    for key, values in groups.items():
        if not values:
            continue
        rows.append({
            "key": str(key),
            "count": len(values),
            "mean_regret": _mean(values),
            "p90_regret": _percentile(sorted(values), 0.90),
        })
    return sorted(rows, key=lambda item: (float(item["mean_regret"]), int(item["count"])), reverse=True)[:20]


def _series(values: list[float]) -> dict[str, Any]:
    ordered = sorted(values)
    return {
        "count": len(values),
        "mean": _mean(values),
        "min": ordered[0] if ordered else 0.0,
        "p50": _percentile(ordered, 0.50),
        "p90": _percentile(ordered, 0.90),
        "max": ordered[-1] if ordered else 0.0,
    }


def _percentile(ordered: list[float], ratio: float) -> float:
    if not ordered:
        return 0.0
    index = min(len(ordered) - 1, max(0, int(round((len(ordered) - 1) * ratio))))
    return float(ordered[index])


def _mean(values: list[float]) -> float:
    return float(statistics.mean(values)) if values else 0.0


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


if __name__ == "__main__":
    raise SystemExit(main())
