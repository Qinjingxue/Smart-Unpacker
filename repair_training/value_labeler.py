from __future__ import annotations

import argparse
import json
from collections import defaultdict
from pathlib import Path
from typing import Any

from repair_training.schemas import TrainingEpisode, TrainingTransition


DEFAULT_GAMMA = 0.85
DEFAULT_STEP_COST = 0.01
DEFAULT_REPEAT_PENALTY = -0.25


def main(argv: list[str] | None = None) -> int:
    args = _parser().parse_args(argv)
    episodes = _read_episodes(Path(args.episodes))
    action_rows: list[dict[str, Any]] = []
    damage_rows: list[dict[str, Any]] = []
    for episode in episodes:
        rows, damage = label_episode_values(
            episode,
            gamma=float(args.gamma),
            step_cost=float(args.step_cost),
            repeat_penalty=float(args.repeat_penalty),
        )
        action_rows.extend(rows)
        damage_rows.extend(damage)
    output = Path(args.output)
    output.parent.mkdir(parents=True, exist_ok=True)
    damage_output = Path(args.damage_output) if args.damage_output else output.with_name("damage_rows.jsonl")
    _write_jsonl(output, action_rows)
    _write_jsonl(damage_output, damage_rows)
    summary = {
        "episodes": len(episodes),
        "action_rows": len(action_rows),
        "damage_rows": len(damage_rows),
        "output": str(output),
        "damage_output": str(damage_output),
    }
    print(json.dumps(summary, ensure_ascii=False, sort_keys=True))
    return 0


def label_episode_values(
    episode: TrainingEpisode,
    *,
    gamma: float = DEFAULT_GAMMA,
    step_cost: float = DEFAULT_STEP_COST,
    repeat_penalty: float = DEFAULT_REPEAT_PENALTY,
) -> tuple[list[dict[str, Any]], list[dict[str, Any]]]:
    transitions_by_state: dict[str, list[TrainingTransition]] = defaultdict(list)
    for transition in episode.transitions:
        transitions_by_state[transition.state_digest].append(transition)
    memo: dict[str, float] = {}

    def value(state_digest: str, visiting: set[str] | None = None) -> float:
        if not state_digest:
            return 0.0
        if state_digest in memo:
            return memo[state_digest]
        visiting = set(visiting or set())
        if state_digest in visiting:
            return repeat_penalty
        visiting.add(state_digest)
        edges = transitions_by_state.get(state_digest, [])
        if not edges:
            memo[state_digest] = 0.0
            return 0.0
        best = max(_q_value(edge, value, visiting, gamma=gamma, step_cost=step_cost, repeat_penalty=repeat_penalty) for edge in edges)
        memo[state_digest] = best
        return best

    # Populate memo before emitting rows so regret can be computed against a stable state value.
    for state_digest in transitions_by_state:
        value(state_digest)

    action_rows: list[dict[str, Any]] = []
    damage_rows: list[dict[str, Any]] = []
    damage_seen: set[str] = set()
    for state_digest, edges in transitions_by_state.items():
        scored = [
            (edge, _q_value(edge, value, set(), gamma=gamma, step_cost=step_cost, repeat_penalty=repeat_penalty))
            for edge in edges
        ]
        if not scored:
            continue
        best_index, best_score = max(enumerate(score for _, score in scored), key=lambda item: item[1])
        for index, (edge, score) in enumerate(scored):
            action = edge.selected_action.to_dict() if edge.selected_action is not None else {}
            action_type = str(action.get("action_type") or "")
            candidate_id = str(action.get("candidate_id") or "")
            current_recovery = _recovery_snapshot(edge.verification_before)
            next_recovery = _recovery_snapshot(edge.verification_after)
            action_rows.append({
                "episode_id": episode.episode_id,
                "format": episode.format,
                "state_digest": state_digest,
                "round_index": edge.round_index,
                "patch_depth": edge.patch_depth,
                "action": action,
                "action_type": action_type,
                "candidate_id": candidate_id,
                "candidate_snapshot": _candidate_snapshot_for_action(edge, candidate_id),
                "damage_analysis_target": dict(edge.damage_analysis_target),
                "current_recovery": current_recovery,
                "next_recovery": next_recovery,
                "recovery_delta": float(edge.verification_after.score or 0.0) - float(edge.verification_before.score or 0.0),
                "score_source": str((next_recovery.get("metadata") or {}).get("score_source") or (current_recovery.get("metadata") or {}).get("score_source") or ""),
                "immediate_reward": _immediate_reward(edge, step_cost=step_cost),
                "long_term_value": score,
                "state_value": best_score,
                "is_best_action": index == best_index,
                "regret": best_score - score,
                "next_state_digest": edge.next_state_digest,
                "terminal": bool(edge.terminal),
            })
        if state_digest not in damage_seen:
            first = edges[0]
            damage_rows.append({
                "episode_id": episode.episode_id,
                "format": episode.format,
                "state_digest": state_digest,
                "round_index": first.round_index,
                "patch_depth": first.patch_depth,
                "damage_analysis_input": dict(first.damage_analysis_request),
                "damage_analysis_target": dict(first.damage_analysis_target),
                "oracle_damage": [label.to_dict() for label in episode.oracle_damage],
            })
            damage_seen.add(state_digest)
    return action_rows, damage_rows


def _q_value(
    edge: TrainingTransition,
    value_fn,
    visiting: set[str],
    *,
    gamma: float,
    step_cost: float,
    repeat_penalty: float,
) -> float:
    action = edge.selected_action.action_type if edge.selected_action is not None else ""
    current_score = float(edge.verification_before.score or 0.0)
    if action == "stop":
        return current_score - step_cost
    if action == "give_up":
        return 0.0 if current_score <= 0.0 else -0.5 - current_score
    if edge.next_state_digest and edge.next_state_digest in visiting:
        return repeat_penalty
    return _immediate_reward(edge, step_cost=step_cost) + gamma * value_fn(edge.next_state_digest, visiting)


def _immediate_reward(edge: TrainingTransition, *, step_cost: float) -> float:
    action = edge.selected_action.action_type if edge.selected_action is not None else ""
    current_score = float(edge.verification_before.score or 0.0)
    next_score = float(edge.verification_after.score or 0.0)
    if action == "undo_patch":
        return next_score - current_score - (step_cost * 0.5)
    if action == "apply_patch":
        return next_score - current_score - step_cost
    return 0.0


def _candidate_snapshot_for_action(edge: TrainingTransition, candidate_id: str) -> dict[str, Any]:
    if not candidate_id:
        return {}
    for candidate in edge.candidate_snapshots:
        if candidate.candidate_id == candidate_id:
            return candidate.to_dict()
    return {}


def _recovery_snapshot(verification) -> dict[str, Any]:
    details = verification.details if isinstance(verification.details, dict) else {}
    recovery = details.get("recovery_snapshot") if isinstance(details.get("recovery_snapshot"), dict) else {}
    if recovery:
        return dict(recovery)
    return {
        "score": float(verification.score or 0.0),
        "status": verification.status,
        "decision_hint": verification.decision_hint,
        "recovered_bytes": int(verification.recovered_bytes or 0),
        "metadata": dict(details),
    }


def _read_episodes(path: Path) -> list[TrainingEpisode]:
    output: list[TrainingEpisode] = []
    with path.open("r", encoding="utf-8") as handle:
        for line in handle:
            if not line.strip():
                continue
            payload = json.loads(line)
            if isinstance(payload, dict):
                output.append(TrainingEpisode.from_dict(payload))
    return output


def _write_jsonl(path: Path, rows: list[dict[str, Any]]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", encoding="utf-8") as handle:
        for row in rows:
            handle.write(json.dumps(row, ensure_ascii=False, sort_keys=True) + "\n")


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Label policy-lab episode transitions with oracle long-term values.")
    parser.add_argument("--episodes", required=True)
    parser.add_argument("--output", required=True)
    parser.add_argument("--damage-output", default="")
    parser.add_argument("--gamma", type=float, default=DEFAULT_GAMMA)
    parser.add_argument("--step-cost", type=float, default=DEFAULT_STEP_COST)
    parser.add_argument("--repeat-penalty", type=float, default=DEFAULT_REPEAT_PENALTY)
    return parser


if __name__ == "__main__":
    raise SystemExit(main())
