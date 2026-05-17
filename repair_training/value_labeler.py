from __future__ import annotations

import argparse
import json
import math
from collections import defaultdict
from pathlib import Path
from typing import Any

from repair_training.schemas import TrainingEpisode, TrainingTransition


DEFAULT_GAMMA = 0.85
DEFAULT_STEP_COST = 0.01
DEFAULT_REPEAT_PENALTY = -0.25


def main(argv: list[str] | None = None) -> int:
    args = _parser().parse_args(argv)
    episodes_path = Path(args.episodes)
    datasets_dir = Path(args.output_dir) if args.output_dir else episodes_path.parent
    datasets_dir.mkdir(parents=True, exist_ok=True)
    damage_output = Path(args.damage_output) if args.damage_output else datasets_dir / "damage_rows.jsonl"
    action_policy_output = Path(args.action_policy_output) if args.action_policy_output else datasets_dir / "action_policy_rows.jsonl"
    state_value_output = Path(args.state_value_output) if args.state_value_output else datasets_dir / "state_value_rows.jsonl"
    report_output = Path(args.report_output) if args.report_output else None
    episodes = 0
    action_count = 0
    damage_count = 0
    stats = _OracleRecoveryStats()
    with damage_output.open("w", encoding="utf-8") as damage_handle, action_policy_output.open("w", encoding="utf-8") as action_policy_handle, state_value_output.open("w", encoding="utf-8") as state_value_handle:
        for episode in _iter_episodes(episodes_path):
            rows, damage = label_episode_values(
                episode,
                gamma=float(args.gamma),
                step_cost=float(args.step_cost),
                repeat_penalty=float(args.repeat_penalty),
            )
            episodes += 1
            action_count += len(rows)
            damage_count += len(damage)
            stats.add_episode(episode, rows)
            _write_jsonl_rows(action_policy_handle, [_action_policy_row(row) for row in rows])
            _write_jsonl_rows(state_value_handle, _state_value_rows_from_action_rows(rows))
            _write_jsonl_rows(damage_handle, damage)
    if report_output is not None:
        report_output.parent.mkdir(parents=True, exist_ok=True)
        stats.write_report(
            report_output,
            episodes_path=episodes_path,
            action_policy_path=action_policy_output,
            state_value_path=state_value_output,
            damage_rows_path=damage_output,
        )
    summary = {
        "episodes": episodes,
        "action_rows": action_count,
        "damage_rows": damage_count,
        "damage_output": str(damage_output),
        "action_policy_output": str(action_policy_output),
        "state_value_output": str(state_value_output),
        "report_output": str(report_output) if report_output is not None else "",
        "streaming": True,
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
    graph_best_value = 0.0
    for transition in episode.transitions:
        transitions_by_state[transition.state_digest].append(transition)
        graph_best_value = max(
            graph_best_value,
            float(transition.verification_before.score or 0.0),
            float(transition.verification_after.score or 0.0),
        )
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
        best = max(_q_value(edge, value, visiting, gamma=gamma, step_cost=step_cost, repeat_penalty=repeat_penalty, graph_best_value=graph_best_value) for edge in edges)
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
            (edge, _q_value(edge, value, set(), gamma=gamma, step_cost=step_cost, repeat_penalty=repeat_penalty, graph_best_value=graph_best_value))
            for edge in edges
        ]
        if not scored:
            continue
        state_candidate_snapshots = _state_candidate_snapshots(edges)
        state_damage_request = _first_transition_payload(edges, "damage_analysis_request")
        state_damage_target = _first_transition_payload(edges, "damage_analysis_target")
        best_index, best_score = max(enumerate(score for _, score in scored), key=lambda item: item[1])
        for index, (edge, score) in enumerate(scored):
            action = edge.selected_action.to_dict() if edge.selected_action is not None else {}
            action_type = str(action.get("action_type") or "")
            candidate_id = str(action.get("candidate_id") or "")
            current_recovery = _compact_action_recovery(_recovery_snapshot(edge.verification_before))
            next_recovery = _compact_action_recovery(_recovery_snapshot(edge.verification_after))
            damage_analysis = _damage_analysis_for_edge(edge, fallback_target=state_damage_target, fallback_candidates=state_candidate_snapshots)
            action_rows.append({
                "episode_id": episode.episode_id,
                "format": episode.format,
                "state_digest": state_digest,
                "round_index": edge.round_index,
                "patch_depth": edge.patch_depth,
                "action": action,
                "action_type": action_type,
                "candidate_id": candidate_id,
                "candidate_snapshot": _candidate_snapshot_for_action(edge, candidate_id, state_candidate_snapshots),
                "damage_analysis_target": {},
                "damage_analysis": damage_analysis,
                "current_recovery": current_recovery,
                "next_recovery": next_recovery,
                "recovery_delta": float(edge.verification_after.score or 0.0) - float(edge.verification_before.score or 0.0),
                "score_source": str((next_recovery.get("metadata") or {}).get("score_source") or (current_recovery.get("metadata") or {}).get("score_source") or ""),
                "immediate_reward": _immediate_reward(edge, step_cost=step_cost),
                "long_term_value": score,
                "policy_prior_label": _policy_prior_label(edge, action_type=action_type, is_best=index == best_index),
                "state_value": best_score,
                "value_gap": best_score - float(current_recovery.get("score") or 0.0),
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
                "damage_analysis_input": dict(first.damage_analysis_request or state_damage_request),
                "damage_analysis_target": dict(first.damage_analysis_target or state_damage_target),
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
    graph_best_value: float = 0.0,
) -> float:
    action = edge.selected_action.action_type if edge.selected_action is not None else ""
    current_score = float(edge.verification_before.score or 0.0)
    if action == "stop":
        return current_score - step_cost
    if action == "give_up":
        return max(current_score, float(graph_best_value or 0.0)) - step_cost
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


def _candidate_snapshot_for_action(edge: TrainingTransition, candidate_id: str, fallback_candidates: list[dict[str, Any]] | None = None) -> dict[str, Any]:
    if not candidate_id:
        return {}
    for candidate in edge.candidate_snapshots:
        if candidate.candidate_id == candidate_id:
            return _scrub_candidate_training_input(candidate.to_dict())
    for candidate in fallback_candidates or []:
        if str(candidate.get("candidate_id") or "") == candidate_id:
            return _scrub_candidate_training_input(candidate)
    return {}


def _state_candidate_snapshots(edges: list[TrainingTransition]) -> list[dict[str, Any]]:
    for edge in edges:
        if edge.candidate_snapshots:
            return [_scrub_candidate_training_input(candidate.to_dict()) for candidate in edge.candidate_snapshots]
    return []


def _first_transition_payload(edges: list[TrainingTransition], attr: str) -> dict[str, Any]:
    for edge in edges:
        value = getattr(edge, attr, None)
        if isinstance(value, dict) and value:
            return dict(value)
    return {}


def _damage_analysis_for_edge(
    edge: TrainingTransition,
    *,
    fallback_target: dict[str, Any] | None = None,
    fallback_candidates: list[dict[str, Any]] | None = None,
) -> dict[str, Any]:
    target = edge.damage_analysis_target if isinstance(edge.damage_analysis_target, dict) and edge.damage_analysis_target else (fallback_target or {})
    if isinstance(target.get("model_damage_analysis"), dict):
        return dict(target["model_damage_analysis"])
    for snapshot in edge.candidate_snapshots:
        payload = snapshot.to_dict()
        metadata = payload.get("metadata") if isinstance(payload.get("metadata"), dict) else {}
        if isinstance(metadata.get("damage_analysis"), dict):
            return dict(metadata["damage_analysis"])
    for payload in fallback_candidates or []:
        metadata = payload.get("metadata") if isinstance(payload.get("metadata"), dict) else {}
        if isinstance(metadata.get("damage_analysis"), dict):
            return dict(metadata["damage_analysis"])
    return dict(target)


def _policy_prior_label(edge: TrainingTransition, *, action_type: str, is_best: bool) -> int:
    current = float(edge.verification_before.score or 0.0)
    next_score = float(edge.verification_after.score or 0.0)
    improvement = next_score - current
    if is_best:
        return 30
    if action_type == "apply_patch":
        if improvement > 0.20:
            return 28
        if improvement > 0.05:
            return 22
        if improvement >= -0.01:
            return 14
        return 6
    if action_type == "undo_patch":
        return 18 if improvement > 0.02 else 8
    if action_type == "stop":
        return 24 if current >= 0.95 else 6
    if action_type == "give_up":
        return 16 if current <= 0.02 else 2
    return 0


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


def _compact_action_recovery(recovery: dict[str, Any]) -> dict[str, Any]:
    metadata = recovery.get("metadata") if isinstance(recovery.get("metadata"), dict) else {}
    return {
        "score": float(recovery.get("score") or 0.0),
        "status": str(recovery.get("status") or ""),
        "decision_hint": str(recovery.get("decision_hint") or ""),
        "completeness": float(recovery.get("completeness") or recovery.get("score") or 0.0),
        "complete_files": int(recovery.get("complete_files") or 0),
        "partial_files": int(recovery.get("partial_files") or 0),
        "failed_files": int(recovery.get("failed_files") or 0),
        "missing_files": int(recovery.get("missing_files") or 0),
        "recovered_bytes": int(recovery.get("recovered_bytes") or 0),
        "metadata": {
            key: metadata.get(key)
            for key in ("score_source", "source", "mode", "module_name", "candidate_status", "status_reason")
            if metadata.get(key) is not None
        },
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


def _iter_episodes(path: Path):
    with path.open("r", encoding="utf-8") as handle:
        for line in handle:
            if not line.strip():
                continue
            payload = json.loads(line)
            if isinstance(payload, dict):
                yield TrainingEpisode.from_dict(payload)


def _write_jsonl(path: Path, rows: list[dict[str, Any]]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", encoding="utf-8") as handle:
        for row in rows:
            handle.write(json.dumps(row, ensure_ascii=False, sort_keys=True) + "\n")


def _write_jsonl_rows(handle, rows: list[dict[str, Any]]) -> None:
    for row in rows:
        handle.write(json.dumps(row, ensure_ascii=False, sort_keys=True) + "\n")
    handle.flush()


def _state_value_rows_from_action_rows(rows: list[dict[str, Any]]) -> list[dict[str, Any]]:
    grouped: dict[str, list[dict[str, Any]]] = defaultdict(list)
    for row in rows:
        grouped[str(row.get("state_digest") or "")].append(row)
    output: list[dict[str, Any]] = []
    for state_digest, group in grouped.items():
        if not group:
            continue
        base = group[0]
        output.append({
            "episode_id": base.get("episode_id"),
            "format": base.get("format"),
            "state_digest": state_digest,
            "round_index": base.get("round_index"),
            "patch_depth": base.get("patch_depth"),
            "damage_analysis": base.get("damage_analysis") if isinstance(base.get("damage_analysis"), dict) else {},
            "current_recovery": base.get("current_recovery") if isinstance(base.get("current_recovery"), dict) else {},
            "best_seen_recovery": base.get("best_seen_recovery") if isinstance(base.get("best_seen_recovery"), dict) else {},
            "parent_recovery": base.get("parent_recovery") if isinstance(base.get("parent_recovery"), dict) else {},
            "repair_history": base.get("repair_history") if isinstance(base.get("repair_history"), dict) else {},
            "candidate_summary": _candidate_summary_from_action_rows(group),
            "reachable_recovery_value": max(float(row.get("state_value") or 0.0) for row in group),
        })
    return output


def _action_policy_row(row: dict[str, Any]) -> dict[str, Any]:
    output = dict(row)
    for key in ("state_value", "value_gap", "long_term_value", "regret", "next_recovery", "recovery_delta", "score_source", "next_state_digest"):
        output.pop(key, None)
    output["candidate_snapshot"] = _scrub_candidate_training_input(output.get("candidate_snapshot") or {})
    return output


def _candidate_summary_from_action_rows(rows: list[dict[str, Any]]) -> dict[str, Any]:
    apply_rows = [row for row in rows if str(row.get("action_type") or "") == "apply_patch"]
    return {
        "candidate_count": len(apply_rows),
        "has_candidate": bool(apply_rows),
        "has_undo_action": any(str(row.get("action_type") or "") == "undo_patch" for row in rows),
        "has_stop_action": any(str(row.get("action_type") or "") == "stop" for row in rows),
        "has_give_up_action": any(str(row.get("action_type") or "") == "give_up" for row in rows),
    }


def _scrub_candidate_training_input(snapshot: dict[str, Any]) -> dict[str, Any]:
    output = dict(snapshot or {})
    for key in (
        "patch_digest",
        "patch_depth",
        "patch_count",
        "last_patch_module",
        "has_archive_state_plan",
        "branchable",
        "recovery_snapshot",
        "recovery_score",
        "recovery_status",
        "recovery_delta",
        "verification_summary",
        "score_source",
        "workspace_paths",
        "repaired_input",
    ):
        output.pop(key, None)
    metadata = output.get("metadata") if isinstance(output.get("metadata"), dict) else {}
    if metadata:
        output["metadata"] = {
            key: value
            for key, value in metadata.items()
            if not str(key).startswith("recovery_")
            and key not in {"verification_summary", "score_source", "candidate_status", "status_reason"}
        }
    validation = output.get("validation_summary") if isinstance(output.get("validation_summary"), dict) else {}
    if validation:
        output["validation_summary"] = {
            key: value
            for key, value in validation.items()
            if not str(key).startswith("recovery_") and key not in {"verification_summary", "score_source"}
        }
    return output


class _OracleRecoveryStats:
    def __init__(self) -> None:
        self.episode_count = 0
        self.root_scores: list[float] = []
        self.best_scores: list[float] = []
        self.transitions_per_episode: list[int] = []
        self.actions_per_episode: list[int] = []
        self.action_rows = 0
        self.all_action_kind: defaultdict[str, int] = defaultdict(int)
        self.best_action_kind: defaultdict[str, int] = defaultdict(int)
        self.best_source: defaultdict[str, int] = defaultdict(int)
        self.profiles: defaultdict[str, dict[str, Any]] = defaultdict(lambda: {
            "n": 0,
            "root": [],
            "best": [],
            "transitions": 0,
            "actions": 0,
        })

    def add_episode(self, episode: TrainingEpisode, action_rows: list[dict[str, Any]]) -> None:
        self.episode_count += 1
        self.action_rows += len(action_rows)
        transitions = list(episode.transitions or [])
        self.transitions_per_episode.append(len(transitions))
        self.actions_per_episode.append(len(action_rows))
        profile = _episode_profile(episode)
        root_score = _transition_score(transitions[0], "before") if transitions else 0.0
        best_score = root_score
        best_source = _transition_score_source(transitions[0], "before") if transitions else ""
        for transition in transitions:
            for side in ("before", "after"):
                score = _transition_score(transition, side)
                if score > best_score:
                    best_score = score
                    best_source = _transition_score_source(transition, side)
        self.root_scores.append(root_score)
        self.best_scores.append(best_score)
        self.best_source[best_source or "unknown"] += 1
        bucket = self.profiles[profile]
        bucket["n"] += 1
        bucket["root"].append(root_score)
        bucket["best"].append(best_score)
        bucket["transitions"] += len(transitions)
        bucket["actions"] += len(action_rows)
        for row in action_rows:
            action_type = str(row.get("action_type") or (row.get("action") or {}).get("action_type") or "")
            self.all_action_kind[action_type or "unknown"] += 1
            if row.get("is_best_action"):
                self.best_action_kind[action_type or "unknown"] += 1

    def to_dict(self, *, episodes_path: Path, action_policy_path: Path, state_value_path: Path, damage_rows_path: Path) -> dict[str, Any]:
        profiles = []
        for name, payload in self.profiles.items():
            best = _quantiles(payload["best"])
            root = _quantiles(payload["root"])
            n = int(payload["n"] or 0)
            profiles.append({
                "profile": name,
                "n": n,
                "root_mean": root.get("mean", 0.0),
                "best_mean": best.get("mean", 0.0),
                "best_p50": best.get("p50", 0.0),
                "best_ge_0_5": best.get("ge_0_50", 0.0),
                "best_ge_0_8": best.get("ge_0_80", 0.0),
                "best_ge_0_95": best.get("ge_0_95", 0.0),
                "complete_ge_0_999": best.get("complete_ge_0_999", 0.0),
                "avg_transitions": float(payload["transitions"] or 0) / max(1, n),
                "avg_action_rows": float(payload["actions"] or 0) / max(1, n),
            })
        return {
            "schema_version": 1,
            "files": {
                "episodes": _file_size_payload(episodes_path),
                "action_policy_rows": _file_size_payload(action_policy_path),
                "state_value_rows": _file_size_payload(state_value_path),
                "damage_rows": _file_size_payload(damage_rows_path),
            },
            "oracle_recovery": {
                "episode_count": self.episode_count,
                "root": _quantiles(self.root_scores),
                "best_reachable": _quantiles(self.best_scores),
                "transitions_per_episode": _quantiles(self.transitions_per_episode),
                "actions_per_episode": _quantiles(self.actions_per_episode),
                "best_score_source": dict(sorted(self.best_source.items())),
            },
            "action_policy": {
                "action_rows": self.action_rows,
                "all_action_kind": dict(sorted(self.all_action_kind.items())),
                "best_action_kind": dict(sorted(self.best_action_kind.items())),
            },
            "profiles_weakest_20": sorted(profiles, key=lambda item: (item["best_mean"], item["best_ge_0_8"], -item["n"]))[:20],
            "profiles_strongest_20": sorted(profiles, key=lambda item: (-item["best_mean"], -item["best_ge_0_8"], -item["n"]))[:20],
        }

    def write_report(self, path: Path, *, episodes_path: Path, action_policy_path: Path, state_value_path: Path, damage_rows_path: Path) -> None:
        path.write_text(
            json.dumps(
                self.to_dict(
                    episodes_path=episodes_path,
                    action_policy_path=action_policy_path,
                    state_value_path=state_value_path,
                    damage_rows_path=damage_rows_path,
                ),
                ensure_ascii=False,
                indent=2,
                sort_keys=True,
            ),
            encoding="utf-8",
        )


def _transition_score(transition: TrainingTransition, side: str) -> float:
    snapshot = transition.verification_before if side == "before" else transition.verification_after
    return float(snapshot.score or 0.0)


def _transition_score_source(transition: TrainingTransition, side: str) -> str:
    snapshot = transition.verification_before if side == "before" else transition.verification_after
    details = snapshot.details if isinstance(snapshot.details, dict) else {}
    recovery = details.get("recovery_snapshot") if isinstance(details.get("recovery_snapshot"), dict) else {}
    metadata = recovery.get("metadata") if isinstance(recovery.get("metadata"), dict) else {}
    return str(details.get("score_source") or metadata.get("score_source") or "")


def _episode_profile(episode: TrainingEpisode) -> str:
    metadata = episode.metadata if isinstance(episode.metadata, dict) else {}
    raw = metadata.get("raw_damage_record") if isinstance(metadata.get("raw_damage_record"), dict) else {}
    taxonomy = metadata.get("taxonomy") if isinstance(metadata.get("taxonomy"), dict) else {}
    target_metadata = taxonomy.get("metadata") if isinstance(taxonomy.get("metadata"), dict) else {}
    return str(raw.get("damage_profile") or target_metadata.get("damage_profile") or "unknown")


def _quantiles(values: list[float] | list[int]) -> dict[str, Any]:
    vals = sorted(float(item or 0.0) for item in values)
    if not vals:
        return {"count": 0}
    def q(percent: float) -> float:
        if len(vals) == 1:
            return vals[0]
        index = (len(vals) - 1) * percent
        lo = int(math.floor(index))
        hi = int(math.ceil(index))
        if lo == hi:
            return vals[lo]
        return vals[lo] * (hi - index) + vals[hi] * (index - lo)
    count = len(vals)
    return {
        "count": count,
        "mean": sum(vals) / count,
        "p50": q(0.50),
        "p75": q(0.75),
        "p90": q(0.90),
        "p95": q(0.95),
        "max": vals[-1],
        "zero_rate": sum(1 for item in vals if item <= 1e-9) / count,
        "ge_0_25": sum(1 for item in vals if item >= 0.25) / count,
        "ge_0_50": sum(1 for item in vals if item >= 0.50) / count,
        "ge_0_80": sum(1 for item in vals if item >= 0.80) / count,
        "ge_0_95": sum(1 for item in vals if item >= 0.95) / count,
        "complete_ge_0_999": sum(1 for item in vals if item >= 0.999) / count,
    }


def _file_size_payload(path: Path) -> dict[str, Any]:
    if not path.exists():
        return {"path": str(path), "exists": False}
    size = path.stat().st_size
    return {
        "path": str(path),
        "exists": True,
        "bytes": size,
        "mb": round(size / 1024 / 1024, 3),
    }


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Label policy-lab episode transitions with oracle long-term values.")
    parser.add_argument("--episodes", required=True)
    parser.add_argument("--output-dir", default="")
    parser.add_argument("--damage-output", default="")
    parser.add_argument("--action-policy-output", default="")
    parser.add_argument("--state-value-output", default="")
    parser.add_argument("--report-output", default="")
    parser.add_argument("--gamma", type=float, default=DEFAULT_GAMMA)
    parser.add_argument("--step-cost", type=float, default=DEFAULT_STEP_COST)
    parser.add_argument("--repeat-penalty", type=float, default=DEFAULT_REPEAT_PENALTY)
    return parser


if __name__ == "__main__":
    raise SystemExit(main())
