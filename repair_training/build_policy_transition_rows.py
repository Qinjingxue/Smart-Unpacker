from __future__ import annotations

import argparse
from concurrent.futures import FIRST_COMPLETED, ProcessPoolExecutor, wait
from dataclasses import replace
import json
from pathlib import Path
import time
from typing import Any

from repair_training.build_policy_graph_rows import _sanitize_action_features, _sanitize_diagnosis_hgt, _sanitize_training_graph
from repair_training.core.datasets import read_jsonl, write_json, write_jsonl
from repair_training.core.repair_policy_transformer.schema import PolicyAction, PolicyGraphTransitionSample
from repair_training.core.repair_policy_transformer.teacher import (
    DEFAULT_TEACHER_BUDGET,
    _RuntimeTeacherContext,
    _best_score,
    _job_from_row,
    _select_runtime_action_proposals,
)
from repair_training.core.repair_policy_transformer.world_rows import _observed_delta
from sunpack.repair.policy.graph import PolicyRepairGraph


EXPLORATION_POLICIES = ("prior_biased", "family_coverage", "bad_branch", "undo_heavy", "teacher_guided")


def main(argv: list[str] | None = None) -> int:
    args = _parser().parse_args(argv)
    rows = read_jsonl(args.input)
    output = Path(args.output)
    if args.no_resume and output.is_file():
        output.unlink()
    existing_rows = read_jsonl(output) if output.is_file() and not args.no_resume else []
    completed_indices = {
        int(((row.get("source") or {}).get("row_index")))
        for row in existing_rows
        if isinstance(row.get("source"), dict) and str((row.get("source") or {}).get("row_index", "")).isdigit()
    }
    budget = {
        **DEFAULT_TEACHER_BUDGET,
        "max_depth": args.max_steps,
        "runtime_action_top_n": args.runtime_action_top_n,
        "teacher_deep_eval_top_n": args.teacher_deep_eval_top_n,
        "teacher_shallow_eval_top_n": args.teacher_shallow_eval_top_n,
        "rollout_depth": args.rollout_depth,
        "max_expansions": args.max_expansions,
        "seed": args.seed,
    }
    started = time.monotonic()
    transitions = _collect_parallel(
        rows,
        format_name=args.format,
        budget=budget,
        workspace=args.workspace,
        recovery_mode=args.recovery_mode,
        workers=max(1, int(args.workers or 1)),
        episodes_per_archive=max(1, int(args.episodes_per_archive or 1)),
        max_steps=max(1, int(args.max_steps or 1)),
        output=output,
        completed_indices=completed_indices,
        max_seconds=float(args.max_seconds or 0.0),
    )
    all_rows = [*existing_rows, *[row.to_dict() for row in transitions]]
    if not args.stream_output:
        write_jsonl(output, all_rows)
    write_json(Path(args.summary_output) if args.summary_output else output.with_name("policy_transition_rows_summary.json"), {
        "rows": len(all_rows),
        "new_rows": len(transitions),
        "input_rows": len(rows),
        "completed_input_rows": len(completed_indices | {int((row.source or {}).get("row_index", -1)) for row in transitions if str((row.source or {}).get("row_index", "")).isdigit()}),
        "workers": max(1, int(args.workers or 1)),
        "episodes_per_archive": max(1, int(args.episodes_per_archive or 1)),
        "elapsed_seconds": time.monotonic() - started,
        "max_seconds": float(args.max_seconds or 0.0),
        "timed_out": bool(args.max_seconds and time.monotonic() - started >= float(args.max_seconds)),
        "exploration_policy_counts": _counts(row.get("exploration_policy") for row in all_rows),
        "formats": sorted({str(row.get("format") or "") for row in all_rows if str(row.get("format") or "")}),
    })
    return 0


def _collect_parallel(
    rows: list[dict[str, Any]],
    *,
    format_name: str,
    budget: dict[str, Any],
    workspace: str,
    recovery_mode: str,
    workers: int,
    episodes_per_archive: int,
    max_steps: int,
    output: Path | None = None,
    completed_indices: set[int] | None = None,
    max_seconds: float = 0.0,
) -> list[PolicyGraphTransitionSample]:
    started = time.monotonic()
    completed_indices = set(completed_indices or set())
    indexed_rows = [(index, row) for index, row in enumerate(rows) if index not in completed_indices]
    if workers <= 1:
        collected: list[PolicyGraphTransitionSample] = []
        for index, row in indexed_rows:
            if max_seconds and time.monotonic() - started >= max_seconds:
                break
            chunk = _collect_one(index, row, format_name, budget, workspace, recovery_mode, episodes_per_archive, max_steps)
            _append_transition_rows(output_path=output, rows=chunk)
            collected.extend(chunk)
        return collected
    root = Path(workspace or "repair_training_policy_transition_workspace")
    root.mkdir(parents=True, exist_ok=True)
    completed: dict[int, list[dict[str, Any]]] = {}
    next_pos = 0
    pending = {}
    pool = ProcessPoolExecutor(max_workers=workers)
    try:
        while next_pos < len(indexed_rows) and len(pending) < workers:
            index, row = indexed_rows[next_pos]
            pending[pool.submit(_worker_collect_one, index, row, format_name, budget, str(root / f"worker_{index % workers}"), recovery_mode, episodes_per_archive, max_steps)] = index
            next_pos += 1
        while pending:
            remaining = max_seconds - (time.monotonic() - started) if max_seconds else None
            if remaining is not None and remaining <= 0:
                break
            done, _ = wait(pending, timeout=remaining if remaining is not None else None, return_when=FIRST_COMPLETED)
            if not done:
                break
            for future in done:
                index = pending.pop(future)
                chunk = future.result()
                completed[index] = chunk
                _append_json_rows(output, chunk)
                if max_seconds and time.monotonic() - started >= max_seconds:
                    continue
                while next_pos < len(indexed_rows) and len(pending) < workers:
                    submit_index, submit_row = indexed_rows[next_pos]
                    pending[pool.submit(_worker_collect_one, submit_index, submit_row, format_name, budget, str(root / f"worker_{submit_index % workers}"), recovery_mode, episodes_per_archive, max_steps)] = submit_index
                    next_pos += 1
    finally:
        for future in pending:
            future.cancel()
        if pending and max_seconds and time.monotonic() - started >= max_seconds:
            _terminate_pool_workers(pool)
        pool.shutdown(wait=False, cancel_futures=True)
    from repair_training.core.repair_policy_transformer.schema import transition_sample_from_dict

    output = []
    for index in sorted(completed):
        output.extend(transition_sample_from_dict(row) for row in completed[index])
    return output


def _append_transition_rows(*, output_path: Path | None, rows: list[PolicyGraphTransitionSample]) -> None:
    if output_path is None or not rows:
        return
    _append_json_rows(output_path, [row.to_dict() for row in rows])


def _append_json_rows(output_path: Path | None, rows: list[dict[str, Any]]) -> None:
    if output_path is None or not rows:
        return
    output_path.parent.mkdir(parents=True, exist_ok=True)
    with output_path.open("a", encoding="utf-8") as handle:
        for row in rows:
            handle.write(json.dumps(row, ensure_ascii=False, sort_keys=True) + "\n")


def _terminate_pool_workers(pool: ProcessPoolExecutor) -> None:
    processes = getattr(pool, "_processes", None)
    if not isinstance(processes, dict):
        return
    for process in list(processes.values()):
        try:
            process.terminate()
        except Exception:
            pass


def _worker_collect_one(index: int, row: dict[str, Any], format_name: str, budget: dict[str, Any], workspace: str, recovery_mode: str, episodes_per_archive: int, max_steps: int) -> list[dict[str, Any]]:
    return [sample.to_dict() for sample in _collect_one(index, row, format_name, {**budget, "seed": int(budget.get("seed", 13) or 13) + index}, workspace, recovery_mode, episodes_per_archive, max_steps)]


def _collect_one(index: int, row: dict[str, Any], format_name: str, budget: dict[str, Any], workspace: str, recovery_mode: str, episodes_per_archive: int, max_steps: int) -> list[PolicyGraphTransitionSample]:
    ctx = _RuntimeTeacherContext(config={}, workspace=Path(workspace) if workspace else None, recovery_mode=recovery_mode, budget=budget)
    output: list[PolicyGraphTransitionSample] = []
    try:
        for episode_index in range(episodes_per_archive):
            policy = EXPLORATION_POLICIES[episode_index % len(EXPLORATION_POLICIES)]
            episode = _run_episode(ctx, row, row_index=index, format_name=format_name, episode_index=episode_index, exploration_policy=policy, max_steps=max_steps)
            output.extend(annotate_episode_future_best_q(episode))
    finally:
        ctx.close()
    return output


def _run_episode(ctx: _RuntimeTeacherContext, row: dict[str, Any], *, row_index: int, format_name: str, episode_index: int, exploration_policy: str, max_steps: int) -> list[PolicyGraphTransitionSample]:
    job = _job_from_row(row, row_index=row_index, format_name=format_name, workspace=ctx.workspace_root)
    if job is None:
        return []
    plugin = __import__("sunpack.repair.policy.formats", fromlist=["get_repair_format_plugin"]).get_repair_format_plugin(job.format)
    if plugin is None:
        return []
    recovery = ctx.evaluator.evaluate_state(job, job.archive_state, mode=ctx.recovery_mode, cache=ctx.cache)
    repair_graph = PolicyRepairGraph.initialize(job, recovery)
    job = ctx._job_with_refreshed_knowledge(job, job.archive_state, recovery=recovery, step=0)
    diagnosis = ctx._diagnose_state(row=row, job=job, repair_graph=repair_graph, recovery=recovery, round_index=0)
    repair_graph.observe_current_state(recovery=recovery, diagnosis_hgt=diagnosis, verification=dict(recovery.verification or {}))
    transitions: list[PolicyGraphTransitionSample] = []
    for step in range(1, max_steps + 1):
        runtime_proposals = plugin.available_modules(scheduler=ctx.scheduler, job=job, diagnosis_hgt=diagnosis, graph=repair_graph.graph)
        exposed_edges = repair_graph.register_proposals([proposal.to_action_payload() for proposal in runtime_proposals], step=step)
        exposed_ids = {edge.candidate_id for edge in exposed_edges}
        proposals = _select_runtime_action_proposals([proposal for proposal in runtime_proposals if proposal.action_id in exposed_ids], repair_graph, ctx.budget)
        actions = [_action_from_payload(proposal.to_action_payload()) for proposal in proposals]
        current = repair_graph.graph.current_node()
        if current is not None and current.parent_id:
            actions.append(PolicyAction(action_type="undo", action_id="undo"))
        actions.append(PolicyAction(action_type="stop", action_id="stop"))
        if not actions:
            break
        chosen = _choose_action(actions, exploration_policy, step, graph=repair_graph.graph.to_dict())
        graph_before = _sanitize_training_graph(repair_graph.graph.to_dict())
        proposal_by_id = {proposal.action_id: proposal for proposal in proposals}
        action_q_values = ctx._evaluate_actions(job=job, plugin=plugin, repair_graph=repair_graph, actions=actions, proposal_by_id=proposal_by_id, step=step)
        applied = ctx._apply_action(job=job, plugin=plugin, repair_graph=repair_graph, action=chosen, step=step, proposal_by_id=proposal_by_id)
        if applied is None or applied.archive_state is None:
            graph_after = _sanitize_training_graph(repair_graph.graph.to_dict())
        else:
            recovery = ctx.evaluator.evaluate_state(job, applied.archive_state, mode=ctx.recovery_mode, cache=ctx.cache)
            job = ctx._job_with_refreshed_knowledge(replace(job, archive_state=applied.archive_state), applied.archive_state, recovery=recovery, step=step)
            diagnosis = ctx._diagnose_state(row=row, job=job, repair_graph=repair_graph, recovery=recovery, round_index=step)
            repair_graph.observe_current_state(recovery=recovery, diagnosis_hgt=diagnosis, verification=dict(recovery.verification or {}))
            graph_after = _sanitize_training_graph(repair_graph.graph.to_dict())
        transitions.append(PolicyGraphTransitionSample(
            sample_id=f"{row.get('sample_id') or job.archive_key}:episode:{episode_index}:step:{step}",
            format=job.format,
            graph_before=graph_before,
            current_node_id=str(graph_before.get("current_node_id") or ""),
            best_node_id=str(graph_before.get("best_node_id") or ""),
            available_actions=actions,
            chosen_action=chosen,
            graph_after=graph_after,
            observed_delta=_observed_delta(graph_before, graph_after),
            action_q_values=action_q_values,
            episode_id=f"{row.get('sample_id') or job.archive_key}:episode:{episode_index}",
            step_index=step,
            exploration_policy=exploration_policy,
            source={"row_index": row_index, "sample_id": row.get("sample_id") or "", "damage_profile": row.get("damage_profile") or ""},
        ))
        if chosen.action_type == "stop":
            break
    return transitions


def annotate_episode_future_best_q(transitions: list[PolicyGraphTransitionSample]) -> list[PolicyGraphTransitionSample]:
    if not transitions:
        return []
    future_best: list[float] = [0.0] * len(transitions)
    running = 0.0
    for index in range(len(transitions) - 1, -1, -1):
        running = max(running, _graph_best_score(transitions[index].graph_after))
        future_best[index] = running
    output: list[PolicyGraphTransitionSample] = []
    for index, transition in enumerate(transitions):
        chosen_q = future_best[index]
        stop_q = _graph_best_score(transition.graph_before)
        q_values = dict(transition.action_q_values or {})
        chosen_key = _action_key(transition.chosen_action)
        q_values[chosen_key] = max(float(q_values.get(chosen_key, 0.0) or 0.0), chosen_q)
        if transition.chosen_action.action_id:
            q_values[transition.chosen_action.action_id] = max(float(q_values.get(transition.chosen_action.action_id, 0.0) or 0.0), chosen_q)
        q_values["stop:stop"] = stop_q
        q_values["stop"] = stop_q
        max_known_q = max([chosen_q, stop_q, *[float(value or 0.0) for value in q_values.values()]] or [stop_q])
        actions = [
            _annotate_action_q(
                action,
                chosen=transition.chosen_action,
                chosen_q=chosen_q,
                stop_q=stop_q,
                action_q_values=q_values,
                max_known_q=max_known_q,
                horizon=len(transitions) - index,
            )
            for action in transition.available_actions
        ]
        chosen = _annotate_action_q(
            transition.chosen_action,
            chosen=transition.chosen_action,
            chosen_q=chosen_q,
            stop_q=stop_q,
            action_q_values=q_values,
            max_known_q=max_known_q,
            horizon=len(transitions) - index,
        )
        output.append(PolicyGraphTransitionSample(
            sample_id=transition.sample_id,
            format=transition.format,
            graph_before=transition.graph_before,
            current_node_id=transition.current_node_id,
            best_node_id=transition.best_node_id,
            available_actions=actions,
            chosen_action=chosen,
            graph_after=transition.graph_after,
            observed_delta=transition.observed_delta,
            action_q_values=q_values,
            episode_id=transition.episode_id,
            step_index=transition.step_index,
            exploration_policy=transition.exploration_policy,
            source={
                **dict(transition.source or {}),
                "q_label_source": "episode_future_best",
                "episode_future_best": chosen_q,
                "stop_q_value": stop_q,
            },
        ))
    return output


def _annotate_action_q(
    action: PolicyAction,
    *,
    chosen: PolicyAction,
    chosen_q: float,
    stop_q: float,
    action_q_values: dict[str, Any] | None = None,
    max_known_q: float,
    horizon: int,
) -> PolicyAction:
    from dataclasses import replace

    if action.action_type == "stop":
        q = stop_q
        source = "episode_stop_current_best"
        evaluated = True
    elif action_q_values and (_action_key(action) in action_q_values or action.action_id in action_q_values):
        q = float(action_q_values.get(_action_key(action), action_q_values.get(action.action_id, 0.0)) or 0.0)
        source = "bounded_action_rollout"
        evaluated = True
    elif _same_action(action, chosen):
        q = chosen_q
        source = "episode_chosen_future_best"
        evaluated = True
    else:
        return action
    q = _clamp01(q)
    max_known_q = _clamp01(max_known_q)
    return replace(
        action,
        action_q_value=q,
        q_source=source,
        q_horizon=max(0, int(horizon or 0)),
        action_regret=max(0.0, max_known_q - q),
        is_teacher_evaluated=evaluated,
        best_action_set_member=max_known_q - q <= 0.02,
        q_bucket=_q_bucket(q),
    )


def _same_action(left: PolicyAction, right: PolicyAction) -> bool:
    if left.action_id and right.action_id and left.action_id == right.action_id:
        return True
    return left.action_type == right.action_type and left.module_name == right.module_name


def _action_key(action: PolicyAction) -> str:
    if action.action_type == "module" and action.module_name:
        return f"module:{action.module_name}"
    return f"{action.action_type}:{action.action_id or action.action_type}"


def _graph_best_score(graph: dict[str, Any]) -> float:
    nodes = graph.get("nodes") if isinstance(graph.get("nodes"), dict) else {}
    best = 0.0
    for node in nodes.values() if isinstance(nodes, dict) else []:
        if not isinstance(node, dict):
            continue
        recovery = node.get("recovery") if isinstance(node.get("recovery"), dict) else {}
        best = max(best, _score(recovery))
    return best


def _score(recovery: dict[str, Any]) -> float:
    try:
        return _clamp01(float(recovery.get("score", recovery.get("completeness", 0.0)) or 0.0))
    except (TypeError, ValueError):
        return 0.0


def _clamp01(value: float) -> float:
    return max(0.0, min(1.0, float(value)))


def _q_bucket(value: float) -> str:
    value = _clamp01(value)
    if value >= 0.99:
        return "complete"
    if value >= 0.75:
        return "high"
    if value >= 0.4:
        return "medium"
    if value > 0.0:
        return "low"
    return "zero"


def _action_from_payload(payload: dict[str, Any]) -> PolicyAction:
    return PolicyAction(
        action_type=str(payload.get("action_type") or "module"),  # type: ignore[arg-type]
        action_id=str(payload.get("action_id") or payload.get("candidate_id") or payload.get("action_type") or ""),
        module_name=str(payload.get("module_name") or payload.get("module") or ""),
        features=_sanitize_action_features(payload),
    )


def _choose_action(actions: list[PolicyAction], policy: str, step: int, *, graph: dict[str, Any] | None = None) -> PolicyAction:
    previous_module, _previous_family = _incoming_module_family(graph or {})
    modules = [action for action in actions if action.action_type == "module"]
    non_repeat_modules = [
        action for action in modules
        if not (previous_module and action.module_name == previous_module)
    ]
    if non_repeat_modules:
        modules = non_repeat_modules
    undo = next((action for action in actions if action.action_type == "undo"), None)
    stop = next((action for action in actions if action.action_type == "stop"), None)
    if policy == "undo_heavy" and undo is not None and step > 1 and step % 2 == 0:
        return undo
    if policy == "bad_branch" and modules:
        return modules[-1]
    if policy == "family_coverage" and modules:
        return modules[(step - 1) % len(modules)]
    if policy == "teacher_guided" and modules:
        return modules[0]
    if modules:
        return modules[0]
    return undo or stop or actions[0]


def _incoming_module_family(graph: dict[str, Any]) -> tuple[str, str]:
    nodes = graph.get("nodes") if isinstance(graph.get("nodes"), dict) else {}
    current_id = str(graph.get("current_node_id") or "")
    current = nodes.get(current_id) if isinstance(nodes.get(current_id), dict) else {}
    parent_id = str(current.get("parent_id") or "") if isinstance(current, dict) else ""
    if not current_id or not parent_id:
        return "", ""
    edges = graph.get("edges") if isinstance(graph.get("edges"), dict) else {}
    for edge in edges.values() if isinstance(edges, dict) else []:
        if not isinstance(edge, dict):
            continue
        if str(edge.get("from_node_id") or "") == parent_id and str(edge.get("to_node_id") or "") == current_id:
            return str(edge.get("module_name") or ""), str(edge.get("module_family") or edge.get("module_name") or "")
    return str(current.get("module_name") or ""), str(current.get("module_name") or "")


def _counts(values) -> dict[str, int]:
    counts: dict[str, int] = {}
    for value in values:
        text = str(value or "")
        counts[text] = counts.get(text, 0) + 1
    return dict(sorted(counts.items()))


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Collect RepairGraph transition rows for world-model policy training.")
    parser.add_argument("--format", default="zip")
    parser.add_argument("--input", required=True)
    parser.add_argument("--output", required=True)
    parser.add_argument("--summary-output", default="")
    parser.add_argument("--workspace", default="")
    parser.add_argument("--workers", type=int, default=1)
    parser.add_argument("--episodes-per-archive", type=int, default=2)
    parser.add_argument("--max-steps", type=int, default=4)
    parser.add_argument("--max-expansions", type=int, default=16)
    parser.add_argument("--runtime-action-top-n", type=int, default=16)
    parser.add_argument("--teacher-deep-eval-top-n", type=int, default=5)
    parser.add_argument("--teacher-shallow-eval-top-n", type=int, default=16)
    parser.add_argument("--rollout-depth", type=int, default=2)
    parser.add_argument("--seed", type=int, default=13)
    parser.add_argument("--recovery-mode", choices=["policy_light", "policy_full", "training_oracle"], default="policy_full")
    parser.add_argument("--max-seconds", type=float, default=0.0)
    parser.add_argument("--no-resume", action="store_true")
    parser.add_argument("--stream-output", action="store_true", default=True)
    return parser


if __name__ == "__main__":
    raise SystemExit(main())
