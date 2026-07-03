from __future__ import annotations

import argparse
from concurrent.futures import FIRST_COMPLETED, ProcessPoolExecutor, wait
from dataclasses import replace
import json
from pathlib import Path
import time
from typing import Any

from repair_training.policy.exploration import EXPLORATION_POLICIES, choose_action
from repair_training.policy.q_labels import annotate_episode_future_best_q
from repair_training.policy.sanitize import sanitize_action_features, sanitize_diagnosis_hgt, sanitize_training_graph
from repair_training.data.io import read_jsonl, write_json, write_jsonl
from sunpack.repair.model.policy.schema import PolicyAction, PolicyGraphTransitionSample
from repair_training.policy.teacher import (
    DEFAULT_TEACHER_BUDGET,
    _RuntimeTeacherContext,
    _best_score,
    _job_from_row,
    _select_runtime_action_proposals,
)
from repair_training.policy.world_rows import observed_delta
from sunpack.repair.search.graph import PolicyRepairGraph



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
        "repeat_module_q_penalty": args.repeat_module_q_penalty,
        "near_tie_q_spread": args.near_tie_q_spread,
        "poor_action_q_penalty": args.poor_action_q_penalty,
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
    from sunpack.repair.model.policy.schema import transition_sample_from_dict

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
            row_format = str(row.get("format") or format_name)
            if format_name not in {"shared", "mixed", "all", "auto"}:
                row_format = format_name
            episode = _run_episode(ctx, row, row_index=index, format_name=row_format, episode_index=episode_index, exploration_policy=policy, max_steps=max_steps)
            output.extend(annotate_episode_future_best_q(episode))
    finally:
        ctx.close()
    return output


def _run_episode(ctx: _RuntimeTeacherContext, row: dict[str, Any], *, row_index: int, format_name: str, episode_index: int, exploration_policy: str, max_steps: int) -> list[PolicyGraphTransitionSample]:
    job = _job_from_row(row, row_index=row_index, format_name=format_name, workspace=ctx.workspace_root)
    if job is None:
        return []
    recovery = ctx.evaluator.evaluate_state(job, job.archive_state, mode=ctx.recovery_mode, cache=ctx.cache)
    repair_graph = PolicyRepairGraph.initialize(job, recovery)
    job = ctx._job_with_refreshed_knowledge(job, job.archive_state, recovery=recovery, step=0)
    diagnosis = ctx._diagnose_state(row=row, job=job, repair_graph=repair_graph, recovery=recovery, round_index=0)
    repair_graph.observe_current_state(recovery=recovery, diagnosis_hgt=diagnosis, verification=dict(recovery.verification or {}))
    transitions: list[PolicyGraphTransitionSample] = []
    for step in range(1, max_steps + 1):
        from sunpack.repair.search.proposals import available_module_proposals

        runtime_proposals = available_module_proposals(scheduler=ctx.scheduler, job=job, diagnosis_hgt=diagnosis, graph=repair_graph.graph)
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
        chosen = choose_action(actions, exploration_policy, step, graph=repair_graph.graph.to_dict())
        graph_before = sanitize_training_graph(repair_graph.graph.to_dict())
        proposal_by_id = {proposal.action_id: proposal for proposal in proposals}
        action_q_values = ctx._evaluate_actions(job=job, repair_graph=repair_graph, actions=actions, proposal_by_id=proposal_by_id, step=step)
        applied = ctx._apply_action(job=job, repair_graph=repair_graph, action=chosen, step=step, proposal_by_id=proposal_by_id)
        if applied is None or applied.archive_state is None:
            graph_after = sanitize_training_graph(repair_graph.graph.to_dict())
        else:
            recovery = ctx.evaluator.evaluate_state(job, applied.archive_state, mode=ctx.recovery_mode, cache=ctx.cache)
            job = ctx._job_with_refreshed_knowledge(replace(job, archive_state=applied.archive_state), applied.archive_state, recovery=recovery, step=step)
            diagnosis = ctx._diagnose_state(row=row, job=job, repair_graph=repair_graph, recovery=recovery, round_index=step)
            repair_graph.observe_current_state(recovery=recovery, diagnosis_hgt=diagnosis, verification=dict(recovery.verification or {}))
            graph_after = sanitize_training_graph(repair_graph.graph.to_dict())
        transitions.append(PolicyGraphTransitionSample(
            sample_id=f"{row.get('sample_id') or job.archive_key}:episode:{episode_index}:step:{step}",
            format=job.format,
            graph_before=graph_before,
            current_node_id=str(graph_before.get("current_node_id") or ""),
            best_node_id=str(graph_before.get("best_node_id") or ""),
            available_actions=actions,
            chosen_action=chosen,
            graph_after=graph_after,
            observed_delta=observed_delta(graph_before, graph_after),
            action_q_values=action_q_values,
            episode_id=f"{row.get('sample_id') or job.archive_key}:episode:{episode_index}",
            step_index=step,
            exploration_policy=exploration_policy,
            source={"row_index": row_index, "sample_id": row.get("sample_id") or "", "damage_profile": row.get("damage_profile") or ""},
        ))
        if chosen.action_type == "stop":
            break
    return transitions


def _action_from_payload(payload: dict[str, Any]) -> PolicyAction:
    return PolicyAction(
        action_type=str(payload.get("action_type") or "module"),  # type: ignore[arg-type]
        action_id=str(payload.get("action_id") or payload.get("candidate_id") or payload.get("action_type") or ""),
        module_name=str(payload.get("module_name") or payload.get("module") or ""),
        features=sanitize_action_features(payload),
    )


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
    parser.add_argument("--repeat-module-q-penalty", type=float, default=0.35)
    parser.add_argument("--near-tie-q-spread", type=float, default=0.04)
    parser.add_argument("--poor-action-q-penalty", type=float, default=0.12)
    parser.add_argument("--seed", type=int, default=13)
    parser.add_argument("--recovery-mode", choices=["policy_light", "policy_full", "training_oracle"], default="policy_full")
    parser.add_argument("--max-seconds", type=float, default=0.0)
    parser.add_argument("--no-resume", action="store_true")
    parser.add_argument("--stream-output", action="store_true", default=True)
    return parser


if __name__ == "__main__":
    raise SystemExit(main())
