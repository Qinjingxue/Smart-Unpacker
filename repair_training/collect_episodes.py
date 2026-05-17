from __future__ import annotations

import argparse
from concurrent.futures import FIRST_COMPLETED, ProcessPoolExecutor, wait
import json
import os
import time
from collections import Counter, deque
from dataclasses import replace
from pathlib import Path
from typing import Any

from repair_training.core.material_records import attach_split_volumes
from repair_training.core.plugin import load_training_format_plugin, normalize_format_name
from repair_training.schemas import (
    TrainingAction,
    TrainingCandidateSnapshot,
    TrainingEpisode,
    TrainingTransition,
    TrainingVerificationSnapshot,
)
from repair_training.taxonomy import normalize_damage_record
from sunpack.contracts.archive_input import ArchiveInputDescriptor
from sunpack.contracts.archive_state import ArchiveState
from sunpack.repair.candidate import RepairCandidate
from sunpack.repair.candidate import CandidateSelector, materialize_candidate
from sunpack.repair.job import RepairJob
from sunpack.repair.policy.training_runtime import (
    build_damage_analysis_request,
    candidate_snapshot,
    request_to_dict,
    state_source_input,
    validate_policy_candidates,
)
from sunpack.repair.policy.recovery_evaluator import PolicyRecoveryMode, PolicyRecoverySnapshot, RecoveryEvaluator
from sunpack.repair.scheduler import RepairScheduler, _job_with_policy_route_flags, _route_flags_from_damage_analysis


DEFAULT_MAX_DEPTH = 4
DEFAULT_MAX_STATES = 32
DEFAULT_ROOT_TOP_K = 8
DEFAULT_BRANCH_TOP_K = 5
_WORKER_SCHEDULER: RepairScheduler | None = None
_WORKER_SETTINGS: dict[str, Any] = {}


def main(argv: list[str] | None = None) -> int:
    args = _parser().parse_args(argv)
    fmt = normalize_format_name(args.format)
    records = _load_records(args.manifest, args.material_root, fmt, limit=args.limit)
    output = Path(args.output)
    output.parent.mkdir(parents=True, exist_ok=True)
    failure_output = Path(args.failure_output) if args.failure_output else output.with_name("episode_failures.jsonl")
    summary_output = Path(args.summary_output) if args.summary_output else output.with_name("collection_summary.json")
    checkpoint_output = Path(args.checkpoint_output) if args.checkpoint_output else output.with_name("collection_checkpoint.json")
    timing_output = Path(args.timing_output) if args.timing_output else output.with_name("collection_timings.jsonl")
    failure_output.parent.mkdir(parents=True, exist_ok=True)
    checkpoint_output.parent.mkdir(parents=True, exist_ok=True)
    timing_output.parent.mkdir(parents=True, exist_ok=True)
    checkpoint = _read_checkpoint(checkpoint_output) if args.resume else {}
    completed = _completed_sample_ids_from_payload(checkpoint) if args.resume else set()
    scheduler_config = _scheduler_config(Path(args.workspace) if args.workspace else output.parent / "workspace")
    scheduler = None if int(args.workers or 1) > 1 else RepairScheduler(scheduler_config)
    previous_summary = checkpoint.get("summary") if isinstance(checkpoint.get("summary"), dict) else {}
    summary = {
        "format": fmt,
        "records": len(records),
        "episodes": int(previous_summary.get("episodes", 0)) if args.resume else 0,
        "failures": int(previous_summary.get("failures", 0)) if args.resume else 0,
        "transitions": int(previous_summary.get("transitions", 0)) if args.resume else 0,
        "candidate_count": int(previous_summary.get("candidate_count", 0)) if args.resume else 0,
        "repeated_digest_count": int(previous_summary.get("repeated_digest_count", 0)) if args.resume else 0,
        "taxonomy_label_counts": dict(previous_summary.get("taxonomy_label_counts") or {}) if args.resume else {},
        "timing": {},
        "checkpoint": str(checkpoint_output),
        "timing_output": str(timing_output),
        "resumed_completed": len(completed),
        "skipped_by_checkpoint": 0,
        "time_limit_seconds": float(args.time_limit_seconds or 0.0),
        "deadline_reached": False,
        "stop_reason": "",
        "wall_seconds": 0.0,
    }
    label_counts: Counter[str] = Counter(summary["taxonomy_label_counts"])
    timings: list[dict[str, Any]] = []
    started = time.perf_counter()
    output_mode = "a" if args.resume else "w"
    with output.open(output_mode, encoding="utf-8") as out, failure_output.open(output_mode, encoding="utf-8") as fail, timing_output.open(output_mode, encoding="utf-8") as timing:
        iterable = enumerate(records, start=1)
        if int(args.workers or 1) > 1:
            _collect_parallel(
                iterable,
                deadline=started + float(args.time_limit_seconds) if float(args.time_limit_seconds or 0.0) > 0 else None,
                completed=completed,
                scheduler_config=scheduler_config,
                args=args,
                out=out,
                fail=fail,
                timing=timing,
                summary=summary,
                label_counts=label_counts,
                checkpoint_output=checkpoint_output,
                output=output,
                failure_output=failure_output,
                timing_output=timing_output,
                timings=timings,
            )
        else:
            for index, record in iterable:
                if float(args.time_limit_seconds or 0.0) > 0 and time.perf_counter() - started >= float(args.time_limit_seconds):
                    summary["deadline_reached"] = True
                    summary["stop_reason"] = "time_limit_reached"
                    break
                _collect_one_and_write(
                    index,
                    record,
                    scheduler=scheduler,
                    completed=completed,
                    args=args,
                    out=out,
                    fail=fail,
                    timing=timing,
                    summary=summary,
                    label_counts=label_counts,
                    checkpoint_output=checkpoint_output,
                    output=output,
                    failure_output=failure_output,
                    timing_output=timing_output,
                    timings=timings,
                )
    summary["taxonomy_label_counts"] = dict(sorted(label_counts.items()))
    summary["timing"] = _timing_summary(timings) if timings else dict(previous_summary.get("timing") or {})
    elapsed_wall = round(time.perf_counter() - started, 3)
    summary["wall_seconds"] = elapsed_wall if timings or not args.resume else float(previous_summary.get("wall_seconds") or elapsed_wall)
    _write_checkpoint(checkpoint_output, completed, summary, last_sample_id="", processed_index=len(records))
    summary_output.write_text(json.dumps(summary, ensure_ascii=False, indent=2, sort_keys=True), encoding="utf-8")
    print(json.dumps(summary, ensure_ascii=False, sort_keys=True))
    return 0


def _scheduler_config(workspace: Path) -> dict[str, Any]:
    return {
        "repair": {
            "workspace": str(workspace),
            "training_module_selection_cache": True,
            "policy": {"enabled": False},
            "module_limits": {"verify_candidates": False},
        }
    }


def _collect_parallel(
    iterable,
    *,
    deadline: float | None,
    completed: set[str],
    scheduler_config: dict[str, Any],
    args: argparse.Namespace,
    out,
    fail,
    timing,
    summary: dict[str, Any],
    label_counts: Counter[str],
    checkpoint_output: Path,
    output: Path,
    failure_output: Path,
    timing_output: Path,
    timings: list[dict[str, Any]],
) -> None:
    pending: list[tuple[int, dict[str, Any]]] = []
    for index, record in iterable:
        sample_id = _record_id(record)
        if sample_id in completed:
            summary["skipped_by_checkpoint"] += 1
            continue
        pending.append((index, record))
    if not pending:
        return
    settings = {
        "max_depth": args.max_depth,
        "max_states": args.max_states,
        "root_top_k": args.root_top_k,
        "branch_top_k": args.branch_top_k,
        "root_materialize_top_k": args.root_materialize_top_k,
        "branch_materialize_top_k": args.branch_materialize_top_k,
        "recovery_mode": args.recovery_mode,
        "max_evaluated_candidates": args.max_evaluated_candidates,
        "damage_model_dir": args.damage_model_dir,
    }
    workers = max(1, int(args.workers or 1))
    max_in_flight = max(workers, int(getattr(args, "max_in_flight", 0) or workers))
    with ProcessPoolExecutor(
        max_workers=workers,
        initializer=_worker_init,
        initargs=(scheduler_config, settings),
    ) as pool:
        future_to_index = {}
        pending_iter = iter(pending)
        processed = 0
        exhausted = False
        while True:
            while not exhausted and len(future_to_index) < max_in_flight and not _deadline_reached(deadline):
                try:
                    index, record = next(pending_iter)
                except StopIteration:
                    exhausted = True
                    break
                future = pool.submit(_worker_collect_record, index, record)
                future_to_index[future] = index
            if not future_to_index:
                break
            timeout = 0.1
            if deadline is not None:
                timeout = max(0.0, min(timeout, deadline - time.perf_counter()))
            done, _pending = wait(future_to_index, timeout=timeout, return_when=FIRST_COMPLETED)
            if not done and _deadline_reached(deadline):
                summary["deadline_reached"] = True
                summary["stop_reason"] = "time_limit_reached"
                for future in list(future_to_index):
                    future.cancel()
                break
            for future in done:
                future_to_index.pop(future, None)
                result = future.result()
                processed += 1
                _write_worker_result(
                    result,
                    completed=completed,
                    out=out,
                    fail=fail,
                    timing=timing,
                    summary=summary,
                    label_counts=label_counts,
                    timings=timings,
                )
                if args.checkpoint_interval and processed % max(1, int(args.checkpoint_interval)) == 0:
                    _write_checkpoint(
                        checkpoint_output,
                        completed,
                        summary,
                        last_sample_id=str(result.get("sample_id") or ""),
                        processed_index=int(result.get("index") or 0),
                    )
            if exhausted and not future_to_index:
                break
        if summary.get("deadline_reached"):
            for future in list(future_to_index):
                future.cancel()
        elif _deadline_reached(deadline):
            summary["deadline_reached"] = True
            summary["stop_reason"] = "time_limit_reached"


def _deadline_reached(deadline: float | None) -> bool:
    return deadline is not None and time.perf_counter() >= deadline


def _collect_one_and_write(
    index: int,
    record: dict[str, Any],
    *,
    scheduler: RepairScheduler | None,
    completed: set[str],
    args: argparse.Namespace,
    out,
    fail,
    timing,
    summary: dict[str, Any],
    label_counts: Counter[str],
    checkpoint_output: Path,
    output: Path,
    failure_output: Path,
    timing_output: Path,
    timings: list[dict[str, Any]],
) -> None:
    sample_id = _record_id(record)
    if sample_id in completed:
        summary["skipped_by_checkpoint"] += 1
        return
    result = _collect_record_payload(
        index,
        record,
        scheduler=scheduler,
        max_depth=args.max_depth,
        max_states=args.max_states,
        root_top_k=args.root_top_k,
        branch_top_k=args.branch_top_k,
        root_materialize_top_k=args.root_materialize_top_k,
        branch_materialize_top_k=args.branch_materialize_top_k,
        recovery_mode=args.recovery_mode,
        max_evaluated_candidates=args.max_evaluated_candidates,
        damage_model_dir=args.damage_model_dir,
    )
    _write_worker_result(
        result,
        completed=completed,
        out=out,
        fail=fail,
        timing=timing,
        summary=summary,
        label_counts=label_counts,
        timings=timings,
    )
    if args.checkpoint_interval and index % max(1, int(args.checkpoint_interval)) == 0:
        _write_checkpoint(checkpoint_output, completed, summary, last_sample_id=sample_id, processed_index=index)


def _worker_init(scheduler_config: dict[str, Any], settings: dict[str, Any]) -> None:
    global _WORKER_SCHEDULER, _WORKER_SETTINGS
    config = json.loads(json.dumps(scheduler_config))
    workspace = Path(config["repair"]["workspace"]) / f"worker_{os.getpid()}"
    config["repair"]["workspace"] = str(workspace)
    _WORKER_SCHEDULER = RepairScheduler(config)
    _WORKER_SETTINGS = dict(settings)


def _worker_collect_record(index: int, record: dict[str, Any]) -> dict[str, Any]:
    return _collect_record_payload(
        index,
        record,
        scheduler=_WORKER_SCHEDULER,
        **_WORKER_SETTINGS,
    )


def _collect_record_payload(
    index: int,
    record: dict[str, Any],
    *,
    scheduler: RepairScheduler | None,
    max_depth: int,
    max_states: int,
    root_top_k: int,
    branch_top_k: int,
    root_materialize_top_k: int,
    branch_materialize_top_k: int,
    recovery_mode: PolicyRecoveryMode,
    max_evaluated_candidates: int,
    damage_model_dir: str = "",
) -> dict[str, Any]:
    sample_id = _record_id(record)
    record_started = time.perf_counter()
    try:
        episode, stats = collect_episode(
            record,
            scheduler=scheduler,
            max_depth=max_depth,
            max_states=max_states,
            root_top_k=root_top_k,
            branch_top_k=branch_top_k,
            root_materialize_top_k=root_materialize_top_k,
            branch_materialize_top_k=branch_materialize_top_k,
            recovery_mode=recovery_mode,
            max_evaluated_candidates=max_evaluated_candidates,
            damage_model_dir=damage_model_dir,
        )
    except Exception as exc:
        elapsed = round(time.perf_counter() - record_started, 6)
        return {
            "index": index,
            "sample_id": sample_id,
            "status": "failure",
            "elapsed_seconds": elapsed,
            "error": str(exc),
            "record": record,
        }
    elapsed = round(time.perf_counter() - record_started, 6)
    return {
        "index": index,
        "sample_id": sample_id,
        "status": "ok",
        "elapsed_seconds": elapsed,
        "episode": episode.to_dict(),
        "stats": {
            "transitions": int(stats.get("transitions", 0)),
            "candidate_count": int(stats.get("candidate_count", 0)),
            "repeated_digest_count": int(stats.get("repeated_digest_count", 0)),
            "phase_timing": dict(stats.get("phase_timing") or {}),
            "phase_counts": dict(stats.get("phase_counts") or {}),
        },
    }


def _write_worker_result(
    result: dict[str, Any],
    *,
    completed: set[str],
    out,
    fail,
    timing,
    summary: dict[str, Any],
    label_counts: Counter[str],
    timings: list[dict[str, Any]],
) -> None:
    sample_id = str(result.get("sample_id") or "")
    elapsed = float(result.get("elapsed_seconds") or 0.0)
    if result.get("status") != "ok":
        summary["failures"] += 1
        failure = {
            "sample_id": sample_id,
            "error": str(result.get("error") or ""),
            "elapsed_seconds": elapsed,
        }
        fail.write(json.dumps(failure, ensure_ascii=False, sort_keys=True) + "\n")
        fail.flush()
        timing_row = {
            "sample_id": sample_id,
            "status": "failure",
            "elapsed_seconds": elapsed,
            "error": str(result.get("error") or ""),
        }
        timing.write(json.dumps(timing_row, ensure_ascii=False, sort_keys=True) + "\n")
        timing.flush()
        timings.append(timing_row)
        completed.add(sample_id)
        return
    episode = result["episode"]
    stats = result["stats"]
    out.write(json.dumps(episode, ensure_ascii=False, sort_keys=True) + "\n")
    out.flush()
    summary["episodes"] += 1
    summary["transitions"] += int(stats.get("transitions", 0))
    summary["candidate_count"] += int(stats.get("candidate_count", 0))
    summary["repeated_digest_count"] += int(stats.get("repeated_digest_count", 0))
    timing_row = {
        "sample_id": sample_id,
        "status": "ok",
        "elapsed_seconds": elapsed,
        "transitions": int(stats.get("transitions", 0)),
        "candidate_count": int(stats.get("candidate_count", 0)),
        "repeated_digest_count": int(stats.get("repeated_digest_count", 0)),
        "phase_timing": dict(stats.get("phase_timing") or {}),
        "phase_counts": dict(stats.get("phase_counts") or {}),
    }
    timing.write(json.dumps(timing_row, ensure_ascii=False, sort_keys=True) + "\n")
    timing.flush()
    timings.append(timing_row)
    completed.add(sample_id)
    for label in episode.get("oracle_damage") or []:
        if isinstance(label, dict):
            label_counts[str(label.get("label") or "")] += 1


def collect_episode(
    record: dict[str, Any],
    *,
    scheduler: RepairScheduler | None = None,
    max_depth: int = DEFAULT_MAX_DEPTH,
    max_states: int = DEFAULT_MAX_STATES,
    root_top_k: int = DEFAULT_ROOT_TOP_K,
    branch_top_k: int = DEFAULT_BRANCH_TOP_K,
    root_materialize_top_k: int = 0,
    branch_materialize_top_k: int = 0,
    recovery_mode: PolicyRecoveryMode = "training_oracle",
    max_evaluated_candidates: int = 0,
    damage_model_dir: str | Path = "",
) -> tuple[TrainingEpisode, dict[str, Any]]:
    scheduler = scheduler or RepairScheduler({"repair": {"training_module_selection_cache": True, "policy": {"enabled": False}, "module_limits": {"verify_candidates": False}}})
    target = normalize_damage_record(record)
    job = _job_from_record(record, target.format)
    root_state = job.archive_state or ArchiveState.from_archive_input(job.archive_input())
    root_digest = root_state.effective_patch_digest()
    transitions: list[TrainingTransition] = []
    queue: deque[tuple[ArchiveState, int, str]] = deque([(root_state, 0, "")])
    seen: set[str] = {root_digest}
    parents: dict[str, str] = {}
    recovery_evaluator = RecoveryEvaluator(getattr(scheduler, "config", {}) or {})
    recovery_cache: dict[str, PolicyRecoverySnapshot] = {}
    oracle = _oracle_from_record(record)
    repeated = 0
    candidate_count = 0
    phase_timing: Counter[str] = Counter()
    phase_counts: Counter[str] = Counter()

    while queue and len(seen) <= max_states:
        phase_counts["states"] += 1
        state, depth, parent_digest = queue.popleft()
        state_digest = state.effective_patch_digest()
        current_job = replace(
            job,
            archive_state=state,
            source_input=dict(job.source_input or {}),
            attempts=depth,
        )
        damage_request = build_damage_analysis_request(
            current_job,
            state,
            diagnosis={"format": target.format},
            round_index=depth,
        )
        damage_request_dict = _compact_damage_request(request_to_dict(damage_request))
        damage_target_dict = _compact_damage_target(target.to_dict())
        damage_analysis = _timed_call(
            phase_timing,
            phase_counts,
            "damage_model",
            _analyze_damage_for_action_features,
            target.format,
            damage_request,
            fallback=damage_target_dict,
            model_dir=damage_model_dir,
        )
        route_flags = _route_flags_from_damage_analysis(damage_analysis)
        routed_job = _job_with_policy_route_flags(current_job, route_flags) if route_flags else current_job
        state_recovery = _timed_call(
            phase_timing,
            phase_counts,
            "state_recovery",
            recovery_evaluator.evaluate_state,
            current_job,
            state,
            mode=recovery_mode,
            oracle=oracle,
            cache=recovery_cache,
        )
        if state_digest in recovery_cache:
            phase_counts["state_recovery.cache_known_after"] += 1
        candidates = _timed_call(
            phase_timing,
            phase_counts,
            "select_candidates",
            _select_candidates,
            scheduler,
            routed_job,
            root_top_k if depth == 0 else branch_top_k,
            materialize_top_k=root_materialize_top_k if depth == 0 else branch_materialize_top_k,
            phase_timing=phase_timing,
            phase_counts=phase_counts,
        )
        if max_evaluated_candidates:
            candidates = candidates[:max(0, int(max_evaluated_candidates))]
        candidate_count += len(candidates)
        candidate_recoveries = []
        for candidate in candidates:
            candidate_state = candidate.repaired_state
            candidate_digest = candidate_state.effective_patch_digest() if candidate_state is not None else ""
            candidate_cache_hit = bool(candidate_digest and candidate_digest in recovery_cache)
            phase_counts["candidate_recovery.cache_hit" if candidate_cache_hit else "candidate_recovery.cache_miss"] += 1
            candidate_recoveries.append(_timed_call(
                phase_timing,
                phase_counts,
                "candidate_recovery",
                recovery_evaluator.evaluate_candidate,
                current_job,
                candidate,
                mode=recovery_mode,
                oracle=oracle,
                cache=recovery_cache,
            ))
            if not candidate_cache_hit:
                _accumulate_recovery_timing(candidate_recoveries[-1], phase_timing, phase_counts, prefix="candidate_recovery")
        candidate_dicts = [
            candidate_snapshot(
                candidate,
                index=index,
                damage_analysis=None,
                current_recovery=_compact_recovery_snapshot(state_recovery.to_dict()),
                recovery_snapshot=_compact_recovery_snapshot(candidate_recoveries[index].to_dict()),
            )
            for index, candidate in enumerate(candidates)
        ]
        candidate_snapshots = [TrainingCandidateSnapshot.from_dict(_with_snapshot_metadata(item)) for item in candidate_dicts]
        actions = [
            TrainingAction(action_type="apply_patch", candidate_id=str(item["candidate_id"]))
            for item in candidate_dicts
            if item.get("candidate_id")
        ]
        if state.patch_depth() > 0 and parent_digest:
            actions.append(TrainingAction(action_type="undo_patch", reason="checkout_parent", metadata={"target_state_digest": parent_digest, "graph_semantics": "checkout_parent"}))
        actions.extend([
            TrainingAction(action_type="stop", reason="stop_signal", metadata={"graph_semantics": "stop_signal"}),
            TrainingAction(action_type="give_up", reason="exhaust_branch", metadata={"graph_semantics": "exhaust_branch"}),
        ])
        before = _training_verification_snapshot(state_recovery)

        for candidate, snapshot, candidate_recovery in zip(candidates, candidate_dicts, candidate_recoveries):
            next_state = candidate.repaired_state
            if next_state is None:
                continue
            next_digest = next_state.effective_patch_digest()
            after = _training_verification_snapshot(candidate_recovery)
            transitions.append(TrainingTransition(
                round_index=depth,
                state_digest=state_digest,
                patch_depth=state.patch_depth(),
                damage_analysis_request=damage_request_dict,
                damage_analysis_target={**damage_target_dict, "model_damage_analysis": _compact_damage_analysis(damage_analysis)},
                candidate_snapshots=candidate_snapshots,
                available_actions=actions,
                selected_action=TrainingAction(action_type="apply_patch", candidate_id=str(snapshot.get("candidate_id") or "")),
                next_state_digest=next_digest,
                verification_before=before,
                verification_after=after,
                reward=after.score - before.score,
                terminal=False,
            ))
            if depth + 1 <= max_depth:
                if next_digest in seen:
                    repeated += 1
                elif len(seen) < max_states:
                    seen.add(next_digest)
                    parents[next_digest] = state_digest
                    queue.append((next_state, depth + 1, state_digest))

        if state.patch_depth() > 0 and parent_digest:
            parent_recovery = recovery_cache.get(parent_digest, PolicyRecoverySnapshot(state_digest=parent_digest))
            parent_after = _training_verification_snapshot(parent_recovery)
            transitions.append(TrainingTransition(
                round_index=depth,
                state_digest=state_digest,
                patch_depth=state.patch_depth(),
                damage_analysis_request=damage_request_dict,
                damage_analysis_target={**damage_target_dict, "model_damage_analysis": _compact_damage_analysis(damage_analysis)},
                candidate_snapshots=candidate_snapshots,
                available_actions=actions,
                selected_action=TrainingAction(action_type="undo_patch", reason="checkout_parent", metadata={"target_state_digest": parent_digest, "graph_semantics": "checkout_parent"}),
                next_state_digest=parent_digest,
                verification_before=before,
                verification_after=parent_after,
                reward=parent_after.score - before.score,
            ))
        transitions.extend([
            _terminal_transition(depth, state, damage_request_dict, {**damage_target_dict, "model_damage_analysis": _compact_damage_analysis(damage_analysis)}, candidate_snapshots, actions, before, "stop"),
            _terminal_transition(depth, state, damage_request_dict, {**damage_target_dict, "model_damage_analysis": _compact_damage_analysis(damage_analysis)}, candidate_snapshots, actions, before, "give_up"),
        ])

    recovery_evaluator.close()
    transitions = _dedupe_transition_payloads(transitions)
    episode = TrainingEpisode(
        episode_id=str(record.get("query_id") or record.get("sample_id") or root_digest),
        format=target.format,
        source_identity={
            "source_archive_id": record.get("source_archive_id"),
            "source_path": record.get("source_path"),
            "clean_sha256": record.get("clean_sha256"),
            "corrupted_sha256": record.get("corrupted_sha256"),
        },
        corrupted_input=dict(record.get("damaged_input") or {}),
        oracle_damage=target.training_labels(),
        initial_state=root_state.to_dict(),
        initial_state_digest=root_digest,
        transitions=transitions,
        terminal={"state_count": len(seen), "max_depth": max_depth, "max_states": max_states},
        metadata={"raw_damage_record": _compact_record_metadata(record), "taxonomy": _compact_damage_target(target.to_dict())},
    )
    return episode, {
        "transitions": len(transitions),
        "candidate_count": candidate_count,
        "repeated_digest_count": repeated,
        "phase_timing": {key: round(float(value), 6) for key, value in sorted(phase_timing.items())},
        "phase_counts": dict(sorted(phase_counts.items())),
    }


def _select_candidates(
    scheduler: RepairScheduler,
    job: RepairJob,
    top_k: int,
    *,
    materialize_top_k: int = 0,
    phase_timing: Counter[str] | None = None,
    phase_counts: Counter[str] | None = None,
) -> list[RepairCandidate]:
    phase_timing = phase_timing if phase_timing is not None else Counter()
    phase_counts = phase_counts if phase_counts is not None else Counter()
    batch = _timed_call(phase_timing, phase_counts, "select_candidates.generate", scheduler.generate_repair_candidates, job, lazy=True)
    raw_candidates = list(batch.candidates)
    materialize_budget = int(materialize_top_k or 0)
    materialize_input = _budgeted_materialize_input(raw_candidates, materialize_budget)
    phase_counts["select_candidates.materialize_budget"] += materialize_budget if materialize_budget > 0 else len(raw_candidates)
    phase_counts["select_candidates.materialize_skipped"] += max(0, len(raw_candidates) - len(materialize_input))
    materialized = _profile_materialize_candidates(
        materialize_input,
        phase_timing=phase_timing,
        phase_counts=phase_counts,
    )
    selector = CandidateSelector(scheduler.config)
    validated: list[RepairCandidate] = []
    for candidate in materialized:
        validated.append(_timed_call(phase_timing, phase_counts, "select_candidates.native_validate", selector._with_native_validation, candidate))
    started = time.perf_counter()
    accepted = [
        candidate
        for candidate in validated
        if candidate.repaired_state is not None
        and not candidate.is_lazy
        and all(validation.accepted for validation in candidate.validations)
    ]
    accepted.sort(key=_candidate_priority, reverse=True)
    phase_timing["select_candidates.filter_sort"] += time.perf_counter() - started
    phase_counts["select_candidates.filter_sort"] += 1
    phase_counts["select_candidates.raw_candidates"] += len(raw_candidates)
    phase_counts["select_candidates.materialized_candidates"] += len(materialized)
    phase_counts["select_candidates.accepted_candidates"] += len(accepted)
    return accepted[:max(0, int(top_k or 0))]


def _budgeted_materialize_input(candidates: list[RepairCandidate], budget: int) -> list[RepairCandidate]:
    scored = sorted(
        ((_candidate_priority(candidate), index, candidate) for index, candidate in enumerate(candidates)),
        key=lambda item: (item[0], -item[1]),
        reverse=True,
    )
    collapsed: list[RepairCandidate] = []
    seen_families: set[str] = set()
    for _, _, candidate in scored:
        family = _materialize_representative_family(candidate)
        if family and family in seen_families:
            continue
        if family:
            seen_families.add(family)
        collapsed.append(candidate)
    if budget <= 0 or len(collapsed) <= budget:
        return collapsed
    return collapsed[:budget]


def _materialize_representative_family(candidate: RepairCandidate) -> str:
    module = str(candidate.module_name or "")
    if module in {
        "zip_rebuild_cd_from_local_headers",
        "zip_rebuild_cd_preserve_raw_names",
        "zip_reconcile_cd_local_headers",
    }:
        return "zip_cd_structure_rebuild"
    return ""


def _timed_call(timing: Counter[str], counts: Counter[str], phase: str, func, *args, **kwargs):
    started = time.perf_counter()
    try:
        return func(*args, **kwargs)
    finally:
        timing[phase] += time.perf_counter() - started
        counts[phase] += 1


def _profile_materialize_candidates(
    candidates: list[RepairCandidate],
    *,
    phase_timing: Counter[str],
    phase_counts: Counter[str],
) -> list[RepairCandidate]:
    output: list[RepairCandidate] = []
    started_all = time.perf_counter()
    for candidate in candidates:
        module = _safe_metric_name(candidate.module_name or "unknown")
        started = time.perf_counter()
        produced = materialize_candidate(candidate)
        elapsed = time.perf_counter() - started
        output.extend(produced)
        phase_timing[f"select_candidates.materialize.module.{module}"] += elapsed
        phase_counts[f"select_candidates.materialize.module.{module}"] += 1
        phase_counts[f"select_candidates.materialize.produced.module.{module}"] += len(produced)
        for item in produced:
            _accumulate_native_materialize_timing(item, module, phase_timing, phase_counts)
            state = item.repaired_state
            phase_counts[f"select_candidates.materialize.patch_bytes.module.{module}"] += _state_patch_data_bytes(state)
            phase_counts[f"select_candidates.materialize.patch_ops.module.{module}"] += _state_patch_operation_count(state)
    phase_timing["select_candidates.materialize"] += time.perf_counter() - started_all
    phase_counts["select_candidates.materialize"] += 1
    return output


def _accumulate_native_materialize_timing(
    candidate: RepairCandidate,
    module: str,
    phase_timing: Counter[str],
    phase_counts: Counter[str],
) -> None:
    seen: set[int] = set()

    def visit(value: Any) -> None:
        if not isinstance(value, dict):
            return
        ident = id(value)
        if ident in seen:
            return
        seen.add(ident)
        timing = value.get("native_timing")
        if isinstance(timing, dict):
            for key, raw in timing.items():
                try:
                    seconds = float(raw or 0.0)
                except (TypeError, ValueError):
                    continue
                metric = _safe_metric_name(str(key or "unknown"))
                phase = f"select_candidates.materialize.native.{module}.{metric}"
                phase_timing[phase] += seconds
                phase_counts[phase] += 1
        for child in value.values():
            if isinstance(child, dict):
                visit(child)
            elif isinstance(child, list):
                for item in child:
                    if isinstance(item, dict):
                        visit(item)

    visit(candidate.diagnosis)


def _accumulate_recovery_timing(snapshot: PolicyRecoverySnapshot, timing: Counter[str], counts: Counter[str], *, prefix: str) -> None:
    metadata = snapshot.metadata if isinstance(snapshot.metadata, dict) else {}
    details = metadata.get("timing") if isinstance(metadata.get("timing"), dict) else {}
    for key, value in details.items():
        phase = f"{prefix}.{key}"
        timing[phase] += float(value or 0.0)
        counts[phase] += 1
    module = _safe_metric_name(str(metadata.get("module_name") or "unknown"))
    if module != "unknown":
        for key, value in details.items():
            phase = f"{prefix}.module.{module}.{key}"
            timing[phase] += float(value or 0.0)
            counts[phase] += 1
        for key in ("state_size_bytes", "extract_output_bytes", "extract_file_count"):
            phase_counts_key = f"{prefix}.module.{module}.{key}"
            counts[phase_counts_key] += int(metadata.get(key) or 0)


def _state_patch_operation_count(state: ArchiveState | None) -> int:
    if state is None:
        return 0
    return sum(len(getattr(patch, "operations", []) or []) for patch in state.patches)


def _state_patch_data_bytes(state: ArchiveState | None) -> int:
    if state is None:
        return 0
    total = 0
    for patch in state.patches:
        for operation in getattr(patch, "operations", []) or []:
            total += _b64_size(getattr(operation, "data_b64", "") or "")
            total += _b64_size(getattr(operation, "expected_b64", "") or "")
    return total


def _b64_size(value: str) -> int:
    if not value:
        return 0
    return max(0, (len(value) * 3 // 4) - value.count("="))


def _safe_metric_name(value: str) -> str:
    text = "".join(ch if ch.isalnum() else "_" for ch in str(value or "unknown"))
    return text.strip("_")[:96] or "unknown"


_DAMAGE_MODEL_CACHE: dict[str, tuple[Any, Any, Any, Any]] = {}


def _analyze_damage_for_action_features(
    fmt: str,
    request,
    *,
    fallback: dict[str, Any],
    model_dir: str | Path = "",
) -> dict[str, Any]:
    if not model_dir:
        return dict(fallback)
    try:
        from repair_training.core.damage_model_inference import DamageAnalysisModel
        from repair_training.core.normal_structure_inference import NormalStructureModel
        from sunpack.repair.policy.adapters.damage import get_damage_analysis_adapter
        from sunpack.repair.policy.adapters.normal_structure import get_normal_structure_adapter

        root = Path(model_dir)
        if (root / "models").is_dir():
            root = root / "models"
        key = str(root.resolve())
        cached = _DAMAGE_MODEL_CACHE.get(key)
        if cached is None:
            plugin = load_training_format_plugin(fmt)
            damage_adapter = get_damage_analysis_adapter(fmt)
            normal_adapter = get_normal_structure_adapter(fmt)
            if damage_adapter is None or normal_adapter is None:
                return dict(fallback)
            cached = (
                plugin,
                normal_adapter,
                NormalStructureModel(model_dir=root / "normal_structure", plugin=plugin),
                DamageAnalysisModel(model_dir=root / "damage_location", plugin=plugin),
            )
            _DAMAGE_MODEL_CACHE[key] = cached
        plugin, normal_adapter, normal_model, damage_model = cached
        damage_adapter = get_damage_analysis_adapter(fmt)
        if damage_adapter is None:
            return dict(fallback)
        payload = damage_adapter.prepare_input(request)
        normal_rows = normal_adapter.rows_from_request_payload(payload)
        normal_scores = normal_model.predict_rows(normal_rows)
        anomaly = normal_adapter.build_anomaly_payload(normal_rows, normal_scores)
        row = {"damage_analysis_input": payload}
        observed_scores = damage_model.predict_rows([row])[0]
        uncertain_scores = damage_model.predict_uncertain_rows([row])[0]
        result = damage_adapter.postprocess_scores(
            observed_scores,
            damage_model.thresholds,
            uncertainty_scores=uncertain_scores,
            uncertainty_thresholds=damage_model.uncertain_thresholds,
            metadata={
                "training_damage_model_dir": str(root),
                "normal_query_count": len(normal_rows),
                "structure_anomaly": anomaly,
            },
        )
        return result.to_dict()
    except Exception as exc:
        payload = dict(fallback)
        payload.setdefault("metadata", {})["damage_model_error"] = str(exc)
        return payload


def _compact_damage_analysis(payload: dict[str, Any]) -> dict[str, Any]:
    metadata = payload.get("metadata") if isinstance(payload.get("metadata"), dict) else {}
    location_model = metadata.get("location_model") if isinstance(metadata.get("location_model"), dict) else {}
    world_model = metadata.get("world_model") if isinstance(metadata.get("world_model"), dict) else {}
    location_scores = location_model.get("raw_scores") if isinstance(location_model.get("raw_scores"), dict) else metadata.get("damage_location_scores") if isinstance(metadata.get("damage_location_scores"), dict) else {}
    uncertainty_head_scores = location_model.get("uncertainty_raw_scores") if isinstance(location_model.get("uncertainty_raw_scores"), dict) else metadata.get("damage_uncertainty_scores") if isinstance(metadata.get("damage_uncertainty_scores"), dict) else {}
    selected_scores = location_model.get("selected_scores") if isinstance(location_model.get("selected_scores"), dict) else metadata.get("selected_scores") if isinstance(metadata.get("selected_scores"), dict) else {}
    uncertain_scores = location_model.get("uncertainty_selected_scores") if isinstance(location_model.get("uncertainty_selected_scores"), dict) else metadata.get("uncertain_scores") if isinstance(metadata.get("uncertain_scores"), dict) else {}
    score_summary = world_model.get("score_summary") if isinstance(world_model.get("score_summary"), dict) else metadata.get("normal_structure_scores") if isinstance(metadata.get("normal_structure_scores"), dict) else {}
    top_anomalies = score_summary.get("top_anomalies") if isinstance(score_summary.get("top_anomalies"), list) else []
    compact_attribution = world_model.get("compact_attribution") if isinstance(world_model.get("compact_attribution"), dict) else {}
    compact_metadata = {
        "provider_id": metadata.get("provider_id"),
            "model_id": metadata.get("model_id"),
            "model_version": metadata.get("model_version"),
            "location_model": {
                "raw_scores": _top_score_dict(location_scores, limit=32),
                "uncertainty_raw_scores": _top_score_dict(uncertainty_head_scores, limit=32),
                "selected_scores": _top_score_dict(selected_scores, limit=16),
                "uncertain_labels": list(location_model.get("uncertain_labels") or metadata.get("uncertain_labels") or [])[:32],
                "uncertainty_selected_scores": _top_score_dict(uncertain_scores, limit=16),
            },
            "world_model": {
                "query_count": (world_model.get("metadata") or {}).get("query_count") if isinstance(world_model.get("metadata"), dict) else metadata.get("normal_query_count"),
                "compact_attribution": _compact_world_attribution(compact_attribution),
                "top_anomalies": [
            {
                "target_field": item.get("target_field"),
                "target_zone": item.get("target_zone"),
                "query_type": item.get("query_type"),
                "relation_kind": item.get("relation_kind"),
                "anomaly_score": item.get("anomaly_score"),
                "normal_confidence": item.get("normal_confidence"),
            }
            for item in top_anomalies[:8]
            if isinstance(item, dict)
        ],
            },
    }
    return {
        "format": payload.get("format"),
        "damage_labels": list(payload.get("damage_labels") or [])[:64],
        "damage_zones": list(payload.get("damage_zones") or [])[:32],
        "confidence": float(payload.get("confidence") or 0.0),
        "route_hints": list(payload.get("route_hints") or [])[:16],
        "blocking_reasons": list(payload.get("blocking_reasons") or [])[:16],
        "metadata": {key: value for key, value in compact_metadata.items() if value not in (None, "", [], {})},
    }


def _top_score_dict(scores: dict[str, Any], *, limit: int) -> dict[str, float]:
    pairs = []
    for key, value in scores.items():
        try:
            pairs.append((str(key), float(value or 0.0)))
        except (TypeError, ValueError):
            continue
    pairs.sort(key=lambda item: item[1], reverse=True)
    return dict(pairs[: max(0, int(limit or 0))])


def _compact_world_attribution(payload: dict[str, Any]) -> dict[str, Any]:
    if not isinstance(payload, dict):
        return {}
    by_field = payload.get("by_field") if isinstance(payload.get("by_field"), dict) else {}
    conflict_pairs = payload.get("conflict_pairs") if isinstance(payload.get("conflict_pairs"), dict) else {}
    top_queries = payload.get("top_queries") if isinstance(payload.get("top_queries"), list) else []
    return {
        "by_field": {
            key: {
                metric: value
                for metric, value in dict(item).items()
                if metric in {"max", "mean_top3", "count_ge_80", "top_relation", "top_query_type"}
            }
            for key, item in by_field.items()
            if isinstance(item, dict)
        },
        "conflict_pairs": {
            key: {
                metric: value
                for metric, value in dict(item).items()
                if metric in {"score", "explained", "top_field", "top_relation"}
            }
            for key, item in conflict_pairs.items()
            if isinstance(item, dict)
        },
        "top_queries": [
            {
                key: item.get(key)
                for key in ("query_type", "target_field", "target_zone", "relation_kind", "anomaly_score", "normal_confidence")
                if item.get(key) is not None
            }
            for item in top_queries[:8]
            if isinstance(item, dict)
        ],
    }


def _compact_damage_request(payload: dict[str, Any]) -> dict[str, Any]:
    compact = dict(payload or {})
    state = compact.get("archive_state") if isinstance(compact.get("archive_state"), dict) else {}
    if state:
        compact["archive_state"] = _compact_state_summary(state)
    runtime = dict(compact.get("runtime_context") or {})
    runtime_state = runtime.get("archive_state") if isinstance(runtime.get("archive_state"), dict) else {}
    if runtime_state:
        runtime["archive_state"] = _compact_state_summary(runtime_state)
    compact["runtime_context"] = runtime
    compact["diagnosis"] = {
        "format": str((compact.get("diagnosis") or {}).get("format") or compact.get("format") or "")
    }
    return _drop_patch_bytes(compact)


def _compact_state_summary(state: dict[str, Any]) -> dict[str, Any]:
    return {
        "schema_version": int(state.get("schema_version") or 0),
        "format": str(state.get("format") or state.get("format_hint") or ""),
        "patch_depth": int(state.get("patch_depth") or state.get("patch_count") or 0),
        "patch_count": int(state.get("patch_count") or state.get("patch_depth") or 0),
        "patch_digest": str(state.get("patch_digest") or ""),
        "source_kind": str(state.get("source_kind") or ""),
        "source_format_hint": str(state.get("source_format_hint") or ""),
        "source_part_count": int(state.get("source_part_count") or 0),
    }


def _compact_damage_target(payload: dict[str, Any]) -> dict[str, Any]:
    labels = []
    for item in payload.get("labels") or []:
        if not isinstance(item, dict):
            continue
        zone = item.get("zone") if isinstance(item.get("zone"), dict) else {}
        labels.append({
            "label": str(item.get("label") or ""),
            "family": str(item.get("family") or ""),
            "zone": {
                "kind": str(zone.get("kind") or ""),
                "path": str(zone.get("path") or ""),
            },
            "severity": float(item.get("severity") or 0.0),
            "expected_min_steps": int(item.get("expected_min_steps") or 1),
        })
    return {
        "schema_version": int(payload.get("schema_version") or 1),
        "format": str(payload.get("format") or ""),
        "labels": labels,
        "damage_labels": [str(item) for item in payload.get("damage_labels") or []],
        "damage_families": [str(item) for item in payload.get("damage_families") or []],
        "route_hints": [str(item) for item in payload.get("route_hints") or []],
        "metadata": {
            key: value
            for key, value in dict(payload.get("metadata") or {}).items()
            if key in {"damage_profile", "damage_layer", "oracle_strength", "difficulty_tags"}
        },
    }


def _drop_patch_bytes(value: Any) -> Any:
    if isinstance(value, dict):
        return {
            key: _drop_patch_bytes(item)
            for key, item in value.items()
            if key not in {"patches", "patch_stack", "data_b64", "expected_b64", "expected_sha256"}
        }
    if isinstance(value, list):
        return [_drop_patch_bytes(item) for item in value]
    return value


def _compact_record_metadata(record: dict[str, Any]) -> dict[str, Any]:
    keep = (
        "sample_id",
        "query_id",
        "source_archive_id",
        "damage_profile",
        "damage_layer",
        "runtime_damage_flags",
        "difficulty_tags",
        "oracle_strength",
        "damaged_path",
        "source_path",
    )
    return {key: record.get(key) for key in keep if record.get(key) is not None}


def _compact_recovery_snapshot(snapshot: dict[str, Any]) -> dict[str, Any]:
    metadata = snapshot.get("metadata") if isinstance(snapshot.get("metadata"), dict) else {}
    verification = snapshot.get("verification") if isinstance(snapshot.get("verification"), dict) else {}
    extraction = snapshot.get("extraction") if isinstance(snapshot.get("extraction"), dict) else {}
    native = snapshot.get("native_validation") if isinstance(snapshot.get("native_validation"), dict) else {}
    coverage = snapshot.get("archive_coverage") if isinstance(snapshot.get("archive_coverage"), dict) else {}
    return {
        "state_digest": snapshot.get("state_digest", ""),
        "patch_depth": int(snapshot.get("patch_depth") or 0),
        "score": float(snapshot.get("score") or 0.0),
        "status": str(snapshot.get("status") or ""),
        "decision_hint": str(snapshot.get("decision_hint") or ""),
        "completeness": float(snapshot.get("completeness") or 0.0),
        "output_quality_score": float(snapshot.get("output_quality_score") or 0.0),
        "output_complete_ratio": float(snapshot.get("output_complete_ratio") or 0.0),
        "complete_files": int(snapshot.get("complete_files") or 0),
        "partial_files": int(snapshot.get("partial_files") or 0),
        "failed_files": int(snapshot.get("failed_files") or 0),
        "missing_files": int(snapshot.get("missing_files") or 0),
        "recovered_bytes": int(snapshot.get("recovered_bytes") or 0),
        "archive_coverage": {
            key: coverage.get(key)
            for key in ("completeness", "file_coverage", "byte_coverage", "expected_files", "matched_files", "complete_files", "partial_files", "failed_files", "missing_files")
            if coverage.get(key) is not None
        },
        "verification": {
            key: verification.get(key)
            for key in ("decision_hint", "assessment_status", "source_integrity", "completeness", "output_quality_score", "output_complete_ratio", "output_file_count", "output_total_bytes", "complete_files", "partial_files", "failed_files", "missing_files")
            if verification.get(key) is not None
        },
        "extraction": {
            key: extraction.get(key)
            for key in ("success", "status", "failure_stage", "failure_kind", "files_written", "bytes_written", "partial_outputs")
            if extraction.get(key) is not None
        },
        "native_validation": {
            "count": int(native.get("count") or 0),
            "accepted": bool(native.get("accepted")),
            "score": float(native.get("score") or 0.0),
        } if native else {},
        "metadata": {
            key: metadata.get(key)
            for key in ("score_source", "source", "mode", "module_name", "candidate_status", "status_reason")
            if metadata.get(key) is not None
        },
    }


def _candidate_priority(candidate: RepairCandidate) -> float:
    validation_score = max([float(item.score or 0.0) for item in candidate.validations], default=0.0)
    return max(float(candidate.confidence or 0.0), float(candidate.score_hint or 0.0), validation_score)


def _job_from_record(record: dict[str, Any], fmt: str) -> RepairJob:
    source_input = dict(record.get("damaged_input") or {})
    attach_split_volumes(source_input, record)
    descriptor = ArchiveInputDescriptor.from_any(
        source_input,
        archive_path=str(source_input.get("path") or record.get("damaged_path") or ""),
        format_hint="7z" if fmt == "seven_zip" else fmt,
    )
    state = ArchiveState.from_archive_input(descriptor)
    plugin = load_training_format_plugin(fmt)
    context = plugin.collection_record_context(record) if plugin.collection_record_context else {}
    knowledge = _knowledge_from_record(record, context, source_input, fmt)
    return RepairJob(
        source_input=source_input,
        format="7z" if fmt == "seven_zip" else fmt,
        confidence=1.0,
        damage_flags=[str(item) for item in record.get("runtime_damage_flags") or record.get("damage_flags") or [] if str(item)],
        password=str(record.get("password") or source_input.get("password") or "") or None,
        archive_key=str(record.get("sample_id") or record.get("query_id") or ""),
        archive_state=state,
        knowledge=knowledge,
    )


def _knowledge_from_record(record: dict[str, Any], context: dict[str, Any], source_input: dict[str, Any], fmt: str) -> dict[str, Any]:
    payload = {}
    if isinstance(context.get("payloads"), dict):
        payload.update(context["payloads"])
    payload.setdefault("source", {})["input"] = dict(source_input)
    payload.setdefault("analysis", {})["summary"] = {"format": "7z" if fmt == "seven_zip" else fmt, "confidence": 1.0}
    payload.setdefault("training", {}).update({
        "sample_id": record.get("sample_id"),
        "damage_profile": record.get("damage_profile"),
        "oracle": record.get("oracle"),
    })
    oracle = _oracle_from_record(record)
    if oracle:
        payload.setdefault("verification", {})["oracle"] = oracle
    return payload


def _training_verification_snapshot(snapshot: PolicyRecoverySnapshot) -> TrainingVerificationSnapshot:
    compact = _compact_recovery_snapshot(snapshot.to_dict())
    return TrainingVerificationSnapshot(
        score=float(snapshot.score or 0.0),
        status=snapshot.status,
        decision_hint=snapshot.decision_hint,
        recovered_files=int(snapshot.complete_files or 0) + int(snapshot.partial_files or 0),
        recovered_bytes=int(snapshot.recovered_bytes or 0),
        details={
            "patch_depth": snapshot.patch_depth,
            "patch_digest": snapshot.state_digest,
            "score_source": snapshot.metadata.get("score_source"),
            "recovery_snapshot": compact,
        },
    )


def _oracle_from_record(record: dict[str, Any]) -> dict[str, Any]:
    oracle = dict(record.get("oracle") or {}) if isinstance(record.get("oracle"), dict) else {}
    for source_key, target_key in (
        ("expected_hashes", "expected_hashes"),
        ("matched_hashes", "matched_hashes"),
        ("expected_crc", "expected_crc"),
        ("matched_crc", "matched_crc"),
        ("expected_files", "expected_files"),
        ("matched_files", "matched_files"),
        ("expected_bytes", "expected_bytes"),
        ("matched_bytes", "matched_bytes"),
    ):
        if record.get(source_key) is not None and oracle.get(target_key) is None:
            oracle[target_key] = record.get(source_key)
    if record.get("oracle_score") is not None:
        oracle["score"] = record.get("oracle_score")
    if record.get("oracle_strength") is not None:
        oracle["oracle_strength"] = record.get("oracle_strength")
    return oracle


def _terminal_transition(
    round_index: int,
    state: ArchiveState,
    damage_request: dict[str, Any],
    target: dict[str, Any],
    candidate_snapshots: list[TrainingCandidateSnapshot],
    actions: list[TrainingAction],
    before: TrainingVerificationSnapshot,
    action_type: str,
) -> TrainingTransition:
    return TrainingTransition(
        round_index=round_index,
        state_digest=state.effective_patch_digest(),
        patch_depth=state.patch_depth(),
        damage_analysis_request=damage_request,
        damage_analysis_target=target,
        candidate_snapshots=candidate_snapshots,
        available_actions=actions,
        selected_action=TrainingAction(
            action_type=action_type,
            reason="stop_signal" if action_type == "stop" else "exhaust_branch",
            metadata={"graph_semantics": "stop_signal" if action_type == "stop" else "exhaust_branch"},
        ),
        next_state_digest="",
        verification_before=before,
        verification_after=before,
        reward=0.0,
        terminal=False,
    )


def _with_snapshot_metadata(snapshot: dict[str, Any]) -> dict[str, Any]:
    snapshot = _scrub_candidate_training_input(snapshot)
    known = {
        "candidate_id",
        "action_type",
        "module_name",
        "module",
        "format",
        "patch_depth",
        "patch_operation_count",
        "confidence",
        "validation_summary",
    }
    return {**snapshot, "metadata": {key: value for key, value in snapshot.items() if key not in known}}


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


def _dedupe_transition_payloads(transitions: list[TrainingTransition]) -> list[TrainingTransition]:
    seen_state_payload: set[str] = set()
    output: list[TrainingTransition] = []
    for transition in transitions:
        if transition.state_digest in seen_state_payload:
            output.append(replace(
                transition,
                damage_analysis_request={},
                damage_analysis_target={},
                candidate_snapshots=[],
                available_actions=[],
            ))
            continue
        seen_state_payload.add(transition.state_digest)
        output.append(transition)
    return output


def _load_records(manifest: str, material_root: str, fmt: str, *, limit: int = 0) -> list[dict[str, Any]]:
    paths: list[Path] = []
    if manifest:
        paths = [Path(manifest)]
    else:
        root = Path(material_root) / fmt
        paths = sorted(root.rglob("damage_manifest.jsonl"))
    output: list[dict[str, Any]] = []
    for path in paths:
        if not path.is_file():
            continue
        with path.open("r", encoding="utf-8") as handle:
            for line in handle:
                if not line.strip():
                    continue
                row = json.loads(line)
                if isinstance(row, dict):
                    output.append(row)
                    if limit and len(output) >= limit:
                        return output
    return output


def _record_id(record: dict[str, Any]) -> str:
    return str(record.get("sample_id") or record.get("query_id") or record.get("corrupted_sha256") or record.get("damaged_path") or json.dumps(record, sort_keys=True, default=str))


def _completed_sample_ids(path: Path) -> set[str]:
    return _completed_sample_ids_from_payload(_read_checkpoint(path))


def _read_checkpoint(path: Path) -> dict[str, Any]:
    if not path.is_file():
        return {}
    try:
        payload = json.loads(path.read_text(encoding="utf-8"))
    except json.JSONDecodeError:
        return {}
    return payload if isinstance(payload, dict) else {}


def _completed_sample_ids_from_payload(payload: dict[str, Any]) -> set[str]:
    return {str(item) for item in payload.get("completed_sample_ids") or [] if str(item)}


def _write_checkpoint(path: Path, completed: set[str], summary: dict[str, Any], *, last_sample_id: str, processed_index: int) -> None:
    payload = {
        "completed_sample_ids": sorted(completed),
        "completed_count": len(completed),
        "last_sample_id": last_sample_id,
        "processed_index": int(processed_index or 0),
        "summary": dict(summary),
        "updated_at_unix": time.time(),
    }
    path.write_text(json.dumps(payload, ensure_ascii=False, indent=2, sort_keys=True), encoding="utf-8")


def _timing_summary(rows: list[dict[str, Any]]) -> dict[str, Any]:
    values = [float(row.get("elapsed_seconds") or 0.0) for row in rows if row.get("status") == "ok"]
    if not values:
        return {"count": 0, "avg_seconds": 0.0, "min_seconds": 0.0, "max_seconds": 0.0}
    values = sorted(values)
    payload = {
        "count": len(values),
        "avg_seconds": round(sum(values) / len(values), 6),
        "min_seconds": round(values[0], 6),
        "p50_seconds": round(values[len(values) // 2], 6),
        "max_seconds": round(values[-1], 6),
    }
    phase_totals: Counter[str] = Counter()
    phase_counts: Counter[str] = Counter()
    for row in rows:
        for key, value in (row.get("phase_timing") or {}).items():
            phase_totals[str(key)] += float(value or 0.0)
        for key, value in (row.get("phase_counts") or {}).items():
            phase_counts[str(key)] += int(value or 0)
    if phase_totals:
        payload["phase_totals"] = {key: round(float(value), 6) for key, value in sorted(phase_totals.items())}
        payload["phase_counts"] = dict(sorted(phase_counts.items()))
        payload["phase_avg_seconds"] = {
            key: round(float(value) / max(1, int(phase_counts.get(key, 0))), 6)
            for key, value in sorted(phase_totals.items())
        }
    return payload


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Collect policy-lab repair episodes from damaged material manifests.")
    parser.add_argument("--format", default="zip")
    parser.add_argument("--material-root", default=str(Path("repair_training") / "material"))
    parser.add_argument("--manifest", default="")
    parser.add_argument("--output", required=True)
    parser.add_argument("--failure-output", default="")
    parser.add_argument("--summary-output", default="")
    parser.add_argument("--workspace", default="")
    parser.add_argument("--limit", type=int, default=0)
    parser.add_argument("--max-depth", type=int, default=DEFAULT_MAX_DEPTH)
    parser.add_argument("--max-states", type=int, default=DEFAULT_MAX_STATES)
    parser.add_argument("--root-top-k", type=int, default=DEFAULT_ROOT_TOP_K)
    parser.add_argument("--branch-top-k", type=int, default=DEFAULT_BRANCH_TOP_K)
    parser.add_argument("--root-materialize-top-k", type=int, default=0, help="Only materialize the top N lazy candidates at root states. 0 means all.")
    parser.add_argument("--branch-materialize-top-k", type=int, default=0, help="Only materialize the top N lazy candidates at non-root states. 0 means all.")
    parser.add_argument("--recovery-mode", choices=["policy_light", "policy_full", "training_oracle"], default="training_oracle")
    parser.add_argument("--max-evaluated-candidates", type=int, default=0)
    parser.add_argument("--damage-model-dir", default="", help="Optional run/models directory used to inject real DamageAnalysisModel output into action features.")
    parser.add_argument("--verification-cache-dir", default="")
    parser.add_argument("--checkpoint-output", default="")
    parser.add_argument("--timing-output", default="")
    parser.add_argument("--checkpoint-interval", type=int, default=1)
    parser.add_argument("--resume", action="store_true")
    parser.add_argument("--workers", type=int, default=1)
    parser.add_argument("--max-in-flight", type=int, default=0)
    parser.add_argument("--time-limit-seconds", type=float, default=0.0)
    return parser


if __name__ == "__main__":
    raise SystemExit(main())
