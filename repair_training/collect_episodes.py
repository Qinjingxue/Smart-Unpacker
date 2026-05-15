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
from sunpack.repair.job import RepairJob
from sunpack.repair.policy.training_runtime import (
    build_damage_analysis_request,
    candidate_snapshot,
    request_to_dict,
    state_source_input,
    validate_policy_candidates,
)
from sunpack.repair.policy.recovery_evaluator import PolicyRecoveryMode, PolicyRecoverySnapshot, RecoveryEvaluator
from sunpack.repair.scheduler import RepairScheduler


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
        "recovery_mode": args.recovery_mode,
        "max_evaluated_candidates": args.max_evaluated_candidates,
    }
    workers = max(1, int(args.workers or 1))
    max_in_flight = max(workers, workers * 2)
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
        recovery_mode=args.recovery_mode,
        max_evaluated_candidates=args.max_evaluated_candidates,
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
    recovery_mode: PolicyRecoveryMode,
    max_evaluated_candidates: int,
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
            recovery_mode=recovery_mode,
            max_evaluated_candidates=max_evaluated_candidates,
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
    recovery_mode: PolicyRecoveryMode = "training_oracle",
    max_evaluated_candidates: int = 0,
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

    while queue and len(seen) <= max_states:
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
            diagnosis={"format": target.format, "taxonomy": target.to_dict()},
            round_index=depth,
        )
        damage_request_dict = request_to_dict(damage_request)
        damage_target_dict = target.to_dict()
        state_recovery = recovery_evaluator.evaluate_state(
            current_job,
            state,
            mode=recovery_mode,
            oracle=oracle,
            cache=recovery_cache,
        )
        candidates = _select_candidates(
            scheduler,
            current_job,
            root_top_k if depth == 0 else branch_top_k,
        )
        if max_evaluated_candidates:
            candidates = candidates[:max(0, int(max_evaluated_candidates))]
        candidate_count += len(candidates)
        candidate_recoveries = [
            recovery_evaluator.evaluate_candidate(
                current_job,
                candidate,
                mode=recovery_mode,
                oracle=oracle,
                cache=recovery_cache,
            )
            for candidate in candidates
        ]
        candidate_dicts = [
            candidate_snapshot(
                candidate,
                index=index,
                damage_analysis=target.to_dict(),
                current_recovery=state_recovery.to_dict(),
                recovery_snapshot=candidate_recoveries[index].to_dict(),
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
            actions.append(TrainingAction(action_type="undo_patch", reason="pop_previous_patch", metadata={"target_state_digest": parent_digest}))
        actions.extend([TrainingAction(action_type="stop", reason="control_stop"), TrainingAction(action_type="give_up", reason="control_give_up")])
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
                damage_analysis_target=damage_target_dict,
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
                damage_analysis_target=damage_target_dict,
                candidate_snapshots=candidate_snapshots,
                available_actions=actions,
                selected_action=TrainingAction(action_type="undo_patch", metadata={"target_state_digest": parent_digest}),
                next_state_digest=parent_digest,
                verification_before=before,
                verification_after=parent_after,
                reward=parent_after.score - before.score,
            ))
        transitions.extend([
            _terminal_transition(depth, state, damage_request_dict, damage_target_dict, candidate_snapshots, actions, before, "stop"),
            _terminal_transition(depth, state, damage_request_dict, damage_target_dict, candidate_snapshots, actions, before, "give_up"),
        ])

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
        metadata={"raw_damage_record": record, "taxonomy": target.to_dict()},
    )
    return episode, {
        "transitions": len(transitions),
        "candidate_count": candidate_count,
        "repeated_digest_count": repeated,
    }


def _select_candidates(scheduler: RepairScheduler, job: RepairJob, top_k: int) -> list[RepairCandidate]:
    batch = scheduler.generate_repair_candidates(job, lazy=True)
    validated = validate_policy_candidates(scheduler.config, list(batch.candidates))
    accepted = [
        candidate
        for candidate in validated
        if candidate.repaired_state is not None
        and not candidate.is_lazy
        and all(validation.accepted for validation in candidate.validations)
    ]
    accepted.sort(key=_candidate_priority, reverse=True)
    return accepted[:max(0, int(top_k or 0))]


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
    return payload


def _training_verification_snapshot(snapshot: PolicyRecoverySnapshot) -> TrainingVerificationSnapshot:
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
            "recovery_snapshot": snapshot.to_dict(),
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
        selected_action=TrainingAction(action_type=action_type, reason=f"control_{action_type}"),
        next_state_digest="",
        verification_before=before,
        verification_after=before,
        reward=0.0,
        terminal=True,
    )


def _with_snapshot_metadata(snapshot: dict[str, Any]) -> dict[str, Any]:
    known = {
        "candidate_id",
        "action_type",
        "module_name",
        "module",
        "format",
        "patch_depth",
        "patch_digest",
        "patch_operation_count",
        "confidence",
        "validation_summary",
    }
    return {**snapshot, "metadata": {key: value for key, value in snapshot.items() if key not in known}}


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
    return {
        "count": len(values),
        "avg_seconds": round(sum(values) / len(values), 6),
        "min_seconds": round(values[0], 6),
        "p50_seconds": round(values[len(values) // 2], 6),
        "max_seconds": round(values[-1], 6),
    }


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
    parser.add_argument("--recovery-mode", choices=["policy_light", "policy_full", "training_oracle"], default="training_oracle")
    parser.add_argument("--max-evaluated-candidates", type=int, default=0)
    parser.add_argument("--verification-cache-dir", default="")
    parser.add_argument("--checkpoint-output", default="")
    parser.add_argument("--timing-output", default="")
    parser.add_argument("--checkpoint-interval", type=int, default=1)
    parser.add_argument("--resume", action="store_true")
    parser.add_argument("--workers", type=int, default=1)
    parser.add_argument("--time-limit-seconds", type=float, default=0.0)
    return parser


if __name__ == "__main__":
    raise SystemExit(main())
