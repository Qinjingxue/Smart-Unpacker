from __future__ import annotations

import argparse
import json
import multiprocessing as mp
import os
import shutil
import sys
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from collections import Counter, defaultdict
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from repair_training.collect_repair_plan_data import (  # noqa: E402
    _attach_split_volumes,
    _materialize_training_archive_state,
    _verify_output_against_oracle,
)
from sunpack.contracts.tasks import ArchiveTask  # noqa: E402
from sunpack.coordinator.analysis_stage import ArchiveAnalysisStage  # noqa: E402
from sunpack.coordinator.repair_runtime_transition import (  # noqa: E402
    RepairRuntimeTransitionEvaluator,
    clone_archive_task,
)
from sunpack.coordinator.repair_runtime_strategy import TrainingExhaustiveStrategy  # noqa: E402
from sunpack.coordinator.repair_stage import ArchiveRepairStage  # noqa: E402
from sunpack.coordinator.task_scan import direct_file_task  # noqa: E402
from sunpack.extraction.knowledge import write_extraction_result  # noqa: E402
from sunpack.extraction.scheduler import ExtractionScheduler  # noqa: E402
from sunpack.repair.candidate import CandidateSelector, candidate_feature_payload, materialize_candidates  # noqa: E402
from sunpack.repair.context import zip_route_evidence_flags  # noqa: E402
from sunpack.repair.policy.runtime_features import FEATURE_CONTRACT_VERSION, policy_candidate_payload  # noqa: E402
from sunpack.support import archive_knowledge_projection as knowledge_view  # noqa: E402
from sunpack.support import repair_trace  # noqa: E402
from sunpack.support.archive_knowledge_writer import (  # noqa: E402
    commit_task_knowledge,
    ensure_knowledge,
    write_flags,
    write_payload,
)
from sunpack.verification import VerificationScheduler  # noqa: E402
from sunpack.verification.result import DECISION_ACCEPT, DECISION_REPAIR  # noqa: E402


DEFAULT_MANIFEST = Path(".sunpack") / "corpus" / "repair_plan_manifest.jsonl"
DEFAULT_SUCCESS_OUTPUT = Path("repair_training") / "datasets" / "runtime_repair_graph_success.jsonl"
DEFAULT_FAILURE_OUTPUT = Path("repair_training") / "datasets" / "runtime_repair_graph_failure.jsonl"
DEFAULT_SUMMARY_OUTPUT = Path("repair_training") / "datasets" / "runtime_repair_graph_summary.json"


def main(argv: list[str] | None = None) -> int:
    args = _parser().parse_args(argv)
    records = _load_manifest(Path(args.manifest), args)
    args.success_output = str(Path(args.success_output))
    args.failure_output = str(Path(args.failure_output))
    args.summary_output = str(Path(args.summary_output))
    Path(args.success_output).parent.mkdir(parents=True, exist_ok=True)
    Path(args.failure_output).parent.mkdir(parents=True, exist_ok=True)
    Path(args.summary_output).parent.mkdir(parents=True, exist_ok=True)
    rows_ok = 0
    rows_failed = 0
    summary: dict[str, Any] = {
        "samples": len(records),
        "success_rows": 0,
        "failure_rows": 0,
        "row_type_counts": {},
        "terminal_status_counts": {},
        "label_counts": {},
        "candidate_id_collision_count": 0,
        "feature_contract_version": FEATURE_CONTRACT_VERSION,
        "collector": "runtime_repair_graph",
    }
    started = time.perf_counter()
    output_mode = "a" if args.append else "w"
    with Path(args.success_output).open(output_mode, encoding="utf-8") as success_handle, Path(args.failure_output).open(output_mode, encoding="utf-8") as failure_handle:
        for sample_status, sample_rows in _iter_collected_samples(records, args):
            handle = success_handle if sample_status == "ok" else failure_handle
            for row in sample_rows:
                handle.write(json.dumps(row, ensure_ascii=False, sort_keys=True, default=str) + "\n")
            handle.flush()
            if sample_status == "ok":
                rows_ok += len(sample_rows)
            else:
                rows_failed += len(sample_rows)
            _accumulate_summary(summary, sample_rows, sample_status)
            if args.progress:
                print(json.dumps({
                    "sample_status": sample_status,
                    "rows": len(sample_rows),
                    "success_rows": rows_ok,
                    "failure_rows": rows_failed,
                }, ensure_ascii=False, sort_keys=True), flush=True)
    summary["success_rows"] = rows_ok
    summary["failure_rows"] = rows_failed
    summary["wall_seconds"] = round(time.perf_counter() - started, 3)
    Path(args.summary_output).write_text(json.dumps(summary, ensure_ascii=False, indent=2, sort_keys=True), encoding="utf-8")
    print(json.dumps(summary, ensure_ascii=False, sort_keys=True))
    return 0


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Collect runtime-aligned repair graph rows by executing the real repair loop in exploration mode.")
    parser.add_argument("--manifest", default="")
    parser.add_argument("--material-root", default=str(Path("repair_training") / "material"))
    parser.add_argument("--formats", default="zip")
    parser.add_argument("--sample", default="")
    parser.add_argument("--limit", type=int, default=0)
    parser.add_argument("--success-output", default=str(DEFAULT_SUCCESS_OUTPUT))
    parser.add_argument("--failure-output", default=str(DEFAULT_FAILURE_OUTPUT))
    parser.add_argument("--summary-output", default=str(DEFAULT_SUMMARY_OUTPUT))
    parser.add_argument("--workspace", default=str(Path(".sunpack") / "runtime-repair-graph"))
    parser.add_argument("--workers", type=int, default=1)
    parser.add_argument("--max-rounds", type=int, default=6)
    parser.add_argument("--max-states", type=int, default=80)
    parser.add_argument("--branch-top-k", type=int, default=5)
    parser.add_argument("--materialize-top-k", type=int, default=16)
    parser.add_argument("--case-timeout-seconds", type=float, default=60.0)
    parser.add_argument("--future-label-discount", type=float, default=0.8)
    parser.add_argument("--append", action="store_true")
    parser.add_argument("--progress", action="store_true")
    parser.add_argument("--no-pretty", action="store_true")
    return parser


def _iter_collected_samples(records: list[dict[str, Any]], args: argparse.Namespace):
    workers = max(1, int(args.workers or 1))
    if workers <= 1:
        for index, record in enumerate(records):
            yield _collect_one_sample(index, record, vars(args))
        return
    with ThreadPoolExecutor(max_workers=workers) as executor:
        futures = [
            executor.submit(_collect_one_sample, index, record, vars(args))
            for index, record in enumerate(records)
        ]
        for future in as_completed(futures):
            yield future.result()


def _collect_one_sample_with_timeout(index: int, record: dict[str, Any], args_dict: dict[str, Any]) -> tuple[str, list[dict[str, Any]]]:
    timeout = max(1.0, float(args_dict.get("case_timeout_seconds", 60.0) or 60.0))
    ctx = mp.get_context("spawn")
    result_dir = Path(str(args_dict.get("workspace") or ".sunpack/runtime-repair-graph")) / ".worker_results"
    result_dir.mkdir(parents=True, exist_ok=True)
    result_path = result_dir / f"sample_{index:06d}_{os.getpid()}_{time.time_ns()}.json"
    proc = ctx.Process(target=_collect_one_child, args=(index, record, args_dict, str(result_path)))
    proc.start()
    proc.join(timeout=timeout)
    if proc.is_alive():
        proc.terminate()
        proc.join(timeout=3)
        return "failed", [{
            "row_type": "collector_timeout",
            "sample_id": record.get("sample_id"),
            "material_format": _record_format(record),
            "terminal_status": "timeout",
            "timeout_seconds": timeout,
        }]
    if result_path.is_file():
        try:
            payload = json.loads(result_path.read_text(encoding="utf-8"))
            return str(payload.get("status") or "failed"), list(payload.get("rows") or [])
        except Exception as exc:
            return "failed", [{
                "row_type": "collector_error",
                "sample_id": record.get("sample_id"),
                "material_format": _record_format(record),
                "terminal_status": "result_read_failed",
                "error": str(exc),
            }]
    return "failed", [{
        "row_type": "collector_error",
        "sample_id": record.get("sample_id"),
        "material_format": _record_format(record),
        "terminal_status": "worker_exited_without_result",
    }]


def _collect_one_child(index: int, record: dict[str, Any], args_dict: dict[str, Any], result_path: str) -> None:
    status, rows = _collect_one_sample(index, record, args_dict)
    Path(result_path).write_text(json.dumps({"status": status, "rows": rows}, ensure_ascii=False, default=str), encoding="utf-8")


def _collect_one_sample_star(payload):
    return _collect_one_sample(*payload)


def _collect_one_sample(index: int, record: dict[str, Any], args_dict: dict[str, Any]) -> tuple[str, list[dict[str, Any]]]:
    args = argparse.Namespace(**args_dict)
    try:
        rows = RuntimeRepairGraphCollector(args, record, index).collect()
        return "ok", rows
    except Exception as exc:
        return "failed", [{
            "row_type": "collector_error",
            "sample_id": record.get("sample_id"),
            "material_format": _record_format(record),
            "error": str(exc),
        }]


class RuntimeRepairGraphCollector:
    def __init__(self, args: argparse.Namespace, record: dict[str, Any], index: int):
        self.args = args
        self.record = _prepare_record(record)
        self.index = index
        self.sample_id = str(self.record.get("sample_id") or f"sample_{index}")
        self.fmt = _record_format(self.record)
        self.workspace = Path(args.workspace) / _safe_name(self.sample_id)
        self.workspace.mkdir(parents=True, exist_ok=True)
        self.output_root = self.workspace / "outputs"
        self.output_root.mkdir(parents=True, exist_ok=True)
        self.config = _runtime_graph_config(args, self.workspace)
        self.analysis_stage = ArchiveAnalysisStage(self.config)
        self.extractor = ExtractionScheduler(
            max_retries=1,
            process_config={
                "max_seconds": max(1.0, float(args.case_timeout_seconds or 60.0)),
                "max_extract_task_seconds": max(1.0, float(args.case_timeout_seconds or 60.0)),
                "process_no_progress_timeout_seconds": max(1.0, float(args.case_timeout_seconds or 60.0)),
            },
            output_config={"root": str(self.output_root)},
            extraction_config={"write_progress_manifest": True},
        )
        self.verifier = VerificationScheduler(self.config, password_session=self.extractor.password_session)
        self.repair_stage = ArchiveRepairStage(self.config)
        self.selector = CandidateSelector(self.config.get("repair") if isinstance(self.config.get("repair"), dict) else self.config)
        self.evaluator = RepairRuntimeTransitionEvaluator(
            extractor=self.extractor,
            verifier=self.verifier,
            repair_stage=self.repair_stage,
            analysis_stage=self.analysis_stage,
        )
        self.strategy = TrainingExhaustiveStrategy(branch_top_k=max(1, int(args.branch_top_k or 1)))
        self.rows: list[dict[str, Any]] = []
        self.state_counter = 0

    def collect(self) -> list[dict[str, Any]]:
        shutil.rmtree(self.workspace, ignore_errors=True)
        self.workspace.mkdir(parents=True, exist_ok=True)
        self.output_root.mkdir(parents=True, exist_ok=True)
        root_task = _task_from_record(self.record)
        self.analysis_stage.refresh_task_analysis(root_task)
        frontier = [self._state(root_task, round_index=0, parent_action_row_id="", parent_candidate_id="")]
        expanded = 0
        for round_index in range(max(1, int(self.args.max_rounds or 1))):
            if not frontier or expanded >= int(self.args.max_states or 80):
                break
            next_frontier: list[dict[str, Any]] = []
            for state in frontier:
                if expanded >= int(self.args.max_states or 80):
                    break
                expanded += 1
                next_frontier.extend(self._expand_state(state, round_index))
            frontier = next_frontier[: max(1, int(self.args.max_states or 80))]
        _backfill_runtime_returns(self.rows, float(self.args.future_label_discount or 0.8))
        return self.rows

    def _state(self, task: ArchiveTask, *, round_index: int, parent_action_row_id: str, parent_candidate_id: str) -> dict[str, Any]:
        self.state_counter += 1
        return {
            "state_id": f"{self.sample_id}:s{self.state_counter}",
            "task": task,
            "round": int(round_index),
            "parent_action_row_id": parent_action_row_id,
            "parent_candidate_id": parent_candidate_id,
        }

    def _expand_state(self, state: dict[str, Any], round_index: int) -> list[dict[str, Any]]:
        task: ArchiveTask = state["task"]
        out_dir = self.output_root / _safe_name(str(state["state_id"]))
        extraction = self.extractor.extract(task, str(out_dir))
        write_extraction_result(task, extraction)
        verification = self.verifier.verify(task, extraction)
        if verification.decision_hint == DECISION_ACCEPT:
            self.rows.append(_terminal_row(self.record, state, "complete", verification))
            return []
        if verification.decision_hint != DECISION_REPAIR:
            self.rows.append(_terminal_row(self.record, state, str(verification.decision_hint or verification.assessment_status or "terminal"), verification))
            return []
        job = self.repair_stage._job_from_verification_assessment(task, extraction, verification)  # noqa: SLF001
        if job is None or self.repair_stage.scheduler is None:
            self.rows.append(_terminal_row(self.record, state, "no_repair_job", verification))
            return []
        batch = self.repair_stage.scheduler.generate_repair_candidates(job)
        if batch.terminal_result is not None or not batch.candidates:
            terminal_status = "no_candidates"
            if batch.terminal_result is not None:
                terminal_status = str(getattr(batch.terminal_result, "status", "") or "repair_terminal")
            row = _terminal_row(self.record, state, terminal_status, verification)
            row["debug_damage_flags"] = list(job.damage_flags or [])
            row["debug_job_format"] = job.format
            row["debug_route_evidence_flags"] = list((knowledge_view.repair_route_context(job.knowledge) or {}).get("route_evidence_flags") or [])
            if batch.terminal_result is not None:
                row["debug_repair_terminal_message"] = str(getattr(batch.terminal_result, "message", "") or "")
                row["debug_repair_terminal_diagnosis"] = dict(getattr(batch.terminal_result, "diagnosis", {}) or {})
            self.rows.append(row)
            return []
        candidates = self._runtime_candidates(batch.candidates)
        if not candidates:
            row = _terminal_row(self.record, state, "no_materialized_candidates", verification)
            row["debug_candidate_count"] = len(batch.candidates)
            row["debug_damage_flags"] = list(job.damage_flags or [])
            self.rows.append(row)
            return []
        payloads = [policy_candidate_payload(job, candidate, index=index) for index, candidate in enumerate(candidates)]
        query_id = f"{state['state_id']}:q"
        collision_count = _candidate_id_collision_count(payloads)
        candidate_set_hash = repair_trace.canonical_hash(_candidate_set_hash_input(payloads))
        strategy_decision = self.strategy.choose(state_id=str(state["state_id"]), candidate_payloads=payloads, context={"sample_id": self.sample_id})
        selected_ids = set(strategy_decision.selected_candidate_ids)
        next_states: list[dict[str, Any]] = []
        for rank, (candidate, payload) in enumerate(zip(candidates, payloads)):
            candidate_id = str(payload.get("candidate_id") or "")
            if selected_ids and candidate_id not in selected_ids:
                self.rows.append(_unexplored_action_row(
                    self.record,
                    state,
                    query_id=query_id,
                    round_index=round_index,
                    rank=rank,
                    payload=payload,
                    candidate_set_hash=candidate_set_hash,
                    collision_count=collision_count,
                    strategy_decision=strategy_decision,
                ))
                continue
            action_row_id = f"{query_id}|{rank}|{candidate_id}"
            branch_task = clone_archive_task(task, key_suffix=f":{rank}")
            transition = self.evaluator.evaluate(
                branch_task,
                candidate,
                temp_dir=self.output_root / f"{_safe_name(str(state['state_id']))}_cand_{rank:02d}",
                restore=False,
                refresh_analysis=True,
                record_repair_history=True,
            )
            archive_path = _archive_path_for_oracle(branch_task, self.fmt)
            oracle = _verify_output_against_oracle(Path(archive_path), self.fmt, self.record.get("oracle") if isinstance(self.record.get("oracle"), dict) else {}) if archive_path else {"status": "missing_output", "label": 0, "completeness": 0.0}
            terminal_status = _transition_terminal_status(transition, oracle)
            row = {
                "row_type": "action",
                "collector": "runtime_repair_graph",
                "sample_id": self.sample_id,
                "episode_id": self.sample_id,
                "state_id": state["state_id"],
                "query_id": query_id,
                "round": int(round_index),
                "action_row_id": action_row_id,
                "candidate_id": candidate_id,
                "candidate_id_collision_count": collision_count,
                "candidate_set_hash": candidate_set_hash,
                "strategy": strategy_decision.mode,
                "strategy_selected_candidate_ids": list(strategy_decision.selected_candidate_ids),
                "current_rank": rank,
                "branchable": True,
                "explored": True,
                "selected": rank == 0,
                "material_format": self.fmt,
                "module": payload.get("module_name") or payload.get("module"),
                "module_name": payload.get("module_name") or payload.get("module"),
                "repair_name": payload.get("repair_name"),
                "native_target": payload.get("native_target"),
                "candidate_status": payload.get("candidate_status"),
                "label": int(oracle.get("label", 0) or 0),
                "label_status": str(oracle.get("status") or ""),
                "recovery_ratio": float(oracle.get("completeness", 0.0) or 0.0),
                "terminal_status": terminal_status,
                "next_state_id": "" if terminal_status in {"complete", "verification_accept_partial"} else f"{self.sample_id}:s{self.state_counter + len(next_states) + 1}",
                "parent_action_row_id": state.get("parent_action_row_id") or "",
                "parent_candidate_id": state.get("parent_candidate_id") or "",
                "runtime_verification": _verification_payload(transition.verification),
                "stable_features": {
                    "runtime_context": payload.get("runtime_context") or {},
                    "candidate_proposal": payload.get("candidate_proposal") or {},
                    "candidate": payload,
                },
                "rl": {
                    "state_features": {"runtime_context": payload.get("runtime_context") or {}},
                    "action_features": {
                        "candidate_proposal": payload.get("candidate_proposal") or {},
                        "repair_prior_features": {},
                    },
                    "reward": float(oracle.get("completeness", 0.0) or 0.0),
                    "done": terminal_status in {"complete", "verification_accept_partial"},
                    "next_state_id": "" if terminal_status in {"complete", "verification_accept_partial"} else f"{self.sample_id}:s{self.state_counter + len(next_states) + 1}",
                    "terminal_reward": float(oracle.get("completeness", 0.0) or 0.0),
                    "future_return": float(oracle.get("completeness", 0.0) or 0.0),
                    "single_path_robust_return": float(oracle.get("completeness", 0.0) or 0.0),
                },
            }
            self.rows.append(row)
            if row["rl"]["done"] or round_index + 1 >= int(self.args.max_rounds or 1):
                continue
            next_states.append(self._state(
                branch_task,
                round_index=round_index + 1,
                parent_action_row_id=action_row_id,
                parent_candidate_id=candidate_id,
            ))
        return next_states[: max(1, int(self.args.branch_top_k or 1))]

    def _runtime_candidates(self, candidates):
        materialized = materialize_candidates(list(candidates)[: max(1, int(self.args.materialize_top_k or 16))])
        validated = [self.selector._with_native_validation(candidate) for candidate in materialized]  # noqa: SLF001
        accepted = [candidate for candidate in validated if self.selector._accepted(candidate)]  # noqa: SLF001
        accepted.sort(key=self.selector.generation_priority, reverse=True)
        return accepted[: max(1, int(self.args.materialize_top_k or 16))]


def _runtime_graph_config(args: argparse.Namespace, workspace: Path) -> dict[str, Any]:
    return {
        "repair": {
            "enabled": True,
            "workspace": str(workspace / "repair"),
            "max_repair_rounds_per_task": max(1, int(args.max_rounds or 1)),
            "max_attempts_per_task": max(1, int(args.max_rounds or 1)),
            "max_repair_seconds_per_task": max(5.0, float(args.case_timeout_seconds or 60.0)),
            "runtime_cache": {"enabled": True, "max_entries": 1024},
            "module_limits": {
                "max_candidates_per_module": 8,
                "verify_candidates": False,
                "max_seconds_per_module": 10.0,
            },
            "beam": {"enabled": False},
            "policy": {"enabled": False, "fallback_to_selector": True},
        },
        "verification": {
            "enabled": True,
            "methods": [{"name": "archive_test_crc"}],
            "max_retries": 0,
            "retry_on_verification_failure": True,
            "cleanup_failed_output": False,
            "accept_partial_when_source_damaged": True,
            "partial_accept_threshold": 0.2,
            "complete_accept_threshold": 0.999,
            "recovery_min_improvement": 0.01,
        },
        "output": {"root": str(workspace / "outputs")},
        "extraction": {"write_progress_manifest": True},
        "performance": {"scheduler_profile": "single"},
    }


def _task_from_record(record: dict[str, Any]) -> ArchiveTask:
    path = str(record.get("damaged_path") or (record.get("damaged_input") or {}).get("path") or "")
    task = direct_file_task(path)
    _attach_split_to_task(task, record)
    _write_record_knowledge(task, record)
    task.ensure_archive_state()
    return task


def _write_record_knowledge(task: ArchiveTask, record: dict[str, Any]) -> None:
    structure = dict(record.get("zip_structure_features") or {})
    tags = [str(item) for item in record.get("zip_container_tags") or [] if str(item)]
    profile = str(record.get("damage_profile") or record.get("profile") or "")
    source_derivation = dict(record.get("source_derivation") or {})
    route_flags = zip_route_evidence_flags({
        "format": _record_format(record),
        "source_input": record.get("damaged_input") or {},
        "zip_structure_features": structure,
        "zip_container_tags": tags,
        "damage_profile": profile,
        "source_derivation": source_derivation,
        "damage_flags": list(record.get("runtime_damage_flags") or record.get("damage_flags") or []),
    })
    knowledge = ensure_knowledge(task)
    write_payload(knowledge, "format.zip", {"structure": structure, "container_tags": tags, "route_evidence_flags": route_flags}, source_layer="training", source_module="runtime_graph")
    write_payload(knowledge, "source", {"profile": profile, "derivation": source_derivation}, source_layer="training", source_module="runtime_graph")
    write_payload(knowledge, "training", {"sample_id": str(record.get("sample_id") or ""), "damage_profile": profile}, source_layer="training", source_module="runtime_graph")
    if route_flags:
        write_flags(knowledge, "format.zip.route_evidence", route_flags, source_layer="training", source_module="runtime_graph")
    commit_task_knowledge(task, knowledge)


def _attach_split_to_task(task: ArchiveTask, record: dict[str, Any]) -> None:
    source_input = dict(record.get("damaged_input") or {})
    _attach_split_volumes(source_input, record)
    part_items = [dict(item) for item in source_input.get("parts") or [] if isinstance(item, dict) and item.get("path")]
    parts = _dedupe([str(item.get("path") or "") for item in part_items if item.get("path")])
    main_path = str(task.main_path)
    if main_path and main_path not in parts and not bool(source_input.get("use_parts_only")):
        parts.append(main_path)
        part_items.append({"path": main_path, "start": 0, "end": None, "role": "main"})
    if len(parts) <= 1:
        return
    task.all_parts = parts
    task.split_info.parts = parts
    task.split_info.is_split = True
    task.split_info.source = "runtime_repair_graph"
    task.split_info.volumes = [{"path": path, "role": "volume"} for path in parts]
    ranges = []
    for item in part_items:
        path = str(item.get("path") or "")
        if path:
            ranges.append({"path": path, "start": int(item.get("start") or 0), "end": item.get("end")})
    if ranges:
        task.set_archive_input({"kind": "concat_ranges", "ranges": ranges, "format_hint": _record_format(record), "path": main_path, "parts": part_items, "use_parts_only": bool(source_input.get("use_parts_only"))})


def _archive_path_for_oracle(task: ArchiveTask, fmt: str) -> str:
    state = task.archive_state()
    if state.patches:
        return _materialize_training_archive_state(state, fmt)
    descriptor = state.to_archive_input_descriptor()
    if descriptor.open_mode == "file" and descriptor.entry_path:
        return descriptor.entry_path
    return _materialize_training_archive_state(state, fmt)


def _transition_terminal_status(transition, oracle: dict[str, Any]) -> str:
    if int(oracle.get("label", 0) or 0) == 3:
        return "complete"
    if transition.accepted_partial:
        return "verification_accept_partial"
    if transition.can_continue_repair:
        return "continue"
    return str(transition.terminal_reason or "terminal")


def _terminal_row(record: dict[str, Any], state: dict[str, Any], status: str, verification) -> dict[str, Any]:
    return {
        "row_type": "terminal",
        "collector": "runtime_repair_graph",
        "sample_id": record.get("sample_id"),
        "episode_id": record.get("sample_id"),
        "state_id": state.get("state_id"),
        "round": state.get("round"),
        "terminal_status": status,
        "material_format": _record_format(record),
        "runtime_verification": _verification_payload(verification),
    }


def _backfill_runtime_returns(rows: list[dict[str, Any]], discount: float) -> None:
    by_state: dict[str, list[dict[str, Any]]] = defaultdict(list)
    for row in rows:
        if row.get("row_type") == "action":
            by_state[str(row.get("state_id") or "")].append(row)

    memo: dict[str, float] = {}

    def best_return(state_id: str) -> float:
        if state_id in memo:
            return memo[state_id]
        best = 0.0
        for row in by_state.get(state_id, []):
            immediate = float(row.get("recovery_ratio", 0.0) or 0.0)
            next_state = str(row.get("next_state_id") or "")
            future = best_return(next_state) if next_state else 0.0
            value = max(immediate, float(discount) * future)
            best = max(best, value)
        memo[state_id] = best
        return best

    for state_id in list(by_state):
        best_return(state_id)
    for row in rows:
        if row.get("row_type") != "action":
            continue
        immediate = float(row.get("recovery_ratio", 0.0) or 0.0)
        next_state = str(row.get("next_state_id") or "")
        future = best_return(next_state) if next_state else 0.0
        value = max(immediate, float(discount) * future)
        row["terminal_recovery_ratio"] = immediate
        if isinstance(row.get("rl"), dict):
            row["rl"]["future_return"] = value
            row["rl"]["single_path_robust_return"] = value
            row["rl"]["terminal_reward"] = immediate


def _unexplored_action_row(
    record: dict[str, Any],
    state: dict[str, Any],
    *,
    query_id: str,
    round_index: int,
    rank: int,
    payload: dict[str, Any],
    candidate_set_hash: str,
    collision_count: int,
    strategy_decision,
) -> dict[str, Any]:
    candidate_id = str(payload.get("candidate_id") or "")
    return {
        "row_type": "action",
        "collector": "runtime_repair_graph",
        "sample_id": record.get("sample_id"),
        "episode_id": record.get("sample_id"),
        "state_id": state.get("state_id"),
        "query_id": query_id,
        "round": int(round_index),
        "action_row_id": f"{query_id}|{rank}|{candidate_id}",
        "candidate_id": candidate_id,
        "candidate_id_collision_count": collision_count,
        "candidate_set_hash": candidate_set_hash,
        "strategy": strategy_decision.mode,
        "strategy_selected_candidate_ids": list(strategy_decision.selected_candidate_ids),
        "current_rank": rank,
        "branchable": True,
        "explored": False,
        "selected": False,
        "material_format": _record_format(record),
        "module": payload.get("module_name") or payload.get("module"),
        "module_name": payload.get("module_name") or payload.get("module"),
        "repair_name": payload.get("repair_name"),
        "native_key": payload.get("native_key"),
        "native_target": payload.get("native_target"),
        "candidate_status": payload.get("candidate_status"),
        "terminal_status": "not_explored",
        "stable_features": {
            "runtime_context": payload.get("runtime_context") or {},
            "candidate_proposal": payload.get("candidate_proposal") or {},
            "candidate": payload,
        },
    }


def _verification_payload(result) -> dict[str, Any]:
    return {
        "decision_hint": getattr(result, "decision_hint", ""),
        "assessment_status": getattr(result, "assessment_status", ""),
        "source_integrity": getattr(result, "source_integrity", ""),
        "completeness": float(getattr(result, "completeness", 0.0) or 0.0),
        "recoverable_upper_bound": float(getattr(result, "recoverable_upper_bound", 0.0) or 0.0),
        "complete_files": int(getattr(result, "complete_files", 0) or 0),
        "partial_files": int(getattr(result, "partial_files", 0) or 0),
        "failed_files": int(getattr(result, "failed_files", 0) or 0),
        "missing_files": int(getattr(result, "missing_files", 0) or 0),
        "unverified_files": int(getattr(result, "unverified_files", 0) or 0),
    }


def _candidate_set_hash_input(payloads: list[dict[str, Any]]) -> list[dict[str, Any]]:
    return [
        {
            "candidate_id": item.get("candidate_id"),
            "module_name": item.get("module_name") or item.get("module"),
            "repair_name": item.get("repair_name"),
            "native_target": item.get("native_target"),
            "candidate_status": item.get("candidate_status"),
        }
        for item in payloads
    ]


def _candidate_id_collision_count(payloads: list[dict[str, Any]]) -> int:
    seen: set[str] = set()
    duplicates = 0
    for payload in payloads:
        candidate_id = str(payload.get("candidate_id") or "")
        if not candidate_id:
            continue
        if candidate_id in seen:
            duplicates += 1
        seen.add(candidate_id)
    return duplicates


def _load_manifest(path: Path, args: argparse.Namespace) -> list[dict[str, Any]]:
    formats = {item.strip().lower() for item in str(args.formats or "").split(",") if item.strip()}
    samples = {item.strip() for item in str(getattr(args, "sample", "") or "").split(",") if item.strip()}
    if not path.is_file():
        return _load_material_root(Path(getattr(args, "material_root", "") or ""), formats=formats, samples=samples, limit=int(args.limit or 0))
    rows: list[dict[str, Any]] = []
    with path.open("r", encoding="utf-8") as handle:
        for line in handle:
            if not line.strip():
                continue
            record = json.loads(line)
            if not isinstance(record, dict):
                continue
            fmt = _record_format(record).lower()
            if formats and fmt not in formats:
                continue
            if samples and str(record.get("sample_name") or record.get("sample") or record.get("profile") or "") not in samples:
                sample_id = str(record.get("sample_id") or "")
                if not any(sample and sample in sample_id for sample in samples):
                    continue
            if not (record.get("damaged_path") or (record.get("damaged_input") or {}).get("path")):
                continue
            rows.append(record)
            if args.limit and len(rows) >= int(args.limit):
                break
    return rows


def _load_material_root(root: Path, *, formats: set[str], samples: set[str], limit: int) -> list[dict[str, Any]]:
    rows: list[dict[str, Any]] = []
    if not root.is_dir():
        return rows
    for manifest in sorted(root.rglob("damage_manifest.jsonl")):
        try:
            relative = manifest.relative_to(root)
        except ValueError:
            relative = manifest
        parts = relative.parts
        fmt = parts[0].lower() if parts else ""
        sample_name = parts[1] if len(parts) > 1 else ""
        if formats and fmt not in formats:
            continue
        if samples and sample_name not in samples:
            continue
        with manifest.open("r", encoding="utf-8") as handle:
            for line in handle:
                line = line.strip()
                if not line:
                    continue
                try:
                    record = json.loads(line)
                except json.JSONDecodeError:
                    continue
                if not isinstance(record, dict):
                    continue
                record.setdefault("format", fmt)
                record.setdefault("sample_name", sample_name)
                rows.append(record)
                if limit and len(rows) >= limit:
                    return rows
    return rows


def _prepare_record(record: dict[str, Any]) -> dict[str, Any]:
    output = dict(record)
    damage_json_path = Path(str(output.get("damage_json_path") or ""))
    if damage_json_path and not damage_json_path.is_absolute():
        damage_json_path = ROOT / damage_json_path
    if damage_json_path.is_file():
        try:
            damage = json.loads(damage_json_path.read_text(encoding="utf-8"))
            merged = dict(damage)
            merged.update(output)
            output = merged
        except Exception:
            pass
    for key in ("damaged_path", "source_path", "damage_json_path"):
        if output.get(key) and not Path(str(output[key])).is_absolute():
            output[key] = str((ROOT / str(output[key])).resolve())
    damaged_input = dict(output.get("damaged_input") or {})
    if damaged_input.get("path") and not Path(str(damaged_input["path"])).is_absolute():
        damaged_input["path"] = str((ROOT / str(damaged_input["path"])).resolve())
    output["damaged_input"] = damaged_input
    return output


def _record_format(record: dict[str, Any]) -> str:
    return str(record.get("format") or record.get("material_format") or (record.get("damaged_input") or {}).get("format_hint") or "zip").lstrip(".")


def _accumulate_summary(summary: dict[str, Any], rows: list[dict[str, Any]], sample_status: str) -> None:
    summary.setdefault("sample_status_counts", {})
    summary["sample_status_counts"][sample_status] = int(summary["sample_status_counts"].get(sample_status, 0) or 0) + 1
    for row in rows:
        row_type = str(row.get("row_type") or "unknown")
        summary["row_type_counts"][row_type] = int(summary["row_type_counts"].get(row_type, 0) or 0) + 1
        if row.get("terminal_status"):
            key = str(row.get("terminal_status") or "")
            summary["terminal_status_counts"][key] = int(summary["terminal_status_counts"].get(key, 0) or 0) + 1
        if row.get("label") is not None:
            key = str(row.get("label"))
            summary["label_counts"][key] = int(summary["label_counts"].get(key, 0) or 0) + 1
        summary["candidate_id_collision_count"] = int(summary.get("candidate_id_collision_count", 0) or 0) + int(row.get("candidate_id_collision_count", 0) or 0)


def _safe_name(value: str) -> str:
    text = "".join(ch if ch.isalnum() or ch in {"-", "_", "."} else "_" for ch in str(value or "sample"))
    return text[:120] or "sample"


def _dedupe(values: list[str]) -> list[str]:
    out: list[str] = []
    seen: set[str] = set()
    for value in values:
        text = str(value or "")
        if not text or text in seen:
            continue
        seen.add(text)
        out.append(text)
    return out


if __name__ == "__main__":
    raise SystemExit(main())
