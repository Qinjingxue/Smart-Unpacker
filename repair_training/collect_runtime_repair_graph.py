from __future__ import annotations

import argparse
import faulthandler
import json
import multiprocessing as mp
import os
import shutil
import sys
import time
from contextlib import contextmanager
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
from sunpack.coordinator.repair_runtime_strategy import RepairRuntimeStrategyDecision, TrainingExhaustiveStrategy  # noqa: E402
from sunpack.coordinator.repair_stage import ArchiveRepairStage  # noqa: E402
from sunpack.coordinator.repair_loop import RepairLoopLimits, RepairLoopState  # noqa: E402
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
        "phase_seconds": {},
        "phase_counts": {},
        "slowest_samples": [],
        "slowest_states": [],
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
    _merge_projection_cache_stats(summary, knowledge_view.projection_cache_stats())
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
    parser.add_argument("--hard-negative-backfill-k", type=int, default=3)
    parser.add_argument("--stop-after-complete-with-negatives", action="store_true", default=True)
    parser.add_argument("--no-stop-after-complete-with-negatives", dest="stop_after_complete_with_negatives", action="store_false")
    parser.add_argument("--target-negative-per-positive", type=int, default=3)
    parser.add_argument("--max-positive-actions-per-sample", type=int, default=4)
    parser.add_argument("--path-filter-json", default="", help="Optional sample_id -> candidate signature path map; when set, collect only those runtime paths.")
    parser.add_argument("--case-timeout-seconds", type=float, default=60.0)
    parser.add_argument("--debug-events-output", default="")
    parser.add_argument("--phase-slow-threshold-ms", type=float, default=500.0)
    parser.add_argument("--dump-stack-after-seconds", type=float, default=0.0)
    parser.add_argument("--disable-process-isolation", action="store_true")
    parser.add_argument("--future-label-discount", type=float, default=0.8)
    parser.add_argument("--append", action="store_true")
    parser.add_argument("--progress", action="store_true")
    parser.add_argument("--no-pretty", action="store_true")
    return parser


def _iter_collected_samples(records: list[dict[str, Any]], args: argparse.Namespace):
    workers = max(1, int(args.workers or 1))
    collector = _collect_one_sample if bool(getattr(args, "disable_process_isolation", False)) else _collect_one_sample_with_timeout
    if workers <= 1:
        for index, record in enumerate(records):
            yield collector(index, record, vars(args))
        return
    with ThreadPoolExecutor(max_workers=workers) as executor:
        futures = [
            executor.submit(collector, index, record, vars(args))
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
    sample_id = str(record.get("sample_id") or f"sample_{index}")
    debug_dir = Path(str(args_dict.get("workspace") or ".sunpack/runtime-repair-graph")) / ".debug_events"
    debug_dir.mkdir(parents=True, exist_ok=True)
    debug_path = debug_dir / f"sample_{index:06d}_{_safe_name(sample_id)}.jsonl"
    stack_path = debug_dir / f"sample_{index:06d}_{_safe_name(sample_id)}.stack.txt"
    child_args = dict(args_dict)
    child_args["_debug_events_path"] = str(debug_path)
    child_args["_stack_dump_path"] = str(stack_path)
    proc = ctx.Process(target=_collect_one_child, args=(index, record, child_args, str(result_path)))
    proc.start()
    proc.join(timeout=timeout)
    if proc.is_alive():
        proc.terminate()
        proc.join(timeout=3)
        last_event = _last_jsonl_event(debug_path)
        return "failed", [{
            "row_type": "collector_timeout",
            "sample_id": record.get("sample_id"),
            "material_format": _record_format(record),
            "terminal_status": "timeout",
            "timeout_seconds": timeout,
            "last_phase": last_event.get("phase", ""),
            "last_state_id": last_event.get("state_id", ""),
            "last_candidate_id": last_event.get("candidate_id", ""),
            "debug_events_path": str(debug_path),
            "stack_dump_path": str(stack_path) if stack_path.exists() else "",
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
        "debug_events_path": str(debug_path),
        "stack_dump_path": str(stack_path) if stack_path.exists() else "",
    }]


def _collect_one_child(index: int, record: dict[str, Any], args_dict: dict[str, Any], result_path: str) -> None:
    dump_after = float(args_dict.get("dump_stack_after_seconds", 0.0) or 0.0)
    stack_handle = None
    try:
        if dump_after > 0:
            stack_path = str(args_dict.get("_stack_dump_path") or "")
            stack_handle = open(stack_path, "w", encoding="utf-8") if stack_path else None
            faulthandler.enable(file=stack_handle)
            faulthandler.dump_traceback_later(dump_after, file=stack_handle, exit=True)
        status, rows = _collect_one_sample(index, record, args_dict)
        Path(result_path).write_text(json.dumps({"status": status, "rows": rows}, ensure_ascii=False, default=str), encoding="utf-8")
    finally:
        if dump_after > 0:
            try:
                faulthandler.cancel_dump_traceback_later()
            except Exception:
                pass
        if stack_handle is not None:
            stack_handle.close()


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


class _CollectorProfiler:
    def __init__(self, args: argparse.Namespace, sample_id: str):
        self.sample_id = sample_id
        self.slow_threshold = max(0.0, float(getattr(args, "phase_slow_threshold_ms", 500.0) or 0.0)) / 1000.0
        self.events_path = Path(str(getattr(args, "_debug_events_path", "") or getattr(args, "debug_events_output", "") or "")) if (getattr(args, "_debug_events_path", "") or getattr(args, "debug_events_output", "")) else None
        self.phase_seconds: Counter[str] = Counter()
        self.phase_counts: Counter[str] = Counter()
        self.slowest: list[dict[str, Any]] = []
        self.last_event: dict[str, Any] = {}

    @contextmanager
    def phase(self, phase: str, *, state_id: str = "", candidate_id: str = ""):
        started = time.perf_counter()
        self._event("phase_start", phase=phase, state_id=state_id, candidate_id=candidate_id)
        try:
            yield
        except Exception as exc:
            elapsed = time.perf_counter() - started
            self._record_phase(phase, elapsed, state_id, candidate_id, status="exception", error=str(exc))
            raise
        else:
            elapsed = time.perf_counter() - started
            self._record_phase(phase, elapsed, state_id, candidate_id, status="ok")

    def summary(self) -> dict[str, Any]:
        return {
            "phase_seconds": {key: round(float(value), 6) for key, value in self.phase_seconds.items()},
            "phase_counts": {key: int(value) for key, value in self.phase_counts.items()},
            "slowest_phases": sorted(self.slowest, key=lambda item: float(item.get("elapsed_seconds", 0.0)), reverse=True)[:20],
        }

    def _record_phase(self, phase: str, elapsed: float, state_id: str, candidate_id: str, *, status: str, error: str = "") -> None:
        self.phase_seconds[phase] += elapsed
        self.phase_counts[phase] += 1
        event = {
            "event": "phase_done",
            "sample_id": self.sample_id,
            "phase": phase,
            "state_id": state_id,
            "candidate_id": candidate_id,
            "elapsed_seconds": round(elapsed, 6),
            "status": status,
        }
        if error:
            event["error"] = error
        if elapsed >= self.slow_threshold or status != "ok":
            self.slowest.append(event)
            self._write_event(event)
        self.last_event = event

    def _event(self, event_name: str, *, phase: str, state_id: str, candidate_id: str) -> None:
        event = {
            "event": event_name,
            "sample_id": self.sample_id,
            "phase": phase,
            "state_id": state_id,
            "candidate_id": candidate_id,
            "time": round(time.time(), 3),
        }
        self.last_event = event
        self._write_event(event)

    def _write_event(self, event: dict[str, Any]) -> None:
        if self.events_path is None:
            return
        try:
            self.events_path.parent.mkdir(parents=True, exist_ok=True)
            with self.events_path.open("a", encoding="utf-8") as handle:
                handle.write(json.dumps(event, ensure_ascii=False, sort_keys=True, default=str) + "\n")
        except OSError:
            pass


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
        self.loop_limits = RepairLoopLimits.from_config(self.repair_stage.config)
        self.path_filter = _load_path_filter(getattr(args, "path_filter_json", ""))
        self.rows: list[dict[str, Any]] = []
        self.state_counter = 0
        self.profiler = _CollectorProfiler(args, self.sample_id)
        self.explored_positive_actions = 0
        self.explored_negative_actions = 0

    def collect(self) -> list[dict[str, Any]]:
        shutil.rmtree(self.workspace, ignore_errors=True)
        self.workspace.mkdir(parents=True, exist_ok=True)
        self.output_root.mkdir(parents=True, exist_ok=True)
        with self.profiler.phase("sample_init"):
            root_task = _task_from_record(self.record)
        with self.profiler.phase("analysis_refresh", state_id=f"{self.sample_id}:root"):
            self.analysis_stage.refresh_task_analysis(root_task, phase_timer=self.profiler.phase, phase_prefix="analysis_refresh")
        frontier = [self._state(root_task, round_index=0, parent_action_row_id="", parent_candidate_id="")]
        expanded = 0
        for round_index in range(max(1, int(self.args.max_rounds or 1))):
            if not frontier or expanded >= int(self.args.max_states or 80):
                break
            next_frontier: list[dict[str, Any]] = []
            for state in frontier:
                if self._training_budget_satisfied():
                    break
                if expanded >= int(self.args.max_states or 80):
                    break
                expanded += 1
                next_frontier.extend(self._expand_state(state, round_index))
                if self._training_budget_satisfied():
                    break
            frontier = next_frontier[: max(1, int(self.args.max_states or 80))]
        with self.profiler.phase("backfill_returns"):
            _backfill_runtime_returns(self.rows, float(self.args.future_label_discount or 0.8))
        self._attach_profile_summary()
        return self.rows

    def _state(self, task: ArchiveTask, *, round_index: int, parent_action_row_id: str, parent_candidate_id: str) -> dict[str, Any]:
        self.state_counter += 1
        parent_path = list(getattr(task, "_runtime_graph_path_signatures", []) or [])
        return {
            "state_id": f"{self.sample_id}:s{self.state_counter}",
            "task": task,
            "round": int(round_index),
            "parent_action_row_id": parent_action_row_id,
            "parent_candidate_id": parent_candidate_id,
            "path_signatures": parent_path,
        }

    def _expand_state(self, state: dict[str, Any], round_index: int) -> list[dict[str, Any]]:
        task: ArchiveTask = state["task"]
        out_dir = self.output_root / _safe_name(str(state["state_id"]))
        with self.profiler.phase("extract_initial", state_id=str(state["state_id"])):
            extraction = self.extractor.extract(task, str(out_dir))
        with self.profiler.phase("write_extraction_knowledge", state_id=str(state["state_id"])):
            write_extraction_result(task, extraction, phase_timer=self.profiler.phase, phase_prefix="write_extraction")
        with self.profiler.phase("verify_initial", state_id=str(state["state_id"])):
            verification = self.verifier.verify(task, extraction, phase_timer=self.profiler.phase, phase_prefix="verify_initial")
            verification = RepairRuntimeTransitionEvaluator.normalize_transition_verification(extraction, verification)
        if verification.decision_hint == DECISION_ACCEPT:
            self._append_terminal_row(state, "complete", verification, task)
            return []
        if verification.decision_hint != DECISION_REPAIR:
            self._append_terminal_row(state, str(verification.decision_hint or verification.assessment_status or "terminal"), verification, task)
            return []
        loop_state = RepairLoopState(task, self.loop_limits)
        if not loop_state.can_attempt(trigger="verification"):
            self._append_terminal_row(state, str(loop_state.terminal_reason or "repair_loop_stopped"), verification, task)
            return []
        with self.profiler.phase("build_repair_job", state_id=str(state["state_id"])):
            job = self.repair_stage._job_from_verification_assessment(task, extraction, verification, phase_timer=self.profiler.phase, phase_prefix="build_repair_job")  # noqa: SLF001
        if job is None or self.repair_stage.scheduler is None:
            self._append_terminal_row(state, "no_repair_job", verification, task)
            return []
        with self.profiler.phase("generate_candidates", state_id=str(state["state_id"])):
            batch = self.repair_stage.scheduler.generate_repair_candidates(job)
        if batch.terminal_result is not None or not batch.candidates:
            terminal_status = "no_candidates"
            if batch.terminal_result is not None:
                terminal_status = str(getattr(batch.terminal_result, "status", "") or "repair_terminal")
            row = self._terminal_row_for_task(state, terminal_status, verification, task)
            row["debug_damage_flags"] = list(job.damage_flags or [])
            row["debug_job_format"] = job.format
            row["debug_route_evidence_flags"] = list((knowledge_view.repair_route_context(job.knowledge) or {}).get("route_evidence_flags") or [])
            if batch.terminal_result is not None:
                row["debug_repair_terminal_message"] = str(getattr(batch.terminal_result, "message", "") or "")
                row["debug_repair_terminal_diagnosis"] = dict(getattr(batch.terminal_result, "diagnosis", {}) or {})
            self.rows.append(row)
            return []
        with self.profiler.phase("materialize_candidates", state_id=str(state["state_id"])):
            candidates = self._runtime_candidates(batch.candidates)
        if not candidates:
            row = self._terminal_row_for_task(state, "no_materialized_candidates", verification, task)
            row["debug_candidate_count"] = len(batch.candidates)
            row["debug_damage_flags"] = list(job.damage_flags or [])
            self.rows.append(row)
            return []
        with self.profiler.phase("policy_payload_build", state_id=str(state["state_id"])):
            payloads = [policy_candidate_payload(job, candidate, index=index) for index, candidate in enumerate(candidates)]
        with self.profiler.phase("collect_state_prepare_query", state_id=str(state["state_id"])):
            query_id = f"{state['state_id']}:q"
            collision_count = _candidate_id_collision_count(payloads)
            candidate_set_hash = repair_trace.canonical_hash(_candidate_set_hash_input(payloads))
        with self.profiler.phase("collect_state_strategy_decision", state_id=str(state["state_id"])):
            strategy_decision = self._strategy_decision_for_state(state, payloads)
            selected_ids = set(strategy_decision.selected_candidate_ids)
            path_filter_active = strategy_decision.mode == "runtime_path_filter"
        next_states: list[dict[str, Any]] = []
        for rank, (candidate, payload) in enumerate(zip(candidates, payloads)):
            with self.profiler.phase("collect_state_candidate_id", state_id=str(state["state_id"])):
                candidate_id = str(payload.get("candidate_id") or "")
            if (path_filter_active and (not selected_ids or candidate_id not in selected_ids)) or (selected_ids and candidate_id not in selected_ids):
                with self.profiler.phase("collect_state_unexplored_row", state_id=str(state["state_id"]), candidate_id=candidate_id):
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
            with self.profiler.phase("collect_state_branch_setup", state_id=str(state["state_id"]), candidate_id=candidate_id):
                action_row_id = f"{query_id}|{rank}|{candidate_id}"
            with self.profiler.phase("collect_state_clone_task", state_id=str(state["state_id"]), candidate_id=candidate_id):
                branch_task = clone_archive_task(task, key_suffix=f":{rank}")
            with self.profiler.phase("collect_state_loop_state_init", state_id=str(state["state_id"]), candidate_id=candidate_id):
                branch_loop_state = RepairLoopState(branch_task, self.loop_limits)
            with self.profiler.phase("transition_evaluate", state_id=str(state["state_id"]), candidate_id=candidate_id):
                transition = self.evaluator.evaluate(
                    branch_task,
                    candidate,
                    temp_dir=self.output_root / f"{_safe_name(str(state['state_id']))}_cand_{rank:02d}",
                    restore=False,
                    refresh_analysis=True,
                    record_repair_history=True,
                    phase_timer=self.profiler.phase,
                    state_id=str(state["state_id"]),
                    candidate_id=candidate_id,
                )
            with self.profiler.phase("collect_state_repair_result", state_id=str(state["state_id"]), candidate_id=candidate_id):
                repair_result = candidate.to_result(selection={"selected_candidate_id": candidate_id, "strategy": "training_exhaustive"})
            with self.profiler.phase("collect_state_loop_record_result", state_id=str(state["state_id"]), candidate_id=candidate_id):
                loop_allows_continue = branch_loop_state.record_result(
                    repair_result,
                    trigger="verification_training",
                    phase_timer=self.profiler.phase,
                    phase_prefix="collect_state_loop_record_result",
                )
            with self.profiler.phase("collect_state_archive_path_for_oracle", state_id=str(state["state_id"]), candidate_id=candidate_id):
                archive_path = _archive_path_for_oracle(branch_task, self.fmt)
            with self.profiler.phase("oracle_verify", state_id=str(state["state_id"]), candidate_id=candidate_id):
                oracle = _verify_output_against_oracle(Path(archive_path), self.fmt, self.record.get("oracle") if isinstance(self.record.get("oracle"), dict) else {}) if archive_path else {"status": "missing_output", "label": 0, "completeness": 0.0}
            with self.profiler.phase("collect_state_terminal_status", state_id=str(state["state_id"]), candidate_id=candidate_id):
                terminal_status = _transition_terminal_status(transition, oracle)
                if bool(transition.can_continue_repair) and not loop_allows_continue:
                    terminal_status = str(branch_loop_state.terminal_reason or "repair_loop_stopped")
                self._record_explored_label(oracle)
            child_state = None
            with self.profiler.phase("collect_state_child_state", state_id=str(state["state_id"]), candidate_id=candidate_id):
                if bool(transition.can_continue_repair) and loop_allows_continue and round_index + 1 < int(self.args.max_rounds or 1):
                    setattr(branch_task, "_runtime_graph_path_signatures", [*list(state.get("path_signatures") or []), _candidate_signature(payload)])
                    child_state = self._state(
                        branch_task,
                        round_index=round_index + 1,
                        parent_action_row_id=action_row_id,
                        parent_candidate_id=candidate_id,
                    )
                next_state_id = str(child_state.get("state_id") or "") if child_state is not None else ""
            with self.profiler.phase("collect_state_build_action_row", state_id=str(state["state_id"]), candidate_id=candidate_id):
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
                    "next_state_id": next_state_id,
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
                        "done": not bool(transition.can_continue_repair and loop_allows_continue),
                        "next_state_id": next_state_id,
                        "terminal_reward": float(oracle.get("completeness", 0.0) or 0.0),
                        "future_return": float(oracle.get("completeness", 0.0) or 0.0),
                        "single_path_robust_return": float(oracle.get("completeness", 0.0) or 0.0),
                    },
                }
            with self.profiler.phase("collect_state_append_action_row", state_id=str(state["state_id"]), candidate_id=candidate_id):
                self.rows.append(row)
            with self.profiler.phase("collect_state_append_child_state", state_id=str(state["state_id"]), candidate_id=candidate_id):
                if child_state is not None:
                    next_states.append(child_state)
        return next_states[: max(1, int(self.args.branch_top_k or 1))]

    def _strategy_decision_for_state(self, state: dict[str, Any], payloads: list[dict[str, Any]]) -> RepairRuntimeStrategyDecision:
        path = list(state.get("path_signatures") or [])
        target_path = self.path_filter.get(self.sample_id) if isinstance(self.path_filter, dict) else None
        if isinstance(target_path, list):
            if path != target_path[: len(path)]:
                return RepairRuntimeStrategyDecision(
                    mode="runtime_path_filter",
                    selected_candidate_ids=[],
                    metadata={"state_id": state.get("state_id"), "reason": "path_prefix_mismatch", "path": path},
                )
            if len(path) >= len(target_path):
                return RepairRuntimeStrategyDecision(
                    mode="runtime_path_filter",
                    selected_candidate_ids=[],
                    metadata={"state_id": state.get("state_id"), "reason": "path_complete", "path": path},
                )
            target_signature = str(target_path[len(path)] or "")
            selected = [
                str(payload.get("candidate_id") or "")
                for payload in payloads
                if _candidate_signature(payload) == target_signature and str(payload.get("candidate_id") or "")
            ]
            return RepairRuntimeStrategyDecision(
                mode="runtime_path_filter",
                selected_candidate_ids=selected[:1],
                metadata={
                    "state_id": state.get("state_id"),
                    "target_signature": target_signature,
                    "matched": bool(selected),
                    "path": path,
                },
            )
        decision = self.strategy.choose(state_id=str(state["state_id"]), candidate_payloads=payloads, context={"sample_id": self.sample_id})
        target_negatives = max(0, int(getattr(self.args, "target_negative_per_positive", 3) or 0))
        extra = max(0, int(getattr(self.args, "hard_negative_backfill_k", 0) or 0))
        if self.explored_positive_actions >= 1 and self.explored_negative_actions < target_negatives:
            extra = max(extra, len(payloads))
        if extra <= 0 or not payloads:
            return decision
        selected = [str(item) for item in decision.selected_candidate_ids if str(item)]
        selected_set = set(selected)
        tail: list[str] = []
        for payload in reversed(payloads):
            candidate_id = str(payload.get("candidate_id") or "")
            if not candidate_id or candidate_id in selected_set:
                continue
            tail.append(candidate_id)
            selected_set.add(candidate_id)
            if len(tail) >= extra:
                break
        if not tail:
            return decision
        metadata = dict(decision.metadata or {})
        metadata["hard_negative_backfill_k"] = extra
        metadata["hard_negative_backfill_selected"] = len(tail)
        return RepairRuntimeStrategyDecision(
            mode=f"{decision.mode}+hard_negative_backfill",
            selected_candidate_ids=[*selected, *tail],
            beam_enabled=decision.beam_enabled,
            metadata=metadata,
        )

    def _terminal_row_for_task(self, state: dict[str, Any], status: str, verification, task: ArchiveTask) -> dict[str, Any]:
        oracle = None
        with self.profiler.phase("terminal_oracle_verify", state_id=str(state.get("state_id") or "")):
            archive_path = _archive_path_for_oracle(task, self.fmt)
            if archive_path:
                oracle = _verify_output_against_oracle(
                    Path(archive_path),
                    self.fmt,
                    self.record.get("oracle") if isinstance(self.record.get("oracle"), dict) else {},
                )
        return _terminal_row(self.record, state, status, verification, oracle=oracle)

    def _append_terminal_row(self, state: dict[str, Any], status: str, verification, task: ArchiveTask) -> None:
        self.rows.append(self._terminal_row_for_task(state, status, verification, task))

    def _record_explored_label(self, oracle: dict[str, Any]) -> None:
        recovery = float(oracle.get("completeness", 0.0) or 0.0)
        label = int(oracle.get("label", 0) or 0)
        if label >= 3 or recovery >= 0.999:
            self.explored_positive_actions += 1
        else:
            self.explored_negative_actions += 1

    def _training_budget_satisfied(self) -> bool:
        if not bool(getattr(self.args, "stop_after_complete_with_negatives", True)):
            return False
        target = max(0, int(getattr(self.args, "target_negative_per_positive", 3) or 0))
        if self.explored_positive_actions >= 1 and self.explored_negative_actions >= target:
            return True
        positive_cap = max(0, int(getattr(self.args, "max_positive_actions_per_sample", 4) or 0))
        return bool(positive_cap > 0 and self.explored_positive_actions >= positive_cap)

    def _runtime_candidates(self, candidates):
        materialized = materialize_candidates(list(candidates))
        validated = [self.selector._with_native_validation(candidate) for candidate in materialized]  # noqa: SLF001
        accepted = [candidate for candidate in validated if self.selector._accepted(candidate)]  # noqa: SLF001
        accepted.sort(key=self.selector.generation_priority, reverse=True)
        return accepted

    def _attach_profile_summary(self) -> None:
        if not self.rows:
            return
        summary = self.profiler.summary()
        if self.rows:
            self.rows[0]["collector_phase_seconds"] = dict(summary.get("phase_seconds") or {})
            self.rows[0]["collector_phase_counts"] = dict(summary.get("phase_counts") or {})
            self.rows[0]["collector_slowest_phases"] = list(summary.get("slowest_phases") or [])
            self.rows[0]["knowledge_projection_cache_stats"] = knowledge_view.projection_cache_stats()


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
    # Terminal/continue status must match production runtime. Oracle is only a
    # post-transition label/reward and must not decide whether a branch stops.
    if transition.accepted_complete:
        return "complete"
    if transition.accepted_partial:
        return "verification_accept_partial"
    if transition.can_continue_repair:
        return "continue"
    return str(transition.terminal_reason or "terminal")


def _terminal_row(record: dict[str, Any], state: dict[str, Any], status: str, verification, *, oracle: dict[str, Any] | None = None) -> dict[str, Any]:
    oracle = oracle if isinstance(oracle, dict) else None
    recovery = float((oracle or {}).get("completeness", getattr(verification, "completeness", 0.0)) or 0.0)
    label = int((oracle or {}).get("label", 3 if recovery >= 0.999 else (1 if recovery > 0 else 0)) or 0)
    label_status = str((oracle or {}).get("status") or status or "")
    row = {
        "row_type": "terminal",
        "collector": "runtime_repair_graph",
        "sample_id": record.get("sample_id"),
        "episode_id": record.get("sample_id"),
        "state_id": state.get("state_id"),
        "round": state.get("round"),
        "terminal_status": status,
        "material_format": _record_format(record),
        "runtime_verification": _verification_payload(verification),
        "label": label,
        "label_status": label_status,
        "recovery_ratio": recovery,
        "terminal_recovery_ratio": recovery,
        "terminal_recovery_ratio_source": "oracle" if oracle is not None else "runtime_verification",
        "rl": {
            "reward": recovery,
            "done": True,
            "terminal_reward": recovery,
            "future_return": recovery,
            "single_path_robust_return": recovery,
        },
    }
    if oracle is not None:
        row["terminal_oracle"] = {
            key: value
            for key, value in oracle.items()
            if key
            in {
                "status",
                "label",
                "completeness",
                "matched_files",
                "wrong_files",
                "unreadable_files",
                "entry_count",
                "expected_files",
            }
        }
    return row


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
        "parent_action_row_id": state.get("parent_action_row_id") or "",
        "parent_candidate_id": state.get("parent_candidate_id") or "",
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


def _candidate_signature(candidate: dict[str, Any]) -> str:
    if not isinstance(candidate, dict) or not candidate:
        return ""
    proposal = candidate.get("candidate_proposal") if isinstance(candidate.get("candidate_proposal"), dict) else {}
    validation = proposal.get("validation_details") if isinstance(proposal.get("validation_details"), dict) else candidate.get("validation_details")
    policy = validation.get("policy") if isinstance(validation, dict) else ""
    facts = proposal.get("patch_facts") or candidate.get("patch_facts") or []
    return "|".join([
        str(candidate.get("module_name") or candidate.get("module") or ""),
        str(candidate.get("repair_name") or ""),
        str(candidate.get("native_target") or ""),
        str(policy or ""),
        ",".join(str(item) for item in facts or []),
    ])


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


def _load_path_filter(path: str) -> dict[str, list[str]]:
    if not path:
        return {}
    item = Path(str(path))
    if not item.is_file():
        return {}
    try:
        payload = json.loads(item.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return {}
    if not isinstance(payload, dict):
        return {}
    output: dict[str, list[str]] = {}
    for sample_id, values in payload.items():
        if isinstance(values, list):
            output[str(sample_id)] = [str(value) for value in values if str(value)]
    return output


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
        phase_seconds = row.get("collector_phase_seconds") if isinstance(row.get("collector_phase_seconds"), dict) else {}
        phase_counts = row.get("collector_phase_counts") if isinstance(row.get("collector_phase_counts"), dict) else {}
        if phase_seconds:
            summary.setdefault("phase_seconds", {})
            for phase, seconds in phase_seconds.items():
                summary["phase_seconds"][phase] = round(float(summary["phase_seconds"].get(phase, 0.0) or 0.0) + float(seconds or 0.0), 6)
        if phase_counts:
            summary.setdefault("phase_counts", {})
            for phase, count in phase_counts.items():
                summary["phase_counts"][phase] = int(summary["phase_counts"].get(phase, 0) or 0) + int(count or 0)
        slowest = row.get("collector_slowest_phases") if isinstance(row.get("collector_slowest_phases"), list) else []
        if slowest:
            summary.setdefault("slowest_states", [])
            summary["slowest_states"].extend(item for item in slowest if isinstance(item, dict))
            summary["slowest_states"] = sorted(summary["slowest_states"], key=lambda item: float(item.get("elapsed_seconds", 0.0) or 0.0), reverse=True)[:50]
        projection_stats = row.get("knowledge_projection_cache_stats") if isinstance(row.get("knowledge_projection_cache_stats"), dict) else {}
        if projection_stats:
            _merge_projection_cache_stats(summary, projection_stats)


def _last_jsonl_event(path: Path) -> dict[str, Any]:
    if not path.is_file():
        return {}
    last = ""
    try:
        with path.open("r", encoding="utf-8") as handle:
            for line in handle:
                if line.strip():
                    last = line
    except OSError:
        return {}
    if not last:
        return {}
    try:
        value = json.loads(last)
    except json.JSONDecodeError:
        return {}
    return dict(value) if isinstance(value, dict) else {}


def _merge_projection_cache_stats(summary: dict[str, Any], stats: dict[str, Any]) -> None:
    target = summary.setdefault("knowledge_projection_cache_stats", {"entries": 0, "max_entries": 0, "hits": 0, "misses": 0, "by_projection": {}})
    target["entries"] = max(int(target.get("entries", 0) or 0), int(stats.get("entries", 0) or 0))
    target["max_entries"] = max(int(target.get("max_entries", 0) or 0), int(stats.get("max_entries", 0) or 0))
    target["hits"] = int(target.get("hits", 0) or 0) + int(stats.get("hits", 0) or 0)
    target["misses"] = int(target.get("misses", 0) or 0) + int(stats.get("misses", 0) or 0)
    by_projection = target.setdefault("by_projection", {})
    for name, payload in (stats.get("by_projection") or {}).items():
        if not isinstance(payload, dict):
            continue
        current = by_projection.setdefault(str(name), {"hits": 0, "misses": 0})
        current["hits"] = int(current.get("hits", 0) or 0) + int(payload.get("hits", 0) or 0)
        current["misses"] = int(current.get("misses", 0) or 0) + int(payload.get("misses", 0) or 0)


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
