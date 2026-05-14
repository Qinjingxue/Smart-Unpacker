from __future__ import annotations

import argparse
import faulthandler
import datetime as _dt
import json
import multiprocessing as mp
import os
import shutil
import subprocess
import sys
import time
import zlib
from contextlib import contextmanager
from concurrent.futures import ThreadPoolExecutor, as_completed
from collections import Counter, defaultdict
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parents[2]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from repair_training.core.plugin import load_training_format_plugin, normalize_format_name  # noqa: E402
from repair_training.core.run_layout import (  # noqa: E402
    create_or_resolve_run_dir,
    ensure_run_layout,
    safe_name,
    update_run_manifest,
    write_latest_run,
)
from repair_training.core.material_records import attach_split_volumes  # noqa: E402
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
from sunpack.repair.control_candidates import with_accept_current_state_candidate  # noqa: E402
from sunpack.repair.policy.runtime_features import FEATURE_CONTRACT_VERSION, policy_candidate_payload, policy_candidate_payloads  # noqa: E402
from sunpack.support import archive_knowledge_projection as knowledge_view  # noqa: E402
from sunpack.support import repair_trace  # noqa: E402
from sunpack.support.archive_knowledge_writer import (  # noqa: E402
    commit_task_knowledge,
    ensure_knowledge,
    write_flags,
    write_payload,
)
from sunpack.support.path_names import clean_relative_archive_path, normalize_match_path  # noqa: E402
from sunpack.verification import VerificationScheduler  # noqa: E402
from sunpack.verification.result import DECISION_ACCEPT, DECISION_REPAIR  # noqa: E402


DEFAULT_MANIFEST = Path("repair_training") / "tmp" / "corpus" / "repair_plan_manifest.jsonl"
DEFAULT_RUN_NAME = "runtime_graph"


def main(argv: list[str] | None = None) -> int:
    args = _parser().parse_args(argv)
    args.format = normalize_format_name(getattr(args, "format", "") or getattr(args, "formats", "") or "zip")
    plugin = load_training_format_plugin(args.format)
    _apply_plugin_defaults(args, plugin)
    run = _configure_run_paths(args)
    records = _load_manifest(Path(args.manifest), args)
    Path(args.success_output).parent.mkdir(parents=True, exist_ok=True)
    Path(args.failure_output).parent.mkdir(parents=True, exist_ok=True)
    Path(args.summary_output).parent.mkdir(parents=True, exist_ok=True)
    if args.debug_events_output:
        Path(args.debug_events_output).parent.mkdir(parents=True, exist_ok=True)
    _write_run_manifest(run, args, status="running", records=len(records), started_at=_now_iso())
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
    try:
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
        write_latest_run(args.format, run["run_dir"])
        _write_run_manifest(
            run,
            args,
            status="ok",
            records=len(records),
            started_at=run["started_at"],
            ended_at=_now_iso(),
            summary=summary,
        )
        if not bool(getattr(args, "skip_analysis_report", False)):
            _run_post_collection_analysis(run["run_dir"])
        print(json.dumps(summary, ensure_ascii=False, sort_keys=True))
        return 0
    except Exception as exc:
        _write_run_manifest(
            run,
            args,
            status="failed",
            records=len(records),
            started_at=run["started_at"],
            ended_at=_now_iso(),
            error=str(exc),
        )
        raise
    finally:
        if run.get("managed_workspace") and not bool(getattr(args, "keep_temp", False)):
            _fast_rmtree(Path(args.workspace))


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Collect runtime-aligned repair graph rows by executing the real repair loop in exploration mode.")
    parser.add_argument("--format", default="zip", help="Training format plugin to use, e.g. zip.")
    parser.add_argument("--run-dir", default="", help="Training run directory. Defaults to repair_training/runs/<date>_<run-name>.")
    parser.add_argument("--run-name", default=DEFAULT_RUN_NAME, help="Suffix used when auto-creating --run-dir.")
    parser.add_argument("--keep-temp", action="store_true", help="Keep run tmp/workspace after collection for debugging.")
    parser.add_argument("--manifest", default="")
    parser.add_argument("--material-root", default=str(Path("repair_training") / "material"))
    parser.add_argument("--formats", default="zip")
    parser.add_argument("--sample", default="")
    parser.add_argument("--limit", type=int, default=0)
    parser.add_argument("--success-output", default="")
    parser.add_argument("--failure-output", default="")
    parser.add_argument("--summary-output", default="")
    parser.add_argument("--workspace", default="")
    parser.add_argument("--workers", type=int, default=6)
    parser.add_argument("--max-rounds", type=int, default=6)
    parser.add_argument("--max-states", type=int, default=20)
    parser.add_argument("--branch-top-k", type=int, default=5)
    parser.add_argument("--root-branch-top-k", type=int, default=5)
    parser.add_argument("--root-complete-explore-all", action="store_true", default=True)
    parser.add_argument("--no-root-complete-explore-all", dest="root_complete_explore_all", action="store_false")
    parser.add_argument("--materialize-top-k", type=int, default=8)
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
    parser.add_argument("--skip-analysis-report", action="store_true", help="Do not run collection analysis after a successful collection.")
    return parser


def _apply_plugin_defaults(args: argparse.Namespace, plugin: Any) -> None:
    args.formats = args.format
    if not str(args.run_name or "").strip() or args.run_name == DEFAULT_RUN_NAME:
        args.run_name = str(plugin.default_run_name or DEFAULT_RUN_NAME)
    budget = getattr(plugin, "default_collection_budget", {}) or {}
    if "workers" in budget and int(getattr(args, "workers", 0) or 0) == 6:
        args.workers = int(budget["workers"])
    if "max_rounds" in budget and int(getattr(args, "max_rounds", 0) or 0) == 6:
        args.max_rounds = int(budget["max_rounds"])
    if "max_states" in budget and int(getattr(args, "max_states", 0) or 0) == 20:
        args.max_states = int(budget["max_states"])
    if "branch_top_k" in budget and int(getattr(args, "branch_top_k", 0) or 0) == 5:
        args.branch_top_k = int(budget["branch_top_k"])
    if "root_branch_top_k" in budget and int(getattr(args, "root_branch_top_k", 0) or 0) == 5:
        args.root_branch_top_k = int(budget["root_branch_top_k"])
    if "materialize_top_k" in budget and int(getattr(args, "materialize_top_k", 0) or 0) == 8:
        args.materialize_top_k = int(budget["materialize_top_k"])


def _configure_run_paths(args: argparse.Namespace) -> dict[str, Any]:
    started_at = _now_iso()
    run_dir = create_or_resolve_run_dir(format_name=args.format, run_name=str(args.run_name or DEFAULT_RUN_NAME), run_dir=args.run_dir)
    layout = ensure_run_layout(run_dir)
    datasets_dir = layout["datasets_dir"]
    logs_dir = layout["logs_dir"]
    tmp_dir = layout["tmp_dir"]
    managed_workspace = not bool(str(args.workspace or "").strip())
    if not args.success_output:
        args.success_output = str(datasets_dir / "runtime_graph_success.jsonl")
    if not args.failure_output:
        args.failure_output = str(datasets_dir / "runtime_graph_failure.jsonl")
    if not args.summary_output:
        args.summary_output = str(datasets_dir / "runtime_graph_summary.json")
    if not args.debug_events_output:
        args.debug_events_output = str(logs_dir / "debug_events.jsonl")
    if not args.workspace:
        args.workspace = str(tmp_dir / "workspace")
    args.run_dir = str(run_dir)
    return {
        "run_dir": run_dir,
        "datasets_dir": datasets_dir,
        "logs_dir": logs_dir,
        "tmp_dir": tmp_dir,
        "managed_workspace": managed_workspace,
        "started_at": started_at,
    }


def _fast_rmtree(path: Path) -> None:
    target = Path(path)
    if not target.exists():
        return
    if os.name == "nt":
        try:
            subprocess.run(
                [
                    "powershell",
                    "-NoProfile",
                    "-NonInteractive",
                    "-Command",
                    "Remove-Item -LiteralPath $args[0] -Recurse -Force -ErrorAction Stop",
                    str(target),
                ],
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
                check=True,
            )
            return
        except Exception:
            pass
    shutil.rmtree(target, ignore_errors=True)


def _write_run_manifest(
    run: dict[str, Any],
    args: argparse.Namespace,
    *,
    status: str,
    records: int,
    started_at: str,
    ended_at: str = "",
    summary: dict[str, Any] | None = None,
    error: str = "",
) -> None:
    payload = {
        "status": status,
        "collector": "runtime_repair_graph",
        "started_at": started_at,
        "ended_at": ended_at,
        "record_count": records,
        "run_dir": str(run["run_dir"]),
        "git_commit": _git_commit(),
        "inputs": {
            "manifest": str(args.manifest or ""),
            "manifest_abs": str(Path(args.manifest).resolve()) if str(args.manifest or "").strip() else "",
            "material_distribution_report": str(_find_sibling_material_report(Path(args.manifest)) or "") if str(args.manifest or "").strip() else "",
            "material_root": str(args.material_root or ""),
            "format": str(args.format or ""),
            "formats": str(args.formats or ""),
            "sample": str(args.sample or ""),
            "limit": int(args.limit or 0),
        },
        "outputs": {
            "success_output": str(args.success_output),
            "failure_output": str(args.failure_output),
            "summary_output": str(args.summary_output),
            "debug_events_output": str(args.debug_events_output),
            "workspace": str(args.workspace),
        },
        "parameters": {
            "workers": int(args.workers or 1),
            "max_rounds": int(args.max_rounds or 0),
            "max_states": int(args.max_states or 0),
            "branch_top_k": int(args.branch_top_k or 0),
            "root_branch_top_k": int(args.root_branch_top_k or 0),
            "materialize_top_k": int(args.materialize_top_k or 0),
            "case_timeout_seconds": float(args.case_timeout_seconds or 0.0),
            "future_label_discount": float(args.future_label_discount or 0.0),
        },
        "summary": summary or {},
    }
    if error:
        payload["error"] = error
    Path(run["run_dir"], "run_manifest.json").write_text(json.dumps(payload, ensure_ascii=False, indent=2, sort_keys=True), encoding="utf-8")


def _run_post_collection_analysis(run_dir: Path) -> None:
    try:
        format_name = _format_from_run_manifest(run_dir)
        plugin = load_training_format_plugin(format_name)
        if plugin.analyze_collection:
            code = plugin.analyze_collection(Path(run_dir))
            if code not in (None, 0):
                raise RuntimeError(f"collection analysis failed with exit code {code}")
    except Exception as exc:
        update_run_manifest(Path(run_dir), collection_analysis={"status": "failed", "error": str(exc)})


def _find_sibling_material_report(manifest: Path) -> Path | None:
    try:
        manifest = manifest.resolve()
    except Exception:
        manifest = Path(manifest)
    if not manifest.is_file():
        return None
    candidates = sorted(manifest.parent.glob("material_distribution_report*.json"))
    return candidates[0].resolve() if candidates else None


def _format_from_run_manifest(run_dir: Path) -> str:
    path = Path(run_dir) / "run_manifest.json"
    if path.is_file():
        try:
            payload = json.loads(path.read_text(encoding="utf-8"))
            value = str(payload.get("inputs", {}).get("format") or payload.get("format") or "").strip()
            if value:
                return normalize_format_name(value)
        except Exception:
            pass
    parent = Path(run_dir).parent.name
    return normalize_format_name(parent or "zip")


def _merge_run_manifest(run_dir: Path, update: dict[str, Any]) -> None:
    path = Path(run_dir) / "run_manifest.json"
    payload: dict[str, Any] = {}
    if path.is_file():
        try:
            loaded = json.loads(path.read_text(encoding="utf-8"))
            payload = loaded if isinstance(loaded, dict) else {}
        except Exception:
            payload = {}
    payload.update(update)
    path.write_text(json.dumps(payload, ensure_ascii=False, indent=2, sort_keys=True), encoding="utf-8")


def _git_commit() -> str:
    try:
        return subprocess.check_output(["git", "rev-parse", "HEAD"], cwd=ROOT, text=True, stderr=subprocess.DEVNULL).strip()
    except Exception:
        return ""


def _now_iso() -> str:
    return _dt.datetime.now(_dt.timezone.utc).astimezone().isoformat(timespec="seconds")


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
    result_dir = Path(str(args_dict.get("workspace") or "repair_training/tmp/runtime-repair-graph")) / ".worker_results"
    result_dir.mkdir(parents=True, exist_ok=True)
    result_path = result_dir / f"sample_{index:06d}_{os.getpid()}_{time.time_ns()}.json"
    sample_id = str(record.get("sample_id") or f"sample_{index}")
    debug_dir = Path(str(args_dict.get("workspace") or "repair_training/tmp/runtime-repair-graph")) / ".debug_events"
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
            extraction_config={"write_progress_manifest": True, "quiet": True},
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
        _fast_rmtree(self.workspace)
        self.workspace.mkdir(parents=True, exist_ok=True)
        self.output_root.mkdir(parents=True, exist_ok=True)
        with self.profiler.phase("sample_init"):
            root_task = _task_from_record(self.record)
        with self.profiler.phase("analysis_refresh", state_id=f"{self.sample_id}:root"):
            self.analysis_stage.refresh_task_analysis(root_task, phase_timer=self.profiler.phase, phase_prefix="analysis_refresh")
        frontier = [self._state(root_task, round_index=0, parent_action_row_id="", parent_candidate_id="", parent_state_id="")]
        expanded = 0
        for round_index in range(max(1, int(self.args.max_rounds or 1))):
            if not frontier or expanded >= int(self.args.max_states or 80):
                break
            next_frontier: list[dict[str, Any]] = []
            for state in frontier:
                if round_index > 0 and self._training_budget_satisfied():
                    break
                if expanded >= int(self.args.max_states or 80):
                    break
                expanded += 1
                next_frontier.extend(self._expand_state(state, round_index))
                if round_index > 0 and self._training_budget_satisfied():
                    break
            frontier = next_frontier[: max(1, int(self.args.max_states or 80))]
        with self.profiler.phase("backfill_returns"):
            _backfill_runtime_returns(self.rows, float(self.args.future_label_discount or 0.8))
        self._attach_profile_summary()
        return self.rows

    def _state(
        self,
        task: ArchiveTask,
        *,
        round_index: int,
        parent_action_row_id: str,
        parent_candidate_id: str,
        parent_state_id: str,
        root_state_id: str = "",
        root_candidate_id: str = "",
        root_candidate_rank: int | None = None,
        path_candidate_ids: list[str] | None = None,
    ) -> dict[str, Any]:
        self.state_counter += 1
        state_id = f"{self.sample_id}:s{self.state_counter}"
        parent_path = list(getattr(task, "_runtime_graph_path_signatures", []) or [])
        candidate_path = list(path_candidate_ids or [])
        return {
            "state_id": state_id,
            "task": task,
            "round": int(round_index),
            "parent_action_row_id": parent_action_row_id,
            "parent_candidate_id": parent_candidate_id,
            "parent_state_id": parent_state_id,
            "root_state_id": root_state_id or state_id,
            "root_candidate_id": root_candidate_id,
            "root_candidate_rank": root_candidate_rank,
            "path_signatures": parent_path,
            "path_candidate_ids": candidate_path,
        }

    def _expand_state(self, state: dict[str, Any], round_index: int) -> list[dict[str, Any]]:
        task: ArchiveTask = state["task"]
        out_dir = self.output_root / _safe_name(str(state["state_id"]))
        with self.profiler.phase("extract_initial", state_id=str(state["state_id"])):
            extraction = self.extractor.extract(task, str(out_dir))
            state["_extraction_result"] = extraction
        with self.profiler.phase("write_extraction_knowledge", state_id=str(state["state_id"])):
            write_extraction_result(task, extraction, phase_timer=self.profiler.phase, phase_prefix="write_extraction")
        with self.profiler.phase("verify_initial", state_id=str(state["state_id"])):
            verification = self.verifier.verify(task, extraction, phase_timer=self.profiler.phase, phase_prefix="verify_initial")
            verification = RepairRuntimeTransitionEvaluator.normalize_transition_verification(extraction, verification)
        if verification.decision_hint == DECISION_ACCEPT:
            self._append_terminal_row(state, "complete", verification, task, extraction)
            return []
        if verification.decision_hint != DECISION_REPAIR:
            self._append_terminal_row(state, str(verification.decision_hint or verification.assessment_status or "terminal"), verification, task, extraction)
            return []
        loop_state = RepairLoopState(task, self.loop_limits)
        if not loop_state.can_attempt(trigger="verification"):
            self._append_terminal_row(state, str(loop_state.terminal_reason or "repair_loop_stopped"), verification, task, extraction)
            return []
        with self.profiler.phase("build_repair_job", state_id=str(state["state_id"])):
            job = self.repair_stage._job_from_verification_assessment(task, extraction, verification, phase_timer=self.profiler.phase, phase_prefix="build_repair_job")  # noqa: SLF001
        if job is None or self.repair_stage.scheduler is None:
            self._append_terminal_row(state, "no_repair_job", verification, task, extraction)
            return []
        with self.profiler.phase("generate_candidates", state_id=str(state["state_id"])):
            batch = self.repair_stage.scheduler.generate_repair_candidates(
                job,
                phase_timer=self.profiler.phase,
                phase_prefix="generate_candidates",
            )
        candidate_source = list(batch.candidates or [])
        with self.profiler.phase("materialize_candidates", state_id=str(state["state_id"])):
            candidates = self._runtime_candidates(with_accept_current_state_candidate(candidate_source, job))
        if not candidates:
            row = self._terminal_row_for_task(state, "no_materialized_candidates", verification, task, extraction)
            row["debug_candidate_count"] = len(batch.candidates)
            row["debug_damage_flags"] = list(job.damage_flags or [])
            self.rows.append(row)
            return []
        with self.profiler.phase("policy_payload_build", state_id=str(state["state_id"])):
            payloads = policy_candidate_payloads(job, candidates)
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
            if _is_noop_payload(payload):
                with self.profiler.phase("collect_state_noop_fast_path", state_id=str(state["state_id"]), candidate_id=candidate_id):
                    self._append_noop_action_row(
                        state,
                        verification,
                        task,
                        query_id=query_id,
                        round_index=round_index,
                        rank=rank,
                        payload=payload,
                        candidate_id=candidate_id,
                        candidate_set_hash=candidate_set_hash,
                        collision_count=collision_count,
                        strategy_decision=strategy_decision,
                        selected_ids=selected_ids,
                    )
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
            with self.profiler.phase("oracle_verify", state_id=str(state["state_id"]), candidate_id=candidate_id):
                oracle = verify_extraction_output_against_oracle(
                    transition.result,
                    self.record.get("oracle") if isinstance(self.record.get("oracle"), dict) else {},
                    record=self.record,
                )
            with self.profiler.phase("collect_state_terminal_status", state_id=str(state["state_id"]), candidate_id=candidate_id):
                terminal_status = _transition_terminal_status(transition, oracle)
                if bool(transition.can_continue_repair) and not loop_allows_continue:
                    terminal_status = str(branch_loop_state.terminal_reason or "repair_loop_stopped")
                self._record_explored_label(oracle)
            child_state = None
            with self.profiler.phase("collect_state_child_state", state_id=str(state["state_id"]), candidate_id=candidate_id):
                if bool(transition.can_continue_repair) and loop_allows_continue and round_index + 1 < int(self.args.max_rounds or 1):
                    path_candidate_ids = [*list(state.get("path_candidate_ids") or []), candidate_id]
                    root_candidate_id = str(state.get("root_candidate_id") or "")
                    root_candidate_rank = state.get("root_candidate_rank")
                    if int(round_index) == 0:
                        root_candidate_id = candidate_id
                        root_candidate_rank = rank
                    setattr(branch_task, "_runtime_graph_path_signatures", [*list(state.get("path_signatures") or []), _candidate_signature(payload)])
                    child_state = self._state(
                        branch_task,
                        round_index=round_index + 1,
                        parent_action_row_id=action_row_id,
                        parent_candidate_id=candidate_id,
                        parent_state_id=str(state["state_id"]),
                        root_state_id=str(state.get("root_state_id") or state["state_id"]),
                        root_candidate_id=root_candidate_id,
                        root_candidate_rank=int(root_candidate_rank) if root_candidate_rank is not None else None,
                        path_candidate_ids=path_candidate_ids,
                    )
                next_state_id = str(child_state.get("state_id") or "") if child_state is not None else ""
                path_candidate_ids_for_row = [*list(state.get("path_candidate_ids") or []), candidate_id]
                root_candidate_id_for_row = str(state.get("root_candidate_id") or "")
                root_candidate_rank_for_row = state.get("root_candidate_rank")
                if int(round_index) == 0:
                    root_candidate_id_for_row = candidate_id
                    root_candidate_rank_for_row = rank
            with self.profiler.phase("collect_state_build_action_row", state_id=str(state["state_id"]), candidate_id=candidate_id):
                row = {
                    "row_type": "action",
                    "collector": "runtime_repair_graph",
                    "sample_id": self.sample_id,
                    "episode_id": self.sample_id,
                    "state_id": state["state_id"],
                    "root_state_id": state.get("root_state_id") or state["state_id"],
                    "parent_state_id": state.get("parent_state_id") or "",
                    "query_id": query_id,
                    "round": int(round_index),
                    "path_depth": int(round_index),
                    "action_row_id": action_row_id,
                    "candidate_id": candidate_id,
                    "path_candidate_ids": path_candidate_ids_for_row,
                    "root_candidate_id": root_candidate_id_for_row,
                    "root_candidate_rank": root_candidate_rank_for_row,
                    "root_action": int(round_index) == 0,
                    "candidate_id_collision_count": collision_count,
                    "candidate_set_hash": candidate_set_hash,
                    "strategy": strategy_decision.mode,
                    "strategy_selected_candidate_ids": list(strategy_decision.selected_candidate_ids),
                    "current_rank": rank,
                    "branchable": bool(payload.get("branchable", True)),
                    "explored": True,
                    "selected": candidate_id in selected_ids,
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
                    "child_state_id": next_state_id,
                    "parent_action_row_id": state.get("parent_action_row_id") or "",
                    "parent_candidate_id": state.get("parent_candidate_id") or "",
                    "runtime_verification": _verification_payload(transition.verification),
                    "oracle_ground_truth": _oracle_ground_truth_payload(oracle),
                    "runtime_oracle_disagreement_reason": _runtime_oracle_disagreement_reason(transition.verification, oracle),
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
                        "child_state_id": next_state_id,
                        "terminal_reward": float(oracle.get("completeness", 0.0) or 0.0),
                        "future_return": float(oracle.get("completeness", 0.0) or 0.0),
                        "single_path_robust_return": float(oracle.get("completeness", 0.0) or 0.0),
                        "sequence_terminal_status": terminal_status,
                        "sequence_repeated_action": "repeated_repair_action" in str(terminal_status).lower(),
                        "sequence_repeated_input": "repeated_repair_input" in str(terminal_status).lower(),
                        "sequence_no_candidate": "no_candidates" in str(terminal_status).lower() or "unrepairable" in str(terminal_status).lower(),
                        "sequence_zero_recovery": float(oracle.get("completeness", 0.0) or 0.0) <= 0.0,
                        "sequence_partial_regression": False,
                    },
                }
            with self.profiler.phase("collect_state_append_action_row", state_id=str(state["state_id"]), candidate_id=candidate_id):
                self.rows.append(row)
            with self.profiler.phase("collect_state_append_child_state", state_id=str(state["state_id"]), candidate_id=candidate_id):
                if child_state is not None:
                    next_states.append(child_state)
        return next_states[: self._state_frontier_limit(round_index)]

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
        if int(state.get("round", 0) or 0) == 0:
            limit = max(1, int(getattr(self.args, "root_branch_top_k", 5) or 5))
            selected = [
                str(item.get("candidate_id") or "")
                for item in list(payloads or [])[:limit]
                if str(item.get("candidate_id") or "")
            ]
            selected = _with_protected_noop_selection(selected, payloads)
            return RepairRuntimeStrategyDecision(
                mode="training_root_exhaustive",
                selected_candidate_ids=selected,
                beam_enabled=False,
                metadata={
                    "state_id": state.get("state_id"),
                    "candidate_count": len(payloads or []),
                    "root_branch_top_k": limit,
                    "root_complete_explore_all": bool(getattr(self.args, "root_complete_explore_all", True)),
                },
            )
        decision = self.strategy.choose(state_id=str(state["state_id"]), candidate_payloads=payloads, context={"sample_id": self.sample_id})
        decision = _decision_with_protected_noop(decision, payloads)
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

    def _state_frontier_limit(self, round_index: int) -> int:
        if int(round_index) == 0:
            return max(1, int(getattr(self.args, "root_branch_top_k", 5) or 5))
        return max(1, int(self.args.branch_top_k or 1))

    def _terminal_row_for_task(self, state: dict[str, Any], status: str, verification, task: ArchiveTask, extraction: Any | None = None) -> dict[str, Any]:
        oracle = None
        with self.profiler.phase("terminal_oracle_verify", state_id=str(state.get("state_id") or "")):
            extraction = extraction or state.get("_extraction_result")
            oracle = verify_extraction_output_against_oracle(
                extraction,
                self.record.get("oracle") if isinstance(self.record.get("oracle"), dict) else {},
                record=self.record,
            )
        return _terminal_row(self.record, state, status, verification, oracle=oracle)

    def _append_terminal_row(self, state: dict[str, Any], status: str, verification, task: ArchiveTask, extraction: Any | None = None) -> None:
        self.rows.append(self._terminal_row_for_task(state, status, verification, task, extraction))

    def _record_explored_label(self, oracle: dict[str, Any]) -> None:
        recovery = float(oracle.get("completeness", 0.0) or 0.0)
        label = int(oracle.get("label", 0) or 0)
        if label >= 3 or recovery >= 0.999:
            self.explored_positive_actions += 1
        else:
            self.explored_negative_actions += 1

    def _append_noop_action_row(
        self,
        state: dict[str, Any],
        verification,
        task: ArchiveTask,
        *,
        query_id: str,
        round_index: int,
        rank: int,
        payload: dict[str, Any],
        candidate_id: str,
        candidate_set_hash: str,
        collision_count: int,
        strategy_decision: RepairRuntimeStrategyDecision,
        selected_ids: set[str],
    ) -> None:
        with self.profiler.phase("collect_state_noop_oracle_verify", state_id=str(state["state_id"]), candidate_id=candidate_id):
            oracle = verify_extraction_output_against_oracle(
                state.get("_extraction_result"),
                self.record.get("oracle") if isinstance(self.record.get("oracle"), dict) else {},
                record=self.record,
            )
        with self.profiler.phase("collect_state_noop_build_row", state_id=str(state["state_id"]), candidate_id=candidate_id):
            self._record_explored_label(oracle)
            action_row_id = f"{query_id}|{rank}|{candidate_id}"
            path_candidate_ids_for_row = [*list(state.get("path_candidate_ids") or []), candidate_id]
            root_candidate_id_for_row = str(state.get("root_candidate_id") or "")
            root_candidate_rank_for_row = state.get("root_candidate_rank")
            if int(round_index) == 0:
                root_candidate_id_for_row = candidate_id
                root_candidate_rank_for_row = rank
            terminal_status = "repair_skipped"
            recovery = float(oracle.get("completeness", 0.0) or 0.0)
            row = {
                "row_type": "action",
                "collector": "runtime_repair_graph",
                "sample_id": self.sample_id,
                "episode_id": self.sample_id,
                "state_id": state["state_id"],
                "root_state_id": state.get("root_state_id") or state["state_id"],
                "parent_state_id": state.get("parent_state_id") or "",
                "query_id": query_id,
                "round": int(round_index),
                "path_depth": int(round_index),
                "action_row_id": action_row_id,
                "candidate_id": candidate_id,
                "path_candidate_ids": path_candidate_ids_for_row,
                "root_candidate_id": root_candidate_id_for_row,
                "root_candidate_rank": root_candidate_rank_for_row,
                "root_action": int(round_index) == 0,
                "candidate_id_collision_count": collision_count,
                "candidate_set_hash": candidate_set_hash,
                "strategy": strategy_decision.mode,
                "strategy_selected_candidate_ids": list(strategy_decision.selected_candidate_ids),
                "current_rank": rank,
                "branchable": False,
                "explored": True,
                "selected": candidate_id in selected_ids,
                "material_format": self.fmt,
                "module": payload.get("module_name") or payload.get("module"),
                "module_name": payload.get("module_name") or payload.get("module"),
                "repair_name": payload.get("repair_name"),
                "native_target": payload.get("native_target"),
                "candidate_status": payload.get("candidate_status"),
                "label": int(oracle.get("label", 0) or 0),
                "label_status": str(oracle.get("status") or ""),
                "recovery_ratio": recovery,
                "terminal_status": terminal_status,
                "next_state_id": "",
                "child_state_id": "",
                "parent_action_row_id": state.get("parent_action_row_id") or "",
                "parent_candidate_id": state.get("parent_candidate_id") or "",
                "runtime_verification": _verification_payload(verification),
                "oracle_ground_truth": _oracle_ground_truth_payload(oracle),
                "runtime_oracle_disagreement_reason": _runtime_oracle_disagreement_reason(verification, oracle),
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
                    "reward": recovery,
                    "done": True,
                    "next_state_id": "",
                    "child_state_id": "",
                    "terminal_reward": recovery,
                    "future_return": recovery,
                    "single_path_robust_return": recovery,
                    "sequence_terminal_status": terminal_status,
                    "sequence_repeated_action": False,
                    "sequence_repeated_input": False,
                    "sequence_no_candidate": False,
                    "sequence_zero_recovery": recovery <= 0.0,
                    "sequence_partial_regression": False,
                },
            }
        with self.profiler.phase("collect_state_noop_append_row", state_id=str(state["state_id"]), candidate_id=candidate_id):
            self.rows.append(row)

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
            "methods": [
                {"name": "extraction_exit_signal"},
                {"name": "archive_test_crc"},
            ],
            "max_retries": 0,
            "retry_on_verification_failure": True,
            "cleanup_failed_output": False,
            "accept_partial_when_source_damaged": True,
            "partial_accept_threshold": 0.2,
            "complete_accept_threshold": 0.999,
            "recovery_min_improvement": 0.01,
        },
        "output": {"root": str(workspace / "outputs")},
        "extraction": {"write_progress_manifest": True, "quiet": True},
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
    plugin = load_training_format_plugin(_record_format(record))
    context = plugin.collection_record_context(record) if plugin.collection_record_context else {}
    knowledge = ensure_knowledge(task)
    payloads = context.get("payloads") if isinstance(context.get("payloads"), dict) else {}
    flags = context.get("flags") if isinstance(context.get("flags"), dict) else {}
    for namespace, payload in payloads.items():
        if isinstance(payload, dict):
            write_payload(knowledge, str(namespace), payload, source_layer="training", source_module="runtime_graph")
    for namespace, values in flags.items():
        if values:
            write_flags(knowledge, str(namespace), values, source_layer="training", source_module="runtime_graph")
    commit_task_knowledge(task, knowledge)


def _attach_split_to_task(task: ArchiveTask, record: dict[str, Any]) -> None:
    source_input = dict(record.get("damaged_input") or {})
    password = _record_password(record)
    if password and not source_input.get("password"):
        source_input["password"] = password
    attach_split_volumes(source_input, record)
    part_items = [dict(item) for item in source_input.get("parts") or [] if isinstance(item, dict) and item.get("path")]
    parts = _dedupe([str(item.get("path") or "") for item in part_items if item.get("path")])
    main_path = str(task.main_path)
    if main_path and main_path not in parts and not bool(source_input.get("use_parts_only")):
        parts.append(main_path)
        part_items.append({"path": main_path, "start": 0, "end": None, "role": "main"})
    if len(parts) <= 1:
        if password and (source_input.get("path") or task.main_path):
            source_input.setdefault("kind", "file")
            source_input.setdefault("path", task.main_path)
            source_input.setdefault("format_hint", _record_format(record))
            task.set_archive_input(source_input)
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
        payload = {"kind": "concat_ranges", "ranges": ranges, "format_hint": _record_format(record), "path": main_path, "parts": part_items, "use_parts_only": bool(source_input.get("use_parts_only"))}
        if password:
            payload["password"] = password
        task.set_archive_input(payload)


def _record_password(record: dict[str, Any]) -> str | None:
    for value in (
        record.get("password"),
        (record.get("damaged_input") or {}).get("password") if isinstance(record.get("damaged_input"), dict) else None,
        (record.get("clean_input") or {}).get("password") if isinstance(record.get("clean_input"), dict) else None,
    ):
        text = str(value or "")
        if text:
            return text
    return None


def verify_extraction_output_against_oracle(extraction_result: Any, oracle: dict[str, Any], *, record: dict[str, Any] | None = None) -> dict[str, Any]:
    oracle = oracle if isinstance(oracle, dict) else {}
    record = record if isinstance(record, dict) else {}
    expected_files = oracle.get("expected_files") if isinstance(oracle.get("expected_files"), dict) else {}
    if expected_files:
        return _verify_expected_files_from_extraction(extraction_result, expected_files, record=record)
    expected_payload = oracle.get("expected_payload") if isinstance(oracle.get("expected_payload"), dict) else {}
    if expected_payload:
        return _verify_expected_payload_from_extraction(extraction_result, expected_payload, record=record)
    expected_bytes = oracle.get("expected_bytes") if isinstance(oracle.get("expected_bytes"), dict) else {}
    if expected_bytes:
        return _oracle_label_status(0, "missing_extraction_oracle_for_archive_bytes", 0.0, oracle_source="extraction_output")
    return _oracle_label_status(0, "no_oracle", 0.0, oracle_source="extraction_output")


def _verify_expected_files_from_extraction(extraction_result: Any, expected_files: dict[str, Any], *, record: dict[str, Any]) -> dict[str, Any]:
    output_items = _oracle_output_items(extraction_result)
    if not output_items:
        return {
            **_oracle_label_status(0, "missing_extraction_output", 0.0, oracle_source="extraction_output"),
            "expected_files": len(expected_files),
            "matched_files": 0,
            "complete_files": 0,
            "partial_files": 0,
            "failed_files": 0,
            "missing_files": len(expected_files),
            "expected_bytes": _expected_file_bytes(expected_files),
            "matched_bytes": 0,
            "complete_bytes": 0,
        }
    output_by_path: dict[str, tuple[dict[str, Any], dict[str, Any]]] = {}
    for item in output_items:
        paths = [item.get("archive_path") or item.get("path")]
        paths.extend(item.get("archive_path_aliases") or [])
        for raw_path in paths:
            key = normalize_match_path(raw_path)
            if not key:
                continue
            alias_meta = {}
            if key != normalize_match_path(item.get("archive_path") or item.get("path")):
                alias_meta = {
                    "oracle_path_alias_used": True,
                    "oracle_segment_prefix": item.get("oracle_segment_prefix") or "",
                    "oracle_output_manifest_source": item.get("oracle_output_manifest_source") or "top_manifest",
                }
            output_by_path.setdefault(key, (item, alias_meta))
    expected_count = 0
    expected_bytes = 0
    matched_files = 0
    complete_files = 0
    partial_files = 0
    failed_files = 0
    missing_files = 0
    matched_bytes = 0
    complete_bytes = 0
    zero_byte_expected = 0
    alias_used = False
    alias_prefixes: set[str] = set()
    manifest_sources: set[str] = set()
    for raw_name, raw_meta in expected_files.items():
        if not isinstance(raw_meta, dict):
            continue
        expected_count += 1
        expected_name = clean_relative_archive_path(raw_meta.get("name") or raw_name)
        expected_size = _safe_int(raw_meta.get("size"))
        expected_crc = _optional_crc32(raw_meta.get("crc32", raw_meta.get("crc")))
        has_crc = bool(raw_meta.get("has_crc", expected_crc is not None))
        if expected_size is not None:
            expected_bytes += max(0, expected_size)
            if expected_size == 0:
                zero_byte_expected += 1
        match = output_by_path.get(normalize_match_path(expected_name))
        if match is None:
            missing_files += 1
            continue
        item, alias_meta = match
        if alias_meta.get("oracle_path_alias_used"):
            alias_used = True
            if alias_meta.get("oracle_segment_prefix"):
                alias_prefixes.add(str(alias_meta.get("oracle_segment_prefix")))
            if alias_meta.get("oracle_output_manifest_source"):
                manifest_sources.add(str(alias_meta.get("oracle_output_manifest_source")))
        matched_files += 1
        actual_size = _safe_int(item.get("size", item.get("bytes_written")))
        actual_crc = _optional_crc32(item.get("crc32"))
        output_status = str(item.get("status") or "")
        size_ok = expected_size is None or actual_size == expected_size
        crc_ok = (not has_crc) or expected_crc is None or (actual_crc is not None and actual_crc == expected_crc)
        if expected_size is not None and actual_size is not None:
            matched_bytes += min(max(0, actual_size), max(0, expected_size))
        if output_status == "failed":
            failed_files += 1
        elif size_ok and crc_ok and actual_size is not None:
            complete_files += 1
            complete_bytes += max(0, actual_size if expected_size is None else expected_size)
        elif actual_size is not None and actual_size > 0 and (expected_size is None or actual_size < expected_size):
            partial_files += 1
        else:
            failed_files += 1
    file_coverage = complete_files / max(1, expected_count)
    byte_coverage = complete_bytes / max(1, expected_bytes) if expected_bytes > 0 else file_coverage
    completeness = min(1.0, max(0.0, (file_coverage + byte_coverage) / 2.0))
    status = "complete"
    label = 3
    if complete_files == expected_count and expected_count > 0 and completeness >= 0.999:
        status = "complete"
        label = 3
    elif complete_files > 0 or partial_files > 0 or matched_files > 0:
        status = "partial" if complete_files or partial_files else "hard_negative"
        label = 1 if complete_files or partial_files else -1
    else:
        status = "no_progress" if output_items else "missing_extraction_output"
        label = 0
    cap_reason = _oracle_completion_cap_reason(record, expected_bytes=expected_bytes, zero_byte_expected=zero_byte_expected, expected_count=expected_count, expected_files=expected_files)
    if cap_reason and label == 3:
        label = 1 if complete_files > 0 or matched_files > 0 else 0
        status = "partial" if label == 1 else "no_progress"
        completeness = min(completeness, 0.999)
    return {
        **_oracle_label_status(label, status, completeness, oracle_source="extraction_output"),
        "matched_files": matched_files,
        "complete_files": complete_files,
        "partial_files": partial_files,
        "failed_files": failed_files,
        "missing_files": missing_files,
        "wrong_files": failed_files,
        "unreadable_files": missing_files,
        "entry_count": len(output_items),
        "expected_files": expected_count,
        "expected_bytes": expected_bytes,
        "matched_bytes": matched_bytes,
        "complete_bytes": complete_bytes,
        **({"oracle_path_alias_used": True} if alias_used else {}),
        **({"oracle_segment_prefix": ",".join(sorted(alias_prefixes))} if alias_prefixes else {}),
        **({"oracle_output_manifest_source": ",".join(sorted(manifest_sources))} if manifest_sources else {}),
        **({"oracle_cap_reason": cap_reason} if cap_reason else {}),
    }


def _verify_expected_payload_from_extraction(extraction_result: Any, expected_payload: dict[str, Any], *, record: dict[str, Any]) -> dict[str, Any]:
    output_items = [item for item in _oracle_output_items(extraction_result) if Path(str(item.get("path") or "")).is_file()]
    if not output_items:
        return _oracle_label_status(0, "missing_extraction_output", 0.0, oracle_source="extraction_output")
    if len(output_items) != 1:
        return {**_oracle_label_status(1, "partial", 0.5, oracle_source="extraction_output"), "oracle_cap_reason": "expected_payload_multiple_outputs"}
    path = Path(str(output_items[0].get("path") or ""))
    data = path.read_bytes()
    expected_sha = str(expected_payload.get("sha256") or "")
    digest = _sha256_bytes(data)
    complete = bool(expected_sha and digest == expected_sha)
    expected_size = _safe_int(expected_payload.get("size")) or len(data)
    completeness = 1.0 if complete else min(1.0, len(data) / max(1, expected_size))
    cap_reason = _oracle_completion_cap_reason(record, expected_bytes=expected_size, zero_byte_expected=1 if expected_size == 0 else 0, expected_count=1, expected_files={})
    if complete and not cap_reason:
        return _oracle_label_status(3, "complete", 1.0, oracle_source="extraction_output")
    return {**_oracle_label_status(1 if completeness > 0 else -1, "partial" if completeness > 0 else "hard_negative", min(completeness, 0.999), oracle_source="extraction_output"), **({"oracle_cap_reason": cap_reason} if cap_reason else {})}


def _oracle_output_items(extraction_result: Any) -> list[dict[str, Any]]:
    if extraction_result is None:
        return []
    manifest = getattr(extraction_result, "progress_manifest_payload", None)
    output_dir = Path(str(getattr(extraction_result, "out_dir", "") or ""))
    items: list[dict[str, Any]] = []
    if isinstance(manifest, dict):
        for raw in manifest.get("files") or []:
            if isinstance(raw, dict):
                items.append(_oracle_output_item(raw, output_dir))
    items = _with_embedded_output_aliases(items, output_dir)
    if not items and output_dir.is_dir():
        for path in output_dir.rglob("*"):
            if path.is_file():
                rel = path.relative_to(output_dir).as_posix()
                items.append(_oracle_output_item({"path": str(path), "archive_path": rel, "status": "complete"}, output_dir))
        items = _with_embedded_output_aliases(items, output_dir)
    return [item for item in items if item.get("archive_path") or item.get("path")]


def _with_embedded_output_aliases(items: list[dict[str, Any]], output_dir: Path) -> list[dict[str, Any]]:
    if not items:
        return items
    prefixes = sorted({prefix for item in items for prefix in [_embedded_segment_prefix(item.get("archive_path"))] if prefix})
    if len(prefixes) != 1:
        return items
    prefix = prefixes[0]
    source = "top_manifest"
    segment_manifest = output_dir / prefix / ".sunpack" / "extraction_manifest.json"
    if segment_manifest.is_file():
        source = "segment_manifest"
    normalized: list[dict[str, Any]] = []
    marker = prefix + "/"
    for item in items:
        copied = dict(item)
        archive_path = clean_relative_archive_path(copied.get("archive_path") or "")
        if archive_path.startswith(marker):
            alias = clean_relative_archive_path(archive_path[len(marker):])
            if alias:
                aliases = list(copied.get("archive_path_aliases") or [])
                if alias not in aliases:
                    aliases.append(alias)
                copied["archive_path_aliases"] = aliases
                copied["oracle_segment_prefix"] = prefix
                copied["oracle_output_manifest_source"] = source
        normalized.append(copied)
    return normalized


def _embedded_segment_prefix(path: Any) -> str:
    text = clean_relative_archive_path(path or "")
    if not text:
        return ""
    parts = text.split("/")
    if len(parts) < 2:
        return ""
    prefix = parts[0]
    if not prefix.startswith("embedded_"):
        return ""
    return prefix


def _oracle_output_item(raw: dict[str, Any], output_dir: Path) -> dict[str, Any]:
    path_text = str(raw.get("path") or "")
    path = Path(path_text)
    if path_text and not path.is_absolute() and output_dir:
        path = output_dir / path
    archive_path = clean_relative_archive_path(raw.get("archive_path") or raw.get("name") or (path.name if path_text else ""))
    size = _safe_int(raw.get("bytes_written", raw.get("size")))
    crc = _optional_crc32(raw.get("crc32"))
    if path.is_file():
        size = path.stat().st_size
        crc = _crc32_file(path)
    return {
        "path": str(path) if path_text else "",
        "archive_path": archive_path,
        "status": str(raw.get("status") or "unverified"),
        "size": size,
        "bytes_written": size,
        "crc32": crc,
    }


def _oracle_completion_cap_reason(record: dict[str, Any], *, expected_bytes: int, zero_byte_expected: int, expected_count: int, expected_files: dict[str, Any]) -> str:
    physical_complete_expected = record.get("physical_complete_expected")
    profile = str(record.get("profile") or record.get("damage_profile") or record.get("sample_id") or "").lower()
    flags = {str(item).lower() for item in record.get("damage_flags") or []}
    expected_has_payload_hash = any(isinstance(meta, dict) and (meta.get("sha256") or meta.get("crc32") is not None or meta.get("crc") is not None) for meta in expected_files.values())
    if str(profile).startswith("partial_") and expected_count > 0 and zero_byte_expected == expected_count:
        return "invalid_physical_partial_sample"
    if physical_complete_expected is False and not expected_has_payload_hash:
        return "physical_complete_not_expected_or_payload_oracle_missing"
    if flags & {"payload_hash_mismatch", "payload_loss", "entry_payload_bad"} and not expected_has_payload_hash:
        return "physical_complete_not_expected_or_payload_oracle_missing"
    if physical_complete_expected is False and expected_bytes <= 0:
        return "physical_complete_not_expected_or_payload_oracle_missing"
    return ""


def _oracle_label_status(label: int, status: str, completeness: float, **extra: Any) -> dict[str, Any]:
    return {"status": status, "label": int(label), "completeness": max(0.0, min(1.0, float(completeness or 0.0))), **extra}


def _oracle_ground_truth_payload(oracle: dict[str, Any]) -> dict[str, Any]:
    keys = {
        "status", "label", "completeness", "matched_files", "complete_files", "partial_files", "failed_files",
        "missing_files", "wrong_files", "unreadable_files", "entry_count", "expected_files", "expected_bytes",
        "matched_bytes", "complete_bytes", "oracle_source", "oracle_cap_reason", "error",
        "oracle_path_alias_used", "oracle_segment_prefix", "oracle_output_manifest_source",
    }
    return {key: value for key, value in dict(oracle or {}).items() if key in keys}


def _runtime_oracle_disagreement_reason(verification: Any, oracle: dict[str, Any]) -> str:
    decision = str(getattr(verification, "decision_hint", "") or "")
    recovery = float((oracle or {}).get("completeness", 0.0) or 0.0)
    status = str((oracle or {}).get("status") or "")
    if decision == DECISION_ACCEPT and recovery < 0.999:
        if status == "missing_extraction_output":
            return "expected_output_missing"
        if (oracle or {}).get("oracle_cap_reason"):
            return str((oracle or {}).get("oracle_cap_reason"))
        if status in {"hard_negative", "partial"}:
            return "payload_hash_mismatch"
        return "metadata_only_match_rejected"
    return ""


def _expected_file_bytes(expected_files: dict[str, Any]) -> int:
    total = 0
    for meta in expected_files.values():
        if isinstance(meta, dict):
            total += max(0, _safe_int(meta.get("size")) or 0)
    return total


def _crc32_file(path: Path) -> int:
    value = 0
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            value = zlib.crc32(chunk, value)
    return value & 0xFFFFFFFF


def _sha256_bytes(data: bytes) -> str:
    import hashlib
    return hashlib.sha256(data).hexdigest()


def _safe_int(value: Any) -> int | None:
    if value is None or value == "":
        return None
    try:
        return int(value)
    except (TypeError, ValueError):
        return None


def _optional_crc32(value: Any) -> int | None:
    if value is None or value == "":
        return None
    try:
        return int(value) & 0xFFFFFFFF
    except (TypeError, ValueError):
        return None


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
        "root_state_id": state.get("root_state_id") or state.get("state_id"),
        "parent_state_id": state.get("parent_state_id") or "",
        "round": state.get("round"),
        "path_depth": state.get("round"),
        "path_candidate_ids": list(state.get("path_candidate_ids") or []),
        "root_candidate_id": state.get("root_candidate_id") or "",
        "root_candidate_rank": state.get("root_candidate_rank"),
        "root_action": False,
        "parent_action_row_id": state.get("parent_action_row_id") or "",
        "parent_candidate_id": state.get("parent_candidate_id") or "",
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
        row["oracle_ground_truth"] = _oracle_ground_truth_payload(oracle)
        row["runtime_oracle_disagreement_reason"] = _runtime_oracle_disagreement_reason(verification, oracle)
    return row


def _backfill_runtime_returns(rows: list[dict[str, Any]], discount: float) -> None:
    by_state: dict[str, list[dict[str, Any]]] = defaultdict(list)
    terminal_by_state: dict[str, tuple[float, str]] = {}
    for row in rows:
        if row.get("row_type") == "action":
            by_state[str(row.get("state_id") or "")].append(row)
        elif row.get("row_type") == "terminal":
            state_id = str(row.get("state_id") or "")
            recovery = float(row.get("terminal_recovery_ratio", row.get("recovery_ratio", 0.0)) or 0.0)
            status = str(row.get("terminal_status") or "")
            current = terminal_by_state.get(state_id)
            if current is None or recovery > current[0]:
                terminal_by_state[state_id] = (recovery, status)

    memo: dict[str, dict[str, Any]] = {}

    def best_info(state_id: str) -> dict[str, Any]:
        if state_id in memo:
            return memo[state_id]
        terminal = terminal_by_state.get(state_id)
        best: dict[str, Any] = {
            "value": float(terminal[0]) if terminal else 0.0,
            "terminal_status": str(terminal[1]) if terminal else "",
            "best_path": [],
        }
        for row in by_state.get(state_id, []):
            if row.get("explored") is False:
                continue
            immediate = float(row.get("recovery_ratio", 0.0) or 0.0)
            next_state = str(row.get("next_state_id") or "")
            child = best_info(next_state) if next_state else {"value": 0.0, "terminal_status": "", "best_path": []}
            discounted_future = float(discount) * float(child.get("value", 0.0) or 0.0)
            if immediate > discounted_future or not child.get("best_path"):
                value = immediate
                terminal_status = str(row.get("terminal_status") or "")
                best_path = [str(row.get("candidate_id") or "")]
            else:
                value = discounted_future
                terminal_status = str(child.get("terminal_status") or row.get("terminal_status") or "")
                best_path = [str(row.get("candidate_id") or ""), *list(child.get("best_path") or [])]
            if value > float(best.get("value", 0.0) or 0.0):
                best = {
                    "value": value,
                    "terminal_status": terminal_status,
                    "best_path": [item for item in best_path if item],
                }
        memo[state_id] = best
        return best

    for state_id in list(by_state):
        best_info(state_id)
    root_return_by_candidate: dict[tuple[str, str], dict[str, Any]] = {}
    for row in rows:
        if row.get("row_type") != "action":
            continue
        if row.get("explored") is False:
            continue
        immediate = float(row.get("recovery_ratio", 0.0) or 0.0)
        next_state = str(row.get("next_state_id") or "")
        child = best_info(next_state) if next_state else {"value": 0.0, "terminal_status": "", "best_path": []}
        future = float(child.get("value", 0.0) or 0.0)
        value = max(immediate, float(discount) * future)
        if immediate > float(discount) * future or not child.get("best_path"):
            subtree_status = str(row.get("terminal_status") or "")
            subtree_path = [str(row.get("candidate_id") or "")]
        else:
            subtree_status = str(child.get("terminal_status") or row.get("terminal_status") or "")
            subtree_path = [str(row.get("candidate_id") or ""), *list(child.get("best_path") or [])]
        root_state_id = str(row.get("root_state_id") or row.get("state_id") or "")
        root_candidate_id = str(row.get("root_candidate_id") or row.get("candidate_id") or "")
        if root_state_id and root_candidate_id and row.get("root_action"):
            root_return_by_candidate[(root_state_id, root_candidate_id)] = {
                "value": value,
                "terminal_status": subtree_status,
                "best_path": [item for item in subtree_path if item],
            }
        row["terminal_recovery_ratio"] = immediate
        if isinstance(row.get("rl"), dict):
            row["rl"]["future_return"] = value
            row["rl"]["single_path_robust_return"] = value
            row["rl"]["terminal_reward"] = immediate
            row["rl"]["subtree_oracle_return"] = value
            row["rl"]["subtree_terminal_status"] = subtree_status
            row["rl"]["subtree_best_path"] = [item for item in subtree_path if item]
            state_terminal = terminal_by_state.get(str(row.get("state_id") or ""))
            current_state_recovery = float(state_terminal[0]) if state_terminal else 0.0
            row["rl"]["transition_value_delta"] = value - current_state_recovery
    for row in rows:
        if row.get("row_type") != "action" or row.get("explored") is False:
            continue
        root_state_id = str(row.get("root_state_id") or row.get("state_id") or "")
        root_candidate_id = str(row.get("root_candidate_id") or row.get("candidate_id") or "")
        root_info = root_return_by_candidate.get((root_state_id, root_candidate_id))
        if not root_info or not isinstance(row.get("rl"), dict):
            continue
        row["rl"]["root_candidate_return"] = float(root_info.get("value", 0.0) or 0.0)
        row["rl"]["root_candidate_terminal_status"] = str(root_info.get("terminal_status") or "")
        row["rl"]["root_candidate_best_path"] = list(root_info.get("best_path") or [])


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
        "root_state_id": state.get("root_state_id") or state.get("state_id"),
        "parent_state_id": state.get("parent_state_id") or "",
        "query_id": query_id,
        "round": int(round_index),
        "path_depth": int(round_index),
        "action_row_id": f"{query_id}|{rank}|{candidate_id}",
        "candidate_id": candidate_id,
        "path_candidate_ids": [*list(state.get("path_candidate_ids") or []), candidate_id],
        "root_candidate_id": candidate_id if int(round_index) == 0 else str(state.get("root_candidate_id") or ""),
        "root_candidate_rank": rank if int(round_index) == 0 else state.get("root_candidate_rank"),
        "root_action": int(round_index) == 0,
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
        "child_state_id": "",
        "next_state_id": "",
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


def _is_noop_payload(payload: dict[str, Any]) -> bool:
    proposal = payload.get("candidate_proposal") if isinstance(payload.get("candidate_proposal"), dict) else {}
    return bool(
        payload.get("noop")
        or payload.get("control_action")
        or proposal.get("noop")
        or proposal.get("control_action")
        or str(payload.get("module_name") or payload.get("module") or "") == "repair_accept_current_state"
    )


def _decision_with_protected_noop(
    decision: RepairRuntimeStrategyDecision,
    payloads: list[dict[str, Any]],
) -> RepairRuntimeStrategyDecision:
    selected = _with_protected_noop_selection(list(decision.selected_candidate_ids or []), payloads)
    if selected == list(decision.selected_candidate_ids or []):
        return decision
    metadata = dict(decision.metadata or {})
    metadata["protected_noop_selected"] = True
    return RepairRuntimeStrategyDecision(
        mode=f"{decision.mode}+protected_noop",
        selected_candidate_ids=selected,
        beam_enabled=decision.beam_enabled,
        metadata=metadata,
    )


def _with_protected_noop_selection(selected: list[str], payloads: list[dict[str, Any]]) -> list[str]:
    output = [str(item) for item in selected if str(item)]
    seen = set(output)
    for payload in payloads or []:
        proposal = payload.get("candidate_proposal") if isinstance(payload.get("candidate_proposal"), dict) else {}
        if not bool(payload.get("noop") or proposal.get("noop")):
            continue
        candidate_id = str(payload.get("candidate_id") or "")
        if candidate_id and candidate_id not in seen:
            output.append(candidate_id)
            seen.add(candidate_id)
    return output


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
        if _safe_int(row.get("round"), -1) == 0 and row.get("row_type") == "action":
            if bool(row.get("root_action")):
                summary["root_action_row_count"] = int(summary.get("root_action_row_count", 0) or 0) + 1
            if row.get("explored") is True:
                summary["root_explored_action_count"] = int(summary.get("root_explored_action_count", 0) or 0) + 1
            elif row.get("explored") is False:
                summary["root_unexplored_candidate_count"] = int(summary.get("root_unexplored_candidate_count", 0) or 0) + 1
            if _safe_int(row.get("current_rank"), 999) < 5:
                summary["root_top5_candidate_count"] = int(summary.get("root_top5_candidate_count", 0) or 0) + 1
                if row.get("explored") is True:
                    summary["root_top5_explored_count"] = int(summary.get("root_top5_explored_count", 0) or 0) + 1
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


def _safe_int(value: Any, default: int = 0) -> int:
    try:
        if value is None or value == "":
            return int(default)
        return int(value)
    except Exception:
        return int(default)


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
