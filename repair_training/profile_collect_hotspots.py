from __future__ import annotations

import argparse
import json
import subprocess
import sys
import time
from collections import Counter, defaultdict
from pathlib import Path
from typing import Any


REPO_ROOT = Path(__file__).resolve().parents[1]


def main(argv: list[str] | None = None) -> int:
    args = _parser().parse_args(argv)
    out_root = Path(args.output_root)
    out_root.mkdir(parents=True, exist_ok=True)
    runs: list[dict[str, Any]] = []
    for workers in _worker_values(args.workers):
        run_dir = out_root / f"w{workers}"
        run_dir.mkdir(parents=True, exist_ok=True)
        runs.append(_run_profile(args, workers, run_dir))
    report = {
        "created_at": time.strftime("%Y-%m-%d %H:%M:%S"),
        "settings": {
            "formats": args.formats,
            "sample": args.sample,
            "limit": args.limit,
            "workers": _worker_values(args.workers),
            "timeout_seconds": args.timeout_seconds,
            "case_timeout_seconds": args.case_timeout_seconds,
            "sample_execution_mode": args.sample_execution_mode,
            "sample_worker_count": args.sample_worker_count,
            "slow_phase_seconds": args.slow_phase_seconds,
            "max_rounds": args.max_rounds,
            "rollout_mode": args.rollout_mode,
            "beam_size": args.beam_size,
            "branch_top_k": args.branch_top_k,
            "materialize_top_k_per_round": args.materialize_top_k_per_round,
        },
        "runs": runs,
    }
    report_path = out_root / "collect_hotspots_report.json"
    report_path.write_text(json.dumps(report, ensure_ascii=False, indent=2, sort_keys=True), encoding="utf-8")
    print(json.dumps(report, ensure_ascii=False, indent=2, sort_keys=True))
    print(f"\nWrote profile report: {report_path}")
    return 0 if all(run.get("returncode") == 0 for run in runs) else 1


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Run bounded repair-training collection profiles and report measured hotspots.")
    parser.add_argument("--output-root", default=".sunpack/collect-profile", help="Directory for temporary outputs and the final profile report.")
    parser.add_argument("--formats", default="zip", help="Collector --formats value.")
    parser.add_argument("--sample", default="", help="Optional collector --sample value.")
    parser.add_argument("--limit", type=int, default=24, help="Number of manifest records per run.")
    parser.add_argument("--workers", default="1,4", help="Comma-separated worker counts to compare. 1 uses the single-process collector; >1 uses the parallel wrapper.")
    parser.add_argument("--timeout-seconds", type=float, default=180.0, help="Wall-clock timeout for each profile run.")
    parser.add_argument("--case-timeout-seconds", type=float, default=12.0, help="Collector per-case timeout.")
    parser.add_argument("--sample-execution-mode", default="worker_pool", choices=["process_per_sample", "worker_pool", "inprocess"])
    parser.add_argument("--sample-worker-count", type=int, default=0)
    parser.add_argument("--total-timeout-seconds", type=float, default=0.0, help="Collector total timeout; 0 lets this profile runner enforce wall time.")
    parser.add_argument("--idle-timeout-seconds", type=float, default=0.0, help="Collector idle timeout.")
    parser.add_argument("--slow-phase-seconds", type=float, default=0.25, help="Breakpoint threshold for phase events.")
    parser.add_argument("--max-rounds", type=int, default=3)
    parser.add_argument("--max-total-states-per-sample", type=int, default=8)
    parser.add_argument("--max-candidates-per-round", type=int, default=8)
    parser.add_argument("--rollout-mode", default="beam", choices=["greedy", "greedy_current_selector", "beam", "counterfactual"])
    parser.add_argument("--beam-size", type=int, default=2)
    parser.add_argument("--branch-top-k", type=int, default=2)
    parser.add_argument("--materialize-top-k-per-round", type=int, default=4)
    parser.add_argument("--queue-batch-size", type=int, default=1, help="Parallel wrapper queue batch size.")
    parser.add_argument("--max-active-collectors", type=int, default=0, help="Parallel wrapper MaxActiveCollectors; 0 means min(workers, 6).")
    parser.add_argument("--no-run", action="store_true", help="Only analyze existing events under --output-root.")
    return parser


def _worker_values(raw: str) -> list[int]:
    values: list[int] = []
    for item in str(raw or "").split(","):
        item = item.strip()
        if not item:
            continue
        values.append(max(1, int(item)))
    return values or [1]


def _run_profile(args: argparse.Namespace, workers: int, run_dir: Path) -> dict[str, Any]:
    events = run_dir / "events.jsonl"
    summary = run_dir / "summary.json"
    success = run_dir / "success.jsonl"
    failure = run_dir / "failure.jsonl"
    stdout_path = run_dir / "stdout.log"
    stderr_path = run_dir / "stderr.log"
    if args.no_run:
        return _summarize_run(workers, run_dir, events, summary, success, failure, stdout_path, stderr_path, 0.0, None)

    for path in (events, summary, success, failure, stdout_path, stderr_path):
        try:
            path.unlink()
        except FileNotFoundError:
            pass
    started = time.perf_counter()
    command = _command(args, workers, events, summary, success, failure, run_dir)
    timed_out = False
    returncode = -999
    try:
        completed = subprocess.run(
            command,
            cwd=REPO_ROOT,
            text=True,
            capture_output=True,
            timeout=max(1.0, float(args.timeout_seconds or 1.0)),
        )
        returncode = int(completed.returncode)
        stdout_path.write_text(completed.stdout or "", encoding="utf-8")
        stderr_path.write_text(completed.stderr or "", encoding="utf-8")
    except subprocess.TimeoutExpired as exc:
        timed_out = True
        returncode = -1
        stdout_path.write_text(exc.stdout or "", encoding="utf-8")
        stderr_path.write_text(exc.stderr or f"profile runner timeout after {args.timeout_seconds}s", encoding="utf-8")
    elapsed = time.perf_counter() - started
    return _summarize_run(workers, run_dir, events, summary, success, failure, stdout_path, stderr_path, elapsed, returncode, timed_out=timed_out, command=command)


def _command(args: argparse.Namespace, workers: int, events: Path, summary: Path, success: Path, failure: Path, run_dir: Path) -> list[str]:
    common = [
        "-Formats", args.formats,
        "-Limit", str(args.limit),
        "-SuccessOutput", str(success),
        "-FailureOutput", str(failure),
        "-DebugEvents", str(events),
        "-SampleExecutionMode", args.sample_execution_mode,
        "-SampleWorkerCount", str(args.sample_worker_count),
        "-MaxRounds", str(args.max_rounds),
        "-MaxCandidatesPerRound", str(args.max_candidates_per_round),
        "-RolloutMode", args.rollout_mode,
        "-BeamSize", str(args.beam_size),
        "-BranchTopK", str(args.branch_top_k),
        "-MaxTotalStatesPerSample", str(args.max_total_states_per_sample),
        "-MaterializeTopKPerRound", str(args.materialize_top_k_per_round),
        "-CaseTimeoutSeconds", str(args.case_timeout_seconds),
        "-NoPretty",
    ]
    if args.sample:
        common.extend(["-Sample", args.sample])
    if args.total_timeout_seconds > 0:
        common.extend(["-TotalTimeoutSeconds", str(args.total_timeout_seconds)])
    if args.idle_timeout_seconds > 0:
        common.extend(["-IdleTimeoutSeconds", str(args.idle_timeout_seconds)])
    if workers <= 1:
        return [
            "powershell",
            "-NoProfile",
            "-ExecutionPolicy",
            "Bypass",
            "-File",
            "repair_training/collect_plan_data.ps1",
            "-SummaryOutput",
            str(summary),
            "-Workspace",
            str(run_dir / "workspace"),
            *common,
        ]
    active = args.max_active_collectors if args.max_active_collectors > 0 else min(workers, 6)
    return [
        "powershell",
        "-NoProfile",
        "-ExecutionPolicy",
        "Bypass",
        "-File",
        "repair_training/collect_plan_data_parallel.ps1",
        "-ParallelSummaryOutput",
        str(summary),
        "-CollectWorkers",
        str(workers),
        "-MaxActiveCollectors",
        str(active),
        "-QueueBatchSize",
        str(args.queue_batch_size),
        *common,
    ]


def _summarize_run(
    workers: int,
    run_dir: Path,
    events_path: Path,
    summary_path: Path,
    success_path: Path,
    failure_path: Path,
    stdout_path: Path,
    stderr_path: Path,
    elapsed_seconds: float,
    returncode: int | None,
    *,
    timed_out: bool = False,
    command: list[str] | None = None,
) -> dict[str, Any]:
    events = _load_jsonl(events_path)
    collector_summary = _load_json(summary_path)
    phase_stats, slow_phases = _phase_report(events, slow_threshold=_current_slow_threshold())
    sample_stats = _sample_report(events)
    lifecycle_stats, lifecycle_breakpoints = _lifecycle_report(events, slow_threshold=_current_slow_threshold())
    no_output_profile = _no_output_profile_report(success_path, failure_path)
    return {
        "workers": workers,
        "returncode": returncode,
        "timed_out": timed_out,
        "elapsed_seconds": round(elapsed_seconds, 3),
        "events_path": str(events_path),
        "summary_path": str(summary_path),
        "success_path": str(success_path),
        "failure_path": str(failure_path),
        "stdout_path": str(stdout_path),
        "stderr_path": str(stderr_path),
        "command": command or [],
        "collector_summary": _compact_collector_summary(collector_summary),
        "event_count": len(events),
        "sample_count": sample_stats["sample_count"],
        "timeout_count": sample_stats["timeout_count"],
        "phase_stats": phase_stats,
        "lifecycle_stats": lifecycle_stats,
        "slow_phase_breakpoints": slow_phases[:30],
        "lifecycle_breakpoints": lifecycle_breakpoints[:30],
        "slow_samples": sample_stats["slow_samples"][:20],
        "sample_status_counts": sample_stats["status_counts"],
        "no_output_profile": no_output_profile,
    }


def _current_slow_threshold() -> float:
    # The caller passes this value through argparse; keeping the lookup local
    # avoids threading extra state through pure report helpers.
    for item in sys.argv:
        if item.startswith("--slow-phase-seconds="):
            return float(item.split("=", 1)[1])
    if "--slow-phase-seconds" in sys.argv:
        index = sys.argv.index("--slow-phase-seconds")
        if index + 1 < len(sys.argv):
            return float(sys.argv[index + 1])
    return 0.25


def _load_jsonl(path: Path) -> list[dict[str, Any]]:
    rows: list[dict[str, Any]] = []
    if not path.is_file():
        return rows
    with path.open(encoding="utf-8") as handle:
        for line in handle:
            if not line.strip():
                continue
            try:
                item = json.loads(line)
            except json.JSONDecodeError:
                continue
            if isinstance(item, dict):
                rows.append(item)
    return rows


def _load_json(path: Path) -> dict[str, Any]:
    if not path.is_file():
        return {}
    try:
        text = path.read_bytes().decode("utf-8-sig")
        payload = json.loads(text)
    except (UnicodeDecodeError, json.JSONDecodeError):
        return {}
    return payload if isinstance(payload, dict) else {}


def _phase_report(events: list[dict[str, Any]], *, slow_threshold: float) -> tuple[dict[str, Any], list[dict[str, Any]]]:
    values: dict[str, list[float]] = defaultdict(list)
    slow: list[dict[str, Any]] = []
    for event in events:
        if event.get("event") != "phase":
            continue
        phase = str(event.get("phase") or "")
        elapsed = float(event.get("elapsed_seconds") or 0.0)
        values[phase].append(elapsed)
        if elapsed >= slow_threshold:
            slow.append({
                "phase": phase,
                "elapsed_seconds": round(elapsed, 3),
                "sample_id": event.get("sample_id"),
                "round": event.get("round"),
                "candidate_count": event.get("candidate_count"),
                "proposal_count": event.get("proposal_count"),
                "accepted_count": event.get("accepted_count"),
                "rejected_count": event.get("rejected_count"),
                "logged_count": event.get("logged_count"),
                "damaged_file_name": event.get("damaged_file_name"),
            })
    stats = {
        phase: {
            "count": len(items),
            "total_seconds": round(sum(items), 3),
            "avg_seconds": round(sum(items) / len(items), 3) if items else 0.0,
            "max_seconds": round(max(items), 3) if items else 0.0,
            "p90_seconds": round(_percentile(items, 0.90), 3),
            "p99_seconds": round(_percentile(items, 0.99), 3),
        }
        for phase, items in sorted(values.items(), key=lambda item: -sum(item[1]))
    }
    slow.sort(key=lambda item: float(item.get("elapsed_seconds") or 0.0), reverse=True)
    return stats, slow


def _sample_report(events: list[dict[str, Any]]) -> dict[str, Any]:
    grouped: dict[str, list[dict[str, Any]]] = defaultdict(list)
    for event in events:
        grouped[str(event.get("sample_id") or "")].append(event)
    slow_samples: list[dict[str, Any]] = []
    status_counts: Counter[str] = Counter()
    timeout_count = 0
    for sample_id, items in grouped.items():
        end = next((event for event in reversed(items) if event.get("event") == "sample_end"), None)
        timeout = next((event for event in items if event.get("event") == "sample_timeout"), None)
        if timeout:
            timeout_count += 1
        if end:
            status = str(end.get("status") or "")
            status_counts[status] += 1
            slow_samples.append({
                "sample_id": sample_id,
                "elapsed_seconds": round(float(end.get("elapsed_seconds") or 0.0), 3),
                "status": status,
                "source_archive_name": end.get("source_archive_name"),
                "damaged_file_name": end.get("damaged_file_name"),
                "last_phase": _last_phase(items),
            })
    slow_samples.sort(key=lambda item: float(item.get("elapsed_seconds") or 0.0), reverse=True)
    return {
        "sample_count": sum(status_counts.values()),
        "timeout_count": timeout_count,
        "slow_samples": slow_samples,
        "status_counts": dict(status_counts),
    }


def _lifecycle_report(events: list[dict[str, Any]], *, slow_threshold: float) -> tuple[dict[str, Any], list[dict[str, Any]]]:
    grouped: dict[str, list[dict[str, Any]]] = defaultdict(list)
    for event in events:
        grouped[str(event.get("sample_id") or "")].append(event)
    buckets: dict[str, list[float]] = defaultdict(list)
    breakpoints: list[dict[str, Any]] = []
    for sample_id, items in grouped.items():
        start = next((event for event in items if event.get("event") == "sample_start"), None)
        worker_start = next((event for event in items if event.get("event") == "worker_start"), None)
        worker_done = next((event for event in reversed(items) if event.get("event") == "worker_done"), None)
        end = next((event for event in reversed(items) if event.get("event") == "sample_end"), None)
        phase_sum = sum(float(event.get("elapsed_seconds") or 0.0) for event in items if event.get("event") == "phase")
        measurements = {
            "sample_start_to_worker_start": _delta(start, worker_start),
            "worker_lifetime": _delta(worker_start, worker_done),
            "worker_done_to_sample_end": _delta(worker_done, end),
            "sample_elapsed_event_clock": _delta(start, end),
        }
        if measurements["sample_elapsed_event_clock"] is not None:
            measurements["unaccounted_vs_phase"] = max(0.0, float(measurements["sample_elapsed_event_clock"]) - phase_sum)
        for name, elapsed in measurements.items():
            if elapsed is None:
                continue
            buckets[name].append(float(elapsed))
            if elapsed >= slow_threshold:
                breakpoints.append({
                    "phase": name,
                    "elapsed_seconds": round(float(elapsed), 3),
                    "sample_id": sample_id,
                    "damaged_file_name": (end or worker_done or worker_start or start or {}).get("damaged_file_name"),
                    "source_archive_name": (end or worker_done or worker_start or start or {}).get("source_archive_name"),
                })
    stats = {
        name: {
            "count": len(items),
            "total_seconds": round(sum(items), 3),
            "avg_seconds": round(sum(items) / len(items), 3) if items else 0.0,
            "max_seconds": round(max(items), 3) if items else 0.0,
            "p90_seconds": round(_percentile(items, 0.90), 3),
            "p99_seconds": round(_percentile(items, 0.99), 3),
        }
        for name, items in sorted(buckets.items(), key=lambda item: -sum(item[1]))
    }
    breakpoints.sort(key=lambda item: float(item.get("elapsed_seconds") or 0.0), reverse=True)
    return stats, breakpoints


def _delta(start: dict[str, Any] | None, end: dict[str, Any] | None) -> float | None:
    if not start or not end:
        return None
    return float(end.get("time") or 0.0) - float(start.get("time") or 0.0)


def _compact_collector_summary(summary: dict[str, Any]) -> dict[str, Any]:
    if not isinstance(summary, dict):
        return {}
    omitted = {"shards"}
    return {key: value for key, value in summary.items() if key not in omitted}


def _no_output_profile_report(success_path: Path, failure_path: Path) -> dict[str, Any]:
    rows = _load_jsonl(success_path) + _load_jsonl(failure_path)
    no_output_rows = [row for row in rows if row.get("row_type") != "terminal" and str(row.get("label_status") or "") == "no_output"]
    reason_counts: Counter[str] = Counter()
    module_counts: Counter[str] = Counter()
    damage_counts: Counter[str] = Counter()
    round_counts: Counter[str] = Counter()
    by_sample: dict[str, list[dict[str, Any]]] = defaultdict(list)
    for row in rows:
        if row.get("row_type") == "terminal":
            continue
        by_sample[str(row.get("sample_id") or "")].append(row)
    for row in no_output_rows:
        details = row.get("label_details") if isinstance(row.get("label_details"), dict) else {}
        reason_counts[str(row.get("no_output_reason") or details.get("no_output_reason") or "unknown")] += 1
        module_counts[str(row.get("module") or "unknown")] += 1
        damage_counts[_row_damage_profile(row)] += 1
        round_counts[str(int(row.get("round") or 0))] += 1

    profile_samples: dict[str, dict[str, Any]] = {}
    for sample_id, sample_rows in by_sample.items():
        profile = _combined_damage_profile(_row_damage_profile(sample_rows[0]))
        stats = profile_samples.setdefault(
            profile,
            {
                "profile": profile,
                "samples": 0,
                "complete": 0,
                "partial": 0,
                "progress": 0,
                "unfixed": 0,
                "no_output_samples": 0,
                "no_output_rows": 0,
                "no_output_modules": Counter(),
                "round_counts": Counter(),
            },
        )
        stats["samples"] += 1
        best_label = max((int(row.get("label") or 0) for row in sample_rows), default=0)
        statuses = {str(row.get("label_status") or "") for row in sample_rows}
        if best_label >= 3 or "complete" in statuses:
            stats["complete"] += 1
        elif "partial" in statuses or best_label == 1:
            stats["partial"] += 1
        elif "state_progress" in statuses:
            stats["progress"] += 1
        else:
            stats["unfixed"] += 1
        sample_no_output = [row for row in sample_rows if str(row.get("label_status") or "") == "no_output"]
        if sample_no_output:
            stats["no_output_samples"] += 1
            stats["no_output_rows"] += len(sample_no_output)
            for row in sample_no_output:
                stats["no_output_modules"][str(row.get("module") or "unknown")] += 1
                stats["round_counts"][str(int(row.get("round") or 0))] += 1

    combined_profiles: list[dict[str, Any]] = []
    for stats in profile_samples.values():
        samples = max(1, int(stats["samples"]))
        combined_profiles.append({
            "profile": stats["profile"],
            "samples": stats["samples"],
            "complete": stats["complete"],
            "partial": stats["partial"],
            "progress": stats["progress"],
            "unfixed": stats["unfixed"],
            "complete_rate": round(float(stats["complete"]) / samples, 4),
            "partial_or_progress_rate": round(float(stats["partial"] + stats["progress"]) / samples, 4),
            "no_output_samples": stats["no_output_samples"],
            "no_output_rows": stats["no_output_rows"],
            "no_output_rows_per_sample": round(float(stats["no_output_rows"]) / samples, 3),
            "top_no_output_modules": dict(stats["no_output_modules"].most_common(8)),
            "round_counts": dict(stats["round_counts"].most_common()),
        })
    combined_profiles.sort(key=lambda item: (int(item["no_output_rows"]), int(item["samples"])), reverse=True)
    return {
        "row_count": len(rows),
        "sample_count": len(by_sample),
        "no_output_rows": len(no_output_rows),
        "reason_counts": dict(reason_counts.most_common()),
        "module_counts": dict(module_counts.most_common(20)),
        "damage_profile_counts": dict(damage_counts.most_common(30)),
        "round_counts": dict(round_counts.most_common()),
        "combined_profiles": combined_profiles[:30],
    }


def _row_damage_profile(row: dict[str, Any]) -> str:
    profile = str(row.get("damage_profile") or "").strip()
    if profile:
        return profile
    sample_id = str(row.get("sample_id") or "")
    tail = sample_id.rsplit("__", 1)[-1] if "__" in sample_id else sample_id
    if tail:
        parts = tail.rsplit("_", 1)
        if len(parts) == 2 and parts[1].isdigit():
            return parts[0]
        return tail
    return "unknown"


def _combined_damage_profile(profile: str) -> str:
    text = str(profile or "unknown")
    parts = text.split("_", 1)
    if len(parts) == 2 and len(parts[0]) == 2 and parts[0][0].lower() == "l" and parts[0][1].isdigit():
        return parts[1]
    return text


def _last_phase(events: list[dict[str, Any]]) -> dict[str, Any] | None:
    for event in reversed(events):
        if event.get("event") == "phase":
            return {
                "phase": event.get("phase"),
                "elapsed_seconds": event.get("elapsed_seconds"),
                "round": event.get("round"),
            }
    return None


def _percentile(values: list[float], q: float) -> float:
    if not values:
        return 0.0
    ordered = sorted(values)
    index = min(len(ordered) - 1, max(0, int(round((len(ordered) - 1) * q))))
    return float(ordered[index])


if __name__ == "__main__":
    raise SystemExit(main())
