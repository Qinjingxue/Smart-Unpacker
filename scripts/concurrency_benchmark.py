from __future__ import annotations

import argparse
import json
import os
import shutil
import statistics
import subprocess
import sys
import tempfile
import threading
import time
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Any

import psutil


ROOT = Path(__file__).resolve().parent
REPO_ROOT = ROOT.parent
TOOLS_DIR = REPO_ROOT / "tools"
SEVEN_Z = next(
    (path for path in (TOOLS_DIR / "7z.exe", TOOLS_DIR / "7zip" / "7z.exe") if path.is_file()),
    TOOLS_DIR / "7z.exe",
)

if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

from smart_unpacker import DecompressionEngine


BYTES_IN_MB = 1024 * 1024


@dataclass
class SamplePoint:
    timestamp: float
    cpu_percent: float
    rss_mb: float
    disk_mbps: float
    active_workers: int
    concurrency_limit: int


@dataclass
class RunMetrics:
    mode: str
    elapsed_seconds: float
    archive_count: int
    payload_mb: int
    detected_max_workers: int
    configured_max_workers: int
    final_concurrency_limit: int
    success_count: int
    failure_count: int
    peak_active_workers: int
    avg_active_workers: float
    peak_concurrency_limit: int
    avg_concurrency_limit: float
    peak_cpu_percent: float
    avg_cpu_percent: float
    peak_disk_mbps: float
    avg_disk_mbps: float
    peak_rss_mb: float
    output_root: str
    failed_tasks: list[str]


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Benchmark smart unpacker concurrency behavior.")
    parser.add_argument("--archives", type=int, default=10, help="Number of archives to generate.")
    parser.add_argument("--payload-mb", type=int, default=256, help="Uncompressed payload size per archive in MB.")
    parser.add_argument(
        "--modes",
        nargs="+",
        default=["adaptive", "relaxed", "fixed:max"],
        help="Benchmark modes: adaptive, relaxed, fixed:N, fixed:max",
    )
    parser.add_argument(
        "--max-workers",
        type=int,
        default=0,
        help="Override engine max_workers_limit. 0 means use auto-detected value.",
    )
    parser.add_argument(
        "--repeat",
        type=int,
        default=1,
        help="Repeat the full suite this many times.",
    )
    parser.add_argument(
        "--data-mode",
        choices=["mixed", "compressible", "randomish"],
        default="mixed",
        help="Payload pattern used to shape compression ratio and CPU pressure.",
    )
    parser.add_argument(
        "--keep-temp",
        action="store_true",
        help="Keep generated benchmark directories instead of deleting them.",
    )
    parser.add_argument(
        "--report-json",
        help="Optional path to write full JSON results.",
    )
    parser.add_argument(
        "--prune-stale-temp",
        action="store_true",
        help="Delete old smart-unpacker-bench-* directories in the repo root before running.",
    )
    return parser


def ensure_prerequisites() -> None:
    if not SEVEN_Z.is_file():
        raise FileNotFoundError(f"Missing 7z executable: {SEVEN_Z}")


def safe_rmtree(path: Path) -> None:
    if not path.exists():
        return
    try:
        shutil.rmtree(path)
    except FileNotFoundError:
        return


def prune_stale_temp_roots(current_root: Path | None = None) -> list[str]:
    removed: list[str] = []
    for candidate in REPO_ROOT.glob("smart-unpacker-bench-*"):
        if not candidate.is_dir():
            continue
        if current_root is not None and candidate.resolve() == current_root.resolve():
            continue
        safe_rmtree(candidate)
        removed.append(str(candidate))
    return removed


def run_cmd(cmd: list[str], cwd: Path) -> None:
    result = subprocess.run(cmd, cwd=str(cwd), capture_output=True, text=True)
    if result.returncode != 0:
        raise RuntimeError(
            f"Command failed ({result.returncode}): {' '.join(map(str, cmd))}\n"
            f"stdout:\n{result.stdout}\n"
            f"stderr:\n{result.stderr}"
        )


def build_chunk(seed: int, chunk_size: int, data_mode: str) -> bytes:
    if data_mode == "compressible":
        token = f"ARCHIVE::{seed:04d}::".encode("ascii")
        return (token * (chunk_size // len(token) + 1))[:chunk_size]

    if data_mode == "randomish":
        data = bytearray(chunk_size)
        value = seed or 1
        for index in range(chunk_size):
            value = (1103515245 * value + 12345) & 0x7FFFFFFF
            data[index] = value & 0xFF
        return bytes(data)

    base = bytearray(chunk_size)
    pattern = f"MIX::{seed:04d}::".encode("ascii")
    repeat = (pattern * (chunk_size // len(pattern) + 1))[: chunk_size // 2]
    base[: len(repeat)] = repeat
    value = seed or 7
    for index in range(chunk_size // 2, chunk_size):
        value = (1664525 * value + 1013904223) & 0xFFFFFFFF
        base[index] = value & 0xFF
    return bytes(base)


def write_payload_file(path: Path, size_mb: int, seed: int, data_mode: str) -> None:
    chunk_size = 1024 * 1024
    chunk = build_chunk(seed, chunk_size, data_mode)
    with open(path, "wb") as handle:
        for _ in range(size_mb):
            handle.write(chunk)


def create_archive(source_dir: Path, archive_path: Path) -> None:
    run_cmd([str(SEVEN_Z), "a", str(archive_path), str(source_dir), "-mx=5", "-y"], REPO_ROOT)


def generate_dataset(root_dir: Path, archives: int, payload_mb: int, data_mode: str) -> list[dict[str, str]]:
    metadata: list[dict[str, str]] = []
    for index in range(archives):
        archive_id = f"bench_{index:03d}"
        source_dir = root_dir / f"{archive_id}_src"
        source_dir.mkdir(parents=True, exist_ok=True)
        marker_name = f"{archive_id}.marker.txt"
        marker_text = f"concurrency-benchmark::{archive_id}"
        (source_dir / marker_name).write_text(marker_text, encoding="utf-8")
        (source_dir / "notes.txt").write_text(f"id={archive_id}\n", encoding="utf-8")
        write_payload_file(source_dir / "payload.bin", payload_mb, index + 1, data_mode)
        archive_path = root_dir / f"{archive_id}.7z"
        create_archive(source_dir, archive_path)
        shutil.rmtree(source_dir)
        metadata.append(
            {
                "archive_id": archive_id,
                "archive_name": archive_path.name,
                "marker_name": marker_name,
                "marker_text": marker_text,
            }
        )
    return metadata


def parse_mode(raw_mode: str, max_workers_limit: int) -> dict[str, Any]:
    if raw_mode == "adaptive":
        return {"name": "adaptive", "kind": "adaptive"}
    if raw_mode == "relaxed":
        return {"name": "relaxed", "kind": "relaxed"}
    if raw_mode.startswith("fixed:"):
        value = raw_mode.split(":", 1)[1]
        limit = max_workers_limit if value == "max" else int(value)
        return {"name": f"fixed:{value}", "kind": "fixed", "limit": max(1, limit)}
    raise ValueError(f"Unsupported mode: {raw_mode}")


def summarize_samples(samples: list[SamplePoint]) -> dict[str, float]:
    if not samples:
        return {
            "peak_active_workers": 0,
            "avg_active_workers": 0.0,
            "peak_concurrency_limit": 0,
            "avg_concurrency_limit": 0.0,
            "peak_cpu_percent": 0.0,
            "avg_cpu_percent": 0.0,
            "peak_disk_mbps": 0.0,
            "avg_disk_mbps": 0.0,
            "peak_rss_mb": 0.0,
        }
    return {
        "peak_active_workers": max(point.active_workers for point in samples),
        "avg_active_workers": round(statistics.mean(point.active_workers for point in samples), 3),
        "peak_concurrency_limit": max(point.concurrency_limit for point in samples),
        "avg_concurrency_limit": round(statistics.mean(point.concurrency_limit for point in samples), 3),
        "peak_cpu_percent": round(max(point.cpu_percent for point in samples), 3),
        "avg_cpu_percent": round(statistics.mean(point.cpu_percent for point in samples), 3),
        "peak_disk_mbps": round(max(point.disk_mbps for point in samples), 3),
        "avg_disk_mbps": round(statistics.mean(point.disk_mbps for point in samples), 3),
        "peak_rss_mb": round(max(point.rss_mb for point in samples), 3),
    }


def count_successes(root_dir: Path, metadata: list[dict[str, str]]) -> int:
    success = 0
    for item in metadata:
        for marker in root_dir.rglob(item["marker_name"]):
            if marker.read_text(encoding="utf-8", errors="ignore") == item["marker_text"]:
                success += 1
                break
    return success


def make_engine_class(mode_spec: dict[str, Any]):
    class BenchmarkEngine(DecompressionEngine):
        def __init__(self, *args, **kwargs):
            super().__init__(*args, **kwargs)
            self.MIN_SIZE = 0
            self.samples: list[SamplePoint] = []
            self.extract_observed_active_workers: list[int] = []
            self._benchmark_stop = threading.Event()
            self._sampler_thread: threading.Thread | None = None
            self._mode_spec = mode_spec

        def start_sampler(self) -> None:
            process = psutil.Process(os.getpid())
            psutil.cpu_percent(interval=None)
            last_disk = psutil.disk_io_counters()
            last_time = time.perf_counter()

            def sample_loop() -> None:
                nonlocal last_disk, last_time
                while not self._benchmark_stop.is_set():
                    now_time = time.perf_counter()
                    cpu = psutil.cpu_percent(interval=None)
                    rss_mb = process.memory_info().rss / BYTES_IN_MB
                    disk = psutil.disk_io_counters()
                    disk_mbps = 0.0
                    if last_disk and disk:
                        delta_bytes = (disk.read_bytes + disk.write_bytes) - (last_disk.read_bytes + last_disk.write_bytes)
                        delta_time = max(now_time - last_time, 1e-6)
                        disk_mbps = delta_bytes / delta_time / BYTES_IN_MB
                    with self.lock:
                        self.samples.append(
                            SamplePoint(
                                timestamp=now_time,
                                cpu_percent=cpu,
                                rss_mb=round(rss_mb, 3),
                                disk_mbps=round(disk_mbps, 3),
                                active_workers=self.active_workers,
                                concurrency_limit=self.current_concurrency_limit,
                            )
                        )
                    last_disk = disk
                    last_time = now_time
                    time.sleep(0.2)

            self._sampler_thread = threading.Thread(target=sample_loop, daemon=True)
            self._sampler_thread.start()

        def stop_sampler(self) -> None:
            self._benchmark_stop.set()
            if self._sampler_thread:
                self._sampler_thread.join(timeout=2)

        def extract(self, task):
            stop_event = threading.Event()

            def observe_extract_activity() -> None:
                while not stop_event.is_set():
                    with self.lock:
                        self.extract_observed_active_workers.append(self.active_workers)
                    time.sleep(0.02)

            observer = threading.Thread(target=observe_extract_activity, daemon=True)
            observer.start()
            try:
                return super().extract(task)
            finally:
                stop_event.set()
                observer.join(timeout=0.2)

        def adjust_workers(self):
            kind = self._mode_spec["kind"]
            if kind == "adaptive":
                return super().adjust_workers()

            if kind == "fixed":
                target_limit = min(self.max_workers_limit, self._mode_spec["limit"])
                with self.concurrency_cond:
                    self.dynamic_floor_workers = target_limit
                    self.current_concurrency_limit = target_limit
                    self.concurrency_cond.notify_all()
                while self.is_running:
                    time.sleep(0.5)
                return

            if kind == "relaxed":
                last = psutil.disk_io_counters()
                last_bytes = (last.read_bytes + last.write_bytes) if last else 0
                with self.concurrency_cond:
                    self.current_concurrency_limit = min(max(6, self.current_concurrency_limit), self.max_workers_limit)
                    self.dynamic_floor_workers = min(max(4, self.dynamic_floor_workers), self.max_workers_limit)
                    self.concurrency_cond.notify_all()
                while self.is_running:
                    time.sleep(1)
                    now = psutil.disk_io_counters()
                    if not now:
                        continue
                    now_bytes = now.read_bytes + now.write_bytes
                    delta = now_bytes - last_bytes
                    last_bytes = now_bytes
                    self.io_history.append(delta)
                    avg_delta = sum(self.io_history) / len(self.io_history)

                    with self.concurrency_cond:
                        backlog = self.pending_task_estimate
                        if self.max_workers_limit <= 1:
                            dynamic_floor = 1
                        elif backlog >= max(24, self.max_workers_limit * 3):
                            dynamic_floor = min(6, self.max_workers_limit)
                        elif backlog >= max(8, self.max_workers_limit * 2):
                            dynamic_floor = min(4, self.max_workers_limit)
                        else:
                            dynamic_floor = min(2, self.max_workers_limit)
                        self.dynamic_floor_workers = dynamic_floor

                        old_limit = self.current_concurrency_limit
                        near_capacity = self.active_workers >= max(1, self.current_concurrency_limit - 1)

                        if avg_delta < 80 * BYTES_IN_MB or (
                            backlog > self.current_concurrency_limit * 2 and avg_delta < 160 * BYTES_IN_MB
                        ):
                            self.scale_up_streak += 1
                            self.scale_down_streak = 0
                        elif avg_delta > 400 * BYTES_IN_MB and near_capacity and backlog <= self.current_concurrency_limit * 4:
                            self.scale_down_streak += 1
                            self.scale_up_streak = 0
                        else:
                            self.scale_up_streak = 0
                            self.scale_down_streak = 0

                        if self.scale_up_streak >= 2 and self.current_concurrency_limit < self.max_workers_limit:
                            step = 2 if backlog >= self.current_concurrency_limit * 3 else 1
                            self.current_concurrency_limit = min(self.max_workers_limit, self.current_concurrency_limit + step)
                            self.scale_up_streak = 0
                        elif self.scale_down_streak >= 2 and self.current_concurrency_limit > dynamic_floor:
                            self.current_concurrency_limit = max(dynamic_floor, self.current_concurrency_limit - 1)
                            self.scale_down_streak = 0

                        self.current_concurrency_limit = max(
                            dynamic_floor,
                            min(self.current_concurrency_limit, self.max_workers_limit),
                        )
                        if old_limit != self.current_concurrency_limit:
                            self.concurrency_cond.notify_all()
                return

            raise RuntimeError(f"Unknown benchmark kind: {kind}")

    return BenchmarkEngine


def run_single_case(
    temp_root: Path,
    mode_spec: dict[str, Any],
    archives: int,
    payload_mb: int,
    data_mode: str,
    max_workers_override: int,
    keep_case_root: bool,
) -> tuple[RunMetrics, list[dict[str, Any]], Path]:
    case_root = temp_root / mode_spec["name"].replace(":", "_")
    case_root.mkdir(parents=True, exist_ok=True)
    metadata = generate_dataset(case_root, archives=archives, payload_mb=payload_mb, data_mode=data_mode)

    EngineClass = make_engine_class(mode_spec)
    logs: list[str] = []
    engine = EngineClass(str(case_root), [], logs.append, lambda: None, use_builtin_passwords=False)
    detected_max_workers = engine.max_workers_limit
    if max_workers_override > 0:
        engine.max_workers_limit = max_workers_override
    engine.max_workers_limit = max(1, engine.max_workers_limit)
    engine.current_concurrency_limit = min(engine.current_concurrency_limit, engine.max_workers_limit)

    if mode_spec["kind"] == "fixed":
        fixed_limit = min(engine.max_workers_limit, mode_spec["limit"])
        engine.dynamic_floor_workers = fixed_limit
        engine.current_concurrency_limit = fixed_limit
    elif mode_spec["kind"] == "relaxed":
        engine.dynamic_floor_workers = min(max(4, engine.dynamic_floor_workers), engine.max_workers_limit)
        engine.current_concurrency_limit = min(max(6, engine.current_concurrency_limit), engine.max_workers_limit)

    start = time.perf_counter()
    engine.start_sampler()
    try:
        summary = engine.run()
    finally:
        engine.stop_sampler()
    elapsed = time.perf_counter() - start

    aggregate = summarize_samples(engine.samples)
    observed_peak = max(engine.extract_observed_active_workers, default=0)
    success_count = count_successes(case_root, metadata)
    failure_count = archives - success_count

    metrics = RunMetrics(
        mode=mode_spec["name"],
        elapsed_seconds=round(elapsed, 4),
        archive_count=archives,
        payload_mb=payload_mb,
        detected_max_workers=detected_max_workers,
        configured_max_workers=engine.max_workers_limit,
        final_concurrency_limit=engine.current_concurrency_limit,
        success_count=success_count,
        failure_count=failure_count,
        peak_active_workers=max(int(aggregate["peak_active_workers"]), observed_peak),
        avg_active_workers=aggregate["avg_active_workers"],
        peak_concurrency_limit=int(aggregate["peak_concurrency_limit"]),
        avg_concurrency_limit=aggregate["avg_concurrency_limit"],
        peak_cpu_percent=aggregate["peak_cpu_percent"],
        avg_cpu_percent=aggregate["avg_cpu_percent"],
        peak_disk_mbps=aggregate["peak_disk_mbps"],
        avg_disk_mbps=aggregate["avg_disk_mbps"],
        peak_rss_mb=aggregate["peak_rss_mb"],
        output_root=str(case_root),
        failed_tasks=list(summary.failed_tasks),
    )
    samples_payload = [asdict(sample) for sample in engine.samples]
    if not keep_case_root:
        safe_rmtree(case_root)
    return metrics, samples_payload, case_root


def print_summary(run_results: list[RunMetrics]) -> None:
    if not run_results:
        return
    baseline = min(run_results, key=lambda item: item.elapsed_seconds)
    print()
    print("Mode               Time(s)  PeakW  AvgW   PeakCPU  AvgCPU  PeakDiskMB/s  AvgDiskMB/s  Success")
    print("-" * 98)
    for item in run_results:
        print(
            f"{item.mode:<18} "
            f"{item.elapsed_seconds:>7.2f} "
            f"{item.peak_active_workers:>6} "
            f"{item.avg_active_workers:>5.2f} "
            f"{item.peak_cpu_percent:>8.1f} "
            f"{item.avg_cpu_percent:>7.1f} "
            f"{item.peak_disk_mbps:>13.1f} "
            f"{item.avg_disk_mbps:>12.1f} "
            f"{item.success_count:>7}/{item.archive_count:<7}"
        )
    print()
    print(f"Fastest mode: {baseline.mode} ({baseline.elapsed_seconds:.2f}s)")
    for item in run_results:
        slowdown = item.elapsed_seconds / baseline.elapsed_seconds if baseline.elapsed_seconds else 1.0
        print(
            f"  {item.mode}: "
            f"final_limit={item.final_concurrency_limit}, "
            f"peak_workers={item.peak_active_workers}, "
            f"avg_cpu={item.avg_cpu_percent:.1f}%, "
            f"avg_disk={item.avg_disk_mbps:.1f} MB/s, "
            f"time_ratio={slowdown:.2f}x"
        )


def main() -> int:
    args = build_parser().parse_args()
    ensure_prerequisites()

    temp_dir_obj: tempfile.TemporaryDirectory[str] | None = None
    if args.keep_temp:
        temp_root = Path(tempfile.mkdtemp(prefix="smart-unpacker-bench-", dir=str(REPO_ROOT)))
    else:
        temp_dir_obj = tempfile.TemporaryDirectory(prefix="smart-unpacker-bench-", dir=str(REPO_ROOT))
        temp_root = Path(temp_dir_obj.name)

    results_payload: dict[str, Any] = {
        "created_at": time.strftime("%Y-%m-%d %H:%M:%S"),
        "temp_root": str(temp_root),
        "archives": args.archives,
        "payload_mb": args.payload_mb,
        "data_mode": args.data_mode,
        "max_workers_override": args.max_workers,
        "repeat": args.repeat,
        "keep_temp": bool(args.keep_temp),
        "prune_stale_temp": bool(args.prune_stale_temp),
        "runs": [],
    }

    try:
        if args.prune_stale_temp:
            removed_roots = prune_stale_temp_roots(current_root=temp_root)
            results_payload["pruned_temp_roots"] = removed_roots
            if removed_roots:
                print(f"Pruned {len(removed_roots)} stale benchmark directories.")

        all_metrics: list[RunMetrics] = []
        for round_index in range(args.repeat):
            round_root = temp_root / f"round_{round_index + 1:02d}"
            round_root.mkdir(parents=True, exist_ok=True)
            print(f"Running round {round_index + 1}/{args.repeat} in {round_root}")
            for raw_mode in args.modes:
                mode_spec = parse_mode(raw_mode, max_workers_limit=max(args.max_workers, 1) if args.max_workers else os.cpu_count() or 4)
                print(f"  -> mode={mode_spec['name']}")
                metrics, samples, case_root = run_single_case(
                    temp_root=round_root,
                    mode_spec=mode_spec,
                    archives=args.archives,
                    payload_mb=args.payload_mb,
                    data_mode=args.data_mode,
                    max_workers_override=args.max_workers,
                    keep_case_root=args.keep_temp,
                )
                all_metrics.append(metrics)
                results_payload["runs"].append(
                    {
                        "round": round_index + 1,
                        "mode": metrics.mode,
                        "metrics": asdict(metrics),
                        "samples": samples,
                        "output_root": str(case_root),
                    }
                )
            if not args.keep_temp:
                safe_rmtree(round_root)

        print_summary(all_metrics)
        if args.report_json:
            report_path = Path(args.report_json)
            report_path.parent.mkdir(parents=True, exist_ok=True)
            report_path.write_text(json.dumps(results_payload, ensure_ascii=False, indent=2), encoding="utf-8")
            print(f"\nWrote JSON report to {report_path}")
        elif args.keep_temp:
            default_report = temp_root / "concurrency_benchmark_report.json"
            default_report.write_text(json.dumps(results_payload, ensure_ascii=False, indent=2), encoding="utf-8")
            print(f"\nWrote JSON report to {default_report}")
        return 0
    finally:
        if temp_dir_obj is not None:
            temp_dir_obj.cleanup()


if __name__ == "__main__":
    raise SystemExit(main())
