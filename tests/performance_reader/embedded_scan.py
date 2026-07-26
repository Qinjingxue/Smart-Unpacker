from __future__ import annotations

import argparse
import json
import os
import statistics
import subprocess
import sys
import time
from pathlib import Path

from sunpack_native import NativeArchiveSession, reader_cache_stats


REPO_ROOT = Path(__file__).resolve().parents[2]
DEFAULT_SAMPLE = REPO_ROOT / "testfiles" / "R243V1.mp4"


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Benchmark full sunpack scan and native embedded archive scanning."
    )
    parser.add_argument("path", nargs="?", type=Path, default=DEFAULT_SAMPLE)
    parser.add_argument("--rounds", type=int, default=3)
    parser.add_argument("--skip-cli", action="store_true")
    return parser.parse_args()


def metrics_delta(before: dict, after: dict) -> dict[str, int]:
    keys = (
        "logical_bytes",
        "physical_bytes",
        "physical_reads",
        "cache_hits",
        "cache_misses",
        "handle_hits",
    )
    return {key: int(after[key]) - int(before[key]) for key in keys}


def benchmark_cli(path: Path) -> dict:
    environment = os.environ.copy()
    started = time.perf_counter_ns()
    completed = subprocess.run(
        [
            sys.executable,
            "-m",
            "sunpack",
            "scan",
            "--json",
            "--quiet",
            "--no-pause",
            str(path),
        ],
        cwd=REPO_ROOT,
        env=environment,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.PIPE,
        text=True,
    )
    elapsed_ms = (time.perf_counter_ns() - started) / 1_000_000
    if completed.returncode:
        raise RuntimeError(
            f"sunpack scan failed ({completed.returncode}):\n{completed.stderr}"
        )
    return {"wall_ms": round(elapsed_ms, 3), "exit_code": completed.returncode}


def benchmark_native(path: Path, rounds: int) -> dict:
    session = NativeArchiveSession(str(path))
    before = dict(reader_cache_stats())
    rows = []
    last_result = None
    for index in range(rounds):
        wall_started = time.perf_counter_ns()
        cpu_started = time.process_time_ns()
        result = dict(session.scan_embedded_archives())
        wall_ms = (time.perf_counter_ns() - wall_started) / 1_000_000
        cpu_ms = (time.process_time_ns() - cpu_started) / 1_000_000
        assert result["complete"] is True
        assert int(result["read_bytes"]) == path.stat().st_size
        rows.append(
            {
                "round": index + 1,
                "wall_ms": round(wall_ms, 3),
                "cpu_ms": round(cpu_ms, 3),
                "hits": len(result["hits"]),
                "candidates": len(result["candidates"]),
                "read_bytes": int(result["read_bytes"]),
            }
        )
        last_result = result
    after = dict(reader_cache_stats())
    wall_values = [row["wall_ms"] for row in rows]
    size = path.stat().st_size
    median_ms = statistics.median(wall_values)
    return {
        "rounds": rows,
        "wall_median_ms": round(median_ms, 3),
        "throughput_gb_s": round(size / 1_000_000_000 / (median_ms / 1000), 3),
        "throughput_gib_s": round(size / (1024**3) / (median_ms / 1000), 3),
        "reader_delta": metrics_delta(before, after),
        "validated_candidates": last_result["candidates"],
    }


def main() -> None:
    args = parse_args()
    path = args.path.resolve()
    if args.rounds < 1:
        raise SystemExit("rounds must be positive")
    if not path.is_file():
        raise SystemExit(f"sample does not exist: {path}")
    result = {
        "path": str(path),
        "size_bytes": path.stat().st_size,
        "cli_scan": None if args.skip_cli else benchmark_cli(path),
        "native_embedded_scan": benchmark_native(path, args.rounds),
    }
    print(json.dumps(result, ensure_ascii=False, indent=2))


if __name__ == "__main__":
    main()
