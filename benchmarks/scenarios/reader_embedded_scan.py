from __future__ import annotations

import argparse
import gc
import os
import random
import statistics
import subprocess
import sys
import time
import zipfile
from pathlib import Path

from sunpack_native import NativeArchiveSession, clear_reader_resources, reader_cache_stats

from benchmarks.harness import (
    BenchmarkWorkspace,
    ProcessSampler,
    measure,
    metrics_delta,
    render_report,
    report_from_payload,
)


REPO_ROOT = Path(__file__).resolve().parents[2]
DEFAULT_SAMPLE = REPO_ROOT / "testfiles" / "R243V1.mp4"
SCENARIO = "reader.embedded-scan"


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Benchmark full SunPack scan and native embedded archive scanning."
    )
    parser.add_argument("path", nargs="?", type=Path, default=DEFAULT_SAMPLE)
    parser.add_argument("--rounds", type=int, default=3)
    parser.add_argument("--skip-cli", action="store_true")
    parser.add_argument(
        "--generate-gib",
        type=float,
        default=0.0,
        help="Generate a stored ZIP64 fixture of this size and benchmark it (for example, 10).",
    )
    parser.add_argument(
        "--iocp-chunk-mib",
        action="append",
        type=float,
        help="Logical chunk size for IOCP mode; repeat to sweep values (default: 2 MiB).",
    )
    parser.add_argument(
        "--iocp-buffers",
        action="append",
        type=int,
        help="Maximum in-flight IOCP buffers; repeat to sweep values (default: 8).",
    )
    parser.add_argument(
        "--iocp-workers",
        action="append",
        type=int,
        help="IOCP scan workers; repeat to sweep values (default: 2).",
    )
    parser.add_argument("--sample-interval", type=float, default=0.1)
    parser.add_argument("--results-root", type=Path)
    parser.add_argument("--keep-workdir", action="store_true")
    return parser.parse_args()


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


def benchmark_native(
    path: Path,
    rounds: int,
    sample_interval: float,
    iocp_chunk_mib: float = 2.0,
    iocp_buffers: int = 8,
    iocp_workers: int = 2,
) -> dict:
    clear_reader_resources()
    session = NativeArchiveSession(str(path))
    before = dict(reader_cache_stats())
    iocp_chunk_bytes = max(64 * 1024, int(iocp_chunk_mib * 1024**2))

    def invoke() -> dict:
        result = dict(
            session.scan_embedded_archives(
                iocp_chunk_bytes=iocp_chunk_bytes,
                iocp_buffers=iocp_buffers,
                iocp_workers=iocp_workers,
            )
        )
        assert result["complete"] is True
        assert int(result["read_bytes"]) == path.stat().st_size
        return result

    sampler = ProcessSampler(interval_seconds=sample_interval)
    sampler.start()
    try:
        measured = measure(invoke, runs=rounds)
    finally:
        process_samples = sampler.stop()

    rows = [{
        "round": row.iteration + 1,
        "wall_ms": round(row.wall_ms, 3),
        "cpu_ms": round(row.cpu_ms, 3),
        "hits": len(row.value["hits"]),
        "candidates": len(row.value["candidates"]),
        "read_bytes": int(row.value["read_bytes"]),
    } for row in measured]
    last_result = measured[-1].value
    after_scan = dict(reader_cache_stats())
    gc.collect()
    cleared = dict(clear_reader_resources())
    after_clear = dict(reader_cache_stats())
    wall_values = [row["wall_ms"] for row in rows]
    size = path.stat().st_size
    median_ms = statistics.median(wall_values)
    peak = max(process_samples, key=lambda sample: sample.rss_mib, default=None)
    peak_private = max(process_samples, key=lambda sample: sample.private_mib, default=None)
    return {
        "rounds": rows,
        "wall_median_ms": round(median_ms, 3),
        "throughput_gb_s": round(size / 1_000_000_000 / (median_ms / 1000), 3),
        "throughput_gib_s": round(size / (1024**3) / (median_ms / 1000), 3),
        "io_mode": "iocp",
        "scan_read_bytes": int(last_result.get("scan_read_bytes") or 0),
        "scan_read_operations": int(last_result.get("scan_read_operations") or 0),
        "iocp_chunk_mib": round(iocp_chunk_mib, 3),
        "iocp_chunk_bytes": iocp_chunk_bytes,
        "iocp_buffers": iocp_buffers,
        "iocp_workers": iocp_workers,
        "reader_delta": metrics_delta(before, after_scan),
        "reader_after_scan": after_scan,
        "reader_after_clear": after_clear,
        "reader_cleanup": cleared,
        "memory": {
            "sample_interval_seconds": sample_interval,
            "sample_count": len(process_samples),
            "peak_rss_mib": round(peak.rss_mib, 3) if peak else 0.0,
            "peak_private_mib": round(peak_private.private_mib, 3) if peak_private else 0.0,
            "peak_rss_sample": peak.to_dict() if peak else None,
            "peak_private_sample": peak_private.to_dict() if peak_private else None,
            "after_scan_sample": process_samples[-1].to_dict() if process_samples else None,
        },
        "validated_candidates": last_result["candidates"],
    }


def generate_stored_zip64(path: Path, payload_gib: float) -> Path:
    """Create a large stored ZIP without retaining the payload in Python memory."""

    payload_size = int(payload_gib * 1024**3)
    if payload_size < 1:
        raise ValueError("payload_gib must be positive")
    path.parent.mkdir(parents=True, exist_ok=True)
    pattern = b"sunpack-embedded-scan-benchmark\n"
    block = (pattern * ((1024 * 1024 // len(pattern)) + 1))[: 1024 * 1024]
    with zipfile.ZipFile(path, "w", compression=zipfile.ZIP_STORED) as archive:
        info = zipfile.ZipInfo("payload.bin")
        info.compress_type = zipfile.ZIP_STORED
        with archive.open(info, "w", force_zip64=payload_size > 0xFFFFFFFF) as writer:
            remaining = payload_size
            while remaining:
                chunk_size = min(remaining, len(block))
                writer.write(block[:chunk_size])
                remaining -= chunk_size
    return path


def run_report(path: Path, args: argparse.Namespace, config: dict[str, object]) -> dict:
    path = path.resolve()
    if not path.is_file():
        raise SystemExit(f"sample does not exist: {path}")
    if args.rounds < 1:
        raise SystemExit("rounds must be positive")
    if args.sample_interval <= 0:
        raise SystemExit("sample-interval must be positive")
    if float(config.get("iocp_chunk_mib", 2.0)) <= 0:
        raise SystemExit("iocp-chunk-mib must be positive")
    if int(config.get("iocp_buffers", 8)) < 2:
        raise SystemExit("iocp-buffers must be at least 2")
    if int(config.get("iocp_workers", 8)) < 1:
        raise SystemExit("iocp-workers must be positive")
    return {
        "path": str(path),
        "size_bytes": path.stat().st_size,
        "cli_scan": None if args.skip_cli else benchmark_cli(path),
        "native_embedded_scan": benchmark_native(
            path,
            args.rounds,
            args.sample_interval,
            float(config.get("iocp_chunk_mib", 2.0)),
            int(config.get("iocp_buffers", 8)),
            int(config.get("iocp_workers", 2)),
        ),
    }


def main() -> None:
    args = parse_args()
    if args.generate_gib < 0:
        raise SystemExit("generate-gib must be nonnegative")
    iocp_chunks = args.iocp_chunk_mib or [2.0]
    iocp_buffers = args.iocp_buffers or [8]
    iocp_workers = args.iocp_workers or [2]
    configs = [
        {
            "io_mode": "iocp",
            "iocp_chunk_mib": chunk,
            "iocp_buffers": buffers,
            "iocp_workers": workers,
        }
        for chunk in iocp_chunks
        for buffers in iocp_buffers
        for workers in iocp_workers
    ]
    if len(configs) > 1:
        random.Random(0x5343_494F).shuffle(configs)
    if args.generate_gib > 0:
        with BenchmarkWorkspace(
            SCENARIO,
            results_root=args.results_root,
            keep_workdir=args.keep_workdir,
        ) as workspace:
            path = generate_stored_zip64(
                workspace.corpus / "embedded-scan-large.zip", args.generate_gib
            )
            results = [run_report(path, args, config) for config in configs]
            generated_fixture = {
                "payload_gib": args.generate_gib,
                "compression": "stored",
                "zip64": True,
            }
            result = {
                "path": str(path.resolve()),
                "size_bytes": path.stat().st_size,
                "generated_fixture": generated_fixture,
                "window_results": results,
            }
            rendered = render_report(report_from_payload(SCENARIO, result))
            workspace.write_result_text("report.json", rendered)
            print(rendered)
        return
    results = [run_report(args.path, args, config) for config in configs]
    if len(results) == 1:
        print(render_report(report_from_payload(SCENARIO, results[0])))
    else:
        print(render_report(report_from_payload(SCENARIO, {
            "path": str(args.path.resolve()),
            "size_bytes": args.path.stat().st_size,
            "window_results": results,
        })))


if __name__ == "__main__":
    main()
