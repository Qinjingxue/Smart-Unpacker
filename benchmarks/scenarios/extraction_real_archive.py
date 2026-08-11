"""Measure end-to-end extraction time and peak process-tree RSS.

This benchmark intentionally runs each extractor in a fresh subprocess.  RSS is
sampled for the parent and all descendants, so persistent/native 7-Zip workers
are included instead of only measuring the Python coordinator process.
"""
from __future__ import annotations

import argparse
import json
import os
import shutil
import statistics
import subprocess
import sys
import tempfile
import time
from pathlib import Path

import psutil

from benchmarks.harness import render_report, report_from_payload


ROOT = Path(__file__).resolve().parents[2]


def output_summary(root: Path) -> dict:
    file_count = 0
    total_bytes = 0
    extensions: dict[str, int] = {}
    sample_paths: list[str] = []
    for directory, _dirs, files in os.walk(root):
        for name in files:
            path = Path(directory, name)
            try:
                total_bytes += path.stat().st_size
                file_count += 1
                extension = path.suffix.lower() or "<none>"
                extensions[extension] = extensions.get(extension, 0) + 1
                if len(sample_paths) < 20:
                    sample_paths.append(path.relative_to(root).as_posix())
            except OSError:
                pass
    return {
        "file_count": file_count,
        "total_bytes": total_bytes,
        "extensions": dict(sorted(extensions.items())),
        "sample_paths": sample_paths,
    }


def sunpack_service_processes() -> list[psutil.Process]:
    members = []
    for process in psutil.process_iter(("name", "cmdline")):
        try:
            name = (process.info["name"] or "").lower()
            command = " ".join(process.info["cmdline"] or []).lower()
            if name == "sunpack_sevenzip_worker.exe" or (
                "sunpack.py" in command and "--persistent-server" in command
            ):
                members.append(process)
        except (psutil.NoSuchProcess, psutil.AccessDenied):
            pass
    return members


def rss_for(processes: list[psutil.Process]) -> tuple[int, int]:
    rss = 0
    live = 0
    seen: set[int] = set()
    for process in processes:
        if process.pid in seen:
            continue
        seen.add(process.pid)
        try:
            rss += process.memory_info().rss
            live += 1
        except (psutil.NoSuchProcess, psutil.AccessDenied):
            pass
    return rss, live


def run_measured(command: list[str], output_dir: Path, sample_ms: int) -> dict:
    idle_service_rss, idle_service_count = rss_for(sunpack_service_processes())
    started = time.perf_counter()
    process = subprocess.Popen(
        command,
        cwd=ROOT,
        stdin=subprocess.DEVNULL,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
    )
    root_process = psutil.Process(process.pid)
    peak_tree_rss = 0
    peak_process_count = 0
    samples = 0

    while process.poll() is None:
        try:
            members = [root_process, *root_process.children(recursive=True)]
        except (psutil.NoSuchProcess, psutil.AccessDenied):
            members = []
        services = sunpack_service_processes()
        members.extend(services)
        for service in services:
            try:
                members.extend(service.children(recursive=True))
            except (psutil.NoSuchProcess, psutil.AccessDenied):
                pass
        tree_rss, live_count = rss_for(members)
        peak_tree_rss = max(peak_tree_rss, tree_rss)
        peak_process_count = max(peak_process_count, live_count)
        samples += 1
        time.sleep(sample_ms / 1000)

    elapsed = time.perf_counter() - started
    return {
        "exit_code": process.returncode,
        "elapsed_seconds": elapsed,
        "peak_tree_rss_bytes": peak_tree_rss,
        "peak_tree_rss_mib": peak_tree_rss / 1024**2,
        "idle_service_rss_bytes": idle_service_rss,
        "idle_service_rss_mib": idle_service_rss / 1024**2,
        "incremental_peak_rss_mib": max(0, peak_tree_rss - idle_service_rss) / 1024**2,
        "idle_service_process_count": idle_service_count,
        "peak_process_count": peak_process_count,
        "rss_samples": samples,
        "output": output_summary(output_dir),
    }


def command_for(archive: Path, output: Path, password: str, recursive: str) -> list[str]:
    command = [
        sys.executable,
        "-m",
        "sunpack",
        "extract",
        "--direct-file",
        "--recur",
        recursive,
        "--cleanup",
        "k",
        "--no-flatten",
        "--no-builtin-pw",
        "--no-dir-pw",
        "--quiet",
        "--no-pause",
        "-o",
        str(output),
    ]
    if password:
        command.extend(["--password", password])
    return [*command, str(archive)]


def median_success(rows: list[dict], field: str) -> float | None:
    values = [float(row[field]) for row in rows if row["exit_code"] == 0]
    return statistics.median(values) if values else None


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("archive", type=Path)
    parser.add_argument("--password", default="")
    parser.add_argument("--recursive", default="*", help="SunPack recursive extraction mode (default: *)")
    parser.add_argument("--runs", type=int, default=3)
    parser.add_argument("--sample-ms", type=int, default=10)
    parser.add_argument("--json-out", type=Path)
    parser.add_argument("--work-dir", type=Path)
    args = parser.parse_args()

    archive = args.archive.resolve()
    if not archive.is_file():
        parser.error(f"archive does not exist: {archive}")
    owned_temp = None
    if args.work_dir:
        work = args.work_dir.resolve()
        work.mkdir(parents=True, exist_ok=True)
    else:
        owned_temp = tempfile.TemporaryDirectory(prefix="sunpack-real-extract-")
        work = Path(owned_temp.name)

    rows: list[dict] = []
    try:
        for run in range(max(1, args.runs)):
            output = work / f"sunpack-{run}"
            shutil.rmtree(output, ignore_errors=True)
            output.mkdir(parents=True)
            row = run_measured(
                command_for(archive, output, args.password, args.recursive),
                output,
                max(1, args.sample_ms),
            )
            row["run"] = run + 1
            rows.append(row)
            shutil.rmtree(output, ignore_errors=True)
    finally:
        if owned_temp is not None:
            owned_temp.cleanup()

    report = {
        "schema_version": 1,
        "archive": {"path": str(archive), "bytes": archive.stat().st_size},
        "sunpack_recursive_mode": args.recursive,
        "environment": {
            "python": sys.version,
            "platform": sys.platform,
            "cpu_count": os.cpu_count(),
            "rss_sample_interval_ms": max(1, args.sample_ms),
        },
        "runs": {"sunpack": rows},
        "summary": {
            "sunpack": {
                "successful_runs": sum(row["exit_code"] == 0 for row in rows),
                "median_elapsed_seconds": median_success(rows, "elapsed_seconds"),
                "median_peak_tree_rss_mib": median_success(rows, "peak_tree_rss_mib"),
                "median_incremental_peak_rss_mib": median_success(rows, "incremental_peak_rss_mib"),
                "outputs_consistent": len({
                    (row["output"]["file_count"], row["output"]["total_bytes"])
                    for row in rows if row["exit_code"] == 0
                }) <= 1,
            }
        },
    }
    rendered = render_report(report_from_payload("extraction.real-archive", report))
    print(rendered)
    if args.json_out:
        args.json_out.parent.mkdir(parents=True, exist_ok=True)
        args.json_out.write_text(rendered, encoding="utf-8")
    return 0 if all(row["exit_code"] == 0 for row in rows) else 1


if __name__ == "__main__":
    raise SystemExit(main())
