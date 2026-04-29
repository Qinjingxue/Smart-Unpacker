"""Small, one-layer probes for root scan performance.

Examples:
    .\.venv\Scripts\python.exe tests\performance\scan_layer_probe.py dir-config .
    .\.venv\Scripts\python.exe tests\performance\scan_layer_probe.py relations .
"""

from __future__ import annotations

import argparse
import gc
import faulthandler
import os
import sys
import time
import tracemalloc
from collections import Counter
from pathlib import Path
from typing import Callable

import psutil


REPO_ROOT = Path(__file__).resolve().parents[2]
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))


def mib(value: int | float) -> float:
    return float(value) / 1024 / 1024


def rss() -> int:
    return psutil.Process(os.getpid()).memory_info().rss


def summarize_snapshot(snapshot) -> dict:
    entries = list(getattr(snapshot, "entries", []) or [])
    root = Path(getattr(snapshot, "root_path", Path.cwd()))
    top = Counter()
    files = dirs = 0
    total_size = 0
    for entry in entries:
        if entry.is_dir:
            dirs += 1
        else:
            files += 1
            total_size += int(entry.size or 0)
        try:
            rel = Path(entry.path).relative_to(root)
            top[rel.parts[0] if rel.parts else "."] += 1
        except ValueError:
            top["<outside>"] += 1
    return {
        "entries": len(entries),
        "files": files,
        "dirs": dirs,
        "total_file_size_mib": round(mib(total_size), 1),
        "top": top.most_common(15),
    }


def run_measured(name: str, fn: Callable[[], object]) -> object:
    gc.collect()
    before = rss()
    tracemalloc.start(15)
    started = time.perf_counter()
    result = fn()
    elapsed = time.perf_counter() - started
    current, peak = tracemalloc.get_traced_memory()
    top_stats = tracemalloc.take_snapshot().statistics("lineno")[:10]
    tracemalloc.stop()
    after = rss()
    print(f"== {name} ==")
    print(f"elapsed_sec={elapsed:.3f}")
    print(f"rss_before_mib={mib(before):.1f}")
    print(f"rss_after_mib={mib(after):.1f}")
    print(f"rss_delta_mib={mib(after - before):.1f}")
    print(f"tracemalloc_current_mib={mib(current):.1f}")
    print(f"tracemalloc_peak_mib={mib(peak):.1f}")
    for stat in top_stats:
        frame = stat.traceback[0]
        print(f"alloc {mib(stat.size):7.1f} MiB {stat.count:8d} {frame.filename}:{frame.lineno}")
    return result


def load_runtime_config() -> dict:
    from sunpack.config.loader import load_config

    return load_config()


def cmd_dir_config(target: str, depth: int | None) -> None:
    from sunpack.filesystem.directory_scanner import DirectoryScanner

    snapshot = run_measured(
        "DirectoryScanner configured",
        lambda: DirectoryScanner(target, max_depth=depth, config=load_runtime_config()).scan(),
    )
    print(summarize_snapshot(snapshot))


def cmd_dir_empty(target: str, depth: int | None) -> None:
    from sunpack.filesystem.directory_scanner import DirectoryScanner

    snapshot = run_measured(
        "DirectoryScanner empty-config",
        lambda: DirectoryScanner(target, max_depth=depth, config={}).scan(),
    )
    print(summarize_snapshot(snapshot))


def cmd_relations(target: str, depth: int | None) -> None:
    from sunpack.filesystem.directory_scanner import DirectoryScanner
    from sunpack.relations.scheduler import RelationsScheduler

    snapshot = DirectoryScanner(target, max_depth=depth, config=load_runtime_config()).scan()
    print(summarize_snapshot(snapshot))
    groups = run_measured(
        "RelationsScheduler.build_candidate_groups",
        lambda: RelationsScheduler().build_candidate_groups(snapshot),
    )
    print({"groups": len(groups)})


def cmd_fact_bags(target: str) -> None:
    from sunpack.detection.internal.scan_session import DetectionScanSession

    session = DetectionScanSession(config=load_runtime_config())
    bags = run_measured(
        "DetectionScanSession.fact_bags_for_directory",
        lambda: session.fact_bags_for_directory(str(Path(target).resolve())),
    )
    print({"bags": len(bags)})


class MemoryStop(RuntimeError):
    pass


def cmd_evaluate_watch(target: str, rss_stop_mib: float | None) -> None:
    import sunpack.filesystem.directory_scanner as directory_scanner
    from sunpack.detection.scheduler import DetectionScheduler

    counts = Counter()
    original_scan = directory_scanner.DirectoryScanner.scan

    def guard(label: str) -> None:
        current = mib(rss())
        if rss_stop_mib is not None and current >= rss_stop_mib:
            print(f"stopping_in={label} rss_mib={current:.1f}", flush=True)
            faulthandler.dump_traceback(file=sys.stdout)
            raise MemoryStop(label)

    def scan_wrapper(self):
        counts["DirectoryScanner.scan"] += 1
        guard("DirectoryScanner.scan:before")
        started = time.perf_counter()
        result = original_scan(self)
        elapsed = time.perf_counter() - started
        entries = len(getattr(result, "entries", []) or [])
        root = getattr(result, "root_path", "")
        if counts["DirectoryScanner.scan"] <= 20 or counts["DirectoryScanner.scan"] % 25 == 0:
            print(
                f"scan#{counts['DirectoryScanner.scan']} entries={entries} "
                f"sec={elapsed:.3f} rss_mib={mib(rss()):.1f} root={root}",
                flush=True,
            )
        guard("DirectoryScanner.scan:after")
        return result

    directory_scanner.DirectoryScanner.scan = scan_wrapper
    faulthandler.enable(file=sys.stdout)
    started = time.perf_counter()
    before = rss()
    try:
        scheduler = DetectionScheduler(load_runtime_config())
        bags = scheduler.build_candidate_fact_bags([str(Path(target).resolve())])
        print({"bags": len(bags), "rss_after_bags_mib": round(mib(rss()), 1)}, flush=True)
        result = scheduler.evaluate_bags(bags)
        print({"detections": len(result)}, flush=True)
    except MemoryStop as exc:
        print(f"memory_stop={exc}", flush=True)
    finally:
        print(f"elapsed_sec={time.perf_counter() - started:.3f}")
        print(f"rss_start_mib={mib(before):.1f}")
        print(f"rss_end_mib={mib(rss()):.1f}")
        print(dict(counts))


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument(
        "probe",
        choices=[
            "dir-config",
            "dir-empty",
            "relations",
            "fact-bags",
            "evaluate-watch",
        ],
    )
    parser.add_argument("target", nargs="?", default=".")
    parser.add_argument("--depth", type=int, default=None)
    parser.add_argument("--limit", type=int, default=None)
    parser.add_argument("--rss-stop-mib", type=float, default=None)
    args = parser.parse_args()

    os.chdir(REPO_ROOT)
    target = str(Path(args.target).resolve())
    if args.probe == "dir-config":
        cmd_dir_config(target, args.depth)
    elif args.probe == "dir-empty":
        cmd_dir_empty(target, args.depth)
    elif args.probe == "relations":
        cmd_relations(target, args.depth)
    elif args.probe == "fact-bags":
        cmd_fact_bags(target)
    elif args.probe == "evaluate-watch":
        cmd_evaluate_watch(target, args.rss_stop_mib)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
