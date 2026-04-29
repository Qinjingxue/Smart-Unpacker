"""Small, one-layer probes for root scan performance.

Examples:
    .\.venv\Scripts\python.exe tests\performance\scan_layer_probe.py dir-config .
    .\.venv\Scripts\python.exe tests\performance\scan_layer_probe.py scene-snapshot . --depth 1
    .\.venv\Scripts\python.exe tests\performance\scan_layer_probe.py relations .
    .\.venv\Scripts\python.exe tests\performance\scan_layer_probe.py scene-dir-walk . --limit 100
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


def cmd_scene_snapshot(target: str, depth: int) -> None:
    from sunpack.detection.internal.scan_session import DetectionScanSession

    session = DetectionScanSession(config=load_runtime_config())
    snapshot = run_measured(
        f"DetectionScanSession.scene_snapshot_for_directory depth={depth}",
        lambda: session.scene_snapshot_for_directory(str(Path(target).resolve()), max_depth=depth),
    )
    print(summarize_snapshot(snapshot))


def cmd_scene_markers(target: str, depth: int) -> None:
    from sunpack.detection.internal.scan_session import DetectionScanSession
    from sunpack.detection.pipeline.facts.collectors.scene_markers import _collect_scene_markers_for_directory
    from sunpack.detection.scene.definitions import scene_rules

    session = DetectionScanSession(config=load_runtime_config())
    rules = scene_rules({})
    directory = str(Path(target).resolve())
    snapshot = session.scene_snapshot_for_directory(directory, max_depth=depth)
    markers = run_measured(
        f"scene marker index/evaluate depth={depth}",
        lambda: _collect_scene_markers_for_directory(directory, rules, snapshot=snapshot),
    )
    print({"marker_count": len(markers), "markers": markers[:30]})


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
    import sunpack.detection.pipeline.facts.collectors.scene_markers as scene_markers
    from sunpack.detection.scheduler import DetectionScheduler

    counts = Counter()
    original_scan = directory_scanner.DirectoryScanner.scan
    original_scene_dir = scene_markers.collect_scene_markers_from_directory
    original_scene_snapshot = scene_markers.collect_scene_markers_from_snapshot

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

    def scene_dir_wrapper(directory, rules):
        counts["scene.from_directory"] += 1
        print(f"scene.from_directory#{counts['scene.from_directory']} rss_mib={mib(rss()):.1f} dir={directory}", flush=True)
        guard("scene.from_directory")
        return original_scene_dir(directory, rules)

    def scene_snapshot_wrapper(snapshot, rules):
        counts["scene.from_snapshot"] += 1
        return original_scene_snapshot(snapshot, rules)

    directory_scanner.DirectoryScanner.scan = scan_wrapper
    scene_markers.collect_scene_markers_from_directory = scene_dir_wrapper
    scene_markers.collect_scene_markers_from_snapshot = scene_snapshot_wrapper
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


def cmd_scene_dir_walk(target: str, limit: int | None, rss_stop_mib: float | None) -> None:
    from sunpack.detection.internal.scan_session import DetectionScanSession
    from sunpack.detection.pipeline.facts.collectors.scene_markers import (
        _scene_snapshot_depth,
        candidate_directories,
    )
    from sunpack.detection.scene.definitions import scene_rules
    from sunpack.support.path_keys import normalized_path, path_key

    rules = scene_rules({})
    depth = _scene_snapshot_depth(rules)
    session = DetectionScanSession(config=load_runtime_config())
    bags = session.fact_bags_for_directory(str(Path(target).resolve()))
    unique_dirs: list[str] = []
    seen: set[str] = set()
    for bag in bags:
        base_path = bag.get("file.path") or ""
        if not base_path:
            continue
        start_dir = os.path.dirname(os.path.abspath(base_path)) if os.path.isfile(base_path) else os.path.abspath(base_path)
        for directory in candidate_directories(start_dir, 4):
            normalized = normalized_path(directory)
            key = path_key(normalized)
            if key in seen:
                continue
            seen.add(key)
            unique_dirs.append(normalized)

    print({"bags": len(bags), "unique_scene_dirs": len(unique_dirs), "scene_snapshot_depth": depth})
    started = time.perf_counter()
    before = rss()
    total_entries = 0
    largest: list[tuple[int, str]] = []
    stop_at = limit if limit is not None else len(unique_dirs)
    for index, directory in enumerate(unique_dirs[:stop_at], start=1):
        snap_started = time.perf_counter()
        snapshot = session.scene_snapshot_for_directory(directory, max_depth=depth)
        entries = len(getattr(snapshot, "entries", []) or [])
        total_entries += entries
        largest.append((entries, directory))
        largest = sorted(largest, reverse=True)[:10]
        current_rss = rss()
        if index <= 10 or index % 25 == 0:
            print(
                f"[{index}/{len(unique_dirs)}] entries={entries} "
                f"snap_sec={time.perf_counter() - snap_started:.3f} "
                f"rss_mib={mib(current_rss):.1f} dir={directory}",
                flush=True,
            )
        if rss_stop_mib is not None and mib(current_rss) >= rss_stop_mib:
            print(f"stopping: rss {mib(current_rss):.1f} MiB >= {rss_stop_mib:.1f} MiB")
            break
    print(f"elapsed_sec={time.perf_counter() - started:.3f}")
    print(f"rss_start_mib={mib(before):.1f}")
    print(f"rss_end_mib={mib(rss()):.1f}")
    print(f"total_snapshot_entries={total_entries}")
    print({"largest_snapshots": largest})


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument(
        "probe",
        choices=[
            "dir-config",
            "dir-empty",
            "scene-snapshot",
            "scene-markers",
            "relations",
            "fact-bags",
            "scene-dir-walk",
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
    elif args.probe == "scene-snapshot":
        cmd_scene_snapshot(target, 1 if args.depth is None else args.depth)
    elif args.probe == "scene-markers":
        cmd_scene_markers(target, 1 if args.depth is None else args.depth)
    elif args.probe == "relations":
        cmd_relations(target, args.depth)
    elif args.probe == "fact-bags":
        cmd_fact_bags(target)
    elif args.probe == "scene-dir-walk":
        cmd_scene_dir_walk(target, args.limit, args.rss_stop_mib)
    elif args.probe == "evaluate-watch":
        cmd_evaluate_watch(target, args.rss_stop_mib)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
