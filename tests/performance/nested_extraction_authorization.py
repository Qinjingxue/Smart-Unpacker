from __future__ import annotations

import argparse
import json
import os
from pathlib import Path
import statistics
import sys
import time
import zipfile

PROJECT_ROOT = Path(__file__).resolve().parents[2]
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from sunpack.config.loader import load_config
from sunpack.contracts.filesystem import DirectorySnapshot, FileEntry
from sunpack.filesystem.directory_scanner import DirectoryScanner
from sunpack_native import (
    authorize_nested_candidates,
    scan_directory_snapshot,
    scan_directory_snapshots,
)


ARCHIVE_EXTENSIONS = {
    ".001", ".7z", ".bz2", ".gz", ".rar",
    ".tar", ".tbz", ".tbz2", ".tgz", ".txz", ".tzst", ".xz",
    ".zip", ".zst",
}


def _call_args(root: str):
    config = load_config()
    config.setdefault("filesystem", {})["directory_scan_mode"] = "recursive"
    scanner = DirectoryScanner(root, config=config)
    options = scanner._native_scan_options()
    if options is None:
        raise RuntimeError("native scan options unavailable")
    return (
        root,
        scanner.max_depth,
        options["patterns"],
        options["prune_dir_globs"],
        options["blocked_extensions"],
        options["blocked_file_names"],
        options["size_ranges"],
        options["mtime_ranges"],
        options["whitelist_rules"],
    )


def _median_ms(values: list[int]) -> float:
    return statistics.median(values) / 1_000_000


def run(root: str, runs: int) -> dict:
    args = _call_args(root)
    scan_directory_snapshot(*args)
    filtered, raw = scan_directory_snapshots(*args)
    paths, is_dirs, _sizes, _mtimes = raw.materialize_columns()
    candidates = [
        (path, [path])
        for path, is_dir in zip(paths, is_dirs)
        if not is_dir and os.path.splitext(path)[1].lower() in ARCHIVE_EXTENSIONS
    ]

    filtered_only_ns: list[int] = []
    dual_snapshot_ns: list[int] = []
    authorization_ns: list[int] = []
    decisions = []
    for _ in range(runs):
        started = time.perf_counter_ns()
        scan_directory_snapshot(*args)
        filtered_only_ns.append(time.perf_counter_ns() - started)

        started = time.perf_counter_ns()
        _filtered, measured_raw = scan_directory_snapshots(*args)
        dual_snapshot_ns.append(time.perf_counter_ns() - started)

        started = time.perf_counter_ns()
        decisions = list(authorize_nested_candidates(
            measured_raw,
            root,
            candidates,
            1.0,
            1.0,
            0.0,
            0.85,
            0.1,
            1000,
        ))
        authorization_ns.append(time.perf_counter_ns() - started)

    filtered_median = _median_ms(filtered_only_ns)
    dual_median = _median_ms(dual_snapshot_ns)
    scaling = {}
    if candidates:
        for count in (1, 10, len(candidates), 1_000, 10_000):
            expanded = [candidates[index % len(candidates)] for index in range(count)]
            samples = []
            for _ in range(runs):
                started = time.perf_counter_ns()
                authorize_nested_candidates(
                    raw,
                    root,
                    expanded,
                    1.0,
                    1.0,
                    0.0,
                    0.85,
                    0.1,
                    1000,
                )
                samples.append(time.perf_counter_ns() - started)
            scaling[str(count)] = {
                "median_ms": _median_ms(samples),
                "min_ms": min(samples) / 1_000_000,
                "max_ms": max(samples) / 1_000_000,
            }
    return {
        "root": str(Path(root).resolve()),
        "runs": runs,
        "evaluation_semantics": "hypothetical_recursive_output",
        "first_round_bypasses_authorization": True,
        "raw_entries": len(paths),
        "candidate_count": len(candidates),
        "allowed_count": sum(bool(dict(row).get("allowed")) for row in decisions),
        "allowed_paths": [
            str(dict(row).get("entry_path") or "")
            for row in decisions
            if dict(row).get("allowed")
        ],
        "filtered_only_scan_median_ms": filtered_median,
        "dual_snapshot_scan_median_ms": dual_median,
        "raw_snapshot_overhead_ms": dual_median - filtered_median,
        "raw_snapshot_overhead_ratio": (
            (dual_median / filtered_median - 1.0) if filtered_median else 0.0
        ),
        "authorization_median_ms": _median_ms(authorization_ns),
        "authorization_min_ms": min(authorization_ns) / 1_000_000,
        "authorization_max_ms": max(authorization_ns) / 1_000_000,
        "authorization_scaling": scaling,
    }


def evaluate_dlc_sample(path: str) -> dict | None:
    archive_path = Path(path)
    if not archive_path.is_file():
        return None
    root = Path(r"C:\sunpack_virtual_output")
    entries: list[FileEntry] = []
    with zipfile.ZipFile(archive_path) as archive:
        for item in archive.infolist():
            entries.append(FileEntry(
                path=root / Path(item.filename),
                is_dir=item.is_dir(),
                size=None if item.is_dir() else item.file_size,
            ))
    snapshot = DirectorySnapshot.from_entries(root, entries, raw_entries=entries)
    inner = root / "dlc003_rocket_launcher_unit_pack" / "dlc003.zip"
    return dict(authorize_nested_candidates(
        snapshot.raw_native_snapshot,
        str(root),
        [(str(inner), [str(inner)])],
        1.0,
        1.0,
        0.0,
        0.85,
        0.1,
        1000,
    )[0])


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("root", nargs="?", default=r"D:\game")
    parser.add_argument("--runs", type=int, default=20)
    parser.add_argument(
        "--dlc-zip",
        default="testfiles/dlc003_rocket_launcher_unit_pack.zip",
    )
    parser.add_argument(
        "--output",
        default=".sunpack_cache/nested_extraction_authorization_result.json",
    )
    args = parser.parse_args()
    result = run(args.root, max(1, args.runs))
    result["dlc_sample"] = evaluate_dlc_sample(args.dlc_zip)
    output = Path(args.output)
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_text(json.dumps(result, ensure_ascii=False, indent=2), encoding="utf-8")
    print(json.dumps(result, ensure_ascii=False, indent=2))


if __name__ == "__main__":
    main()
