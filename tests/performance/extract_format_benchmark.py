"""Reproducible archive workload and detection regression benchmark.

The public mode creates many-small-file and few-large-file corpora, measures
SunPack and raw 7-Zip extraction, and measures detection without interpreter
startup.  ``--compare-root`` can point at a second Git worktree so that the
same archives are scanned by both revisions on the same machine.
"""
from __future__ import annotations

import argparse
import json
import os
import random
import shutil
import statistics
import subprocess
import sys
import tempfile
import time
from pathlib import Path
from typing import Any

import zstandard


ROOT = Path(__file__).resolve().parents[2]
PYTHON = ROOT / ".venv" / "Scripts" / "python.exe"
if not PYTHON.exists():
    PYTHON = Path(sys.executable)
SEVEN_ZIP = ROOT / "tools" / "7z.exe"
RAR = ROOT / "tools" / "Rar.exe"
SUPPORTED = ("zip", "7z", "rar", "gz", "bz2", "xz", "zst", "Z", "tar", "tgz", "tbz2", "txz", "tzst")
GENERATED_FORMATS = (
    "zip", "7z", "7z-split", "rar", "rar-split", "tar", "gz", "bz2", "xz", "zst", "tgz", "tbz2", "txz", "tzst",
)


def timed(command: list[str], cwd: Path) -> tuple[float, int]:
    started = time.perf_counter()
    result = subprocess.run(
        command,
        cwd=cwd,
        stdin=subprocess.DEVNULL,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
    )
    return time.perf_counter() - started, result.returncode


def _run_7z(command: list[str]) -> bool:
    result = subprocess.run(
        [str(SEVEN_ZIP), *command],
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
    )
    return result.returncode == 0


def _run_rar(command: list[str]) -> bool:
    result = subprocess.run(
        [str(RAR), *command],
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
    )
    return result.returncode == 0


def _write_payloads(root: Path, small_files: int, large_files: int, large_file_mib: int) -> dict[str, Path]:
    small = root / "many-small"
    large = root / "few-large"
    small.mkdir(parents=True)
    large.mkdir(parents=True)
    for index in range(small_files):
        (small / f"file-{index:05d}.txt").write_text(f"record {index}\n" * 4, encoding="utf-8")

    chunk_size = 1024 * 1024
    rng = random.Random(20260729)
    compressible_chunk = (b"sunpack-benchmark\n" * ((chunk_size // 18) + 1))[:chunk_size]
    for index in range(large_files):
        with (large / f"large-{index:02d}.bin").open("wb") as stream:
            for _ in range(large_file_mib):
                stream.write(compressible_chunk if index % 2 == 0 else rng.randbytes(chunk_size))
    return {"many_small": small, "few_large": large}


def _create_archive(target: Path, archive_type: str, source: Path) -> bool:
    return _run_7z(["a", "-y", f"-t{archive_type}", str(target), str(source)]) and target.exists()


def _create_zstd_archive(target: Path, source: Path) -> bool:
    try:
        with source.open("rb") as input_stream, target.open("wb") as output_stream:
            zstandard.ZstdCompressor(level=3).copy_stream(input_stream, output_stream)
    except (OSError, zstandard.ZstdError):
        return False
    return target.exists()


def create_corpus(
    root: Path,
    extra: dict[str, Path],
    small_files: int,
    large_files: int,
    large_file_mib: int,
) -> tuple[dict[str, dict[str, Any]], dict[str, str]]:
    root.mkdir(parents=True)
    payloads = _write_payloads(root / "payloads", small_files, large_files, large_file_mib)
    corpus: dict[str, dict[str, Any]] = {}
    skipped: dict[str, str] = {}

    for workload, source in payloads.items():
        base_archives: dict[str, Path] = {}
        for archive_type in ("zip", "7z", "tar"):
            target = root / f"{workload}.{archive_type}"
            if _create_archive(target, archive_type, source):
                base_archives[archive_type] = target
                corpus[f"{workload}:{archive_type}"] = {
                    "workload": workload,
                    "format": archive_type,
                    "path": target,
                }
            else:
                skipped[f"{workload}:{archive_type}"] = "bundled 7-Zip cannot create this format"

        split_size = "4k" if workload == "many_small" else "8m"
        split_target = root / f"{workload}.split.7z"
        split_first = root / f"{workload}.split.7z.001"
        split_created = _run_7z(["a", "-y", "-t7z", f"-v{split_size}", str(split_target), str(source)])
        split_volumes = sorted(root.glob(f"{workload}.split.7z.*")) if split_created else []
        if len(split_volumes) > 1 and split_first.exists():
            corpus[f"{workload}:7z-split"] = {
                "workload": workload,
                "format": "7z-split",
                "path": split_first,
            }
        else:
            skipped[f"{workload}:7z-split"] = "workload did not produce multiple 7z volumes"

        rar_target = root / f"{workload}.rar"
        if _run_rar(["a", "-idq", "-r", "-ep1", str(rar_target), str(source)]) and rar_target.exists():
            corpus[f"{workload}:rar"] = {"workload": workload, "format": "rar", "path": rar_target}
        else:
            skipped[f"{workload}:rar"] = "bundled RAR cannot create this format"

        rar_split_target = root / f"{workload}.split.rar"
        if _run_rar(["a", "-idq", "-r", "-ep1", f"-v{split_size}", str(rar_split_target), str(source)]):
            rar_volumes = sorted(root.glob(f"{workload}.split.part*.rar"))
            if not rar_volumes and rar_split_target.exists():
                rar_volumes = [rar_split_target]
        else:
            rar_volumes = []
        if len(rar_volumes) > 1:
            corpus[f"{workload}:rar-split"] = {
                "workload": workload,
                "format": "rar-split",
                "path": rar_volumes[0],
            }
        else:
            skipped[f"{workload}:rar-split"] = "workload did not produce multiple RAR volumes"

        tar_source = base_archives.get("tar")
        for ext, archive_type in {"gz": "gzip", "bz2": "bzip2", "xz": "xz"}.items():
            target = root / f"{workload}.tar.{ext}"
            if tar_source is not None and _create_archive(target, archive_type, tar_source):
                corpus[f"{workload}:{ext}"] = {"workload": workload, "format": ext, "path": target}
                alias = {"gz": "tgz", "bz2": "tbz2", "xz": "txz"}[ext]
                alias_target = root / f"{workload}.{alias}"
                shutil.copy2(target, alias_target)
                corpus[f"{workload}:{alias}"] = {"workload": workload, "format": alias, "path": alias_target}
            else:
                skipped[f"{workload}:{ext}"] = "bundled 7-Zip cannot create this format"

        zstd_target = root / f"{workload}.tar.zst"
        if tar_source is not None and _create_zstd_archive(zstd_target, tar_source):
            corpus[f"{workload}:zst"] = {"workload": workload, "format": "zst", "path": zstd_target}
            tzst_target = root / f"{workload}.tzst"
            shutil.copy2(zstd_target, tzst_target)
            corpus[f"{workload}:tzst"] = {"workload": workload, "format": "tzst", "path": tzst_target}
        else:
            skipped[f"{workload}:zst"] = "zstandard runtime cannot create this format"

    for name, source in extra.items():
        key = f"external:{name}"
        corpus[key] = {"workload": "external", "format": name, "path": source}
    for ext in SUPPORTED:
        if not any(item["format"] == ext for item in corpus.values()):
            skipped.setdefault(ext, "provide a valid archive with --sample EXT=PATH")
    return corpus, skipped


def _median(values: list[float | None]) -> float | None:
    successful = [value for value in values if value is not None]
    return statistics.median(successful) if successful else None


def _worker_detection(archives: list[tuple[str, Path]], runs: int, warmups: int) -> int:
    """Run detection in-process; imports and CLI startup are outside samples."""
    from sunpack.config.loader import load_config
    from sunpack.coordinator.scanner import ScanOrchestrator

    config = load_config()
    rows: dict[str, dict[str, Any]] = {}
    for name, archive in archives:
        samples: list[float] = []
        result_count = 0
        try:
            for _ in range(warmups):
                ScanOrchestrator(config).scan_targets([str(archive)])
            for _ in range(runs):
                started = time.perf_counter()
                results = ScanOrchestrator(config).scan_targets([str(archive)])
                samples.append(time.perf_counter() - started)
                result_count = len(results)
        except Exception as exc:  # Keep a single unsupported/broken format from aborting the matrix.
            rows[name] = {
                "samples_seconds": [],
                "median_seconds": None,
                "result_count": None,
                "error": f"{type(exc).__name__}: {exc}",
            }
            continue
        rows[name] = {
            "samples_seconds": samples,
            "median_seconds": statistics.median(samples),
            "result_count": result_count,
            "error": None,
        }
    print(json.dumps(rows, ensure_ascii=False))
    return 0


def _detection_for_root(
    source_root: Path,
    archives: dict[str, dict[str, Any]],
    runs: int,
    warmups: int,
) -> dict[str, dict[str, Any]]:
    command = [str(PYTHON), str(Path(__file__).resolve()), "--detection-worker", "--runs", str(runs), "--warmups", str(warmups)]
    for name, item in archives.items():
        command.extend(["--worker-archive", f"{name}={item['path']}"])
    environment = os.environ.copy()
    environment["PYTHONPATH"] = str(source_root)
    result = subprocess.run(command, cwd=source_root, env=environment, text=True, capture_output=True)
    if result.returncode != 0:
        raise RuntimeError(f"detection worker failed for {source_root}: {result.stderr.strip()}")
    return json.loads(result.stdout)


def _merge_detection_passes(
    first: dict[str, dict[str, Any]],
    second: dict[str, dict[str, Any]],
) -> dict[str, dict[str, Any]]:
    merged: dict[str, dict[str, Any]] = {}
    for name, first_row in first.items():
        second_row = second[name]
        if first_row.get("error") or second_row.get("error"):
            merged[name] = first_row if first_row.get("error") else second_row
            continue
        if first_row["result_count"] != second_row["result_count"]:
            raise RuntimeError(f"detection result count changed between passes for {name}")
        samples = [*first_row["samples_seconds"], *second_row["samples_seconds"]]
        merged[name] = {
            "samples_seconds": samples,
            "median_seconds": statistics.median(samples),
            "result_count": first_row["result_count"],
            "error": None,
        }
    return merged


def benchmark(
    archives: dict[str, dict[str, Any]],
    work: Path,
    runs: int,
    warmups: int,
    compare_root: Path | None,
) -> list[dict[str, Any]]:
    current_detection = _detection_for_root(ROOT, archives, runs, warmups)
    comparison_detection: dict[str, dict[str, Any]] = {}
    if compare_root is not None:
        # ABBA order reduces revision bias from cache warmth, CPU frequency, and
        # other short-lived machine drift. Each reported median has 2 * runs.
        comparison_first = _detection_for_root(compare_root, archives, runs, warmups)
        comparison_second = _detection_for_root(compare_root, archives, runs, warmups)
        current_second = _detection_for_root(ROOT, archives, runs, warmups)
        current_detection = _merge_detection_passes(current_detection, current_second)
        comparison_detection = _merge_detection_passes(comparison_first, comparison_second)
    rows: list[dict[str, Any]] = []
    for name, item in archives.items():
        archive = Path(item["path"])
        raw: list[float | None] = []
        full: list[float | None] = []
        for run in range(runs):
            for label in ("raw", "sunpack"):
                output = work / f"out-{name.replace(':', '-')}-{label}-{run}"
                shutil.rmtree(output, ignore_errors=True)
                output.mkdir()
                if label == "raw":
                    command = [str(SEVEN_ZIP), "x", "-y", "-bd", "-bso0", f"-o{output}", str(archive)]
                else:
                    command = [
                        str(PYTHON), "-m", "sunpack", "extract", "--direct-file", "--recur", "1",
                        "--cleanup", "k", "--no-flatten", "--no-builtin-pw", "--no-dir-pw", "--quiet",
                        "--no-pause", "-o", str(output), str(archive),
                    ]
                elapsed, code = timed(command, ROOT)
                (raw if label == "raw" else full).append(elapsed if code == 0 else None)
                shutil.rmtree(output, ignore_errors=True)

        raw_m = _median(raw)
        full_m = _median(full)
        current = current_detection[name]
        comparison = comparison_detection.get(name)
        delta = None
        delta_percent = None
        if current["median_seconds"] is not None and comparison and comparison["median_seconds"]:
            delta = current["median_seconds"] - comparison["median_seconds"]
            delta_percent = delta / comparison["median_seconds"] * 100.0
        rows.append({
            "name": name,
            "workload": item["workload"],
            "format": item["format"],
            "bytes": archive.stat().st_size,
            "runs": runs,
            "seven_zip_seconds": raw_m,
            "sunpack_seconds": full_m,
            "detection": {
                "current": current,
                "comparison": comparison,
                "delta_seconds": delta,
                "delta_percent": delta_percent,
            },
            "overhead_seconds": full_m - raw_m if full_m is not None and raw_m is not None else None,
        })
    return rows


def _summary(rows: list[dict[str, Any]]) -> dict[str, Any]:
    current = [
        row["detection"]["current"]["median_seconds"]
        for row in rows
        if row["detection"]["current"]["median_seconds"] is not None
    ]
    comparable = [
        row for row in rows
        if row["detection"]["current"]["median_seconds"] is not None
        and row["detection"]["comparison"] is not None
        and row["detection"]["comparison"]["median_seconds"] is not None
    ]
    summary: dict[str, Any] = {
        "case_count": len(rows),
        "detection_current_total_seconds": sum(current),
        "detection_current_median_seconds": statistics.median(current) if current else None,
        "successful_extraction_cases": sum(row["sunpack_seconds"] is not None for row in rows),
        "successful_detection_cases": len(current),
        "detection_error_cases": len(rows) - len(current),
    }
    if comparable:
        current_total = sum(row["detection"]["current"]["median_seconds"] for row in comparable)
        comparison_total = sum(row["detection"]["comparison"]["median_seconds"] for row in comparable)
        summary.update({
            "detection_comparison_total_seconds": comparison_total,
            "detection_total_delta_seconds": current_total - comparison_total,
            "detection_total_delta_percent": (
                (current_total - comparison_total) / comparison_total * 100.0 if comparison_total else None
            ),
        })
    return summary


def _git_revision(root: Path) -> str | None:
    result = subprocess.run(
        ["git", "rev-parse", "HEAD"],
        cwd=root,
        text=True,
        capture_output=True,
    )
    return result.stdout.strip() if result.returncode == 0 else None


def _parse_archive_args(values: list[str]) -> list[tuple[str, Path]]:
    archives = []
    for value in values:
        name, path = value.split("=", 1)
        archives.append((name, Path(path).resolve()))
    return archives


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--runs", type=int, default=3)
    parser.add_argument("--warmups", type=int, default=1)
    parser.add_argument("--small-files", type=int, default=2000)
    parser.add_argument("--large-files", type=int, default=2)
    parser.add_argument("--large-file-mib", type=int, default=32)
    parser.add_argument("--sample", action="append", default=[], metavar="EXT=PATH")
    parser.add_argument("--compare-root", type=Path)
    parser.add_argument("--json-out", type=Path)
    parser.add_argument("--detection-worker", action="store_true", help=argparse.SUPPRESS)
    parser.add_argument("--worker-archive", action="append", default=[], help=argparse.SUPPRESS)
    args = parser.parse_args()

    if args.detection_worker:
        return _worker_detection(_parse_archive_args(args.worker_archive), max(1, args.runs), max(0, args.warmups))
    if not SEVEN_ZIP.is_file():
        parser.error(f"bundled 7-Zip does not exist: {SEVEN_ZIP}")
    if not RAR.is_file():
        parser.error(f"bundled RAR does not exist: {RAR}")
    compare_root = args.compare_root.resolve() if args.compare_root else None
    if compare_root is not None and not (compare_root / "sunpack").is_dir():
        parser.error(f"comparison root does not contain sunpack package: {compare_root}")

    extra = dict(_parse_archive_args(args.sample))
    with tempfile.TemporaryDirectory(prefix="sunpack-format-bench-") as temp:
        work = Path(temp)
        corpus, skipped = create_corpus(
            work / "corpus",
            extra,
            max(1, args.small_files),
            max(1, args.large_files),
            max(1, args.large_file_mib),
        )
        rows = benchmark(corpus, work, max(1, args.runs), max(0, args.warmups), compare_root)
        report = {
            "schema_version": 2,
            "supported_formats": list(SUPPORTED),
            "generated_formats": list(GENERATED_FORMATS),
            "workloads": {
                "many_small": {"file_count": max(1, args.small_files)},
                "few_large": {"file_count": max(1, args.large_files), "file_size_mib": max(1, args.large_file_mib)},
            },
            "environment": {
                "python": sys.version,
                "platform": sys.platform,
                "cpu_count": os.cpu_count(),
                "current_root": str(ROOT),
                "current_revision": _git_revision(ROOT),
                "compare_root": str(compare_root) if compare_root else None,
                "compare_revision": _git_revision(compare_root) if compare_root else None,
            },
            "results": rows,
            "summary": _summary(rows),
            "skipped": skipped,
        }
        rendered = json.dumps(report, ensure_ascii=False, indent=2)
        if args.json_out:
            args.json_out.parent.mkdir(parents=True, exist_ok=True)
            args.json_out.write_text(rendered, encoding="utf-8")
        print(rendered)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
