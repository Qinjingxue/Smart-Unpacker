"""Reproducible SunPack versus 7-Zip extraction benchmark.

Generates every project-supported format that bundled 7-Zip can create. RAR,
Unix compress (.Z), and zstd variants can be supplied with --sample EXT=PATH.
The JSON output separates startup, detection, metadata, backend extraction,
output inventory, verification, and nested-output scanning where observable.
"""
from __future__ import annotations

import argparse, json, os, random, shutil, statistics, subprocess, sys, tempfile, time
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
PYTHON_CANDIDATES = (
    ROOT / ".venv-build" / "Scripts" / "python.exe",
    ROOT / ".venv" / "Scripts" / "python.exe",
)
PYTHON = next((path for path in PYTHON_CANDIDATES if path.exists()), Path(sys.executable))
SEVEN_ZIP = ROOT / "tools" / "7z.exe"
SUPPORTED = ("zip", "7z", "rar", "gz", "bz2", "xz", "zst", "Z", "tar", "tgz", "tbz2", "txz", "tzst")


def timed(command: list[str], cwd: Path) -> tuple[float, int]:
    started = time.perf_counter()
    result = subprocess.run(command, cwd=cwd, stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    return time.perf_counter() - started, result.returncode


def create_corpus(root: Path, extra: dict[str, Path], small_files: int) -> tuple[dict[str, Path], dict[str, str]]:
    payload = root / "payload"
    payload.mkdir(parents=True)
    (payload / "compressible.bin").write_bytes((b"sunpack-benchmark\n" * 65536))
    (payload / "incompressible.bin").write_bytes(random.Random(20260711).randbytes(1024 * 1024))
    many = payload / "many-small-files"; many.mkdir()
    for index in range(small_files):
        (many / f"file-{index:05d}.txt").write_text(f"record {index}\n" * 4, encoding="utf-8")
    corpus, skipped = dict(extra), {}
    create_specs = {"zip": ("zip", payload), "7z": ("7z", payload), "tar": ("tar", payload)}
    for ext, (archive_type, source) in create_specs.items():
        if ext in corpus:
            continue
        target = root / f"sample.{ext}"
        result = subprocess.run([str(SEVEN_ZIP), "a", "-y", f"-t{archive_type}", str(target), str(source)], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        if result.returncode == 0 and target.exists(): corpus[ext] = target
        else: skipped[ext] = "bundled 7-Zip cannot create this format"
    for ext, archive_type in {"gz": "gzip", "bz2": "bzip2", "xz": "xz"}.items():
        target = root / f"sample.tar.{ext}"
        source = corpus.get("tar")
        result = subprocess.run([str(SEVEN_ZIP), "a", "-y", f"-t{archive_type}", str(target), str(source)], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL) if source else None
        if result is not None and result.returncode == 0 and target.exists(): corpus[ext] = target
        else: skipped[ext] = "bundled 7-Zip cannot create this format"
    # Conventional aliases exercise detection independently of backend format.
    for alias, source in (("tgz", "gz"), ("tbz2", "bz2"), ("txz", "xz")):
        if source in corpus:
            target = root / f"sample.{alias}"; shutil.copy2(corpus[source], target); corpus[alias] = target
    split = root / "sample.split.7z"
    result = subprocess.run([str(SEVEN_ZIP), "a", "-y", "-t7z", "-v256k", str(split), str(payload)], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    first_volume = root / "sample.split.7z.001"
    if result.returncode == 0 and first_volume.exists(): corpus["7z-split"] = first_volume
    many_zip = root / "many-files.zip"
    subprocess.run([str(SEVEN_ZIP), "a", "-y", "-tzip", str(many_zip), str(many)], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    if many_zip.exists(): corpus["zip-many-files"] = many_zip
    for ext in SUPPORTED:
        if ext not in corpus and ext not in skipped: skipped[ext] = "provide a valid archive with --sample EXT=PATH"
    return corpus, skipped


def benchmark(archives: dict[str, Path], work: Path, runs: int) -> list[dict]:
    rows = []
    startup, startup_code = timed([str(PYTHON), "-m", "sunpack", "--help"], ROOT)
    for name, archive in archives.items():
        raw, full, detection = [], [], []
        for run in range(runs):
            for label in ("raw", "sunpack"):
                out = work / f"out-{name}-{label}-{run}"; shutil.rmtree(out, ignore_errors=True); out.mkdir()
                if label == "raw": command = [str(SEVEN_ZIP), "x", "-y", "-bd", "-bso0", f"-o{out}", str(archive)]
                else: command = [str(PYTHON), "-m", "sunpack", "extract", "--direct-file", "--recur", "1", "--cleanup", "k", "--no-flatten", "--no-builtin-pw", "--no-dir-pw", "--quiet", "--no-pause", "-o", str(out), str(archive)]
                elapsed, code = timed(command, ROOT)
                (raw if label == "raw" else full).append(elapsed if code == 0 else None)
            elapsed, code = timed([str(PYTHON), "-m", "sunpack", "scan", "--json", str(archive)], ROOT)
            detection.append(elapsed if code == 0 else None)
        med = lambda values: statistics.median(v for v in values if v is not None) if any(v is not None for v in values) else None
        raw_m, full_m, detect_m = med(raw), med(full), med(detection)
        rows.append({"format": name, "bytes": archive.stat().st_size, "runs": runs,
            "seven_zip_seconds": raw_m, "sunpack_seconds": full_m,
            "phases_seconds": {"startup": startup if startup_code == 0 else None, "detection": detect_m,
                "metadata": None, "seven_zip_extraction": raw_m, "output_inventory": None,
                "verification": None, "nested_scan": None,
                "combined_in_process_pipeline": max(0.0, full_m-startup) if full_m else None},
            "overhead_seconds": full_m-raw_m if full_m is not None and raw_m is not None else None})
    return rows


def main() -> int:
    parser = argparse.ArgumentParser(); parser.add_argument("--runs", type=int, default=3); parser.add_argument("--small-files", type=int, default=2000)
    parser.add_argument("--sample", action="append", default=[], metavar="EXT=PATH"); parser.add_argument("--json-out", type=Path)
    args = parser.parse_args(); extra = {}
    for value in args.sample:
        ext, path = value.split("=", 1); extra[ext] = Path(path).resolve()
    with tempfile.TemporaryDirectory(prefix="sunpack-format-bench-") as temp:
        work = Path(temp); corpus, skipped = create_corpus(work / "corpus", extra, args.small_files)
        report = {"supported_formats": list(SUPPORTED), "environment": {"python": sys.version, "platform": sys.platform},
                  "results": benchmark(corpus, work, max(1, args.runs)), "skipped": skipped}
        rendered = json.dumps(report, ensure_ascii=False, indent=2)
        if args.json_out: args.json_out.write_text(rendered, encoding="utf-8")
        print(rendered)
    return 0


if __name__ == "__main__": raise SystemExit(main())
