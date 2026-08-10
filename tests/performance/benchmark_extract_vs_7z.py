from __future__ import annotations

import argparse
import hashlib
import json
import shutil
import statistics
import subprocess
import time
from pathlib import Path


FORMATS = ("zip", "7z", "rar", "tar", "gz", "bz2", "xz")


def run(command: list[str]) -> float:
    started = time.perf_counter()
    completed = subprocess.run(command, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    elapsed = time.perf_counter() - started
    if completed.returncode != 0:
        raise RuntimeError(f"command failed ({completed.returncode}): {command}")
    return elapsed


def output_signature(root: Path) -> dict[str, object]:
    files = sorted(path for path in root.rglob("*") if path.is_file())
    digest = hashlib.sha256()
    total = 0
    for path in files:
        size = path.stat().st_size
        total += size
        file_hash = hashlib.sha256()
        with path.open("rb") as stream:
            for chunk in iter(lambda: stream.read(1024 * 1024), b""):
                file_hash.update(chunk)
        digest.update(file_hash.digest())
    return {"files": len(files), "bytes": total, "content_sha256": digest.hexdigest()}


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--sunpack", required=True, type=Path)
    parser.add_argument("--sevenzip", required=True, type=Path)
    parser.add_argument("--corpus", required=True, type=Path)
    parser.add_argument("--output-root", required=True, type=Path)
    parser.add_argument("--json-output", required=True, type=Path)
    parser.add_argument("--repeats", type=int, default=7)
    args = parser.parse_args()

    args.output_root.mkdir(parents=True, exist_ok=True)
    subprocess.run([str(args.sunpack), "--persistent-shutdown"], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    run([str(args.sunpack), "--reuse", "config", "validate", "--json"])

    rows: list[dict[str, object]] = []
    signatures: dict[str, dict[str, object]] = {}
    try:
        for archive_format in FORMATS:
            archive_dir = args.corpus / archive_format
            archives = list(archive_dir.glob("*"))
            if len(archives) != 1:
                raise RuntimeError(f"expected one {archive_format} archive under {archive_dir}")
            archive = archives[0]
            samples: dict[str, list[float]] = {"sunpack": [], "7z": []}
            final_outputs: dict[str, Path] = {}
            for iteration in range(-1, args.repeats):
                order = ("sunpack", "7z") if iteration % 2 else ("7z", "sunpack")
                for tool in order:
                    output = args.output_root / f"{tool}-{archive_format}-{iteration + 1}"
                    shutil.rmtree(output, ignore_errors=True)
                    if tool == "sunpack":
                        command = [
                            str(args.sunpack), "--reuse", "extract", str(archive_dir),
                            "--out-dir", str(output), "--cleanup", "k", "--no-flatten",
                            "--no-dir-pw", "--recur", "1", "--json", "--no-pause",
                        ]
                    else:
                        output.mkdir(parents=True, exist_ok=True)
                        command = [str(args.sevenzip), "x", str(archive), f"-o{output}", "-y"]
                    elapsed = run(command)
                    rows.append({
                        "tool": tool, "format": archive_format, "iteration": iteration,
                        "warmup": iteration < 0, "seconds": elapsed,
                    })
                    if iteration >= 0:
                        samples[tool].append(elapsed)
                        final_outputs[tool] = output
            for tool in ("sunpack", "7z"):
                signatures[f"{tool}:{archive_format}"] = output_signature(final_outputs[tool])
                print(f"{tool:7s} {archive_format:3s} median={statistics.median(samples[tool]):.6f}s")
    finally:
        subprocess.run([str(args.sunpack), "--persistent-shutdown"], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)

    for archive_format in FORMATS:
        if signatures[f"sunpack:{archive_format}"] != signatures[f"7z:{archive_format}"]:
            raise RuntimeError(f"output mismatch for {archive_format}")

    payload = {"results": rows, "hashes": signatures}
    args.json_output.parent.mkdir(parents=True, exist_ok=True)
    args.json_output.write_text(json.dumps(payload, ensure_ascii=False, indent=2), encoding="utf-8")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
