from __future__ import annotations

import collections
import gc
import json
import os
import shutil
import sys
import tempfile
import tracemalloc
import zipfile
from pathlib import Path

import psutil

PROJECT_ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(PROJECT_ROOT))


def process_sample(label: str, *, snapshot: bool = False) -> dict:
    gc.collect()
    proc = psutil.Process()
    memory = proc.memory_info()
    current, peak = tracemalloc.get_traced_memory()
    counts = collections.Counter(type(item).__module__ + "." + type(item).__qualname__ for item in gc.get_objects())
    return {
        "label": label,
        "rss_mib": round(memory.rss / 1024 / 1024, 2),
        "private_mib": round(getattr(memory, "private", 0) / 1024 / 1024, 2),
        "traced_current_mib": round(current / 1024 / 1024, 2),
        "traced_peak_mib": round(peak / 1024 / 1024, 2),
        "threads": proc.num_threads(),
        "handles": proc.num_handles(),
        "objects": counts,
        "snapshot": tracemalloc.take_snapshot() if snapshot else None,
    }


def public_sample(sample: dict) -> dict:
    return {key: value for key, value in sample.items() if key not in {"objects", "snapshot"}}


def main() -> int:
    tracemalloc.start(25)
    from sunpack.cli.cli import main as cli_main
    from sunpack.cli import persistent_runtime

    root = Path(tempfile.mkdtemp(prefix="sunpack-profile-memory-"))
    seed = root / "seed.zip"
    payload = os.urandom(1024 * 1024)
    with zipfile.ZipFile(seed, "w", compression=zipfile.ZIP_DEFLATED) as archive:
        archive.writestr("payload.bin", payload)

    samples = []
    persistent_runtime.enable_persistent_runtime()
    try:
        samples.append(process_sample("baseline", snapshot=True))
        for batch in range(1, 5):
            input_dir = root / f"input-{batch}"
            output_dir = root / f"output-{batch}"
            input_dir.mkdir()
            for index in range(30):
                shutil.copyfile(seed, input_dir / f"archive-{batch}-{index:04d}.zip")
            exit_code = cli_main([
                "extract", str(input_dir), "--out-dir", str(output_dir),
                "--cleanup", "k", "--no-flatten", "--no-pause", "--quiet",
            ])
            if exit_code:
                raise RuntimeError(f"batch {batch} failed: {exit_code}")
            samples.append(process_sample(f"batch-{batch}", snapshot=batch == 4))

        before_close = samples[-1]
        engine = persistent_runtime._ENGINE
        report_cache = engine._runtime.analysis_stage._report_cache
        report_cache_entries = len(report_cache)
        report_cache.clear()
        samples.append(process_sample("after-report-cache-clear"))
        from sunpack.support.archive_sessions import clear_archive_sessions
        clear_archive_sessions()
        samples.append(process_sample("after-archive-sessions-clear"))
        del report_cache, engine
        persistent_runtime.close_persistent_runtime()
        samples.append(process_sample("after-engine-close"))

        diffs = []
        for stat in before_close["snapshot"].compare_to(samples[0]["snapshot"], "lineno")[:30]:
            diffs.append({"trace": str(stat.traceback), "size_mib": round(stat.size_diff / 1024 / 1024, 4), "count": stat.count_diff})
        object_deltas = []
        for name, count in (before_close["objects"] - samples[0]["objects"]).most_common(40):
            object_deltas.append({"type": name, "count": count})
        close_deltas = []
        for name, count in (before_close["objects"] - samples[-1]["objects"]).most_common(40):
            close_deltas.append({"type": name, "released": count})
        print(json.dumps({
            "samples": [public_sample(sample) for sample in samples],
            "top_allocations_batch4_vs_baseline": diffs,
            "top_object_growth": object_deltas,
            "objects_released_by_engine_close": close_deltas,
            "report_cache_entries_before_clear": report_cache_entries,
        }, ensure_ascii=False, indent=2))
    finally:
        persistent_runtime.close_persistent_runtime()
        shutil.rmtree(root, ignore_errors=True)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
