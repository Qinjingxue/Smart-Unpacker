from __future__ import annotations

import gc
import json
import os
import shutil
import sys
import tempfile
import time
import zipfile
from pathlib import Path

import psutil

PROJECT_ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(PROJECT_ROOT))


def sample(label: str, engine=None) -> dict:
    gc.collect()
    process = psutil.Process()
    memory = process.memory_info()
    pools = []
    if engine is not None:
        runtime = engine._runtime
        pools = [
            runtime.executor_pool.live_thread_count,
            runtime.analysis_executor_pool.live_thread_count,
            runtime.analysis_module_pool.live_thread_count,
        ]
    return {
        "label": label,
        "rss_mib": round(memory.rss / 1024**2, 2),
        "private_mib": round(getattr(memory, "private", 0) / 1024**2, 2),
        "process_threads": process.num_threads(),
        "pool_threads": pools,
    }


def wait_for_pool_retirement(engine, timeout: float = 5.0) -> None:
    deadline = time.monotonic() + timeout
    pools = (
        engine._runtime.executor_pool,
        engine._runtime.analysis_executor_pool,
        engine._runtime.analysis_module_pool,
    )
    while time.monotonic() < deadline and any(pool.live_thread_count for pool in pools):
        time.sleep(0.05)


def main() -> int:
    from sunpack.config.loader import load_config
    from sunpack.coordinator.engine import PipelineEngine

    root = Path(tempfile.mkdtemp(prefix="sunpack-idle-thread-reclaim-"))
    try:
        input_dir = root / "input"
        output_dir = root / "output"
        input_dir.mkdir()
        archives = []
        for index in range(50):
            path = input_dir / f"archive-{index:04d}.zip"
            with zipfile.ZipFile(path, "w", compression=zipfile.ZIP_STORED) as archive:
                archive.writestr("payload.bin", os.urandom(128 * 1024))
            archives.append(str(path))

        config = load_config()
        config["pipeline"]["thread_pool_idle_seconds"] = 1.0
        config["cli"]["quiet"] = True
        config.setdefault("output", {})["root"] = str(output_dir)
        config["post_extract"]["archive_cleanup_mode"] = "keep"
        config["post_extract"]["flatten_single_directory"] = False

        rows = [sample("before-engine")]
        engine = PipelineEngine(config).start()
        try:
            rows.append(sample("engine-cold", engine))
            engine.submit(archives, direct=True).result(timeout=120)
            rows.append(sample("batch-complete", engine))
            wait_for_pool_retirement(engine)
            rows.append(sample("idle-retired", engine))
            engine.submit(archives[:5], direct=True).result(timeout=120)
            rows.append(sample("reuse-complete", engine))
            wait_for_pool_retirement(engine)
            rows.append(sample("reuse-idle-retired", engine))
        finally:
            engine.close()
        rows.append(sample("engine-closed"))
        print(json.dumps(rows, ensure_ascii=False, indent=2))
    finally:
        shutil.rmtree(root, ignore_errors=True)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
