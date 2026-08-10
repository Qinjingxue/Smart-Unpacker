from __future__ import annotations

import gc
import json
import os
import shutil
import sys
import tempfile
import zipfile
from pathlib import Path

import psutil

PROJECT_ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(PROJECT_ROOT))


def sample(label: str, persistent_runtime) -> dict:
    gc.collect()
    process = psutil.Process()
    info = process.memory_info()
    engine = persistent_runtime._ENGINE
    if engine is None:
        report_entries = 0
    else:
        report_entries = len(engine._runtime.analysis_stage._report_cache)
    from sunpack.support import archive_sessions
    return {
        "label": label,
        "rss_mib": round(info.rss / 1024 / 1024, 2),
        "private_mib": round(getattr(info, "private", 0) / 1024 / 1024, 2),
        "threads": process.num_threads(),
        "handles": process.num_handles(),
        "analysis_report_cache": report_entries,
        "native_archive_sessions": len(archive_sessions._SESSIONS),
    }


def main() -> int:
    from sunpack.cli.cli import main as cli_main
    from sunpack.cli import persistent_runtime

    root = Path(tempfile.mkdtemp(prefix="sunpack-cache-saturation-"))
    rows = []
    persistent_runtime.enable_persistent_runtime()
    try:
        rows.append(sample("baseline", persistent_runtime))
        for batch in range(1, 8):
            input_dir = root / f"input-{batch}"
            output_dir = root / f"output-{batch}"
            input_dir.mkdir()
            for index in range(100):
                path = input_dir / f"archive-{batch}-{index:04d}.zip"
                with zipfile.ZipFile(path, "w", compression=zipfile.ZIP_STORED) as archive:
                    archive.writestr("payload.bin", os.urandom(128 * 1024))
            code = cli_main([
                "extract", *[str(path) for path in sorted(input_dir.glob("*.zip"))], "--direct-file", "--out-dir", str(output_dir),
                "--cleanup", "k", "--no-flatten", "--no-pause", "--quiet",
            ])
            if code:
                raise RuntimeError(f"batch {batch} failed: {code}")
            rows.append(sample(f"batch-{batch}", persistent_runtime))
        print(json.dumps(rows, ensure_ascii=False, indent=2))
    finally:
        persistent_runtime.close_persistent_runtime()
        shutil.rmtree(root, ignore_errors=True)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
