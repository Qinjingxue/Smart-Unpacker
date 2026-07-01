import contextlib
import gc
import os
import shutil
import zipfile
from pathlib import Path

import psutil
import pytest

from sunpack.config.schema import normalize_config
from sunpack.coordinator.engine import PipelineEngine
from sunpack.filesystem.watcher.scheduler import WatchScheduler
from sunpack.support.resources import get_7z_dll_path, get_sevenzip_bridge_worker_path


ARCHIVE_COUNT = 100
SAMPLE_EVERY = 10


@pytest.mark.skipif(os.name != "nt", reason="bundled persistent worker probe is Windows-specific")
def test_watch_service_memory_remains_bounded_across_many_archives(tmp_path):
    worker_path = Path(get_sevenzip_bridge_worker_path())
    dll_path = Path(get_7z_dll_path())
    if not worker_path.exists() or not dll_path.exists():
        pytest.skip("bundled sevenzip worker or 7z.dll is unavailable")

    watch_root = tmp_path / "watch"
    output_root = tmp_path / "output"
    watch_root.mkdir()
    output_root.mkdir()
    config = normalize_config({
        "recursive_extract": "1",
        "cli": {"quiet": True},
        "analysis": {"enabled": False},
        "detection": {"enabled": False},
        "repair": {"enabled": False},
        "verification": {"enabled": False, "methods": []},
        "pipeline": {
            "batch_window_seconds": 0,
            "max_batch_requests": 64,
            "queue_capacity": 256,
        },
        "performance": {
            "persistent_workers": True,
            "persistent_worker_count": 2,
        },
        "post_extract": {
            "archive_cleanup_mode": "k",
            "flatten_single_directory": False,
        },
        "extraction": {"quiet": True},
        "watch": {"clipboard_monitor_enabled": False},
    })

    process = psutil.Process(os.getpid())
    samples = []

    def sample(engine, watcher, archive_count):
        gc.collect()
        children = [child for child in process.children(recursive=True) if child.is_running()]
        samples.append({
            "archives": archive_count,
            "parent_rss": process.memory_info().rss,
            "worker_rss": sum(child.memory_info().rss for child in children),
            "child_count": len(children),
            "snapshots": len(watcher.state.snapshots),
            "known_output_roots": len(watcher._known_output_roots),
            "password_contexts": len(engine.batch_runner.directory_password_contexts._contexts),
            "feedback_samples": len(engine.resource_scheduler.feedback.feedback_window),
        })

    with PipelineEngine(config) as engine:
        watcher = WatchScheduler(
            config,
            [str(watch_root)],
            out_dir=str(output_root),
            state_path=str(tmp_path / "watch-state.json"),
            quiet_seconds=0,
            initial_scan=False,
            pipeline_engine=engine,
        )
        sample(engine, watcher, 0)
        with open(os.devnull, "w", encoding="utf-8") as sink, contextlib.redirect_stdout(sink):
            for start in range(0, ARCHIVE_COUNT, SAMPLE_EVERY):
                for index in range(start, start + SAMPLE_EVERY):
                    archive = watch_root / f"archive-{index:04d}.zip"
                    with zipfile.ZipFile(archive, "w", zipfile.ZIP_DEFLATED) as handle:
                        handle.writestr("payload.txt", "payload" * 128)
                    watcher.enqueue(str(archive))
                result = watcher.run_once()
                assert result.succeeded == SAMPLE_EVERY
                sample(engine, watcher, start + SAMPLE_EVERY)

        warm = samples[1:]
        parent_growth = warm[-1]["parent_rss"] - warm[0]["parent_rss"]
        worker_growth = warm[-1]["worker_rss"] - warm[0]["worker_rss"]
        assert parent_growth < 16 * 1024 * 1024
        assert worker_growth < 4 * 1024 * 1024
        assert max(item["child_count"] for item in warm) == min(item["child_count"] for item in warm)
        assert warm[-1]["snapshots"] == ARCHIVE_COUNT
        assert warm[-1]["known_output_roots"] <= 2
        assert all(item["password_contexts"] == 0 for item in warm)
        assert all(item["feedback_samples"] <= engine.resource_scheduler.feedback.feedback_window_size for item in warm)

    shutil.rmtree(output_root, ignore_errors=True)
