import time
import zipfile
import threading
from pathlib import Path

import psutil
import pytest

from smart_unpacker.config.schema import normalize_config
from smart_unpacker.coordinator.runner import PipelineRunner


MiB = 1024 * 1024
WRITE_CHUNK_SIZE = 4 * MiB


def large_archive_extract_config(scheduler_profile: str = "auto") -> dict:
    return normalize_config({
        "recursive_extract": "1",
        "post_extract": {
            "archive_cleanup_mode": "k",
            "flatten_single_directory": False,
        },
        "max_retries": 1,
        "performance": {"scheduler_profile": scheduler_profile},
    })


def write_stored_zip(path: Path, payload_size: int, label: str) -> None:
    chunk = (f"LARGE-PRESSURE::{label}::".encode("ascii") * WRITE_CHUNK_SIZE)[:WRITE_CHUNK_SIZE]
    with zipfile.ZipFile(path, "w", compression=zipfile.ZIP_STORED, allowZip64=True) as archive:
        with archive.open(f"{label}.bin", "w", force_zip64=True) as entry:
            remaining = payload_size
            while remaining > 0:
                piece = chunk[: min(len(chunk), remaining)]
                entry.write(piece)
                remaining -= len(piece)


def build_large_archive_corpus(root: Path, count: int, size_mb: int) -> list[str]:
    payload_size = size_mb * MiB
    expected = []
    for index in range(count):
        name = f"large_archive_{index:02d}.zip"
        write_stored_zip(root / name, payload_size, f"archive-{index:02d}")
        expected.append(name)
    return sorted(expected)


class SevenZipProcessSampler:
    def __init__(self, interval_seconds: float = 0.01):
        self.interval_seconds = interval_seconds
        self.samples: list[int] = []
        self.max_count = 0
        self._stop = threading.Event()
        self._thread = threading.Thread(target=self._run, daemon=True)

    def __enter__(self):
        self._thread.start()
        return self

    def __exit__(self, exc_type, exc, tb):
        self._stop.set()
        self._thread.join(timeout=2.0)

    def _run(self):
        current = psutil.Process()
        while not self._stop.is_set():
            count = 0
            try:
                for child in current.children(recursive=True):
                    try:
                        if child.name().lower() == "7z.exe":
                            count += 1
                    except (psutil.NoSuchProcess, psutil.AccessDenied):
                        pass
            except (psutil.NoSuchProcess, psutil.AccessDenied):
                count = 0
            self.samples.append(count)
            self.max_count = max(self.max_count, count)
            time.sleep(self.interval_seconds)


def extracted_marker_paths(root: Path, expected_names: list[str]) -> list[Path]:
    markers = []
    for archive_name in expected_names:
        label = archive_name.removesuffix(".zip").replace("large_archive_", "archive-")
        marker = root / archive_name.removesuffix(".zip") / f"{label}.bin"
        if marker.is_file():
            markers.append(marker)
    return markers


@pytest.mark.large_archive_performance
def test_parallel_extract_ten_300mb_plain_archives(tmp_path, request, record_property):
    count = request.config.getoption("--large-archive-count")
    size_mb = request.config.getoption("--large-archive-size-mb")
    max_extract_seconds = request.config.getoption("--large-archive-max-extract-seconds")
    min_parallel_7z = request.config.getoption("--large-archive-min-parallel-7z")
    scheduler_profile = request.config.getoption("--large-archive-scheduler-profile")

    started = time.perf_counter()
    expected = build_large_archive_corpus(tmp_path, count=count, size_mb=size_mb)
    build_seconds = time.perf_counter() - started

    started = time.perf_counter()
    with SevenZipProcessSampler() as sampler:
        summary = PipelineRunner(large_archive_extract_config(scheduler_profile)).run(str(tmp_path))
    extract_seconds = time.perf_counter() - started

    total_mb = count * size_mb

    record_property("archive_count", count)
    record_property("archive_size_mb", size_mb)
    record_property("total_payload_mb", total_mb)
    record_property("build_seconds", round(build_seconds, 3))
    record_property("extract_seconds", round(extract_seconds, 3))
    record_property("extract_mb_per_second", round(total_mb / extract_seconds, 3) if extract_seconds else 0)
    record_property("max_parallel_7z", sampler.max_count)
    record_property("success_count", summary.success_count)
    record_property("scheduler_profile", scheduler_profile)
    print(
        f"large_archive_performance: profile={scheduler_profile}, count={count}, size_mb={size_mb}, "
        f"total_mb={total_mb}, build_seconds={build_seconds:.3f}, extract_seconds={extract_seconds:.3f}, "
        f"extract_mb_per_second={(total_mb / extract_seconds) if extract_seconds else 0:.3f}, "
        f"max_parallel_7z={sampler.max_count}, failed_tasks={summary.failed_tasks}"
    )

    assert summary.success_count == count
    assert not summary.failed_tasks
    assert len(extracted_marker_paths(tmp_path, expected)) == count
    assert sampler.max_count >= min_parallel_7z
    assert extract_seconds < max_extract_seconds
