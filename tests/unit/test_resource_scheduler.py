import json
import threading
import time
import os
from types import SimpleNamespace

from sunpack.contracts.detection import FactBag
from sunpack.contracts.tasks import ArchiveTask
from sunpack.coordinator.scheduling.concurrency import ConcurrencyScheduler
from sunpack.coordinator.scheduling.executor import TaskExecutor
from sunpack.coordinator.scheduling.resource_model import build_resource_profile_key, estimate_resource_demand


def test_resource_demand_estimation_distinguishes_heavy_lzma_archive():
    light = SimpleNamespace(
        ok=True,
        dominant_method="Deflate",
        archive_type="zip",
        archive_size=8 * 1024 * 1024,
        total_unpacked_size=16 * 1024 * 1024,
        total_packed_size=8 * 1024 * 1024,
        largest_dictionary_size=0,
        file_count=2,
        solid=False,
    )
    heavy = SimpleNamespace(
        ok=True,
        dominant_method="LZMA2",
        archive_type="7z",
        archive_size=2 * 1024 * 1024 * 1024,
        total_unpacked_size=6 * 1024 * 1024 * 1024,
        total_packed_size=2 * 1024 * 1024 * 1024,
        largest_dictionary_size=256 * 1024 * 1024,
        file_count=75_000,
        solid=True,
    )

    light_demand = estimate_resource_demand(light)
    heavy_demand = estimate_resource_demand(heavy)

    assert heavy_demand.cpu > light_demand.cpu
    assert heavy_demand.io > light_demand.io
    assert heavy_demand.memory > light_demand.memory


def test_resource_profile_key_groups_algorithm_shape():
    analysis = SimpleNamespace(
        ok=True,
        dominant_method="LZMA2:24",
        archive_type="7z",
        total_unpacked_size=2 * 1024 * 1024 * 1024,
        largest_dictionary_size=128 * 1024 * 1024,
        file_count=20_000,
        solid=True,
    )

    assert build_resource_profile_key(analysis) == "7z|lzma|solid|dict<256m|size<4g|files<50k"


def test_concurrency_scheduler_requires_all_resource_dimensions():
    scheduler = ConcurrencyScheduler(
        {
            "initial_concurrency_limit": 4,
            "cpu_tokens": 2,
            "io_tokens": 4,
            "memory_tokens": 4,
        },
        current_limit=4,
        max_workers=4,
    )

    assert scheduler.try_acquire_slot(demand={"cpu": 2, "io": 1, "memory": 1}) is True
    assert scheduler.try_acquire_slot(demand={"cpu": 1, "io": 1, "memory": 1}) is False

    scheduler.release_slot(demand={"cpu": 2, "io": 1, "memory": 1})
    assert scheduler.try_acquire_slot(demand={"cpu": 1, "io": 1, "memory": 1}) is True


def test_concurrency_scheduler_adjusts_cpu_io_memory_limits_independently():
    scheduler = ConcurrencyScheduler(
        {
            "initial_concurrency_limit": 2,
            "cpu_tokens": 6,
            "io_tokens": 6,
            "memory_tokens": 6,
            "scale_up_threshold_mb_s": 10,
            "scale_up_backlog_threshold_mb_s": 20,
            "scale_down_threshold_mb_s": 100,
            "cpu_scale_up_threshold_percent": 65,
            "cpu_scale_down_threshold_percent": 85,
            "memory_scale_down_available_mb": 1024,
            "memory_scale_up_available_mb": 2048,
            "scale_up_streak_required": 1,
            "scale_down_streak_required": 1,
        },
        current_limit=2,
        max_workers=6,
    )
    scheduler.pending_task_estimate = 20

    scheduler.adjust_once(
        0,
        cpu_percent=95,
        available_memory=512 * 1024 * 1024,
    )

    assert scheduler.io_limit > 2
    assert scheduler.cpu_limit == 2
    assert scheduler.memory_limit == 2

    scheduler.active_memory_tokens = scheduler.memory_limit
    scheduler.adjust_once(
        150 * 1024 * 1024,
        cpu_percent=95,
        available_memory=512 * 1024 * 1024,
    )

    assert scheduler.memory_limit == 1
    assert scheduler.io_limit >= 2
    assert scheduler.cpu_limit >= 1


def test_concurrency_scheduler_blocks_scale_up_when_throughput_regresses():
    scheduler = ConcurrencyScheduler(
        {
            "initial_concurrency_limit": 2,
            "cpu_tokens": 6,
            "io_tokens": 6,
            "memory_tokens": 6,
            "throughput_window_size": 4,
            "throughput_regression_ratio": 0.95,
            "scale_up_threshold_mb_s": 10,
            "scale_up_backlog_threshold_mb_s": 20,
            "cpu_scale_up_threshold_percent": 65,
            "memory_scale_up_available_mb": 2048,
            "scale_up_streak_required": 1,
            "scale_down_streak_required": 1,
        },
        current_limit=2,
        max_workers=6,
    )
    for active_workers, duration in ((1, 1.0), (1, 1.0), (3, 4.0), (3, 4.0)):
        scheduler.record_task_feedback(
            demand={"cpu": 1, "io": 1, "memory": 1},
            duration_seconds=duration,
            estimated_bytes=100 * 1024 * 1024,
            active_workers_at_start=active_workers,
            success=True,
        )
    scheduler.pending_task_estimate = 20

    scheduler.adjust_once(
        0,
        cpu_percent=20,
        available_memory=8 * 1024 * 1024 * 1024,
    )

    assert scheduler.cpu_limit == 2
    assert scheduler.io_limit == 2
    assert scheduler.memory_limit == 2


def test_concurrency_scheduler_allows_scale_up_when_total_throughput_improves():
    scheduler = ConcurrencyScheduler(
        {
            "initial_concurrency_limit": 2,
            "cpu_tokens": 6,
            "io_tokens": 6,
            "memory_tokens": 6,
            "throughput_window_size": 4,
            "throughput_regression_ratio": 0.95,
            "scale_up_threshold_mb_s": 10,
            "scale_up_backlog_threshold_mb_s": 20,
            "cpu_scale_up_threshold_percent": 65,
            "memory_scale_up_available_mb": 2048,
            "scale_up_streak_required": 1,
            "scale_down_streak_required": 1,
        },
        current_limit=2,
        max_workers=6,
    )
    for active_workers, duration in ((1, 1.0), (1, 1.0), (3, 2.0), (3, 2.0)):
        scheduler.record_task_feedback(
            demand={"cpu": 1, "io": 1, "memory": 1},
            duration_seconds=duration,
            estimated_bytes=100 * 1024 * 1024,
            active_workers_at_start=active_workers,
            success=True,
        )
    scheduler.pending_task_estimate = 20

    scheduler.adjust_once(
        0,
        cpu_percent=20,
        available_memory=8 * 1024 * 1024 * 1024,
    )

    assert scheduler.cpu_limit > 2
    assert scheduler.io_limit > 2
    assert scheduler.memory_limit > 2


def test_profile_calibration_raises_tokens_when_same_profile_regresses():
    scheduler = ConcurrencyScheduler(
        {
            "initial_concurrency_limit": 2,
            "profile_calibration_window_size": 4,
            "profile_regression_ratio": 0.95,
            "profile_calibration_max_delta": 2,
            "profile_calibration_min_parallel": 1,
        },
        current_limit=2,
        max_workers=6,
    )
    profile_key = "7z|lzma|solid|dict>=256m|size>=4g|files<1k"
    for active_workers, duration in ((1, 1.0), (1, 1.0), (3, 4.0), (3, 4.0)):
        scheduler.record_task_feedback(
            demand={"cpu": 2, "io": 2, "memory": 1},
            duration_seconds=duration,
            estimated_bytes=100 * 1024 * 1024,
            active_workers_at_start=active_workers,
            success=True,
            profile_key=profile_key,
        )

    adjusted = scheduler.apply_profile_calibration({"cpu": 2, "io": 2, "memory": 1}, profile_key)

    assert adjusted.cpu == 3
    assert adjusted.io == 3
    assert adjusted.memory == 1


def test_profile_calibration_lowers_tokens_when_same_profile_improves():
    scheduler = ConcurrencyScheduler(
        {
            "initial_concurrency_limit": 2,
            "profile_calibration_window_size": 4,
            "profile_improvement_ratio": 1.05,
        },
        current_limit=2,
        max_workers=6,
    )
    profile_key = "zip|deflate|nonsolid|dict<16m|size<1g|files<1k"
    for active_workers, duration in ((1, 1.0), (1, 1.0), (3, 2.0), (3, 2.0)):
        scheduler.record_task_feedback(
            demand={"cpu": 2, "io": 2, "memory": 1},
            duration_seconds=duration,
            estimated_bytes=100 * 1024 * 1024,
            active_workers_at_start=active_workers,
            success=True,
            profile_key=profile_key,
        )

    adjusted = scheduler.apply_profile_calibration({"cpu": 2, "io": 2, "memory": 1}, profile_key)

    assert adjusted.cpu == 1
    assert adjusted.io == 2
    assert adjusted.memory == 1


def test_task_executor_submits_only_after_resource_tokens_are_available(tmp_path):
    scheduler = ConcurrencyScheduler(
        {
            "initial_concurrency_limit": 3,
            "cpu_tokens": 1,
            "io_tokens": 1,
            "memory_tokens": 1,
            "poll_interval_ms": 100,
        },
        current_limit=3,
        max_workers=3,
    )
    executor = TaskExecutor(scheduler, max_workers=3)
    lock = threading.Lock()
    active = 0
    peak_active = 0

    def make_task(index: int) -> ArchiveTask:
        bag = FactBag()
        bag.set("resource.tokens", {"cpu": 1, "io": 1, "memory": 1})
        archive = tmp_path / f"sample_{index}.zip"
        archive.write_bytes(b"PK")
        return ArchiveTask(fact_bag=bag, score=1, main_path=str(archive), all_parts=[str(archive)])

    def worker(task: ArchiveTask):
        nonlocal active, peak_active
        with lock:
            active += 1
            peak_active = max(peak_active, active)
        time.sleep(0.02)
        with lock:
            active -= 1
        return task.main_path

    results = executor.execute_all([make_task(index) for index in range(4)], worker)

    assert len(results) == 4
    assert peak_active == 1


def test_process_sample_updates_live_pressure_and_memory_profile_adjustment():
    scheduler = ConcurrencyScheduler(
        {
            "initial_concurrency_limit": 2,
            "profile_calibration_max_delta": 2,
            "profile_calibration_min_parallel": 1,
        },
        current_limit=2,
        max_workers=4,
    )
    profile_key = "7z|lzma|solid|dict>=256m|size>=4g|files<1k"

    scheduler.record_process_sample(
        cpu_percent=200,
        memory_bytes=3 * 1024 * 1024 * 1024,
        io_bytes=1234,
        profile_key=profile_key,
    )
    adjusted = scheduler.apply_profile_calibration({"cpu": 2, "io": 2, "memory": 1}, profile_key)

    assert scheduler.live_process_cpu_percent > 0
    assert scheduler.live_process_io_bytes == 1234
    assert adjusted.memory == 2


def test_process_sample_pressure_feeds_next_scheduler_adjustment():
    scheduler = ConcurrencyScheduler(
        {
            "initial_concurrency_limit": 2,
            "cpu_tokens": 4,
            "io_tokens": 4,
            "memory_tokens": 4,
            "cpu_scale_down_threshold_percent": 80,
            "scale_down_streak_required": 1,
            "scale_up_streak_required": 1,
            "medium_backlog_threshold": 100,
            "high_backlog_threshold": 200,
        },
        current_limit=2,
        max_workers=4,
    )
    scheduler.active_cpu_tokens = 2
    scheduler.record_process_sample(
        cpu_percent=(os.cpu_count() or 1) * 95,
        memory_bytes=256 * 1024 * 1024,
        io_bytes=0,
    )

    scheduler.adjust_once(
        0,
        cpu_percent=5,
        available_memory=8 * 1024 * 1024 * 1024,
    )

    assert scheduler.cpu_limit == 1


def test_profile_calibration_persists_to_project_cache_path(tmp_path):
    cache_path = tmp_path / ".sunpack_cache" / "profile_calibration.json"
    profile_key = "7z|lzma|solid|dict>=256m|size>=4g|files<1k"
    scheduler = ConcurrencyScheduler(
        {
            "initial_concurrency_limit": 2,
            "profile_calibration_cache_path": str(cache_path),
            "profile_calibration_window_size": 4,
            "profile_regression_ratio": 0.95,
            "profile_calibration_min_parallel": 1,
        },
        current_limit=2,
        max_workers=6,
    )
    for active_workers, duration in ((1, 1.0), (1, 1.0), (3, 4.0), (3, 4.0)):
        scheduler.record_task_feedback(
            demand={"cpu": 2, "io": 2, "memory": 1},
            duration_seconds=duration,
            estimated_bytes=100 * 1024 * 1024,
            active_workers_at_start=active_workers,
            success=True,
            profile_key=profile_key,
        )

    scheduler.stop()

    payload = json.loads(cache_path.read_text(encoding="utf-8"))
    assert payload["version"] == 3
    assert payload["profiles"][profile_key]["cpu"] == 1
    assert payload["profiles"][profile_key]["io"] == 1

    loaded_scheduler = ConcurrencyScheduler(
        {
            "initial_concurrency_limit": 2,
            "profile_calibration_cache_path": str(cache_path),
            "profile_calibration_min_parallel": 1,
        },
        current_limit=2,
        max_workers=6,
    )
    adjusted = loaded_scheduler.apply_profile_calibration({"cpu": 2, "io": 2, "memory": 1}, profile_key)

    assert adjusted.cpu == 3
    assert adjusted.io == 3


def test_profile_calibration_ignores_corrupt_project_cache(tmp_path):
    cache_path = tmp_path / ".sunpack_cache" / "profile_calibration.json"
    cache_path.parent.mkdir(parents=True)
    cache_path.write_text("{not-json", encoding="utf-8")

    scheduler = ConcurrencyScheduler(
        {
            "initial_concurrency_limit": 2,
            "profile_calibration_cache_path": str(cache_path),
        },
        current_limit=2,
        max_workers=4,
    )

    assert scheduler.profile_adjustments == {}

