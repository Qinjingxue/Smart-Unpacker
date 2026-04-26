import threading
import time
from types import SimpleNamespace

from smart_unpacker.contracts.detection import FactBag
from smart_unpacker.contracts.tasks import ArchiveTask
from smart_unpacker.extraction.internal.concurrency import ConcurrencyScheduler
from smart_unpacker.extraction.internal.executor import TaskExecutor
from smart_unpacker.extraction.internal.resource_model import estimate_resource_demand


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
