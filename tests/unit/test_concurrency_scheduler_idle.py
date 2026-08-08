from __future__ import annotations

import threading
import time
from types import SimpleNamespace

import sunpack.coordinator.scheduling.concurrency as concurrency_module
from sunpack.coordinator.scheduling import ConcurrencyScheduler


def test_resource_scheduler_parks_while_idle_and_wakes_for_pipeline_backlog(monkeypatch):
    disk_samples = []
    sampled = threading.Event()

    def disk_io_counters():
        disk_samples.append(time.monotonic())
        sampled.set()
        return SimpleNamespace(read_bytes=len(disk_samples), write_bytes=0)

    monkeypatch.setattr(concurrency_module.psutil, "disk_io_counters", disk_io_counters)
    monkeypatch.setattr(concurrency_module.psutil, "cpu_percent", lambda interval=None: 0.0)
    monkeypatch.setattr(
        concurrency_module.psutil,
        "virtual_memory",
        lambda: SimpleNamespace(available=16 * 1024**3),
    )
    scheduler = ConcurrencyScheduler({"poll_interval_ms": 100}, current_limit=2, max_workers=4)
    scheduler.start()
    try:
        assert not sampled.wait(timeout=0.25)

        scheduler.set_pipeline_request_backlog(1)
        assert sampled.wait(timeout=1.0)

        scheduler.set_pipeline_request_backlog(0)
        time.sleep(0.2)
        parked_sample_count = len(disk_samples)
        time.sleep(0.3)
        assert len(disk_samples) == parked_sample_count
    finally:
        scheduler.stop()


def test_direct_worker_activity_wakes_idle_resource_scheduler(monkeypatch):
    sampled = threading.Event()

    def disk_io_counters():
        sampled.set()
        return SimpleNamespace(read_bytes=0, write_bytes=0)

    monkeypatch.setattr(concurrency_module.psutil, "disk_io_counters", disk_io_counters)
    monkeypatch.setattr(concurrency_module.psutil, "cpu_percent", lambda interval=None: 0.0)
    monkeypatch.setattr(
        concurrency_module.psutil,
        "virtual_memory",
        lambda: SimpleNamespace(available=16 * 1024**3),
    )
    scheduler = ConcurrencyScheduler({"poll_interval_ms": 100}, current_limit=2, max_workers=4)
    scheduler.start()
    try:
        scheduler.acquire_slot()
        assert sampled.wait(timeout=1.0)
        scheduler.release_slot()
    finally:
        scheduler.stop()


def test_scheduler_rotates_slot_admission_between_runnable_requests():
    scheduler = ConcurrencyScheduler({}, current_limit=2, max_workers=2)
    first = scheduler.register_workload(2, request_id="first")
    second = scheduler.register_workload(2, request_id="second")

    assert scheduler.try_acquire_slot(workload_id=first)
    scheduler.release_slot()
    assert not scheduler.try_acquire_slot(workload_id=first)
    assert scheduler.try_acquire_slot(workload_id=second)
    scheduler.release_slot()

    scheduler.unregister_workload(first)
    scheduler.unregister_workload(second)
