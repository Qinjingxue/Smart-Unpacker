from __future__ import annotations

import asyncio
import os
import threading
import time

import pytest

import sunpack.support.resource_lifecycle as lifecycle
from sunpack.support.resource_lifecycle import (
    ResourceBusyError,
    ResourceKind,
    TaskResourceScope,
    named_task_temporary_file,
    open_task_file,
    promotion_barrier,
    register_current_task_resource,
    register_service_resource,
    reset_resource_lifecycle_for_tests,
    resource_snapshot,
)
from sunpack.coordinator.async_work import AsyncWorkBroker


@pytest.fixture(autouse=True)
def _clean_lifecycle_registry():
    reset_resource_lifecycle_for_tests()
    yield
    reset_resource_lifecycle_for_tests()


def test_task_scope_releases_resources_in_reverse_creation_order(tmp_path):
    path = tmp_path / "input.bin"
    path.write_bytes(b"payload")
    released: list[str] = []
    scope = TaskResourceScope("task-lifo", files=(path,))

    with scope.activate():
        register_current_task_resource(
            object(),
            (path,),
            lambda: released.append("first"),
            kind=ResourceKind.OTHER,
        )
        register_current_task_resource(
            object(),
            (path,),
            lambda: released.append("second"),
            kind=ResourceKind.OTHER,
        )

    report = scope.close()

    assert report.released == 2
    assert released == ["second", "first"]
    assert resource_snapshot((path,)) == ()


def test_promotion_gate_excludes_new_overlapping_file_opens(tmp_path):
    root = tmp_path / "output"
    root.mkdir()
    path = root / "held.bin"
    path.write_bytes(b"payload")
    entered = threading.Event()
    completed = threading.Event()

    def open_in_thread() -> None:
        entered.set()
        with open_task_file(path, "rb") as handle:
            assert handle.read() == b"payload"
        completed.set()

    with promotion_barrier((root,), strict_open_file_audit=False):
        worker = threading.Thread(target=open_in_thread)
        worker.start()
        assert entered.wait(1.0)
        assert not completed.wait(0.05)

    worker.join(1.0)
    assert completed.is_set()


def test_named_temporary_file_in_ancestor_sibling_does_not_conflict_with_child_promotion(tmp_path):
    promoted = tmp_path / "out" / "archive"
    promoted.mkdir(parents=True)

    with promotion_barrier((promoted,), strict_open_file_audit=False):
        with named_task_temporary_file(
            mode="w",
            encoding="utf-8",
            dir=tmp_path,
            prefix=".state.",
            suffix=".tmp",
            delete=False,
        ) as handle:
            handle.write("state")
            temporary_path = tmp_path / os.path.basename(handle.name)

    assert temporary_path.read_text(encoding="utf-8") == "state"
    temporary_path.unlink()


def test_named_temporary_file_waits_for_parent_promotion(tmp_path):
    child = tmp_path / "state"
    child.mkdir()
    entered = threading.Event()
    completed = threading.Event()

    def create_temporary_file() -> None:
        entered.set()
        with named_task_temporary_file(dir=child) as handle:
            handle.write(b"state")
        completed.set()

    with promotion_barrier((tmp_path,), strict_open_file_audit=False):
        worker = threading.Thread(target=create_temporary_file)
        worker.start()
        assert entered.wait(1.0)
        assert not completed.wait(0.05)

    worker.join(1.0)
    assert completed.is_set()


def test_promotion_fails_closed_for_another_tasks_live_resource(tmp_path):
    root = tmp_path / "output"
    root.mkdir()
    path = root / "held.bin"
    path.write_bytes(b"payload")
    scope = TaskResourceScope("other-task", files=(path,))
    released = threading.Event()
    with scope.activate():
        register_current_task_resource(
            object(),
            (path,),
            released.set,
            kind=ResourceKind.PYTHON_FILE,
        )

    with pytest.raises(ResourceBusyError, match="other-task"):
        with promotion_barrier((root,), timeout=0.01, strict_open_file_audit=False):
            pass

    assert not released.is_set()
    scope.close()
    assert released.is_set()


def test_promotion_waits_for_current_tasks_concurrent_operation(tmp_path):
    root = tmp_path / "output"
    root.mkdir()
    scope = TaskResourceScope("current-task", files=(root,))
    entered = threading.Event()
    release = threading.Event()

    def run_operation() -> None:
        with scope.activate(), scope.operation():
            entered.set()
            assert release.wait(1.0)

    worker = threading.Thread(target=run_operation)
    worker.start()
    assert entered.wait(1.0)
    timer = threading.Timer(0.05, release.set)
    timer.start()

    started = time.perf_counter()
    with scope.activate(), promotion_barrier((root,), timeout=1.0):
        pass
    elapsed = time.perf_counter() - started

    worker.join(1.0)
    timer.join(1.0)
    assert elapsed >= 0.04
    scope.close()


def test_service_owned_file_resource_blocks_promotion(tmp_path):
    root = tmp_path / "output"
    root.mkdir()
    path = root / "service.log"
    path.write_text("held", encoding="utf-8")
    released = threading.Event()
    lease = register_service_resource(
        object(),
        (path,),
        released.set,
        kind=ResourceKind.PYTHON_FILE,
    )

    with pytest.raises(ResourceBusyError, match="service_owned"):
        with promotion_barrier((root,), timeout=0.01):
            pass

    assert not released.is_set()
    lease.close()
    assert released.is_set()


def test_unscoped_tracked_handle_is_closed_before_replace(tmp_path):
    source = tmp_path / "source"
    target = tmp_path / "target"
    source.mkdir()
    handle = open_task_file(source / "payload.bin", "wb")
    handle.write(b"payload")
    handle.flush()

    with promotion_barrier((source,)):
        assert handle.closed
        os.replace(source, target)

    assert (target / "payload.bin").read_bytes() == b"payload"


def test_clean_promotion_barrier_fast_path_p95_and_p99_are_bounded(tmp_path):
    root = tmp_path / "output"
    root.mkdir()

    with promotion_barrier((root,), strict_open_file_audit=False):
        pass
    samples = []
    for _index in range(100):
        started = time.perf_counter()
        with promotion_barrier((root,), strict_open_file_audit=False) as report:
            pass
        samples.append(time.perf_counter() - started)
    samples.sort()
    p95 = samples[94]
    p99 = samples[98]

    assert report.released_resources == 0
    assert p95 < 0.05
    assert p99 < 0.25


def test_work_broker_inherits_scope_when_request_id_is_omitted(tmp_path):
    path = tmp_path / "broker.bin"
    path.write_bytes(b"payload")
    holder = {}

    async def scenario() -> None:
        broker = AsyncWorkBroker(thread_capacity=1)
        scope = TaskResourceScope("broker-task", files=(path,))

        def create_handle() -> None:
            holder["handle"] = open_task_file(path, "rb")

        with scope.activate():
            await broker.run("read", str(path), create_handle)
            snapshot = resource_snapshot((path,))
            assert any(item["task_id"] == "broker-task" for item in snapshot)
            await scope.aclose()
        await broker.close()

    asyncio.run(scenario())
    assert holder["handle"].closed


def test_work_broker_file_operation_uses_lightweight_path_counter(tmp_path, monkeypatch):
    path = tmp_path / "lightweight-operation.bin"
    path.write_bytes(b"payload")
    operation_started = threading.Event()
    release_operation = threading.Event()

    async def scenario() -> None:
        broker = AsyncWorkBroker(thread_capacity=1)
        scope = TaskResourceScope("lightweight-operation-task", files=(path,))

        def slow_operation() -> None:
            operation_started.set()
            assert release_operation.wait(1.0)

        def unexpected_uuid():
            raise AssertionError("broker file operations must not allocate resource UUIDs")

        monkeypatch.setattr(lifecycle.uuid, "uuid4", unexpected_uuid)
        with scope.activate():
            task = asyncio.create_task(broker.run("read", str(path), slow_operation))
            await asyncio.to_thread(operation_started.wait, 1.0)
            operations = [
                item
                for item in resource_snapshot((tmp_path,))
                if item["kind"] == ResourceKind.FILE_OPERATION.value
            ]
            assert len(operations) == 1
            assert operations[0]["task_id"] == scope.task_id
            assert operations[0]["active_count"] == 1
            release_operation.set()
            await task
            assert not any(
                item["kind"] == ResourceKind.FILE_OPERATION.value
                for item in resource_snapshot((tmp_path,))
            )
            await scope.aclose()
        await broker.close()

    asyncio.run(scenario())


def test_work_broker_reuses_file_identity_for_nested_tracked_open(tmp_path, monkeypatch):
    path = tmp_path / "identity-reuse.bin"
    path.write_bytes(b"payload")

    async def scenario() -> None:
        broker = AsyncWorkBroker(thread_capacity=1)
        scope = TaskResourceScope("identity-reuse-task", files=(path,))
        real_stat = lifecycle.os.stat
        stat_calls = 0

        def counted_stat(*args, **kwargs):
            nonlocal stat_calls
            stat_calls += 1
            return real_stat(*args, **kwargs)

        def read_operation() -> bytes:
            with open_task_file(path, "rb") as handle:
                return handle.read()

        monkeypatch.setattr(lifecycle.os, "stat", counted_stat)
        with scope.activate():
            assert await broker.run("read", str(path), read_operation) == b"payload"
            await scope.aclose()
        await broker.close()
        assert stat_calls == 1

    asyncio.run(scenario())


def test_promotion_waits_for_other_tasks_broker_file_operation(tmp_path):
    path = tmp_path / "broker-operation.bin"
    path.write_bytes(b"payload")
    operation_started = threading.Event()
    release_operation = threading.Event()
    barrier_completed = threading.Event()

    async def scenario() -> None:
        broker = AsyncWorkBroker(thread_capacity=1)
        scope = TaskResourceScope("broker-operation-task", files=(path,))

        def slow_operation() -> None:
            operation_started.set()
            assert release_operation.wait(1.0)

        with scope.activate():
            task = asyncio.create_task(broker.run("read", str(path), slow_operation))
            await asyncio.to_thread(operation_started.wait, 1.0)

            def promote() -> None:
                with promotion_barrier((tmp_path,), timeout=1.0):
                    barrier_completed.set()

            worker = threading.Thread(target=promote)
            worker.start()
            await asyncio.sleep(0.05)
            assert not barrier_completed.is_set()
            release_operation.set()
            await task
            await asyncio.to_thread(worker.join, 1.0)
            assert barrier_completed.is_set()
            await scope.aclose()
        await broker.close()

    asyncio.run(scenario())


def test_async_scope_close_waits_for_cancelled_worker_without_blocking_loop(tmp_path):
    path = tmp_path / "cancel.bin"
    path.write_bytes(b"payload")
    started = threading.Event()

    async def scenario() -> None:
        broker = AsyncWorkBroker(thread_capacity=1)
        scope = TaskResourceScope("cancel-task", files=(path,))

        def slow_operation() -> None:
            started.set()
            time.sleep(0.05)

        with scope.activate():
            task = asyncio.create_task(broker.run("read", str(path), slow_operation))
            await asyncio.to_thread(started.wait, 1.0)
            task.cancel()
            await asyncio.gather(task, return_exceptions=True)
            close_started = time.perf_counter()
            await scope.aclose()
            assert time.perf_counter() - close_started < 1.0
        await broker.close()

    asyncio.run(scenario())
