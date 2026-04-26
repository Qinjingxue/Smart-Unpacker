import concurrent.futures
import time
from typing import Any, Callable

from smart_unpacker.extraction.internal.concurrency import ConcurrencyScheduler
from smart_unpacker.extraction.internal.resource_model import (
    ResourceDemand,
    demand_from_value,
    estimate_task_work_bytes,
    task_profile_key,
)


class TaskExecutor:
    def __init__(self, scheduler: ConcurrencyScheduler, max_workers: int = 8):
        self.scheduler = scheduler
        self.max_workers = max_workers

    def execute_all(self, tasks: list[Any], worker_func: Callable[[Any], Any]) -> list[Any]:
        results = []

        self.scheduler.update_pending_task_estimate(len(tasks), 0)
        self.scheduler.start()

        def wrapped_worker(task: Any, demand: ResourceDemand, profile_key: str) -> Any:
            started_at = time.perf_counter()
            active_workers_at_start = self.scheduler.active_workers_snapshot()
            success = False
            try:
                result = worker_func(task)
                success = self._worker_result_success(result)
                return result
            finally:
                duration = time.perf_counter() - started_at
                self.scheduler.record_task_feedback(
                    demand=demand,
                    duration_seconds=duration,
                    estimated_bytes=estimate_task_work_bytes(task),
                    active_workers_at_start=active_workers_at_start,
                    success=success,
                    profile_key=profile_key,
                )
                self.scheduler.release_slot(demand=demand)

        try:
            with concurrent.futures.ThreadPoolExecutor(max_workers=self.max_workers) as pool:
                pending = list(tasks)
                futures: dict[concurrent.futures.Future, ResourceDemand] = {}
                while pending or futures:
                    submitted = False
                    index = 0
                    while index < len(pending):
                        task = pending[index]
                        demand = self._resource_demand(task)
                        profile_key = task_profile_key(task)
                        demand = self.scheduler.apply_profile_calibration(demand, profile_key)
                        if not self.scheduler.try_acquire_slot(demand=demand):
                            index += 1
                            continue
                        pending.pop(index)
                        try:
                            future = pool.submit(wrapped_worker, task, demand, profile_key)
                        except Exception:
                            self.scheduler.release_slot(demand=demand)
                            raise
                        futures[future] = demand
                        submitted = True
                        self.scheduler.update_pending_task_estimate(len(pending), len(futures))

                    if not futures:
                        task = pending.pop(0)
                        demand = self._resource_demand(task)
                        profile_key = task_profile_key(task)
                        demand = self.scheduler.apply_profile_calibration(demand, profile_key)
                        self.scheduler.acquire_slot(demand=demand)
                        try:
                            future = pool.submit(wrapped_worker, task, demand, profile_key)
                        except Exception:
                            self.scheduler.release_slot(demand=demand)
                            raise
                        futures[future] = demand
                        self.scheduler.update_pending_task_estimate(len(pending), len(futures))
                        continue

                    if not submitted:
                        done, _running = concurrent.futures.wait(
                            futures,
                            return_when=concurrent.futures.FIRST_COMPLETED,
                        )
                    else:
                        done = {future for future in futures if future.done()}
                        if not done:
                            done, _running = concurrent.futures.wait(
                                futures,
                                timeout=0.05,
                                return_when=concurrent.futures.FIRST_COMPLETED,
                            )
                            if not done:
                                continue

                    for future in done:
                        futures.pop(future, None)
                        results.append(future.result())
                    self.scheduler.update_pending_task_estimate(len(pending), len(futures))
        finally:
            self.scheduler.update_pending_task_estimate(0, 0)
            self.scheduler.stop()

        return results

    def _token_cost(self, task: Any) -> int:
        return self._resource_demand(task).scalar_cost

    def _resource_demand(self, task: Any) -> ResourceDemand:
        fact_bag = getattr(task, "fact_bag", None)
        if fact_bag is not None:
            try:
                tokens = fact_bag.get("resource.tokens")
                if tokens:
                    return demand_from_value(tokens)
                value = fact_bag.get("resource.token_cost")
                if value:
                    return demand_from_value(value)
            except Exception:
                pass
        return demand_from_value(getattr(task, "resource_token_cost", 1) or 1)

    def _worker_result_success(self, result: Any) -> bool:
        if isinstance(result, tuple) and len(result) >= 2:
            result = result[1]
        success = getattr(result, "success", None)
        if success is not None:
            return bool(success)
        return True
