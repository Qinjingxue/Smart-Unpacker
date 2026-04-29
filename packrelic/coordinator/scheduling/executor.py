import concurrent.futures
import inspect
import time
from typing import Any, Callable

from packrelic.coordinator.scheduling.concurrency import ConcurrencyScheduler
from packrelic.coordinator.scheduling.resource_model import (
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
        pass_scheduler = self._worker_accepts_scheduler(worker_func)
        fifo_selection = self._can_use_fifo_selection(tasks)

        self.scheduler.update_pending_task_estimate(len(tasks), 0)
        self.scheduler.start()

        def wrapped_worker(task: Any, demand: ResourceDemand, profile_key: str) -> Any:
            started_at = time.perf_counter()
            active_workers_at_start = self.scheduler.active_workers_snapshot()
            success = False
            try:
                result = worker_func(task, self.scheduler) if pass_scheduler else worker_func(task)
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
                    while pending:
                        selected = self._select_next_task(pending, fifo=fifo_selection)
                        if selected is None:
                            break
                        index, task, demand, profile_key = selected
                        if not self.scheduler.try_acquire_slot(demand=demand):
                            break
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

    def _select_best_fit_task(self, pending: list[Any]) -> tuple[int, Any, ResourceDemand, str] | None:
        best: tuple[int, int, Any, ResourceDemand, str] | None = None
        for index, task in enumerate(pending):
            demand = self._resource_demand(task)
            profile_key = task_profile_key(task)
            demand = self.scheduler.apply_profile_calibration(demand, profile_key)
            score = self.scheduler.fit_score(demand)
            if score is None:
                continue
            if best is None or score < best[0]:
                best = (score, index, task, demand, profile_key)
        if best is None:
            return None
        _score, index, task, demand, profile_key = best
        return index, task, demand, profile_key

    def _select_next_task(self, pending: list[Any], *, fifo: bool = False) -> tuple[int, Any, ResourceDemand, str] | None:
        if not fifo:
            return self._select_best_fit_task(pending)
        task = pending[0]
        demand = self._resource_demand(task)
        profile_key = task_profile_key(task)
        demand = self.scheduler.apply_profile_calibration(demand, profile_key)
        if self.scheduler.fit_score(demand) is None:
            return None
        return 0, task, demand, profile_key

    def _can_use_fifo_selection(self, tasks: list[Any]) -> bool:
        if len(tasks) <= 1:
            return True
        first_demand = self._resource_demand(tasks[0])
        first_profile = task_profile_key(tasks[0])
        for task in tasks[1:]:
            if task_profile_key(task) != first_profile:
                return False
            if self._resource_demand(task) != first_demand:
                return False
        return True

    def _worker_result_success(self, result: Any) -> bool:
        if isinstance(result, tuple) and len(result) >= 2:
            result = result[1]
        success = getattr(result, "success", None)
        if success is not None:
            return bool(success)
        return True

    def _worker_accepts_scheduler(self, worker_func: Callable[[Any], Any]) -> bool:
        try:
            parameters = inspect.signature(worker_func).parameters
        except (TypeError, ValueError):
            return False
        return len(parameters) >= 2
