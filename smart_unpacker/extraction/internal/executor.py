import concurrent.futures
from typing import Any, Callable

from smart_unpacker.extraction.internal.concurrency import ConcurrencyScheduler


class TaskExecutor:
    def __init__(self, scheduler: ConcurrencyScheduler, max_workers: int = 8):
        self.scheduler = scheduler
        self.max_workers = max_workers

    def execute_all(self, tasks: list[Any], worker_func: Callable[[Any], Any]) -> list[Any]:
        results = []

        self.scheduler.update_pending_task_estimate(len(tasks), 0)
        self.scheduler.start()

        def wrapped_worker(task: Any) -> Any:
            self.scheduler.acquire_slot()
            try:
                return worker_func(task)
            finally:
                self.scheduler.release_slot()

        try:
            with concurrent.futures.ThreadPoolExecutor(max_workers=self.max_workers) as pool:
                futures = []
                for index, task in enumerate(tasks):
                    futures.append(pool.submit(wrapped_worker, task))
                    self.scheduler.update_pending_task_estimate(len(tasks) - index - 1, len(futures))
                for future in concurrent.futures.as_completed(futures):
                    results.append(future.result())
                    self.scheduler.update_pending_task_estimate(0, sum(1 for item in futures if not item.done()))
        finally:
            self.scheduler.update_pending_task_estimate(0, 0)
            self.scheduler.stop()

        return results
