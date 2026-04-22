from __future__ import annotations

import time

import psutil


class WorkerScheduler:
    def __init__(self, engine):
        self.engine = engine

    def adjust_workers(self):
        config = self.engine.app_config
        poll_interval_seconds = max(config.scheduler_poll_interval_ms, 100) / 1000
        scale_up_threshold = config.scheduler_scale_up_threshold_mb_s * 1024 * 1024
        scale_up_backlog_threshold = config.scheduler_scale_up_backlog_threshold_mb_s * 1024 * 1024
        scale_down_threshold = config.scheduler_scale_down_threshold_mb_s * 1024 * 1024
        scale_up_streak_required = max(1, config.scheduler_scale_up_streak_required)
        scale_down_streak_required = max(1, config.scheduler_scale_down_streak_required)
        medium_backlog_threshold = max(1, config.scheduler_medium_backlog_threshold)
        high_backlog_threshold = max(medium_backlog_threshold, config.scheduler_high_backlog_threshold)
        medium_floor_workers = max(1, config.scheduler_medium_floor_workers)
        high_floor_workers = max(medium_floor_workers, config.scheduler_high_floor_workers)
        last = psutil.disk_io_counters()
        last_bytes = (last.read_bytes + last.write_bytes) if last else 0
        while self.engine.is_running:
            time.sleep(poll_interval_seconds)
            now = psutil.disk_io_counters()
            if not now:
                continue
            now_bytes = now.read_bytes + now.write_bytes
            delta = now_bytes - last_bytes
            last_bytes = now_bytes
            self.engine.io_history.append(delta)
            avg_delta = sum(self.engine.io_history) / len(self.engine.io_history)

            with self.engine.concurrency_cond:
                backlog = self.engine.pending_task_estimate
                if self.engine.max_workers_limit <= 1:
                    dynamic_floor = 1
                elif backlog >= max(high_backlog_threshold, self.engine.max_workers_limit * 4) and self.engine.max_workers_limit >= 4:
                    dynamic_floor = min(high_floor_workers, self.engine.max_workers_limit)
                elif backlog >= max(medium_backlog_threshold, self.engine.max_workers_limit * 2):
                    dynamic_floor = min(medium_floor_workers, self.engine.max_workers_limit)
                else:
                    dynamic_floor = self.engine.min_workers
                self.engine.dynamic_floor_workers = dynamic_floor

                old_limit = self.engine.current_concurrency_limit
                near_capacity = self.engine.active_workers >= max(1, self.engine.current_concurrency_limit - 1)

                if avg_delta < scale_up_threshold or (
                    backlog > self.engine.current_concurrency_limit * 2 and avg_delta < scale_up_backlog_threshold
                ):
                    self.engine.scale_up_streak += 1
                    self.engine.scale_down_streak = 0
                elif avg_delta > scale_down_threshold and near_capacity and backlog <= self.engine.current_concurrency_limit * 4:
                    self.engine.scale_down_streak += 1
                    self.engine.scale_up_streak = 0
                else:
                    self.engine.scale_up_streak = 0
                    self.engine.scale_down_streak = 0

                if self.engine.scale_up_streak >= scale_up_streak_required and self.engine.current_concurrency_limit < self.engine.max_workers_limit:
                    step = 2 if backlog >= self.engine.current_concurrency_limit * 4 and avg_delta < scale_up_threshold else 1
                    self.engine.current_concurrency_limit = min(self.engine.max_workers_limit, self.engine.current_concurrency_limit + step)
                    self.engine.scale_up_streak = 0
                elif self.engine.scale_down_streak >= scale_down_streak_required and self.engine.current_concurrency_limit > dynamic_floor:
                    self.engine.current_concurrency_limit = max(dynamic_floor, self.engine.current_concurrency_limit - 1)
                    self.engine.scale_down_streak = 0

                self.engine.current_concurrency_limit = max(dynamic_floor, min(self.engine.current_concurrency_limit, self.engine.max_workers_limit))
                if old_limit != self.engine.current_concurrency_limit:
                    self.engine.concurrency_cond.notify_all()

    def update_pending_task_estimate(self, pending_count, futures_count):
        with self.engine.lock:
            self.engine.pending_task_estimate = pending_count + futures_count + len(self.engine.in_progress)
