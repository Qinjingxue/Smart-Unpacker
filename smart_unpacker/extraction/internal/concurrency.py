import os
import subprocess
import threading
import time

import psutil


SCHEDULER_PROFILES = {
    "conservative": {
        "initial_concurrency_limit": 4,
        "poll_interval_ms": 1000,
        "scale_up_threshold_mb_s": 20,
        "scale_up_backlog_threshold_mb_s": 40,
        "scale_down_threshold_mb_s": 140,
        "scale_up_streak_required": 2,
        "scale_down_streak_required": 3,
        "medium_backlog_threshold": 8,
        "high_backlog_threshold": 24,
        "medium_floor_workers": 2,
        "high_floor_workers": 3,
    },
    "aggressive": {
        "initial_concurrency_limit": 6,
        "poll_interval_ms": 500,
        "scale_up_threshold_mb_s": 80,
        "scale_up_backlog_threshold_mb_s": 160,
        "scale_down_threshold_mb_s": 400,
        "scale_up_streak_required": 2,
        "scale_down_streak_required": 3,
        "medium_backlog_threshold": 8,
        "high_backlog_threshold": 24,
        "medium_floor_workers": 4,
        "high_floor_workers": 6,
    },
}


def select_auto_scheduler_profile() -> str:
    cpu_count = os.cpu_count() or 4
    memory_gb = 0.0
    try:
        memory_gb = psutil.virtual_memory().total / (1024**3)
    except Exception:
        memory_gb = 0.0
    if cpu_count >= 12 and memory_gb >= 24:
        return "aggressive"
    return "conservative"


def build_scheduler_profile_config(requested_profile: str | None) -> dict:
    requested_profile = requested_profile or "auto"
    resolved_profile = select_auto_scheduler_profile() if requested_profile == "auto" else requested_profile
    config = dict(SCHEDULER_PROFILES.get(resolved_profile, SCHEDULER_PROFILES["conservative"]))
    config["scheduler_profile"] = requested_profile
    config["resolved_scheduler_profile"] = resolved_profile
    return config


def detect_max_workers() -> int:
    cpu_count = os.cpu_count() or 4
    if os.name == "nt":
        try:
            result = subprocess.run(
                ["powershell", "-Command", "Get-PhysicalDisk | Select-Object -Property MediaType"],
                capture_output=True,
                text=True,
                stdin=subprocess.DEVNULL,
            )
            if "SSD" in result.stdout.upper():
                return max(2, cpu_count)
        except Exception:
            pass
    return 2


def resolve_max_workers() -> int:
    return max(1, detect_max_workers())


class ConcurrencyScheduler:
    def __init__(self, config: dict, current_limit: int = 2, max_workers: int = 8):
        self.config = config
        initial_limit = config.get("initial_concurrency_limit", current_limit)
        self.current_limit = max(1, min(initial_limit, max_workers))
        self.max_workers = max_workers
        self.min_workers = 1
        self.dynamic_floor_workers = 1

        self.is_running = False
        self.active_workers = 0
        self.active_resource_tokens = 0
        self.pending_task_estimate = 0

        self.scale_up_streak = 0
        self.scale_down_streak = 0
        self.io_history = []

        self.cond = threading.Condition()
        self.thread = None

    def start(self):
        self.is_running = True
        self.thread = threading.Thread(target=self._adjust_loop, daemon=True)
        self.thread.start()

    def stop(self):
        self.is_running = False
        if self.thread:
            self.thread.join(timeout=2.0)

    def _adjust_loop(self):
        poll_interval = max(self.config.get("poll_interval_ms", 1000), 100) / 1000.0
        last_io = psutil.disk_io_counters()
        last_bytes = (last_io.read_bytes + last_io.write_bytes) if last_io else 0

        while self.is_running:
            time.sleep(poll_interval)
            now_io = psutil.disk_io_counters()
            if not now_io:
                continue

            now_bytes = now_io.read_bytes + now_io.write_bytes
            delta = now_bytes - last_bytes
            last_bytes = now_bytes

            self.io_history.append(delta)
            if len(self.io_history) > 5:
                self.io_history.pop(0)

            avg_delta = sum(self.io_history) / len(self.io_history)
            self.adjust_once(avg_delta)

    def adjust_once(self, avg_delta: float):
        scale_up_threshold = self.config.get("scale_up_threshold_mb_s", 50) * 1024 * 1024
        scale_up_backlog_threshold = self.config.get(
            "scale_up_backlog_threshold_mb_s",
            self.config.get("scale_up_threshold_mb_s", 50) * 2,
        ) * 1024 * 1024
        scale_down_threshold = self.config.get("scale_down_threshold_mb_s", 200) * 1024 * 1024
        scale_up_streak_req = max(1, self.config.get("scale_up_streak_required", 3))
        scale_down_streak_req = max(1, self.config.get("scale_down_streak_required", 2))
        medium_backlog_threshold = max(1, self.config.get("medium_backlog_threshold", 8))
        high_backlog_threshold = max(medium_backlog_threshold, self.config.get("high_backlog_threshold", 24))
        medium_floor_workers = max(1, self.config.get("medium_floor_workers", 2))
        high_floor_workers = max(medium_floor_workers, self.config.get("high_floor_workers", 3))

        with self.cond:
            backlog = self.pending_task_estimate
            if self.max_workers <= 1:
                dynamic_floor = 1
            elif backlog >= max(high_backlog_threshold, self.max_workers * 4) and self.max_workers >= 4:
                dynamic_floor = min(high_floor_workers, self.max_workers)
            elif backlog >= max(medium_backlog_threshold, self.max_workers * 2):
                dynamic_floor = min(medium_floor_workers, self.max_workers)
            else:
                dynamic_floor = self.min_workers
            self.dynamic_floor_workers = dynamic_floor

            old_limit = self.current_limit
            near_capacity = self.active_resource_tokens >= max(1, self.current_limit - 1)

            if avg_delta < scale_up_threshold or (
                backlog > self.current_limit * 2 and avg_delta < scale_up_backlog_threshold
            ):
                self.scale_up_streak += 1
                self.scale_down_streak = 0
            elif avg_delta > scale_down_threshold and near_capacity and backlog <= self.current_limit * 4:
                self.scale_down_streak += 1
                self.scale_up_streak = 0
            else:
                self.scale_up_streak = 0
                self.scale_down_streak = 0

            if self.scale_up_streak >= scale_up_streak_req and self.current_limit < self.max_workers:
                step = 2 if backlog >= self.current_limit * 4 and avg_delta < scale_up_threshold else 1
                self.current_limit = min(self.max_workers, self.current_limit + step)
                self.scale_up_streak = 0
            elif self.scale_down_streak >= scale_down_streak_req and self.current_limit > dynamic_floor:
                self.current_limit = max(dynamic_floor, self.current_limit - 1)
                self.scale_down_streak = 0

            self.current_limit = max(dynamic_floor, min(self.current_limit, self.max_workers))
            if old_limit != self.current_limit:
                self.cond.notify_all()

    def update_pending_task_estimate(self, pending_count: int, futures_count: int = 0):
        with self.cond:
            self.pending_task_estimate = pending_count + futures_count + self.active_workers

    def acquire_slot(self, token_cost: int = 1):
        token_cost = max(1, int(token_cost or 1))
        with self.cond:
            while self.active_workers > 0 and self.active_resource_tokens + token_cost > self.current_limit:
                self.cond.wait()
            self.active_workers += 1
            self.active_resource_tokens += token_cost

    def release_slot(self, token_cost: int = 1):
        token_cost = max(1, int(token_cost or 1))
        with self.cond:
            self.active_workers -= 1
            self.active_resource_tokens = max(0, self.active_resource_tokens - token_cost)
            self.cond.notify_all()
