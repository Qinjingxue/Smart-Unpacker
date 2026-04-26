import json
import os
import subprocess
import threading
import time
from collections import defaultdict, deque
from pathlib import Path

import psutil

from smart_unpacker.extraction.internal.resource_model import (
    ResourceDemand,
    TaskRunFeedback,
    build_resource_budget,
    demand_from_value,
)


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
        self.cpu_limit = self.current_limit
        self.io_limit = self.current_limit
        self.memory_limit = self.current_limit
        self.max_workers = max_workers
        self.min_workers = 1
        self.dynamic_floor_workers = 1
        self.base_budget = build_resource_budget(config, max_workers)

        self.is_running = False
        self.active_workers = 0
        self.active_resource_tokens = 0
        self.active_cpu_tokens = 0
        self.active_io_tokens = 0
        self.active_memory_tokens = 0
        self.pending_task_estimate = 0

        self.scale_up_streak = 0
        self.scale_down_streak = 0
        self.cpu_scale_up_streak = 0
        self.cpu_scale_down_streak = 0
        self.io_scale_up_streak = 0
        self.io_scale_down_streak = 0
        self.memory_scale_up_streak = 0
        self.memory_scale_down_streak = 0
        self.io_history = []
        self.feedback_window_size = max(4, int(config.get("throughput_window_size", 8) or 8))
        self.throughput_regression_ratio = float(config.get("throughput_regression_ratio", 0.95) or 0.95)
        self.feedback_window: deque[TaskRunFeedback] = deque(maxlen=self.feedback_window_size)
        self.profile_window_size = max(4, int(config.get("profile_calibration_window_size", 4) or 4))
        self.profile_regression_ratio = float(config.get("profile_regression_ratio", 0.95) or 0.95)
        self.profile_improvement_ratio = float(config.get("profile_improvement_ratio", 1.05) or 1.05)
        self.profile_calibration_max_delta = max(0, int(config.get("profile_calibration_max_delta", 2) or 2))
        self.profile_feedback_windows: dict[str, deque[TaskRunFeedback]] = defaultdict(
            lambda: deque(maxlen=self.profile_window_size)
        )
        self.profile_calibration_cache_enabled = bool(config.get("profile_calibration_cache_enabled", True))
        self.profile_calibration_cache_path = self._resolve_profile_calibration_cache_path(
            config.get("profile_calibration_cache_path")
        )
        self.profile_adjustments: dict[str, dict[str, int]] = self._load_profile_adjustments()
        self.profile_adjustments_dirty = False
        self.live_process_cpu_percent = 0.0
        self.live_process_memory_bytes = 0
        self.live_process_io_bytes = 0

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
        self._save_profile_adjustments()

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
            try:
                cpu_percent = psutil.cpu_percent(interval=None)
            except Exception:
                cpu_percent = None
            try:
                available_memory = psutil.virtual_memory().available
            except Exception:
                available_memory = None

            self.io_history.append(delta)
            if len(self.io_history) > 5:
                self.io_history.pop(0)

            avg_delta = sum(self.io_history) / len(self.io_history)
            self.adjust_once(avg_delta, cpu_percent=cpu_percent, available_memory=available_memory)

    def adjust_once(self, avg_delta: float, cpu_percent: float | None = None, available_memory: int | None = None):
        scale_up_threshold = self.config.get("scale_up_threshold_mb_s", 50) * 1024 * 1024
        scale_up_backlog_threshold = self.config.get(
            "scale_up_backlog_threshold_mb_s",
            self.config.get("scale_up_threshold_mb_s", 50) * 2,
        ) * 1024 * 1024
        scale_down_threshold = self.config.get("scale_down_threshold_mb_s", 200) * 1024 * 1024
        cpu_scale_up_threshold = self.config.get("cpu_scale_up_threshold_percent", 65)
        cpu_scale_down_threshold = self.config.get("cpu_scale_down_threshold_percent", 88)
        memory_scale_down_available = self.config.get("memory_scale_down_available_mb", 1024) * 1024 * 1024
        memory_scale_up_available = self.config.get("memory_scale_up_available_mb", 2048) * 1024 * 1024
        scale_up_streak_req = max(1, self.config.get("scale_up_streak_required", 3))
        scale_down_streak_req = max(1, self.config.get("scale_down_streak_required", 2))
        medium_backlog_threshold = max(1, self.config.get("medium_backlog_threshold", 8))
        high_backlog_threshold = max(medium_backlog_threshold, self.config.get("high_backlog_threshold", 24))
        medium_floor_workers = max(1, self.config.get("medium_floor_workers", 2))
        high_floor_workers = max(medium_floor_workers, self.config.get("high_floor_workers", 3))

        with self.cond:
            backlog = self.pending_task_estimate
            if cpu_percent is None:
                effective_cpu_percent = self.live_process_cpu_percent
            else:
                effective_cpu_percent = max(float(cpu_percent), self.live_process_cpu_percent)
            effective_avg_delta = max(float(avg_delta or 0.0), float(self.live_process_io_bytes))
            self.live_process_cpu_percent = 0.0
            self.live_process_io_bytes = 0
            if self.max_workers <= 1:
                dynamic_floor = 1
            elif backlog >= max(high_backlog_threshold, self.max_workers * 4) and self.max_workers >= 4:
                dynamic_floor = min(high_floor_workers, self.max_workers)
            elif backlog >= max(medium_backlog_threshold, self.max_workers * 2):
                dynamic_floor = min(medium_floor_workers, self.max_workers)
            else:
                dynamic_floor = self.min_workers
            self.dynamic_floor_workers = dynamic_floor

            old_limits = (self.cpu_limit, self.io_limit, self.memory_limit, self.current_limit)
            backlog_wants_more = backlog > max(self.cpu_limit, self.io_limit, self.memory_limit) * 2
            throughput_allows_scale_up = self._throughput_allows_scale_up_locked()

            self._adjust_cpu_limit_locked(
                effective_cpu_percent,
                backlog_wants_more and throughput_allows_scale_up,
                dynamic_floor,
                scale_up_streak_req,
                scale_down_streak_req,
                cpu_scale_up_threshold,
                cpu_scale_down_threshold,
            )
            self._adjust_io_limit_locked(
                effective_avg_delta,
                backlog,
                dynamic_floor,
                throughput_allows_scale_up,
                scale_up_threshold,
                scale_up_backlog_threshold,
                scale_down_threshold,
                scale_up_streak_req,
                scale_down_streak_req,
            )
            self._adjust_memory_limit_locked(
                available_memory,
                backlog_wants_more and throughput_allows_scale_up,
                dynamic_floor,
                scale_up_streak_req,
                scale_down_streak_req,
                memory_scale_down_available,
                memory_scale_up_available,
            )
            self._refresh_current_limit_locked()
            if old_limits != (self.cpu_limit, self.io_limit, self.memory_limit, self.current_limit):
                self.cond.notify_all()

    def update_pending_task_estimate(self, pending_count: int, futures_count: int = 0):
        with self.cond:
            self.pending_task_estimate = pending_count + futures_count + self.active_workers

    def active_workers_snapshot(self) -> int:
        with self.cond:
            return self.active_workers

    def record_task_feedback(
        self,
        demand: ResourceDemand | dict,
        duration_seconds: float,
        estimated_bytes: int,
        active_workers_at_start: int,
        success: bool,
        profile_key: str = "",
    ) -> None:
        feedback = TaskRunFeedback(
            demand=demand_from_value(demand),
            duration_seconds=max(0.0, float(duration_seconds or 0.0)),
            estimated_bytes=max(0, int(estimated_bytes or 0)),
            active_workers_at_start=max(1, int(active_workers_at_start or 1)),
            success=bool(success),
            profile_key=str(profile_key or ""),
        )
        if feedback.throughput_bytes_per_second <= 0:
            return
        with self.cond:
            self.feedback_window.append(feedback)
            if feedback.profile_key:
                window = self.profile_feedback_windows[feedback.profile_key]
                window.append(feedback)
                self._recalibrate_profile_locked(feedback.profile_key, window)

    def record_process_sample(
        self,
        cpu_percent: float = 0.0,
        memory_bytes: int = 0,
        io_bytes: int = 0,
        profile_key: str = "",
    ) -> None:
        cpu_count = os.cpu_count() or 1
        normalized_cpu = max(0.0, float(cpu_percent or 0.0)) / max(1, cpu_count)
        with self.cond:
            self.live_process_cpu_percent = max(self.live_process_cpu_percent, normalized_cpu)
            self.live_process_memory_bytes = max(self.live_process_memory_bytes, max(0, int(memory_bytes or 0)))
            self.live_process_io_bytes += max(0, int(io_bytes or 0))
            if profile_key and memory_bytes > 0:
                adjustment = dict(self.profile_adjustments.get(profile_key, {"cpu": 0, "io": 0, "memory": 0}))
                memory_mb = memory_bytes / (1024 * 1024)
                if memory_mb >= 2048:
                    adjustment["memory"] = min(self.profile_calibration_max_delta, int(adjustment.get("memory", 0)) + 1)
                    self._set_profile_adjustment_locked(profile_key, adjustment)

    def apply_profile_calibration(self, demand: ResourceDemand | dict, profile_key: str = "") -> ResourceDemand:
        demand_value = demand_from_value(demand)
        if not profile_key:
            return demand_value
        with self.cond:
            adjustment = self.profile_adjustments.get(profile_key, {})
            return ResourceDemand(
                cpu=max(1, demand_value.cpu + int(adjustment.get("cpu", 0))),
                io=max(1, demand_value.io + int(adjustment.get("io", 0))),
                memory=max(1, demand_value.memory + int(adjustment.get("memory", 0))),
            ).normalized()

    def acquire_slot(self, token_cost: int = 1, demand: ResourceDemand | dict | None = None):
        demand_value = demand_from_value(demand or token_cost)
        with self.cond:
            while not self._can_acquire_locked(demand_value):
                self.cond.wait()
            self.active_workers += 1
            self._add_demand_locked(demand_value)

    def try_acquire_slot(self, token_cost: int = 1, demand: ResourceDemand | dict | None = None) -> bool:
        demand_value = demand_from_value(demand or token_cost)
        with self.cond:
            if not self._can_acquire_locked(demand_value):
                return False
            self.active_workers += 1
            self._add_demand_locked(demand_value)
            return True

    def fit_score(self, demand: ResourceDemand | dict) -> int | None:
        demand_value = demand_from_value(demand)
        with self.cond:
            if not self._can_acquire_locked(demand_value):
                return None
            budget = self._effective_budget_locked()
            remaining_cpu = budget.cpu - (self.active_cpu_tokens + demand_value.cpu)
            remaining_io = budget.io - (self.active_io_tokens + demand_value.io)
            remaining_memory = budget.memory - (self.active_memory_tokens + demand_value.memory)
            return remaining_cpu + remaining_io + remaining_memory

    def release_slot(self, token_cost: int = 1, demand: ResourceDemand | dict | None = None):
        demand_value = demand_from_value(demand or token_cost)
        with self.cond:
            self.active_workers = max(0, self.active_workers - 1)
            self.active_cpu_tokens = max(0, self.active_cpu_tokens - demand_value.cpu)
            self.active_io_tokens = max(0, self.active_io_tokens - demand_value.io)
            self.active_memory_tokens = max(0, self.active_memory_tokens - demand_value.memory)
            self._refresh_active_scalar_locked()
            self.cond.notify_all()

    def _effective_budget_locked(self):
        normalized = self.base_budget.normalized()
        return type(normalized)(
            cpu=max(1, min(normalized.cpu, self.cpu_limit)),
            io=max(1, min(normalized.io, self.io_limit)),
            memory=max(1, min(normalized.memory, self.memory_limit)),
        )

    def _can_acquire_locked(self, demand: ResourceDemand) -> bool:
        demand = demand.normalized()
        budget = self._effective_budget_locked()
        if self.active_workers <= 0:
            return True
        if self.active_workers >= self.max_workers:
            return False
        return (
            self.active_cpu_tokens + demand.cpu <= budget.cpu
            and self.active_io_tokens + demand.io <= budget.io
            and self.active_memory_tokens + demand.memory <= budget.memory
        )

    def _add_demand_locked(self, demand: ResourceDemand) -> None:
        demand = demand.normalized()
        self.active_cpu_tokens += demand.cpu
        self.active_io_tokens += demand.io
        self.active_memory_tokens += demand.memory
        self._refresh_active_scalar_locked()

    def _refresh_active_scalar_locked(self) -> None:
        self.active_resource_tokens = max(
            self.active_cpu_tokens,
            self.active_io_tokens,
            self.active_memory_tokens,
        )

    def _adjust_cpu_limit_locked(
        self,
        cpu_percent: float | None,
        backlog_wants_more: bool,
        dynamic_floor: int,
        scale_up_streak_req: int,
        scale_down_streak_req: int,
        scale_up_threshold: float,
        scale_down_threshold: float,
    ) -> None:
        if cpu_percent is None:
            self.cpu_limit = max(dynamic_floor, min(self.cpu_limit, self.max_workers))
            return
        near_capacity = self.active_cpu_tokens >= max(1, self.cpu_limit - 1)
        if backlog_wants_more and cpu_percent < scale_up_threshold:
            self.cpu_scale_up_streak += 1
            self.cpu_scale_down_streak = 0
        elif cpu_percent > scale_down_threshold and near_capacity:
            self.cpu_scale_down_streak += 1
            self.cpu_scale_up_streak = 0
        else:
            self.cpu_scale_up_streak = 0
            self.cpu_scale_down_streak = 0

        if self.cpu_scale_up_streak >= scale_up_streak_req and self.cpu_limit < self.max_workers:
            self.cpu_limit = min(self.max_workers, self.cpu_limit + 1)
            self.cpu_scale_up_streak = 0
        elif self.cpu_scale_down_streak >= scale_down_streak_req and self.cpu_limit > dynamic_floor:
            self.cpu_limit = max(dynamic_floor, self.cpu_limit - 1)
            self.cpu_scale_down_streak = 0
        self.cpu_limit = max(dynamic_floor, min(self.cpu_limit, self.max_workers))

    def _adjust_io_limit_locked(
        self,
        avg_delta: float,
        backlog: int,
        dynamic_floor: int,
        throughput_allows_scale_up: bool,
        scale_up_threshold: float,
        scale_up_backlog_threshold: float,
        scale_down_threshold: float,
        scale_up_streak_req: int,
        scale_down_streak_req: int,
    ) -> None:
        near_capacity = self.active_io_tokens >= max(1, self.io_limit - 1)
        if throughput_allows_scale_up and (
            avg_delta < scale_up_threshold or (backlog > self.io_limit * 2 and avg_delta < scale_up_backlog_threshold)
        ):
            self.io_scale_up_streak += 1
            self.io_scale_down_streak = 0
            self.scale_up_streak = self.io_scale_up_streak
            self.scale_down_streak = 0
        elif avg_delta > scale_down_threshold and near_capacity and backlog <= self.io_limit * 4:
            self.io_scale_down_streak += 1
            self.io_scale_up_streak = 0
            self.scale_down_streak = self.io_scale_down_streak
            self.scale_up_streak = 0
        else:
            self.io_scale_up_streak = 0
            self.io_scale_down_streak = 0
            self.scale_up_streak = 0
            self.scale_down_streak = 0

        if self.io_scale_up_streak >= scale_up_streak_req and self.io_limit < self.max_workers:
            step = 2 if backlog >= self.io_limit * 4 and avg_delta < scale_up_threshold else 1
            self.io_limit = min(self.max_workers, self.io_limit + step)
            self.io_scale_up_streak = 0
            self.scale_up_streak = 0
        elif self.io_scale_down_streak >= scale_down_streak_req and self.io_limit > dynamic_floor:
            self.io_limit = max(dynamic_floor, self.io_limit - 1)
            self.io_scale_down_streak = 0
            self.scale_down_streak = 0
        self.io_limit = max(dynamic_floor, min(self.io_limit, self.max_workers))

    def _adjust_memory_limit_locked(
        self,
        available_memory: int | None,
        backlog_wants_more: bool,
        dynamic_floor: int,
        scale_up_streak_req: int,
        scale_down_streak_req: int,
        scale_down_available: int,
        scale_up_available: int,
    ) -> None:
        if available_memory is None:
            self.memory_limit = max(dynamic_floor, min(self.memory_limit, self.max_workers))
            return
        memory_floor = self.min_workers if available_memory < scale_down_available else dynamic_floor
        near_capacity = self.active_memory_tokens >= max(1, self.memory_limit - 1)
        if backlog_wants_more and available_memory > scale_up_available:
            self.memory_scale_up_streak += 1
            self.memory_scale_down_streak = 0
        elif available_memory < scale_down_available and near_capacity:
            self.memory_scale_down_streak += 1
            self.memory_scale_up_streak = 0
        else:
            self.memory_scale_up_streak = 0
            self.memory_scale_down_streak = 0

        if self.memory_scale_up_streak >= scale_up_streak_req and self.memory_limit < self.max_workers:
            self.memory_limit = min(self.max_workers, self.memory_limit + 1)
            self.memory_scale_up_streak = 0
        elif self.memory_scale_down_streak >= scale_down_streak_req and self.memory_limit > memory_floor:
            self.memory_limit = max(memory_floor, self.memory_limit - 1)
            self.memory_scale_down_streak = 0
        self.memory_limit = max(memory_floor, min(self.memory_limit, self.max_workers))

    def _refresh_current_limit_locked(self) -> None:
        self.current_limit = max(1, min(self.max_workers, max(self.cpu_limit, self.io_limit, self.memory_limit)))

    def _throughput_allows_scale_up_locked(self) -> bool:
        if len(self.feedback_window) < self.feedback_window_size:
            return True
        samples = [sample for sample in self.feedback_window if sample.success and sample.throughput_bytes_per_second > 0]
        if len(samples) < self.feedback_window_size:
            return True
        midpoint = len(samples) // 2
        previous = samples[:midpoint]
        recent = samples[midpoint:]
        previous_throughput = sum(item.throughput_bytes_per_second for item in previous) / len(previous)
        recent_throughput = sum(item.throughput_bytes_per_second for item in recent) / len(recent)
        previous_workers = sum(item.active_workers_at_start for item in previous) / len(previous)
        recent_workers = sum(item.active_workers_at_start for item in recent) / len(recent)
        if recent_workers <= previous_workers:
            return True
        previous_total_throughput = previous_throughput * previous_workers
        recent_total_throughput = recent_throughput * recent_workers
        return recent_total_throughput >= previous_total_throughput * self.throughput_regression_ratio

    def _recalibrate_profile_locked(self, profile_key: str, window: deque[TaskRunFeedback]) -> None:
        if len(window) < self.profile_window_size:
            return
        samples = [sample for sample in window if sample.success and sample.throughput_bytes_per_second > 0]
        if len(samples) < self.profile_window_size:
            return
        midpoint = len(samples) // 2
        previous = samples[:midpoint]
        recent = samples[midpoint:]
        previous_total = self._estimated_total_throughput(previous)
        recent_total = self._estimated_total_throughput(recent)
        previous_workers = sum(item.active_workers_at_start for item in previous) / len(previous)
        recent_workers = sum(item.active_workers_at_start for item in recent) / len(recent)
        if recent_workers <= previous_workers:
            return

        adjustment = dict(self.profile_adjustments.get(profile_key, {"cpu": 0, "io": 0, "memory": 0}))
        if recent_total < previous_total * self.profile_regression_ratio:
            adjustment["cpu"] = min(self.profile_calibration_max_delta, int(adjustment.get("cpu", 0)) + 1)
            adjustment["io"] = min(self.profile_calibration_max_delta, int(adjustment.get("io", 0)) + 1)
        elif recent_total > previous_total * self.profile_improvement_ratio:
            adjustment["cpu"] = max(-1, int(adjustment.get("cpu", 0)) - 1)
            adjustment["io"] = max(-1, int(adjustment.get("io", 0)) - 1)
        self._set_profile_adjustment_locked(profile_key, adjustment)

    def _estimated_total_throughput(self, samples: list[TaskRunFeedback]) -> float:
        throughput = sum(item.throughput_bytes_per_second for item in samples) / len(samples)
        workers = sum(item.active_workers_at_start for item in samples) / len(samples)
        return throughput * workers

    def _set_profile_adjustment_locked(self, profile_key: str, adjustment: dict[str, int]) -> None:
        cleaned = {
            "cpu": max(-1, min(self.profile_calibration_max_delta, int(adjustment.get("cpu", 0)))),
            "io": max(-1, min(self.profile_calibration_max_delta, int(adjustment.get("io", 0)))),
            "memory": max(0, min(self.profile_calibration_max_delta, int(adjustment.get("memory", 0)))),
        }
        if self.profile_adjustments.get(profile_key) != cleaned:
            self.profile_adjustments[profile_key] = cleaned
            self.profile_adjustments_dirty = True

    def _resolve_profile_calibration_cache_path(self, configured_path) -> Path:
        if configured_path:
            return Path(configured_path)
        project_root = Path(__file__).resolve().parents[3]
        return project_root / ".smart_unpacker_cache" / "profile_calibration.json"

    def _load_profile_adjustments(self) -> dict[str, dict[str, int]]:
        if not self.profile_calibration_cache_enabled:
            return {}
        try:
            payload = json.loads(self.profile_calibration_cache_path.read_text(encoding="utf-8"))
        except Exception:
            return {}
        profiles = payload.get("profiles", {}) if isinstance(payload, dict) else {}
        if not isinstance(profiles, dict):
            return {}
        loaded: dict[str, dict[str, int]] = {}
        for profile_key, adjustment in profiles.items():
            if not isinstance(profile_key, str) or not isinstance(adjustment, dict):
                continue
            try:
                loaded[profile_key] = {
                    "cpu": max(-1, min(self.profile_calibration_max_delta, int(adjustment.get("cpu", 0)))),
                    "io": max(-1, min(self.profile_calibration_max_delta, int(adjustment.get("io", 0)))),
                    "memory": max(0, min(self.profile_calibration_max_delta, int(adjustment.get("memory", 0)))),
                }
            except Exception:
                continue
        return loaded

    def _save_profile_adjustments(self) -> None:
        if (
            not self.profile_calibration_cache_enabled
            or not self.profile_adjustments_dirty
            or not self.profile_adjustments
        ):
            return
        with self.cond:
            profiles = dict(self.profile_adjustments)
            self.profile_adjustments_dirty = False
        payload = {
            "version": 1,
            "updated_at": int(time.time()),
            "profiles": profiles,
        }
        try:
            self.profile_calibration_cache_path.parent.mkdir(parents=True, exist_ok=True)
            temporary_path = self.profile_calibration_cache_path.with_suffix(
                self.profile_calibration_cache_path.suffix + ".tmp"
            )
            temporary_path.write_text(json.dumps(payload, ensure_ascii=False, indent=2, sort_keys=True), encoding="utf-8")
            os.replace(temporary_path, self.profile_calibration_cache_path)
        except Exception:
            with self.cond:
                self.profile_adjustments_dirty = True
