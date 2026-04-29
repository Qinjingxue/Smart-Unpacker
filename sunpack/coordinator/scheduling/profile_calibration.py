from collections import defaultdict, deque

from sunpack.coordinator.scheduling.profile_cache import (
    clean_profile_adjustment,
    load_profile_adjustments,
    resolve_profile_calibration_cache_path,
    save_profile_adjustments,
)
from sunpack.coordinator.scheduling.resource_model import ResourceDemand, TaskRunFeedback, demand_from_value


class SchedulerFeedback:
    def __init__(self, config: dict):
        self.feedback_window_size = max(4, int(config.get("throughput_window_size", 8) or 8))
        self.throughput_regression_ratio = float(config.get("throughput_regression_ratio", 0.95) or 0.95)
        self.feedback_window: deque[TaskRunFeedback] = deque(maxlen=self.feedback_window_size)

        self.profile_window_size = max(4, int(config.get("profile_calibration_window_size", 4) or 4))
        self.profile_regression_ratio = float(config.get("profile_regression_ratio", 0.80) or 0.80)
        self.profile_improvement_ratio = float(config.get("profile_improvement_ratio", 1.20) or 1.20)
        self.profile_calibration_max_delta = max(0, int(config.get("profile_calibration_max_delta", 1) or 1))
        self.profile_calibration_min_parallel = max(1, int(config.get("profile_calibration_min_parallel", 2) or 2))
        self.profile_feedback_windows: dict[str, deque[TaskRunFeedback]] = defaultdict(
            lambda: deque(maxlen=self.profile_window_size)
        )

        self.profile_calibration_cache_enabled = bool(config.get("profile_calibration_cache_enabled", True))
        self.profile_calibration_cache_path = resolve_profile_calibration_cache_path(
            config.get("profile_calibration_cache_path")
        )
        self.profile_adjustments: dict[str, dict[str, int]] = load_profile_adjustments(
            self.profile_calibration_cache_path,
            self.profile_calibration_max_delta,
            enabled=self.profile_calibration_cache_enabled,
        )
        self.profile_adjustments_dirty = False

    def record_task_feedback(self, feedback: TaskRunFeedback) -> None:
        if feedback.throughput_bytes_per_second <= 0:
            return
        self.feedback_window.append(feedback)
        if feedback.profile_key:
            window = self.profile_feedback_windows[feedback.profile_key]
            window.append(feedback)
            self._recalibrate_profile(feedback.profile_key, window)

    def record_process_memory_sample(self, profile_key: str, memory_bytes: int) -> None:
        if not profile_key or memory_bytes <= 0:
            return
        adjustment = dict(self.profile_adjustments.get(profile_key, {"cpu": 0, "io": 0, "memory": 0}))
        memory_mb = memory_bytes / (1024 * 1024)
        if memory_mb >= 2048:
            adjustment["memory"] = min(
                self.profile_calibration_max_delta,
                int(adjustment.get("memory", 0)) + 1,
            )
            self._set_profile_adjustment(profile_key, adjustment)

    def apply_profile_calibration(
        self,
        demand: ResourceDemand | dict,
        profile_key: str = "",
        current_limit: int = 1,
    ) -> ResourceDemand:
        demand_value = demand_from_value(demand)
        if not profile_key:
            return demand_value
        adjustment = self.profile_adjustments.get(profile_key, {})
        calibrated = ResourceDemand(
            cpu=max(1, demand_value.cpu + int(adjustment.get("cpu", 0))),
            io=max(1, demand_value.io + int(adjustment.get("io", 0))),
            memory=max(1, demand_value.memory + int(adjustment.get("memory", 0))),
        ).normalized()
        if self.profile_calibration_min_parallel > 1 and any(
            int(adjustment.get(key, 0)) > 0 for key in ("cpu", "io", "memory")
        ):
            min_parallel_cap = max(1, current_limit // self.profile_calibration_min_parallel)
            calibrated = ResourceDemand(
                cpu=min(calibrated.cpu, max(demand_value.cpu, min_parallel_cap)),
                io=min(calibrated.io, max(demand_value.io, min_parallel_cap)),
                memory=min(calibrated.memory, max(demand_value.memory, min_parallel_cap)),
            ).normalized()
        return calibrated

    def throughput_allows_scale_up(self) -> bool:
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

    def save(self) -> None:
        if (
            not self.profile_calibration_cache_enabled
            or not self.profile_adjustments_dirty
            or not self.profile_adjustments
        ):
            return
        save_profile_adjustments(self.profile_calibration_cache_path, dict(self.profile_adjustments))
        self.profile_adjustments_dirty = False

    def mark_save_failed(self) -> None:
        self.profile_adjustments_dirty = True

    def _recalibrate_profile(self, profile_key: str, window: deque[TaskRunFeedback]) -> None:
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
            average_cpu_demand = sum(item.demand.cpu for item in samples) / len(samples)
            average_io_demand = sum(item.demand.io for item in samples) / len(samples)
            if average_cpu_demand > 1:
                adjustment["cpu"] = max(-1, int(adjustment.get("cpu", 0)) - 1)
            if average_io_demand > 2:
                adjustment["io"] = max(-1, int(adjustment.get("io", 0)) - 1)
        self._set_profile_adjustment(profile_key, adjustment)

    def _estimated_total_throughput(self, samples: list[TaskRunFeedback]) -> float:
        throughput = sum(item.throughput_bytes_per_second for item in samples) / len(samples)
        workers = sum(item.active_workers_at_start for item in samples) / len(samples)
        return throughput * workers

    def _set_profile_adjustment(self, profile_key: str, adjustment: dict[str, int]) -> None:
        cleaned = clean_profile_adjustment(adjustment, self.profile_calibration_max_delta)
        if self.profile_adjustments.get(profile_key) != cleaned:
            self.profile_adjustments[profile_key] = cleaned
            self.profile_adjustments_dirty = True
