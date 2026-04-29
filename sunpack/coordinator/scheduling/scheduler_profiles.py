import os

import psutil


SCHEDULER_PROFILES = {
    "conservative": {
        "initial_concurrency_limit": 4,
        "poll_interval_ms": 1000,
        "process_sample_interval_ms": 500,
        "max_extract_task_seconds": 0,
        "process_no_progress_timeout_seconds": 0,
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
        "process_sample_interval_ms": 500,
        "max_extract_task_seconds": 0,
        "process_no_progress_timeout_seconds": 0,
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
