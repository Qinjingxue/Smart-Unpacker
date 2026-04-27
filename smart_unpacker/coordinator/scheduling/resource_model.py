from __future__ import annotations

import os
from dataclasses import dataclass
from typing import Any

import psutil


@dataclass(frozen=True)
class ResourceDemand:
    cpu: int = 1
    io: int = 1
    memory: int = 1

    def normalized(self) -> "ResourceDemand":
        return ResourceDemand(
            cpu=max(1, int(self.cpu or 1)),
            io=max(1, int(self.io or 1)),
            memory=max(1, int(self.memory or 1)),
        )

    @property
    def scalar_cost(self) -> int:
        return max(self.cpu, self.io, self.memory, 1)

    def as_dict(self) -> dict[str, int]:
        normalized = self.normalized()
        return {
            "cpu": normalized.cpu,
            "io": normalized.io,
            "memory": normalized.memory,
        }


@dataclass(frozen=True)
class ResourceBudget:
    cpu: int
    io: int
    memory: int

    def normalized(self) -> "ResourceBudget":
        return ResourceBudget(
            cpu=max(1, int(self.cpu or 1)),
            io=max(1, int(self.io or 1)),
            memory=max(1, int(self.memory or 1)),
        )

    def scale(self, limit: int, max_workers: int) -> "ResourceBudget":
        limit = max(1, int(limit or 1))
        normalized = self.normalized()
        return ResourceBudget(
            cpu=max(1, min(normalized.cpu, limit)),
            io=max(1, min(normalized.io, limit)),
            memory=max(1, min(normalized.memory, limit)),
        )


@dataclass(frozen=True)
class TaskRunFeedback:
    demand: ResourceDemand
    duration_seconds: float
    estimated_bytes: int
    active_workers_at_start: int
    success: bool
    profile_key: str = ""

    @property
    def throughput_bytes_per_second(self) -> float:
        if self.duration_seconds <= 0 or self.estimated_bytes <= 0:
            return 0.0
        return self.estimated_bytes / self.duration_seconds


def build_resource_budget(config: dict, max_workers: int) -> ResourceBudget:
    max_workers = max(1, int(max_workers or 1))
    cpu_tokens = int(config.get("cpu_tokens", _default_cpu_tokens(max_workers)) or max_workers)
    io_tokens = int(config.get("io_tokens", max_workers) or max_workers)
    memory_tokens = int(config.get("memory_tokens", _default_memory_tokens(max_workers)) or max_workers)
    return ResourceBudget(cpu=cpu_tokens, io=io_tokens, memory=memory_tokens).normalized()


def _default_cpu_tokens(max_workers: int) -> int:
    return max(1, min(max_workers, os.cpu_count() or max_workers))


def _default_memory_tokens(max_workers: int) -> int:
    try:
        available_mb = psutil.virtual_memory().available / (1024 * 1024)
    except Exception:
        return max_workers
    return max(1, min(max_workers, int(available_mb // 512) or 1))


def demand_from_value(value: Any) -> ResourceDemand:
    if isinstance(value, ResourceDemand):
        return value.normalized()
    if isinstance(value, dict):
        return ResourceDemand(
            cpu=value.get("cpu", 1),
            io=value.get("io", 1),
            memory=value.get("memory", 1),
        ).normalized()
    if value:
        scalar = max(1, int(value))
        return ResourceDemand(cpu=scalar, io=scalar, memory=scalar).normalized()
    return ResourceDemand()


def estimate_resource_demand(analysis: Any) -> ResourceDemand:
    if not getattr(analysis, "ok", False):
        return ResourceDemand()

    method = (getattr(analysis, "dominant_method", "") or "").lower()
    archive_type = (getattr(analysis, "archive_type", "") or "").lower()
    archive_mb = max(0, int(getattr(analysis, "archive_size", 0) or 0)) / (1024 * 1024)
    unpacked_mb = max(0, int(getattr(analysis, "total_unpacked_size", 0) or 0)) / (1024 * 1024)
    packed_mb = max(0, int(getattr(analysis, "total_packed_size", 0) or 0)) / (1024 * 1024)
    dictionary_mb = max(0, int(getattr(analysis, "largest_dictionary_size", 0) or 0)) / (1024 * 1024)
    file_count = max(0, int(getattr(analysis, "file_count", 0) or 0))
    solid = bool(getattr(analysis, "solid", False))

    cpu = 1
    io = 1
    memory = 1

    if any(token in method for token in ("lzma", "ppmd")):
        cpu += 2
    elif any(token in method for token in ("bzip2", "deflate64")):
        cpu += 1
    elif "deflate" in method:
        cpu += 1

    if solid:
        cpu += 1
        memory += 1
    if archive_type == "7z" and not method:
        cpu += 1

    if dictionary_mb >= 256:
        memory += 3
    elif dictionary_mb >= 64:
        memory += 2
    elif dictionary_mb >= 16:
        memory += 1

    total_io_mb = max(archive_mb + unpacked_mb, packed_mb + unpacked_mb)
    if total_io_mb >= 4096:
        io += 3
    elif total_io_mb >= 1024:
        io += 2
    elif total_io_mb >= 256:
        io += 1

    if file_count >= 50_000:
        io += 2
        cpu += 1
    elif file_count >= 10_000:
        io += 1

    return ResourceDemand(
        cpu=min(cpu, 6),
        io=min(io, 6),
        memory=min(memory, 6),
    ).normalized()


def build_resource_profile_key(analysis: Any) -> str:
    archive_type = _analysis_value(analysis, "archive_type", "unknown") or "unknown"
    method = _method_family(str(_analysis_value(analysis, "dominant_method", "") or ""))
    solid = "solid" if bool(_analysis_value(analysis, "solid", False)) else "nonsolid"
    dictionary_mb = max(0, int(_analysis_value(analysis, "largest_dictionary_size", 0) or 0)) / (1024 * 1024)
    unpacked_mb = max(0, int(_analysis_value(analysis, "total_unpacked_size", 0) or 0)) / (1024 * 1024)
    file_count = max(0, int(_analysis_value(analysis, "file_count", 0) or 0))
    return "|".join(
        [
            str(archive_type).lower() or "unknown",
            method,
            solid,
            _bucket(dictionary_mb, [(16, "dict<16m"), (64, "dict<64m"), (256, "dict<256m")], "dict>=256m"),
            _bucket(unpacked_mb, [(256, "size<256m"), (1024, "size<1g"), (4096, "size<4g")], "size>=4g"),
            _bucket(file_count, [(1000, "files<1k"), (10000, "files<10k"), (50000, "files<50k")], "files>=50k"),
        ]
    )


def estimate_task_work_bytes(task: Any) -> int:
    fact_bag = getattr(task, "fact_bag", None)
    if fact_bag is not None:
        try:
            analysis = fact_bag.get("resource.analysis") or {}
            archive_size = int(analysis.get("archive_size", 0) or 0)
            unpacked_size = int(analysis.get("total_unpacked_size", 0) or 0)
            packed_size = int(analysis.get("total_packed_size", 0) or 0)
            estimated = max(archive_size + unpacked_size, packed_size + unpacked_size)
            if estimated > 0:
                return estimated
        except Exception:
            pass

    total = 0
    for path in list(getattr(task, "all_parts", None) or []) or [getattr(task, "main_path", "")]:
        try:
            total += os.path.getsize(path)
        except Exception:
            pass
    return max(0, total)


def task_profile_key(task: Any) -> str:
    fact_bag = getattr(task, "fact_bag", None)
    if fact_bag is None:
        return ""
    try:
        return str(fact_bag.get("resource.profile_key") or "")
    except Exception:
        return ""


def _analysis_value(analysis: Any, key: str, default: Any = None) -> Any:
    if isinstance(analysis, dict):
        return analysis.get(key, default)
    return getattr(analysis, key, default)


def _method_family(method: str) -> str:
    value = method.lower()
    if "lzma" in value:
        return "lzma"
    if "ppmd" in value:
        return "ppmd"
    if "bzip2" in value:
        return "bzip2"
    if "deflate64" in value:
        return "deflate64"
    if "deflate" in value:
        return "deflate"
    if any(token in value for token in ("copy", "store")):
        return "store"
    return value.strip() or "unknown"


def _bucket(value: float, thresholds: list[tuple[float, str]], default: str) -> str:
    for upper_bound, label in thresholds:
        if value < upper_bound:
            return label
    return default
