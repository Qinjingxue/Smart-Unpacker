from __future__ import annotations

import gc
import json
import os
import random
import shutil
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Callable

import psutil
import pytest

from sunpack.coordinator.engine import PipelineEngine
from sunpack.coordinator.watch_group_coordinator import WatchGroupCoordinator
from sunpack.filesystem.watcher.scheduler import WatchRunResult, WatchScheduler
from tests.helpers.marker_utils import marker_was_extracted
from tests.helpers.real_archives import ArchiveCase, ArchiveFixtureFactory
from tests.real.plan1_real_archives.plan1_support import plan1_config


PASSWORD = "sunpack-plan7-acceptance"
WRONG_PASSWORD_COUNT = 24
DOWNLOAD_CHUNK_SIZE = 16 * 1024
CHUNK_DELAY_SECONDS = 0.001
MAX_COMPLETION_LATENCY_SECONDS = 60.0
MAX_WATCH_TICK_LATENCY_SECONDS = 5.0
PLAIN_PAYLOAD_SIZE = 64 * 1024
SPLIT_PAYLOAD_SIZE = 420 * 1024

# 第 7 条格式矩阵：普通/SFX 单文件 + 分卷/SFX 分卷。
PLAIN_FORMATS = ("zip", "7z", "rar", "tar", "gzip", "bzip2", "xz", "zstd")
SFX_FORMATS = ("7z", "zip", "rar")
SPLIT_FORMATS = ("7z", "zip", "rar")

FACTORY = ArchiveFixtureFactory()


@dataclass
class Plan7Case:
    key: str
    archive_format: str
    kind: str  # plain / sfx / split / sfx_split
    case: ArchiveCase
    stable_at: float = 0.0
    completion_latency: float | None = None


@dataclass
class WatchHarness:
    watch_root: Path
    output_root: Path
    config: dict[str, Any]
    engine: Any
    watcher: WatchScheduler
    submit_times: list[float] = field(default_factory=list)

    def close(self) -> None:
        self.engine.close()


class _TimedPipelineEngine:
    """记录 pipeline 提交次数，用于断言每个完成的归档恰好提交一次。"""

    def __init__(self, delegate: PipelineEngine, submit_times: list[float]):
        self.delegate = delegate
        self.submit_times = submit_times
        self.handles = []

    def submit(self, *args, **kwargs):
        self.submit_times.append(time.perf_counter())
        handle = self.delegate.submit(*args, **kwargs)
        self.handles.append(handle)
        return handle

    def __getattr__(self, name):
        return getattr(self.delegate, name)


class MemorySampler:
    """按文件到达/完成数量采样进程与 worker 内存。"""

    def __init__(self):
        self.process = psutil.Process(os.getpid())
        self.samples: list[dict[str, Any]] = []

    def sample(
        self,
        *,
        installed_volumes: int,
        completed_archives: int,
        elapsed: float,
        label: str = "",
    ) -> dict[str, Any]:
        gc.collect()
        children = [
            child for child in self.process.children(recursive=True) if child.is_running()
        ]
        row = {
            "label": label,
            "installed_volumes": installed_volumes,
            "completed_archives": completed_archives,
            "parent_rss": self.process.memory_info().rss,
            "worker_rss": sum(child.memory_info().rss for child in children),
            "child_count": len(children),
            "elapsed_seconds": round(elapsed, 3),
        }
        self.samples.append(row)
        return row

    def summary(self) -> dict[str, Any]:
        if len(self.samples) < 2:
            return {"samples": len(self.samples)}
        completion_samples = [
            item for item in self.samples if str(item["label"]).startswith("after_")
        ] or self.samples[1:]
        warm = completion_samples
        return {
            "samples": len(self.samples),
            "arrival_samples": sum(
                1 for item in self.samples if str(item["label"]).startswith("arrived_")
            ),
            "completion_samples": len(completion_samples),
            "parent_growth": warm[-1]["parent_rss"] - warm[0]["parent_rss"],
            "worker_growth": warm[-1]["worker_rss"] - warm[0]["worker_rss"],
            "child_count_range": [
                min(item["child_count"] for item in warm),
                max(item["child_count"] for item in warm),
            ],
            "final_parent_rss": warm[-1]["parent_rss"],
            "final_worker_rss": warm[-1]["worker_rss"],
        }


def plan7_watch_config(passwords: list[str] | None = None) -> dict:
    """plan1 全检测配置 + watch 运行参数（保留持久 worker 以观察内存）。"""
    config = plan1_config(passwords=passwords or [PASSWORD])
    config["cli"] = {**(config.get("cli") or {}), "quiet": True}
    config["post_extract"] = {
        **(config.get("post_extract") or {}),
        "archive_cleanup_mode": "keep",
        "flatten_single_directory": False,
    }
    config["watch"] = {
        **(config.get("watch") or {}),
        "clipboard_monitor_enabled": False,
        "password_retry_debounce_seconds": 0,
    }
    config["performance"] = {
        **(config.get("performance") or {}),
        "persistent_workers": True,
        "persistent_worker_count": 2,
    }
    config["user_passwords"] = [f"wrong-{index:02d}" for index in range(WRONG_PASSWORD_COUNT)]
    config["user_passwords"].extend(passwords or [PASSWORD])
    config["builtin_passwords"] = []
    return config


def wrong_password_list() -> list[str]:
    return [f"wrong-{index:02d}" for index in range(WRONG_PASSWORD_COUNT)]


def build_plain_sfx_cases(root: Path) -> tuple[dict[str, Plan7Case], list[str]]:
    """普通压缩包（zip/rar/7z 加密 + tar/流格式）与 SFX 压缩包。"""
    cases: dict[str, Plan7Case] = {}
    skipped: list[str] = []
    for fmt in PLAIN_FORMATS:
        encrypted = fmt in {"zip", "rar", "7z"}
        key = f"plain_{fmt}"
        try:
            case = FACTORY.create(
                root,
                f"p7_{key}",
                fmt,
                password=PASSWORD if encrypted else None,
                payload_size=PLAIN_PAYLOAD_SIZE,
            )
        except (FileNotFoundError, RuntimeError) as exc:
            skipped.append(f"{key}: {exc}")
            continue
        cases[key] = Plan7Case(key=key, archive_format=fmt, kind="plain", case=case)
    for fmt in SFX_FORMATS:
        key = f"sfx_{fmt}"
        try:
            case = FACTORY.create(
                root,
                f"p7_{key}",
                fmt,
                password=PASSWORD,
                sfx=True,
                payload_size=PLAIN_PAYLOAD_SIZE,
            )
        except (FileNotFoundError, RuntimeError) as exc:
            skipped.append(f"{key}: {exc}")
            continue
        cases[key] = Plan7Case(key=key, archive_format=fmt, kind="sfx", case=case)
    return cases, skipped


def build_split_cases(root: Path) -> tuple[dict[str, Plan7Case], list[str]]:
    """各种形式分卷压缩包与 SFX 分卷压缩包（全部加密）。"""
    cases: dict[str, Plan7Case] = {}
    skipped: list[str] = []
    for fmt in SPLIT_FORMATS:
        for kind in ("split", "sfx_split"):
            key = f"{kind}_{fmt}"
            try:
                case = FACTORY.create(
                    root,
                    f"p7_{key}",
                    fmt,
                    password=PASSWORD,
                    split=True,
                    sfx=(kind == "sfx_split"),
                    payload_size=SPLIT_PAYLOAD_SIZE,
                )
            except (FileNotFoundError, RuntimeError) as exc:
                skipped.append(f"{key}: {exc}")
                continue
            cases[key] = Plan7Case(
                key=key,
                archive_format=fmt,
                kind=kind,
                case=case,
            )
    return cases, skipped


def start_watch(
    tmp_path: Path,
    label: str,
    *,
    passwords: list[str],
) -> WatchHarness:
    watch_root = tmp_path / label / "watch"
    output_root = tmp_path / label / "out"
    watch_root.mkdir(parents=True)
    output_root.mkdir(parents=True)
    (watch_root / ".sunpack-passwords.txt").write_text(
        "\n".join(passwords) + "\n",
        encoding="utf-8",
    )
    config = plan7_watch_config(passwords=passwords)
    submit_times: list[float] = []
    delegate = PipelineEngine(config).start()
    engine = _TimedPipelineEngine(delegate, submit_times)
    watcher = WatchScheduler(
        config,
        [str(watch_root)],
        out_dir=str(output_root),
        state_path=str(tmp_path / label / "state.json"),
        quiet_seconds=0,
        initial_scan=False,
        pipeline_engine=engine,
        group_coordinator=WatchGroupCoordinator(config),
    )
    return WatchHarness(
        watch_root=watch_root,
        output_root=output_root,
        config=config,
        engine=engine,
        watcher=watcher,
        submit_times=submit_times,
    )


def arrive_slowly(
    harness: WatchHarness,
    source: Path,
    *,
    tick_latencies: list[float] | None = None,
) -> WatchRunResult:
    """模拟真实下载：分块写入 .downloading 临时文件，完成后改名为最终文件名。"""
    tmp = harness.watch_root / f"{source.name}.downloading"
    destination = harness.watch_root / source.name
    with source.open("rb") as reader, tmp.open("wb") as writer:
        while chunk := reader.read(DOWNLOAD_CHUNK_SIZE):
            writer.write(chunk)
            writer.flush()
            os.fsync(writer.fileno())
            harness.watcher.enqueue(str(tmp), event_type="modified")
            tick_started_at = time.perf_counter()
            harness.watcher.run_once()
            if tick_latencies is not None:
                tick_latencies.append(time.perf_counter() - tick_started_at)
            time.sleep(CHUNK_DELAY_SECONDS)
    os.replace(tmp, destination)
    harness.watcher.notify_path_departed(str(tmp))
    harness.watcher.enqueue(str(destination), event_type="moved", src_path=str(tmp))
    tick_started_at = time.perf_counter()
    result = harness.watcher.run_once()
    if tick_latencies is not None:
        tick_latencies.append(time.perf_counter() - tick_started_at)
    return result


def split_arrival_order(plan7_case: Plan7Case, rng: random.Random) -> list[Path]:
    """分卷乱序到达：非头卷随机乱序，头卷最后（保证组完整后才提交）。"""
    case = plan7_case.case
    parts = sorted(
        (path for path in case.archive_dir.iterdir() if path.is_file()),
        key=lambda path: path.name.lower(),
    )
    head = case.entry_path.resolve()
    non_heads = [path.resolve() for path in parts if path.resolve() != head]
    rng.shuffle(non_heads)
    return [*non_heads, head]


def marker_text_extracted(
    root: Path,
    marker_name: str,
    marker_text: str,
    *,
    retries: int = 4,
) -> bool:
    """marker_was_extracted 的容错版：解压完成瞬间文件可能仍被占用，重试读取。"""
    for _ in range(retries):
        if marker_was_extracted(root, marker_name, marker_text):
            return True
        time.sleep(0.05)
    return marker_was_extracted(root, marker_name, marker_text)


def drive_watch_until(
    watcher: WatchScheduler,
    condition: Callable[[], bool],
    *,
    timeout_seconds: float = MAX_COMPLETION_LATENCY_SECONDS,
) -> WatchRunResult:
    """轮询 run_once 直到条件成立且无在途/待收尾请求。"""
    deadline = time.perf_counter() + timeout_seconds
    combined = WatchRunResult()
    while time.perf_counter() < deadline:
        result = watcher.run_once()
        combined.processed += result.processed
        combined.succeeded += result.succeeded
        combined.failed += result.failed
        combined.pending = result.pending
        combined.errors.extend(result.errors)
        with watcher._lock:
            inflight = bool(watcher._inflight_requests)
            completion_pending = bool(watcher._completion_requests)
        if condition() and watcher.pending_count == 0 and not inflight and not completion_pending:
            return combined
        time.sleep(0.01)
    pytest.fail(
        "watch condition did not settle before timeout: "
        f"pending={watcher.pending_count}, entries={watcher.state.entries}, "
        f"groups={watcher.state.groups}"
    )


def assert_plan7_success(
    harness: WatchHarness,
    cases: dict[str, Plan7Case],
    *,
    sampler: MemorySampler,
    tick_latencies: list[float],
    expect_exact_submissions: bool = True,
    error_info: dict[str, Any] | None = None,
    record_property: Callable[[str, Any], None] | None = None,
) -> None:
    """第 7 条主断言：全部归档完成、无失败、不重复提交，且内存随到达数量被记录。"""
    root = harness.output_root
    for plan7_case in cases.values():
        assert marker_text_extracted(root, plan7_case.case.marker_name, plan7_case.case.marker_text), (
            f"marker missing for {plan7_case.key}: {plan7_case.case.marker_name}"
        )
    assert not any(harness.watcher.state.entries.values()), "watch state must not retain failures"
    assert harness.submit_times, "pipeline never submitted any archive"

    completed_count = len(cases)
    for plan7_case in cases.values():
        assert plan7_case.completion_latency is not None
        assert plan7_case.completion_latency < MAX_COMPLETION_LATENCY_SECONDS, (
            f"{plan7_case.key} took {plan7_case.completion_latency:.3f}s after its final "
            "volume became stable (file complete but watch did not react)"
        )

    # 单文件归档每个恰好提交一次；分卷乱序到达时，watch 会对“已到头卷但还
    # 缺尾卷”的不完整组做探测性提交（借后端确认缺卷），所以分卷场景只要求
    # 每个归档至少提交一次。两者都要求完成后重放不得再次提交。
    if expect_exact_submissions:
        assert len(harness.submit_times) == completed_count, harness.submit_times
    else:
        assert len(harness.submit_times) >= completed_count, harness.submit_times
    submissions_after_success = len(harness.submit_times)
    for plan7_case in cases.values():
        for path in harness.watch_root.iterdir():
            if path.name == ".sunpack-passwords.txt":
                continue
            harness.watcher.enqueue(str(path))
    replay = drive_watch_until(harness.watcher, lambda: True, timeout_seconds=10)
    assert replay.processed == 0, replay
    assert len(harness.submit_times) == submissions_after_success, harness.submit_times

    assert max(tick_latencies) < MAX_WATCH_TICK_LATENCY_SECONDS, tick_latencies
    memory = sampler.summary()
    assert memory["samples"] >= completed_count + 1, memory
    assert memory["arrival_samples"] >= completed_count, memory
    assert memory["completion_samples"] >= completed_count, memory
    assert memory["parent_growth"] < 128 * 1024 * 1024, memory
    assert memory["worker_growth"] < 64 * 1024 * 1024, memory
    assert memory["child_count_range"][1] - memory["child_count_range"][0] <= 1, memory

    if error_info is not None:
        error_info.update({
            "completed_archives": completed_count,
            "pipeline_submissions": len(harness.submit_times),
            "tick_count": len(tick_latencies),
            "max_tick_latency_ms": round(max(tick_latencies) * 1000, 3),
            "completion_latencies": {
                key: round(case.completion_latency or 0.0, 3)
                for key, case in cases.items()
            },
            "memory_summary": memory,
        })
    if record_property is not None:
        record_property("archive_count", completed_count)
        record_property("pipeline_submissions", len(harness.submit_times))
        record_property("max_watch_tick_latency_ms", round(max(tick_latencies) * 1000, 3))
        record_property("memory_summary", json.dumps(memory, ensure_ascii=False))
        record_property(
            "memory_timeline",
            json.dumps(sampler.samples, ensure_ascii=False),
        )
        print(
            "\nplan7 memory timeline (archives completed -> parent/worker RSS):\n"
            + "\n".join(
                f"  {str(item['label']):<18s} "
                f"completed={item['completed_archives']:>2d} -> "
                f"parent={item['parent_rss'] / 1024 / 1024:7.1f}MB "
                f"worker={item['worker_rss'] / 1024 / 1024:6.1f}MB "
                f"children={item['child_count']} "
                f"volumes={item['installed_volumes']}"
                for item in sampler.samples
            )
        )


__all__ = [
    "PASSWORD",
    "WRONG_PASSWORD_COUNT",
    "DOWNLOAD_CHUNK_SIZE",
    "MAX_COMPLETION_LATENCY_SECONDS",
    "MAX_WATCH_TICK_LATENCY_SECONDS",
    "PLAIN_FORMATS",
    "SFX_FORMATS",
    "SPLIT_FORMATS",
    "Plan7Case",
    "WatchHarness",
    "MemorySampler",
    "wrong_password_list",
    "build_plain_sfx_cases",
    "build_split_cases",
    "start_watch",
    "arrive_slowly",
    "split_arrival_order",
    "marker_text_extracted",
    "drive_watch_until",
    "assert_plan7_success",
]
