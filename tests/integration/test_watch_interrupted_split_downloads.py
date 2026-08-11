from __future__ import annotations

import os
import threading
import time
from pathlib import Path

import pytest

from sunpack.config.loader import load_config
from sunpack.coordinator.engine import PipelineEngine
from sunpack.coordinator.watch_group_coordinator import WatchGroupCoordinator
from sunpack.filesystem.watcher.scheduler import WatchRunResult, WatchScheduler
from tests.helpers.real_archives import ArchiveCase, ArchiveFixtureFactory


MAX_SETTLE_SECONDS = 45.0
PAYLOAD_SIZE = 768 * 1024


class _GatedPipelineHandle:
    def __init__(self, delegate, entered: threading.Event, release: threading.Event):
        self.delegate = delegate
        self.entered = entered
        self.release = release

    def result(self, timeout=None):
        self.entered.set()
        if not self.release.wait(timeout=MAX_SETTLE_SECONDS):
            raise TimeoutError("test did not release the interrupted request completion")
        return self.delegate.result(timeout=timeout)

    def add_done_callback(self, callback):
        self.delegate.add_done_callback(lambda _handle: callback(self))

    def __getattr__(self, name):
        return getattr(self.delegate, name)


class _RecordingPipelineEngine:
    def __init__(
        self,
        delegate: PipelineEngine,
        *,
        gated_head_name: str,
        gated_attempt: int,
    ):
        self.delegate = delegate
        self.submissions: list[tuple[str, ...]] = []
        self.handles = []
        self.gated_head_name = gated_head_name
        self.gated_attempt = gated_attempt
        self.gated_entered = threading.Event()
        self.gated_release = threading.Event()
        self._head_attempts: dict[str, int] = {}

    def submit(self, targets, *args, **kwargs):
        materialized = tuple(targets)
        self.submissions.append(
            tuple(os.path.abspath(getattr(target, "path", str(target))) for target in materialized)
        )
        handle = self.delegate.submit(materialized, *args, **kwargs)
        head_name = Path(self.submissions[-1][0]).name
        attempt = self._head_attempts.get(head_name, 0) + 1
        self._head_attempts[head_name] = attempt
        if head_name == self.gated_head_name and attempt == self.gated_attempt:
            handle = _GatedPipelineHandle(handle, self.gated_entered, self.gated_release)
        self.handles.append(handle)
        return handle

    def __getattr__(self, name):
        return getattr(self.delegate, name)


def _watch_config() -> dict:
    config = load_config()
    config["cli"] = {**(config.get("cli") or {}), "quiet": True}
    config["filesystem"] = {**(config.get("filesystem") or {}), "scan_filters": []}
    config["pipeline"] = {
        **(config.get("pipeline") or {}),
        "max_active_pipeline_requests": 3,
    }
    config["performance"] = {
        **(config.get("performance") or {}),
        "max_extract_task_seconds": 8,
        "process_no_progress_timeout_seconds": 4,
        "process_sample_interval_ms": 100,
    }
    # Match the Lite build exercised by Watch users and keep deliberately
    # incomplete inputs from spending the full repair budget in this test.
    config["repair"] = {**(config.get("repair") or {}), "enabled": False}
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
    config["detection"] = {
        "fact_collectors": [],
        "processors": [],
        "rule_pipeline": {"precheck": [], "scoring": []},
    }
    return config


def _create_split_zip(root: Path, case_id: str) -> ArchiveCase:
    try:
        case = ArchiveFixtureFactory().create(
            root,
            case_id,
            "zip",
            split=True,
            payload_size=PAYLOAD_SIZE,
        )
    except (FileNotFoundError, RuntimeError) as exc:
        pytest.skip(str(exc))
    assert len(_parts(case)) >= 4
    return case


def _parts(case: ArchiveCase) -> list[Path]:
    return sorted(
        (path.resolve() for path in case.archive_dir.iterdir() if path.is_file()),
        key=lambda path: path.name.lower(),
    )


def _append_to_size(source: Path, destination: Path, target_size: int, *, chunk_size: int) -> None:
    """Advance one download without replacing its inode, like a browser .part rename flow."""

    destination.parent.mkdir(parents=True, exist_ok=True)
    current_size = destination.stat().st_size if destination.exists() else 0
    target_size = min(max(current_size, target_size), source.stat().st_size)
    with source.open("rb") as reader, destination.open("ab") as writer:
        reader.seek(current_size)
        remaining = target_size - current_size
        while remaining:
            block = reader.read(min(chunk_size, remaining))
            assert block
            writer.write(block)
            writer.flush()
            remaining -= len(block)
    os.utime(destination, None)


def _overwrite_downloaded_prefix(
    source: Path,
    destination: Path,
    target_size: int,
    *,
    chunk_size: int,
) -> None:
    """Fill a preallocated download progressively while keeping its final size."""

    destination.parent.mkdir(parents=True, exist_ok=True)
    if not destination.exists():
        with destination.open("wb") as writer:
            writer.truncate(source.stat().st_size)
    with source.open("rb") as reader, destination.open("r+b") as writer:
        remaining = min(target_size, source.stat().st_size)
        while remaining:
            block = reader.read(min(chunk_size, remaining))
            assert block
            writer.write(block)
            writer.flush()
            remaining -= len(block)
    os.utime(destination, None)


def _advance_interrupted_group(
    watcher: WatchScheduler,
    case: ArchiveCase,
    watch_root: Path,
    *,
    middle_fraction: float,
) -> None:
    """Write a valid head/tail around incomplete middle volumes, then pause."""

    parts = _parts(case)
    for index, source in enumerate(parts):
        if index in {0, len(parts) - 1}:
            target_size = source.stat().st_size
        else:
            target_size = max(1, int(source.stat().st_size * middle_fraction))
        destination = watch_root / source.name
        _overwrite_downloaded_prefix(
            source,
            destination,
            target_size,
            chunk_size=13 * 1024,
        )
        watcher.enqueue(str(destination), event_type="modified")


def _install_complete_group(watcher: WatchScheduler, case: ArchiveCase, watch_root: Path) -> None:
    for source in _parts(case):
        destination = watch_root / source.name
        if destination.exists():
            _overwrite_downloaded_prefix(
                source,
                destination,
                source.stat().st_size,
                chunk_size=17 * 1024,
            )
        else:
            _append_to_size(source, destination, source.stat().st_size, chunk_size=17 * 1024)
        watcher.enqueue(str(destination), event_type="modified")


def _is_settled(watcher: WatchScheduler) -> bool:
    with watcher._lock:
        return (
            not watcher._pending
            and not watcher._inflight_requests
            and not watcher._completion_requests
        )


def _drive_until(
    watcher: WatchScheduler,
    condition,
    *,
    timeout: float = MAX_SETTLE_SECONDS,
    require_settled: bool = True,
) -> WatchRunResult:
    deadline = time.perf_counter() + timeout
    combined = WatchRunResult()
    while time.perf_counter() < deadline:
        result = watcher.run_once()
        combined.processed += result.processed
        combined.succeeded += result.succeeded
        combined.failed += result.failed
        combined.errors.extend(result.errors)
        combined.pending = result.pending
        if condition() and (not require_settled or _is_settled(watcher)):
            return combined
        time.sleep(0.01)
    pytest.fail(
        "watch did not settle: "
        f"pending={watcher.pending_count}, submissions={getattr(watcher.pipeline_engine, 'submissions', [])}, "
        f"entries={watcher.state.entries}, groups={watcher.state.groups}"
    )


def _probe_owner_dirs(watch_root: Path) -> list[Path]:
    probe_root = watch_root / ".sunpack_watch_probes"
    return list(probe_root.iterdir()) if probe_root.exists() else []


@pytest.mark.slow_real_archive
def test_watch_retries_interrupted_split_downloads_without_cross_task_blocking(tmp_path):
    """Exercise real extraction against split volumes that pause while still incomplete.

    Every group has all expected filenames from the first pause, so readiness by
    filename alone permits the deliberately premature extraction attempts.  The
    test guards the intended product contract: failed/partial probe data is
    discarded, changed bytes cause a fresh attempt, and another logical archive
    can finish while the first archive is still incomplete.
    """

    fixture_root = tmp_path / "fixtures"
    watch_root = tmp_path / "downloads"
    output_root = tmp_path / "out"
    watch_root.mkdir()
    output_root.mkdir()
    interrupted = _create_split_zip(fixture_root, "interrupted_bundle")
    independent = _create_split_zip(fixture_root, "independent_bundle")

    config = _watch_config()
    delegate = PipelineEngine(config).start()
    engine = _RecordingPipelineEngine(
        delegate,
        gated_head_name=interrupted.entry_path.name,
        gated_attempt=2,
    )
    watcher = WatchScheduler(
        config,
        [str(watch_root)],
        out_dir=str(output_root),
        state_path=str(tmp_path / "watch-state.json"),
        quiet_seconds=0,
        initial_scan=False,
        pipeline_engine=engine,
        group_coordinator=WatchGroupCoordinator(config),
    )

    try:
        # First network pause: every numbered volume exists, but middle volumes
        # contain only a short prefix.  Exactly one logical request may run.
        _advance_interrupted_group(watcher, interrupted, watch_root, middle_fraction=0.20)
        first = _drive_until(watcher, lambda: len(engine.submissions) >= 1)
        assert first.succeeded == 0
        assert len(engine.submissions) == 1, engine.submissions
        assert len(engine.submissions[0]) == 1
        assert not list(output_root.rglob(interrupted.marker_name))
        assert not _probe_owner_dirs(watch_root)

        # The same downloads resume, slow down, and pause again.  At the same
        # time a separate split ZIP completes.  Its successful extraction must
        # not be gated by the still-broken logical group.
        _advance_interrupted_group(watcher, interrupted, watch_root, middle_fraction=0.61)
        watcher.run_once()
        _install_complete_group(watcher, independent, watch_root)
        second = _drive_until(
            watcher,
            lambda: bool(list(output_root.rglob(independent.marker_name))),
            require_settled=False,
        )
        independent_outputs = list(output_root.rglob(independent.marker_name))
        assert len(independent_outputs) == 1
        assert independent_outputs[0].read_text(encoding="utf-8") == independent.marker_text
        assert not list(output_root.rglob(interrupted.marker_name))
        assert len(engine.submissions) == 3, engine.submissions
        assert all(len(targets) == 1 for targets in engine.submissions)
        assert second.succeeded == 1
        assert engine.gated_entered.is_set()

        # The incomplete request is deliberately held in completion handling.
        # Releasing it now proves the independent output above was harvested by
        # another completion worker rather than waiting behind this request.
        engine.gated_release.set()
        _drive_until(watcher, lambda: True)
        assert not _probe_owner_dirs(watch_root)

        # Final resume completes the original files in place.  The changed
        # group fingerprint must schedule one last request and promote only the
        # verified complete result.
        _install_complete_group(watcher, interrupted, watch_root)
        final = _drive_until(
            watcher,
            lambda: bool(list(output_root.rglob(interrupted.marker_name))),
        )
        interrupted_outputs = list(output_root.rglob(interrupted.marker_name))
        assert len(interrupted_outputs) == 1
        assert interrupted_outputs[0].read_text(encoding="utf-8") == interrupted.marker_text
        assert final.succeeded == 1
        assert len(engine.submissions) == 4, engine.submissions
        assert not _probe_owner_dirs(watch_root)

        # Two pauses plus final completion are three attempts for one split
        # archive, while all of the independent archive's volumes collapse to
        # its single request.
        submitted_heads = [Path(targets[0]).name for targets in engine.submissions]
        assert submitted_heads.count(interrupted.entry_path.name) == 3, submitted_heads
        assert submitted_heads.count(independent.entry_path.name) == 1, submitted_heads

        interrupted_responses = [
            handle.result()
            for targets, handle in zip(engine.submissions, engine.handles)
            if Path(targets[0]).name == interrupted.entry_path.name
        ]
        assert len(interrupted_responses) == 3
        assert interrupted_responses[-1].summary.success_count == 1
        # Partial probe data is deliberately discarded under the default
        # "complete" content requirement (unified partial/complete recovery
        # semantics): incomplete attempts report plain damage without
        # promoting any recovered outputs.
        assert all(
            response.summary.partial_success_count == 0
            and not response.summary.recovered_outputs
            for response in interrupted_responses[:-1]
        )
    finally:
        engine.gated_release.set()
        delegate.close()
