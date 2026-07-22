from __future__ import annotations

import shutil
import time
from pathlib import Path

import pytest

from sunpack.config.loader import load_config
from sunpack.coordinator.engine import PipelineEngine
from sunpack.coordinator.watch_group_coordinator import WatchGroupCoordinator
from sunpack.filesystem.watcher.scheduler import WatchScheduler
from tests.helpers.real_archives import ArchiveCase, ArchiveFixtureFactory


MAX_COMPLETION_LATENCY_SECONDS = 30.0
PAYLOAD_SIZE = 256 * 1024


class _TimedPipelineEngine:
    def __init__(self, delegate: PipelineEngine):
        self.delegate = delegate
        self.submit_times: list[float] = []

    def submit(self, *args, **kwargs):
        self.submit_times.append(time.perf_counter())
        return self.delegate.submit(*args, **kwargs)

    def __getattr__(self, name):
        return getattr(self.delegate, name)


def _watch_config() -> dict:
    config = load_config()
    config["cli"] = {**(config.get("cli") or {}), "quiet": True}
    config["filesystem"] = {**(config.get("filesystem") or {}), "scan_filters": []}
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
    # The watch split-group coordinator runs independently of the detection
    # pipeline. Disabling detection keeps this test focused on relation
    # completeness, retry gating, and real extraction behavior.
    config["detection"] = {
        "fact_collectors": [],
        "processors": [],
        "rule_pipeline": {"precheck": [], "scoring": [], "confirmation": []},
    }
    return config


def _create_case_or_skip(
    root: Path,
    *,
    archive_format: str,
    sfx: bool,
) -> ArchiveCase:
    case_id = f"watch_order_{archive_format}_{'sfx' if sfx else 'plain'}"
    try:
        return ArchiveFixtureFactory().create(
            root,
            case_id,
            archive_format,
            split=True,
            sfx=sfx,
            payload_size=PAYLOAD_SIZE,
        )
    except (FileNotFoundError, RuntimeError) as exc:
        pytest.skip(str(exc))


def _chaotic_download_order(case: ArchiveCase) -> list[Path]:
    parts = sorted(
        (path for path in case.archive_dir.iterdir() if path.is_file()),
        key=lambda path: path.name.lower(),
    )
    head = case.entry_path.resolve()
    non_heads = [path.resolve() for path in parts if path.resolve() != head]
    assert len(non_heads) >= 2, [path.name for path in parts]

    # A later volume appears first, then the canonical head appears too early.
    # Remaining volumes arrive in reverse order, creating both an unknown tail
    # and (for four-part fixtures) a confirmed middle gap before completion.
    return [non_heads[0], head, *reversed(non_heads[1:])]


@pytest.mark.slow_real_archive
@pytest.mark.parametrize(
    ("archive_format", "sfx"),
    [
        pytest.param("7z", False, id="7z"),
        pytest.param("zip", False, id="zip"),
        pytest.param("rar", False, id="rar"),
        pytest.param("7z", True, id="7z-sfx"),
        pytest.param("zip", True, id="zip-sfx"),
        pytest.param("rar", True, id="rar-sfx"),
    ],
)
def test_watch_extracts_real_split_download_once_after_chaotic_arrival(
    tmp_path,
    record_property,
    archive_format,
    sfx,
):
    fixture_root = tmp_path / "fixtures"
    watch_root = tmp_path / "watch"
    output_root = tmp_path / "out"
    watch_root.mkdir()
    output_root.mkdir()
    case = _create_case_or_skip(fixture_root, archive_format=archive_format, sfx=sfx)
    download_order = _chaotic_download_order(case)

    config = _watch_config()
    delegate = PipelineEngine(config).start()
    engine = _TimedPipelineEngine(delegate)
    watcher = WatchScheduler(
        config,
        [str(watch_root)],
        out_dir=str(output_root),
        state_path=str(tmp_path / "state.json"),
        quiet_seconds=0,
        initial_scan=False,
        pipeline_engine=engine,
        group_coordinator=WatchGroupCoordinator(config),
    )

    premature_processed = 0
    premature_failures = 0
    try:
        for source in download_order[:-1]:
            destination = watch_root / source.name
            shutil.copy2(source, destination)
            watcher.enqueue(str(destination))
            result = watcher.run_once()
            premature_processed += result.processed
            premature_failures += result.failed

            assert result.succeeded == 0, (source.name, result)
            assert not list(output_root.rglob(case.marker_name)), source.name

        final_source = download_order[-1]
        final_destination = watch_root / final_source.name
        shutil.copy2(final_source, final_destination)
        final_stable_at = time.perf_counter()
        watcher.enqueue(str(final_destination))
        submits_before_completion = len(engine.submit_times)
        final_result = watcher.run_once()
        completed_at = time.perf_counter()

        final_submit_times = engine.submit_times[submits_before_completion:]
        assert len(final_submit_times) == 1, final_submit_times
        dispatch_latency = final_submit_times[0] - final_stable_at
        completion_latency = completed_at - final_stable_at

        extracted = list(output_root.rglob(case.marker_name))
        assert final_result.succeeded == 1, final_result
        assert final_result.failed == 0, final_result
        assert len(extracted) == 1, extracted
        assert extracted[0].read_text(encoding="utf-8") == case.marker_text
        assert completion_latency < MAX_COMPLETION_LATENCY_SECONDS

        # Ordinary replayed/duplicate watchdog events after completion must not
        # start a second extraction for the unchanged split-group fingerprint.
        # ``force=True`` is deliberately excluded: its public meaning is to
        # forget persisted path/group state and request a fresh attempt.
        submits_before_replay = len(engine.submit_times)
        for source in reversed(download_order):
            watcher.enqueue(str(watch_root / source.name))
        replay_result = watcher.run_once()
        assert replay_result.processed == 0, replay_result
        assert len(engine.submit_times) == submits_before_replay
    finally:
        delegate.close()

    record_property("archive_format", archive_format)
    record_property("sfx", sfx)
    record_property("download_order", ",".join(path.name for path in download_order))
    record_property("premature_pipeline_attempts", premature_processed)
    record_property("premature_failures", premature_failures)
    record_property("dispatch_latency_ms", round(dispatch_latency * 1000, 3))
    record_property("completion_latency_ms", round(completion_latency * 1000, 3))
