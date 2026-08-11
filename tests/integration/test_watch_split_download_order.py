from __future__ import annotations

import os
import random
import shutil
import statistics
import time
import uuid
from pathlib import Path

import pytest

from sunpack.config.loader import load_config
from sunpack.coordinator.engine import PipelineEngine
from sunpack.coordinator.watch_group_coordinator import WatchGroupCoordinator
from sunpack.filesystem.watcher.group_models import BLOCKER_MISSING_VOLUME, BLOCKER_PASSWORD
from sunpack.filesystem.watcher.scheduler import WatchRunResult, WatchScheduler
from sunpack.support.sevenzip_bridge import (
    STATUS_NEEDS_VOLUME_OR_TAIL_DAMAGED,
    get_native_password_tester,
)
from tests.helpers.real_archives import ArchiveCase, ArchiveFixtureFactory


MAX_COMPLETION_LATENCY_SECONDS = 30.0
PAYLOAD_SIZE = 256 * 1024
BULK_PAYLOAD_SIZE = 1024 * 1024
BULK_WRONG_PASSWORD_COUNT = 48
SLOW_DOWNLOAD_CHUNK_SIZE = 32 * 1024
SLOW_DOWNLOAD_CHUNK_DELAY_SECONDS = 0.003
MAX_BULK_COMPLETION_LATENCY_SECONDS = 60.0
MAX_WATCH_TICK_LATENCY_SECONDS = 5.0
MAX_SPLIT_PERFORMANCE_RATIO = 4.0
MAX_SPLIT_ADDITIONAL_LATENCY_SECONDS = 2.0


class _TimedPipelineEngine:
    def __init__(self, delegate: PipelineEngine):
        self.delegate = delegate
        self.submit_times: list[float] = []
        self.handles = []

    def submit(self, *args, **kwargs):
        self.submit_times.append(time.perf_counter())
        handle = self.delegate.submit(*args, **kwargs)
        self.handles.append(handle)
        return handle

    def __getattr__(self, name):
        return getattr(self.delegate, name)


def _drive_watch_until(
    watcher: WatchScheduler,
    condition,
    *,
    timeout_seconds: float = MAX_COMPLETION_LATENCY_SECONDS,
) -> WatchRunResult:
    """Poll run_once until a state condition is true and futures are harvested."""

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


def _watch_config() -> dict:
    config = load_config()
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
    # The watch split-group coordinator runs independently of the detection
    # pipeline. Disabling detection keeps this test focused on relation
    # completeness, retry gating, and real extraction behavior.
    config["detection"] = {
        "fact_collectors": [],
        "processors": [],
        "rule_pipeline": {"precheck": [], "scoring": []},
    }
    return config


def _create_case_or_skip(
    root: Path,
    *,
    archive_format: str,
    sfx: bool,
    password: str | None = None,
) -> ArchiveCase:
    case_id = f"watch_order_{archive_format}_{'sfx' if sfx else 'plain'}"
    try:
        return ArchiveFixtureFactory().create(
            root,
            case_id,
            archive_format,
            password=password,
            split=True,
            sfx=sfx,
            payload_size=PAYLOAD_SIZE,
        )
    except (FileNotFoundError, RuntimeError) as exc:
        pytest.skip(str(exc))


def _archive_parts(case: ArchiveCase) -> tuple[Path, list[Path]]:
    parts = sorted(
        (path for path in case.archive_dir.iterdir() if path.is_file()),
        key=lambda path: path.name.lower(),
    )
    head = case.entry_path.resolve()
    non_heads = [path.resolve() for path in parts if path.resolve() != head]
    assert len(non_heads) >= 2, [path.name for path in parts]
    return head, non_heads


def _download_order(case: ArchiveCase, strategy: str) -> list[Path]:
    head, non_heads = _archive_parts(case)
    if strategy == "tail_reverse_head_last":
        # The terminal volume appears first; every remaining non-head volume
        # then arrives in descending order, and the data head is last.  For
        # 7z/ZIP SFX, the executable is a launcher while ``.001`` is the actual
        # first archive volume, so place the launcher immediately before it.
        numbered_data_heads = [path for path in non_heads if path.name.lower().endswith(".001")]
        if case.sfx and numbered_data_heads:
            data_head = numbered_data_heads[0]
            tails = [path for path in non_heads if path != data_head]
            return [*reversed(tails), head, data_head]
        return [*reversed(non_heads), head]

    # A later volume appears first, then the canonical head appears too early.
    # Remaining volumes arrive in reverse order, creating both an unknown tail
    # and (for four-part fixtures) a confirmed middle gap before completion.
    return [non_heads[0], head, *reversed(non_heads[1:])]


def _run_completed_mixed_batch(
    tmp_path: Path,
    *,
    label: str,
    cases: dict[str, ArchiveCase],
    password_candidates: list[str],
    split: bool,
) -> dict[str, float | int]:
    """Run one real mixed-format batch from complete-on-disk to harvested success.

    Split members that do not make a group complete arrive first in a stable,
    deterministic disorder and are offered to watch immediately.  The heads
    are then installed without running the scheduler between copies, so the
    measured interval starts only after every archive in the batch is complete.
    Single-volume inputs use the same final batching rule.
    """

    watch_root = tmp_path / label / "watch"
    output_root = tmp_path / label / "out"
    watch_root.mkdir(parents=True)
    output_root.mkdir(parents=True)
    (watch_root / ".sunpack-passwords.txt").write_text(
        "\n".join(password_candidates) + "\n",
        encoding="utf-8",
    )

    config = _watch_config()
    delegate = PipelineEngine(config).start()
    engine = _TimedPipelineEngine(delegate)
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
    precomplete_tick_latencies: list[float] = []
    installed_volume_count = 0

    try:
        final_sources: list[Path] = []
        if split:
            rng = random.Random(0xC0FFEE)
            incomplete_sources: list[Path] = []
            for case in cases.values():
                head, non_heads = _archive_parts(case)
                rng.shuffle(non_heads)
                incomplete_sources.extend(non_heads)
                final_sources.append(head)
            rng.shuffle(incomplete_sources)
            rng.shuffle(final_sources)

            for source in incomplete_sources:
                destination = watch_root / source.name
                shutil.copy2(source, destination)
                installed_volume_count += 1
                watcher.enqueue(str(destination))
                tick_started_at = time.perf_counter()
                result = watcher.run_once()
                precomplete_tick_latencies.append(time.perf_counter() - tick_started_at)
                assert result.succeeded == 0, (source.name, result)
                assert not any(
                    any(output_root.rglob(case.marker_name))
                    for case in cases.values()
                ), source.name
        else:
            final_sources = [case.entry_path for case in cases.values()]

        # Do not run watch between these copies.  The stopwatch therefore sees
        # an equally complete three-archive batch in both comparison arms.
        for source in final_sources:
            destination = watch_root / source.name
            shutil.copy2(source, destination)
            installed_volume_count += 1
            watcher.enqueue(str(destination))

        all_inputs_stable_at = time.perf_counter()
        result = _drive_watch_until(
            watcher,
            lambda: all(
                bool(list(output_root.rglob(case.marker_name)))
                for case in cases.values()
            ),
            timeout_seconds=MAX_BULK_COMPLETION_LATENCY_SECONDS,
        )
        completion_latency = time.perf_counter() - all_inputs_stable_at

        for case in cases.values():
            extracted = list(output_root.rglob(case.marker_name))
            assert len(extracted) == 1, (case.case_id, extracted)
            assert extracted[0].read_text(encoding="utf-8") == case.marker_text
        assert result.succeeded == len(cases), result
        assert result.failed == 0, result
        assert not result.errors, result
        assert len(engine.submit_times) == len(cases), engine.submit_times
        return {
            "completion_latency": completion_latency,
            "max_precomplete_tick_latency": max(precomplete_tick_latencies, default=0.0),
            "pipeline_submissions": len(engine.submit_times),
            "volume_count": installed_volume_count,
        }
    finally:
        delegate.close()


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
@pytest.mark.parametrize(
    "arrival_strategy",
    ["head_early", "tail_reverse_head_last"],
)
def test_watch_extracts_real_split_download_once_after_chaotic_arrival(
    tmp_path,
    record_property,
    archive_format,
    sfx,
    arrival_strategy,
):
    fixture_root = tmp_path / "fixtures"
    watch_root = tmp_path / "watch"
    output_root = tmp_path / "out"
    watch_root.mkdir()
    output_root.mkdir()
    # RAR SFX multi-volume planning intentionally uses a bounded first-volume
    # password probe.  Make that case explicitly encrypted so this scheduling
    # test exercises the supported strong RAR5 header check instead of turning
    # an inconclusive unencrypted first-volume probe into a password-policy test.
    password = f"watch-order-{archive_format}-sfx" if archive_format == "rar" and sfx else None
    case = _create_case_or_skip(
        fixture_root,
        archive_format=archive_format,
        sfx=sfx,
        password=password,
    )
    if password:
        (watch_root / ".sunpack-passwords.txt").write_text(password + "\n", encoding="utf-8")
    download_order = _download_order(case, arrival_strategy)

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
        active_request_spans_final_write = any(not handle.done() for handle in engine.handles)
        final_result = _drive_watch_until(
            watcher,
            lambda: bool(list(output_root.rglob(case.marker_name))),
        )
        completed_at = time.perf_counter()

        final_submit_times = engine.submit_times[submits_before_completion:]
        assert final_submit_times or active_request_spans_final_write, (
            final_submit_times,
            active_request_spans_final_write,
        )
        dispatch_latency = (
            min(final_submit_times) - final_stable_at
            if final_submit_times
            else 0.0
        )
        completion_latency = completed_at - final_stable_at

        extracted = list(output_root.rglob(case.marker_name))
        assert len(extracted) == 1, extracted
        assert extracted[0].read_text(encoding="utf-8") == case.marker_text
        assert completion_latency < MAX_COMPLETION_LATENCY_SECONDS
        if sfx:
            # SFX success is decided by the verified embedded archive payload,
            # not by coverage of the executable carrier bytes.
            response = engine.handles[-1].result()
            assert response.summary.success_count >= 1
            assert response.summary.partial_success_count == 0

        # Ordinary replayed/duplicate watchdog events after completion must not
        # start a second extraction for the unchanged split-group fingerprint.
        # ``force=True`` is deliberately excluded: its public meaning is to
        # forget persisted path/group state and request a fresh attempt.
        submits_before_replay = len(engine.submit_times)
        for source in reversed(download_order):
            watcher.enqueue(str(watch_root / source.name))
        replay_result = _drive_watch_until(watcher, lambda: True)
        assert replay_result.processed == 0, replay_result
        assert len(engine.submit_times) == submits_before_replay
    finally:
        delegate.close()

    record_property("archive_format", archive_format)
    record_property("sfx", sfx)
    record_property("download_order", ",".join(path.name for path in download_order))
    record_property("arrival_strategy", arrival_strategy)
    record_property("premature_pipeline_attempts", premature_processed)
    record_property("premature_failures", premature_failures)
    record_property("dispatch_latency_ms", round(dispatch_latency * 1000, 3))
    record_property("completion_latency_ms", round(completion_latency * 1000, 3))


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
@pytest.mark.parametrize(
    "unblock_order",
    ["volumes_then_password", "password_then_volumes"],
)
def test_watch_resolves_wrong_password_and_incomplete_split_in_either_order(
    tmp_path,
    archive_format,
    sfx,
    unblock_order,
):
    fixture_root = tmp_path / "fixtures"
    watch_root = tmp_path / "watch"
    output_root = tmp_path / "out"
    watch_root.mkdir()
    output_root.mkdir()
    password = f"correct-{archive_format}-{uuid.uuid4().hex}"
    wrong_password = f"wrong-{uuid.uuid4().hex}"
    case_id = f"watch_dual_{archive_format}_{'sfx' if sfx else 'plain'}"
    try:
        case = ArchiveFixtureFactory().create(
            fixture_root,
            case_id,
            archive_format,
            password=password,
            split=True,
            sfx=sfx,
            payload_size=PAYLOAD_SIZE,
        )
    except (FileNotFoundError, RuntimeError) as exc:
        pytest.skip(str(exc))

    password_file = watch_root / ".sunpack-passwords.txt"
    password_file.write_text(wrong_password + "\n", encoding="utf-8")
    head, non_heads = _archive_parts(case)
    initial_sources = [non_heads[0], head]
    remaining_sources = list(reversed(non_heads[1:]))

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

    def arrive(source: Path):
        destination = watch_root / source.name
        shutil.copy2(source, destination)
        watcher.enqueue(str(destination))
        return watcher.run_once()

    try:
        initial_results = [arrive(source) for source in initial_sources]
        assert all(result.succeeded == 0 for result in initial_results), initial_results
        assert not list(output_root.rglob(case.marker_name))
        _drive_watch_until(
            watcher,
            lambda: (
                any(entry.status == "failed_password" for entry in watcher.state.entries.values())
                or any(BLOCKER_PASSWORD in group.blockers for group in watcher.state.groups.values())
                or any(BLOCKER_MISSING_VOLUME in group.blockers for group in watcher.state.groups.values())
            ),
        )
        assert engine.submit_times, "the incomplete contiguous prefix must exercise the backend"
        initial_password_blocker = (
            any(entry.status == "failed_password" for entry in watcher.state.entries.values())
            or any(BLOCKER_PASSWORD in group.blockers for group in watcher.state.groups.values())
        )
        initial_missing_blocker = any(
            BLOCKER_MISSING_VOLUME in group.blockers
            for group in watcher.state.groups.values()
        )
        assert initial_password_blocker or initial_missing_blocker

        if unblock_order == "volumes_then_password":
            volume_results = [arrive(source) for source in remaining_sources]
            assert all(result.succeeded == 0 for result in volume_results), volume_results
            _drive_watch_until(
                watcher,
                lambda: (
                    any(
                        entry.status == "failed_password"
                        for entry in watcher.state.entries.values()
                    )
                    or any(
                        BLOCKER_PASSWORD in group.blockers
                        for group in watcher.state.groups.values()
                    )
                ),
            )
            assert not list(output_root.rglob(case.marker_name))
            assert any(
                entry.status == "failed_password" for entry in watcher.state.entries.values()
            ) or any(
                BLOCKER_PASSWORD in group.blockers for group in watcher.state.groups.values()
            )
            assert watcher.run_once().processed == 0
            time.sleep(0.05)

            password_file.write_text(password + "\n", encoding="utf-8")
            watcher.notify_password_table_changed(str(password_file))
            final_result = _drive_watch_until(
                watcher,
                lambda: bool(list(output_root.rglob(case.marker_name))),
            )
        else:
            password_file.write_text(password + "\n", encoding="utf-8")
            watcher.notify_password_table_changed(str(password_file))
            submits_before_password = len(engine.submit_times)
            if initial_password_blocker:
                password_result = _drive_watch_until(
                    watcher,
                    lambda: len(engine.submit_times) > submits_before_password,
                )
                assert password_result.succeeded == 0, password_result
            else:
                # A tail-read failure carries only the missing-volume blocker.
                # Password-table changes must not spin the unchanged input.
                assert watcher.run_once().processed == 0
                assert len(engine.submit_times) == submits_before_password
            assert not list(output_root.rglob(case.marker_name))
            assert watcher.run_once().processed == 0
            time.sleep(0.05)

            final_result = None
            for source in remaining_sources:
                result = arrive(source)
                final_result = result
            assert final_result is not None
            final_result = _drive_watch_until(
                watcher,
                lambda: bool(list(output_root.rglob(case.marker_name))),
            )

        extracted = list(output_root.rglob(case.marker_name))
        assert len(extracted) == 1, extracted
        assert extracted[0].read_text(encoding="utf-8") == case.marker_text

        submits_after_success = len(engine.submit_times)
        for source in [*initial_sources, *remaining_sources]:
            watcher.enqueue(str(watch_root / source.name))
        assert _drive_watch_until(watcher, lambda: True).processed == 0
        assert len(engine.submit_times) == submits_after_success
    finally:
        delegate.close()


@pytest.mark.slow_real_archive
@pytest.mark.parametrize(
    "archive_format",
    [
        pytest.param("rar", id="rar"),
        pytest.param("7z", id="7z"),
        pytest.param("zip", id="zip"),
    ],
)
def test_watch_suspends_incomplete_encrypted_split_after_wrong_password_candidates(
    tmp_path,
    archive_format,
):
    """Wrong candidates before the right password must still expose a missing tail."""

    fixture_root = tmp_path / "fixtures"
    watch_root = tmp_path / "watch"
    output_root = tmp_path / "out"
    watch_root.mkdir()
    output_root.mkdir()
    correct_password = f"correct-{archive_format}-{uuid.uuid4().hex}"
    wrong_passwords = [
        f"wrong-{archive_format}-{index:02d}-{uuid.uuid4().hex}"
        for index in range(BULK_WRONG_PASSWORD_COUNT)
    ]
    try:
        case = ArchiveFixtureFactory().create(
            fixture_root,
            f"watch_missing_tail_wrong_password_{archive_format}",
            archive_format,
            password=correct_password,
            split=True,
            payload_size=PAYLOAD_SIZE,
        )
    except (FileNotFoundError, RuntimeError) as exc:
        pytest.skip(str(exc))

    (watch_root / ".sunpack-passwords.txt").write_text(
        "\n".join([*wrong_passwords, correct_password]) + "\n",
        encoding="utf-8",
    )
    head, non_heads = _archive_parts(case)
    # A contiguous prefix has no filename-visible gap, so watch must submit it
    # and learn about the absent tail through the real format/backend path.
    arrived = [head, *non_heads[:-1]]
    omitted = non_heads[-1:]
    assert omitted, [path.name for path in non_heads]

    native_probe = get_native_password_tester().try_passwords(
        str(head),
        [*wrong_passwords, correct_password],
        part_paths=[str(path) for path in arrived],
    )
    assert native_probe.status == STATUS_NEEDS_VOLUME_OR_TAIL_DAMAGED, native_probe
    if archive_format in {"7z", "zip"}:
        assert native_probe.attempts == 0, native_probe
    else:
        # Header-encrypted RAR cannot request the next named volume until a
        # password has unlocked the header.  It must still stop at that first
        # callback failure instead of converting it to a password verdict.
        assert native_probe.attempts <= len(wrong_passwords) + 1, native_probe
    assert "evidence=" in native_probe.message, native_probe

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

    try:
        for source in arrived:
            destination = watch_root / source.name
            shutil.copy2(source, destination)
            watcher.enqueue(str(destination))

        result = _drive_watch_until(
            watcher,
            lambda: any(
                group.status == "suspended"
                for group in watcher.state.groups.values()
            ),
        )
        assert engine.submit_times, "the contiguous incomplete prefix was never submitted"
        assert result.succeeded == 0, result
        assert not list(output_root.rglob(case.marker_name))
        suspended_groups = [
            group
            for group in watcher.state.groups.values()
            if BLOCKER_MISSING_VOLUME in group.blockers
        ]
        assert len(suspended_groups) == 1, watcher.state.groups
        assert suspended_groups[0].status == "suspended"
        assert BLOCKER_PASSWORD not in suspended_groups[0].blockers
        diagnostic = str(
            (suspended_groups[0].failure_payload.get("details") or {}).get("diagnostic")
            or suspended_groups[0].failure_payload.get("message")
            or ""
        ).lower()
        assert "missing" in diagnostic or "tail" in diagnostic or "尾部" in diagnostic

        submissions_after_suspend = len(engine.submit_times)
        for _ in range(5):
            idle_result = watcher.run_once()
            assert idle_result.processed == 0, idle_result
            assert idle_result.succeeded == 0, idle_result
        assert len(engine.submit_times) == submissions_after_suspend
    finally:
        delegate.close()


@pytest.mark.slow_real_archive
def test_watch_extracts_many_real_encrypted_split_downloads_with_wrong_password_pressure(
    tmp_path,
    record_property,
):
    """Exercise the real watch pipeline under the reported download pattern.

    Three encrypted split archives are downloaded together.  Their volumes
    arrive in a deterministic chaotic order, every volume is written slowly to
    a downloader temporary file before being renamed, and every correct
    password sits behind dozens of wrong candidates.
    """

    fixture_root = tmp_path / "fixtures"
    watch_root = tmp_path / "watch"
    output_root = tmp_path / "out"
    watch_root.mkdir()
    output_root.mkdir()

    formats = ("rar", "7z", "zip")
    passwords = {
        archive_format: f"correct-{archive_format}-{uuid.uuid4().hex}"
        for archive_format in formats
    }
    cases: dict[str, ArchiveCase] = {}
    for archive_format in formats:
        try:
            cases[archive_format] = ArchiveFixtureFactory().create(
                fixture_root,
                f"watch_bulk_{archive_format}",
                archive_format,
                password=passwords[archive_format],
                split=True,
                payload_size=BULK_PAYLOAD_SIZE,
            )
        except (FileNotFoundError, RuntimeError) as exc:
            pytest.skip(str(exc))

    wrong_passwords = [f"wrong-password-{index:02d}" for index in range(BULK_WRONG_PASSWORD_COUNT)]
    password_candidates = [*wrong_passwords, *(passwords[archive_format] for archive_format in formats)]
    password_file = watch_root / ".sunpack-passwords.txt"
    password_file.write_text("\n".join(password_candidates) + "\n", encoding="utf-8")

    rng = random.Random(0x5A17C0DE)
    per_format_orders: dict[str, list[Path]] = {}
    for archive_format, case in cases.items():
        head, non_heads = _archive_parts(case)
        rng.shuffle(non_heads)
        per_format_orders[archive_format] = [*non_heads, head]

    # Round-robin the independently shuffled groups so unrelated archives are
    # active together.  Keeping each canonical head last prevents an accidental
    # early success from weakening the incomplete-group portion of the test.
    download_order: list[tuple[str, Path]] = []
    round_index = 0
    while any(round_index < len(parts) for parts in per_format_orders.values()):
        round_formats = list(formats)
        rng.shuffle(round_formats)
        for archive_format in round_formats:
            parts = per_format_orders[archive_format]
            if round_index < len(parts):
                download_order.append((archive_format, parts[round_index]))
        round_index += 1

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

    run_results = []
    tick_latencies: list[float] = []
    async_inflight_observed = False
    download_started_at = time.perf_counter()
    final_volume_stable_at = download_started_at

    def run_watch_tick():
        nonlocal async_inflight_observed
        tick_started_at = time.perf_counter()
        result = watcher.run_once()
        tick_latencies.append(time.perf_counter() - tick_started_at)
        run_results.append(result)
        async_inflight_observed = async_inflight_observed or any(
            not handle.done() for handle in engine.handles
        )
        return result

    try:
        for _archive_format, source in download_order:
            temporary = watch_root / f"{source.name}.baiduyun.p.downloading"
            destination = watch_root / source.name
            with source.open("rb") as reader, temporary.open("wb") as writer:
                while chunk := reader.read(SLOW_DOWNLOAD_CHUNK_SIZE):
                    writer.write(chunk)
                    writer.flush()
                    os.fsync(writer.fileno())
                    watcher.enqueue(str(temporary), event_type="modified")
                    run_watch_tick()
                    time.sleep(SLOW_DOWNLOAD_CHUNK_DELAY_SECONDS)

            os.replace(temporary, destination)
            watcher.notify_path_departed(str(temporary))
            watcher.enqueue(str(destination), event_type="moved", src_path=str(temporary))
            final_volume_stable_at = time.perf_counter()
            run_watch_tick()

        deadline = final_volume_stable_at + MAX_BULK_COMPLETION_LATENCY_SECONDS
        while time.perf_counter() < deadline:
            extracted_count = sum(
                len(list(output_root.rglob(case.marker_name)))
                for case in cases.values()
            )
            if (
                extracted_count == len(cases)
                and engine.handles
                and all(handle.done() for handle in engine.handles)
            ):
                # A worker can finish after the preceding tick's harvest.  One
                # final non-blocking tick must account for that response in the
                # scheduler result/state before declaring the test complete.
                run_watch_tick()
                if sum(result.succeeded for result in run_results) == len(cases):
                    break
            run_watch_tick()
            time.sleep(0.01)
        else:
            pytest.fail(
                "watch did not finish encrypted split downloads before the deadline: "
                f"pending={watcher.pending_count}, entries={watcher.state.entries}, "
                f"groups={watcher.state.groups}"
            )

        completed_at = time.perf_counter()
        for case in cases.values():
            extracted = list(output_root.rglob(case.marker_name))
            assert len(extracted) == 1, (case.case_id, extracted)
            assert extracted[0].read_text(encoding="utf-8") == case.marker_text

        assert len(engine.submit_times) == len(cases), engine.submit_times
        assert sum(result.succeeded for result in run_results) == len(cases), run_results
        assert not any(result.errors for result in run_results), run_results
        assert async_inflight_observed, (
            "the real pipeline never remained in flight, so this run did not exercise async harvesting"
        )
        assert max(tick_latencies) < MAX_WATCH_TICK_LATENCY_SECONDS, tick_latencies
        assert completed_at - final_volume_stable_at < MAX_BULK_COMPLETION_LATENCY_SECONDS

        submits_after_success = len(engine.submit_times)
        for _archive_format, source in reversed(download_order):
            watcher.enqueue(str(watch_root / source.name))
        replay_result = run_watch_tick()
        assert replay_result.processed == 0, replay_result
        assert len(engine.submit_times) == submits_after_success
    finally:
        delegate.close()

    record_property("archive_formats", ",".join(formats))
    record_property("archive_count", len(cases))
    record_property("volume_count", len(download_order))
    record_property("wrong_password_count", len(wrong_passwords))
    record_property("password_candidate_count", len(password_candidates))
    record_property("download_order", ",".join(source.name for _, source in download_order))
    record_property("pipeline_submissions", len(engine.submit_times))
    record_property("max_watch_tick_latency_ms", round(max(tick_latencies) * 1000, 3))
    record_property(
        "post_download_completion_latency_ms",
        round((completed_at - final_volume_stable_at) * 1000, 3),
    )
    record_property(
        "total_download_and_completion_ms",
        round((completed_at - download_started_at) * 1000, 3),
    )


@pytest.mark.slow_real_archive
def test_watch_mixed_chaotic_split_completion_latency_vs_single_volume(
    tmp_path,
    record_property,
):
    """Compare complete-to-harvest latency for equivalent real watch batches."""

    formats = ("rar", "7z", "zip")
    passwords = {
        archive_format: f"perf-{archive_format}-{uuid.uuid4().hex}"
        for archive_format in formats
    }
    wrong_passwords = [
        f"perf-wrong-password-{index:02d}"
        for index in range(BULK_WRONG_PASSWORD_COUNT)
    ]
    password_candidates = [
        *wrong_passwords,
        *(passwords[archive_format] for archive_format in formats),
    ]

    cases_by_kind: dict[str, dict[str, ArchiveCase]] = {"single": {}, "split": {}}
    try:
        for kind, split in (("single", False), ("split", True)):
            for archive_format in formats:
                cases_by_kind[kind][archive_format] = ArchiveFixtureFactory().create(
                    tmp_path / "fixtures",
                    f"watch_perf_{kind}_{archive_format}",
                    archive_format,
                    password=passwords[archive_format],
                    split=split,
                    payload_size=BULK_PAYLOAD_SIZE,
                )
    except (FileNotFoundError, RuntimeError) as exc:
        pytest.skip(str(exc))

    # ABBA order balances process/DLL warm-up effects without making the
    # benchmark depend on one unusually fast or slow extraction.
    run_order = ("single", "split", "split", "single")
    metrics_by_kind: dict[str, list[dict[str, float | int]]] = {
        "single": [],
        "split": [],
    }
    for run_index, kind in enumerate(run_order):
        metrics_by_kind[kind].append(
            _run_completed_mixed_batch(
                tmp_path,
                label=f"perf_{run_index}_{kind}",
                cases=cases_by_kind[kind],
                password_candidates=password_candidates,
                split=kind == "split",
            )
        )

    single_latency = statistics.median(
        float(metrics["completion_latency"])
        for metrics in metrics_by_kind["single"]
    )
    split_latency = statistics.median(
        float(metrics["completion_latency"])
        for metrics in metrics_by_kind["split"]
    )
    latency_ratio = split_latency / max(single_latency, 1e-9)
    additional_latency = split_latency - single_latency
    # Both limits apply: the ratio catches proportional regressions and the
    # additive cap still protects slower CI hosts where a ratio alone is loose.
    split_budget = min(
        single_latency * MAX_SPLIT_PERFORMANCE_RATIO,
        single_latency + MAX_SPLIT_ADDITIONAL_LATENCY_SECONDS,
    )

    assert split_latency < MAX_BULK_COMPLETION_LATENCY_SECONDS
    assert split_latency <= split_budget, (
        f"chaotic mixed split watch latency regressed: single={single_latency:.3f}s, "
        f"split={split_latency:.3f}s, ratio={latency_ratio:.2f}x, "
        f"budget={split_budget:.3f}s"
    )
    assert max(
        float(metrics["max_precomplete_tick_latency"])
        for metrics in metrics_by_kind["split"]
    ) < MAX_WATCH_TICK_LATENCY_SECONDS

    single_ms = round(single_latency * 1000, 3)
    split_ms = round(split_latency * 1000, 3)
    print(
        "watch mixed-format completion latency: "
        f"single={single_ms}ms split-chaotic={split_ms}ms "
        f"delta={additional_latency * 1000:.3f}ms ratio={latency_ratio:.3f}x"
    )
    record_property("archive_formats", ",".join(formats))
    record_property("archive_count", len(formats))
    record_property("wrong_password_count", len(wrong_passwords))
    record_property("single_volume_completion_latency_ms", single_ms)
    record_property("chaotic_split_completion_latency_ms", split_ms)
    record_property("chaotic_split_additional_latency_ms", round(additional_latency * 1000, 3))
    record_property("chaotic_split_to_single_ratio", round(latency_ratio, 3))
    record_property(
        "split_volume_count",
        metrics_by_kind["split"][0]["volume_count"],
    )
