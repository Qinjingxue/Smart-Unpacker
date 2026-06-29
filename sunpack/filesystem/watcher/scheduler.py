from __future__ import annotations

import errno
import hashlib
import json
import os
import shutil
import threading
import time
from dataclasses import dataclass, field, replace
from pathlib import Path
from typing import Iterable

from sunpack.config.detection_view import directory_scan_is_recursive
from sunpack.config.fields.watch import DEFAULT_WATCH_CONFIG
from sunpack.contracts.detection import FactBag
from sunpack.contracts.failures import FailureKind
from sunpack.contracts.filesystem import FileEntry
from sunpack.contracts.results import OutcomeKind
from sunpack.contracts.tasks import ArchiveTask
from sunpack.filesystem.directory_scanner import apply_ordered_filters_to_entries
from sunpack.filesystem.filters import build_filters
from sunpack.filesystem.watcher.log import WatchLogStore
from sunpack.filesystem.watcher.group_dispatch import NullWatchGroupResolver, plan_watch_dispatches
from sunpack.filesystem.watcher.group_models import (
    BLOCKER_MISSING_VOLUME,
    BLOCKER_PASSWORD,
    WatchGroupSnapshot,
)
from sunpack.filesystem.watcher.scanner import WatchCandidate, scan_watch_candidates
from sunpack.filesystem.watcher.scanner import _candidate_for as _watch_candidate_for_path
from sunpack.filesystem.watcher.state import WatchInputSnapshot, WatchStateStore
from sunpack.passwords.internal import builtin as builtin_passwords_module
from sunpack.passwords.internal.builtin import get_builtin_passwords
from sunpack.passwords.internal.clipboard_monitor import ClipboardPasswordMonitor
from sunpack.passwords.internal.lists import dedupe_passwords
from sunpack.passwords.internal.local_files import DIRECTORY_PASSWORD_FILE_NAME, is_directory_password_file
from sunpack.support.output_paths import default_output_dir_for_task

from watchdog.events import FileSystemEvent, FileSystemEventHandler
from watchdog.observers import Observer


@dataclass
class WatchRunResult:
    processed: int = 0
    succeeded: int = 0
    failed: int = 0
    pending: int = 0
    errors: list[str] = field(default_factory=list)


@dataclass
class _PendingCandidateState:
    first_seen: float
    last_changed: float
    event_type: str = "unknown"
    src_path: str = ""
    force: bool = False
    change_count: int = 0
    size_change_count: int = 0
    saw_copy_final_attributes: bool = False
    from_temporary_download: bool = False
    sample_invalidated: bool = False
    filter_revision: int = 0


class WatchScheduler:
    def __init__(
        self,
        config: dict,
        watch_roots: list[str],
        *,
        out_dir: str,
        state_path: str,
        interval_seconds: float | None = None,
        stable_seconds: float | None = None,
        recursive: bool | None = None,
        initial_scan: bool | None = None,
        observer_stop_timeout_seconds: float | None = None,
        runner_factory=None,
        group_coordinator=None,
    ):
        self.config = config
        self.watch_roots = [os.path.abspath(path) for path in watch_roots]
        expanded_out_dir = os.path.expanduser(out_dir)
        self._relative_out_dir = not os.path.isabs(expanded_out_dir)
        self.out_dir = os.path.normpath(expanded_out_dir) if self._relative_out_dir else os.path.abspath(expanded_out_dir)
        self.interval_seconds = max(0.1, float(DEFAULT_WATCH_CONFIG["interval_seconds"] if interval_seconds is None else interval_seconds))
        self.stable_seconds = max(0.0, float(DEFAULT_WATCH_CONFIG["stable_seconds"] if stable_seconds is None else stable_seconds))
        self.recursive = directory_scan_is_recursive(config) if recursive is None else bool(recursive)
        self.initial_scan = bool(DEFAULT_WATCH_CONFIG["initial_scan"] if initial_scan is None else initial_scan)
        self.observer_stop_timeout_seconds = max(
            0.0,
            float(
                DEFAULT_WATCH_CONFIG["observer_stop_timeout_seconds"]
                if observer_stop_timeout_seconds is None
                else observer_stop_timeout_seconds
            ),
        )
        self._filter_revision = 0
        self._filters = []
        self.filters = build_filters(config)
        self.state = WatchStateStore(state_path)
        self.group_coordinator = group_coordinator or NullWatchGroupResolver()
        log_path = Path(state_path).with_name("events.jsonl")
        self.log = WatchLogStore(str(log_path))
        state_parent = Path(state_path).parent
        self.metadata_dir = os.path.abspath(str(state_parent)) if state_parent.name == ".sunpack_watch" else ""
        self.metadata_files = {
            os.path.abspath(str(Path(state_path))),
            os.path.abspath(str(log_path)),
        }
        self._lock = threading.Lock()
        self._password_source_lock = threading.Lock()
        self._pending: dict[str, WatchCandidate] = {}
        self._stable_since: dict[str, float] = {}
        self._pending_states: dict[str, _PendingCandidateState] = {}
        self._password_dirty_dirs: dict[str, float] = {}
        self._active_output_roots: dict[str, int] = {}
        self._recent_output_roots: dict[str, float] = {}
        self._known_output_roots: list[str] = self.state.generated_output_roots()
        self._observer = Observer()
        self._started = False
        self.runner_factory = runner_factory
        watch_config = config.get("watch") if isinstance(config.get("watch"), dict) else {}
        self.fast_stable_seconds = max(0.0, float(watch_config.get("fast_stable_seconds", 0.5)))
        self.copy_final_stable_seconds = max(0.0, float(watch_config.get("copy_final_stable_seconds", 0.75)))
        self.new_file_stable_seconds = max(0.0, float(watch_config.get("new_file_stable_seconds", 1.0)))
        self.pending_check_interval_seconds = max(0.1, float(watch_config.get("pending_check_interval_seconds", 0.5)))
        self.output_suppression_seconds = max(0.0, float(watch_config.get("output_suppression_seconds", 120.0)))
        self.password_retry_debounce_seconds = max(0.0, float(watch_config.get("password_retry_debounce_seconds", 1.0)))
        self.password_retry_include_subtree = bool(watch_config.get("password_retry_include_subtree", True))
        self.partial_retry_seconds = max(1.0, float(watch_config.get("partial_retry_seconds", 30.0)))
        self._configured_user_passwords = dedupe_passwords(list(config.get("user_passwords") or []))
        self._configured_builtin_passwords = dedupe_passwords(list(config.get("builtin_passwords") or []))
        self.builtin_password_file = os.path.abspath(str(builtin_passwords_module.builtin_password_path()))
        self._recent_passwords: list[str] = []
        self._password_source_signature = self._refresh_password_sources()
        if self.state.record_password_source_signature(self._password_source_signature):
            self._mark_all_password_failures_dirty()
        self._clipboard_monitor = ClipboardPasswordMonitor(
            on_passwords_changed=self.notify_password_source_changed,
            enabled=bool(watch_config.get("clipboard_monitor_enabled", False)),
            max_entries=int(watch_config.get("clipboard_builtin_max_entries", 30)),
        )

    def start(self):
        if self._started:
            return
        self._ensure_directory_password_files()
        self._recover_probe_workspaces()
        handler = _WatchEventHandler(self)
        scheduled_paths: set[str] = set()
        for root in self.watch_roots:
            watch_path = root if os.path.isdir(root) else os.path.dirname(root)
            self._observer.schedule(handler, watch_path, recursive=self.recursive and os.path.isdir(root))
            scheduled_paths.add(os.path.normcase(os.path.abspath(watch_path)))
        builtin_password_dir = os.path.dirname(self.builtin_password_file)
        builtin_password_dir_key = os.path.normcase(os.path.abspath(builtin_password_dir))
        if os.path.isdir(builtin_password_dir) and builtin_password_dir_key not in scheduled_paths:
            self._observer.schedule(handler, builtin_password_dir, recursive=False)
        self._observer.start()
        self._clipboard_monitor.start()
        self._started = True
        for snapshot in self.state.pending_snapshots():
            if os.path.exists(snapshot.path):
                self.enqueue(snapshot.path, force=True, event_type="recovery")
            else:
                self.state.forget_path(snapshot.path)
        if self.initial_scan:
            for candidate in scan_watch_candidates(self.watch_roots, recursive=self.recursive):
                self.enqueue(candidate.path, event_type="initial_scan")
        self.log.write(
            "scheduler_started",
            roots=self.watch_roots,
            out_dir=self.out_dir,
            recursive=self.recursive,
            initial_scan=self.initial_scan,
            pending=self.pending_count,
            stable_seconds=self.stable_seconds,
            interval_seconds=self.interval_seconds,
        )

    def _ensure_directory_password_files(self) -> None:
        for root in self.watch_roots:
            if not os.path.isdir(root):
                continue
            password_file = Path(root) / DIRECTORY_PASSWORD_FILE_NAME
            if not is_directory_password_file(str(password_file), self.config):
                continue
            try:
                password_file.open("x", encoding="utf-8").close()
            except FileExistsError:
                pass

    def stop(self):
        if not self._started:
            return
        self._observer.stop()
        self._observer.join(timeout=self.observer_stop_timeout_seconds)
        self._clipboard_monitor.stop()
        self._started = False

    def run_forever(self):
        self.start()
        try:
            while True:
                self.run_once()
                time.sleep(self.interval_seconds)
        finally:
            self.stop()

    def run_once(self) -> WatchRunResult:
        now = time.time()
        self._process_password_dirty_dirs(now)
        self._process_due_partial_probes(now)
        ready = self._pop_ready(now)
        with self._lock:
            unstable_paths = {os.path.normcase(os.path.abspath(path)) for path in self._pending}
        dispatches, waiting = plan_watch_dispatches(
            ready,
            unstable_paths=unstable_paths,
            coordinator=self.group_coordinator,
            state=self.state,
            prepare_candidate=self._prepare_group_head,
        )
        for snapshot in waiting:
            self.log.write(
                "split_group_suspended",
                group_id=snapshot.group_id,
                head_path=snapshot.head_path,
                member_paths=list(snapshot.member_paths),
                missing_reason=snapshot.missing_reason,
                missing_indices=list(snapshot.missing_indices),
            )
        result = WatchRunResult(pending=self.pending_count)
        for dispatch in dispatches:
            single = self._process_candidate(dispatch.candidate, group=dispatch.group)
            result.processed += single.processed
            result.succeeded += single.succeeded
            result.failed += single.failed
            result.errors.extend(single.errors)
        self.state.complete_work(candidate.path for candidate in ready)
        result.pending = self.pending_count
        return result

    @property
    def pending_count(self) -> int:
        with self._lock:
            return len(self._pending)

    @property
    def filters(self):
        return self._filters

    @filters.setter
    def filters(self, value) -> None:
        self._filters = list(value or [])
        self._filter_revision += 1

    def next_delay_seconds(self) -> float:
        now = time.time()
        partial_retry_at = self.state.next_partial_retry_at()
        partial_delay = max(0.0, partial_retry_at - now) if partial_retry_at is not None else None
        with self._lock:
            if not self._pending:
                return min(self.interval_seconds, partial_delay) if partial_delay is not None else self.interval_seconds
            delays = []
            for path in self._pending:
                stable_since = self._stable_since.get(path, now)
                state = self._pending_states.get(path) or _PendingCandidateState(first_seen=stable_since, last_changed=stable_since)
                delays.append(max(0.0, self._candidate_ready_delay(state) - (now - stable_since)))
            next_ready = min(delays) if delays else self.pending_check_interval_seconds
        delays = [self.pending_check_interval_seconds, next_ready]
        if partial_delay is not None:
            delays.append(partial_delay)
        return max(0.0, min(delays))

    def enqueue(self, path: str, *, force: bool = False, event_type: str = "unknown", src_path: str = ""):
        if self.should_ignore_event_path(path):
            return
        if is_directory_password_file(path, self.config):
            self._log_candidate_ignored(path, "directory_password_file")
            return
        if _is_temporary_download_path(path):
            self._log_candidate_ignored(path, "temporary_download_file")
            return
        candidate = _candidate_for_event_path(path)
        if candidate is None:
            self._log_candidate_ignored(path, "not_a_file_or_unreadable")
            return
        if not self._is_under_watched_root(candidate.path):
            self._log_candidate_ignored(candidate.path, "outside_watched_roots")
            return
        output_reason = self._output_suppression_reason(candidate.path)
        if output_reason:
            self._log_candidate_ignored(candidate.path, output_reason)
            return
        if self._is_under_broad_output_root(candidate.path):
            self._log_candidate_ignored(candidate.path, "under_output_root")
            return
        if self._is_under_metadata_dir(candidate.path):
            self._log_candidate_ignored(candidate.path, "under_metadata_dir")
            return
        filter_revision = self._filter_revision
        now = time.time()
        with self._lock:
            previous = self._pending.get(candidate.path)
            previous_state = self._pending_states.get(candidate.path)
            if (
                previous is not None
                and previous.size == candidate.size
                and previous.mtime == candidate.mtime
                and previous_state is not None
                and previous_state.filter_revision == filter_revision
                and not force
            ):
                previous_state.event_type = _prefer_event_type(previous_state.event_type, event_type)
                previous_state.src_path = src_path or previous_state.src_path
                previous_state.from_temporary_download = previous_state.from_temporary_download or _is_temporary_download_path(src_path)
                if event_type == "modified":
                    self._stable_since[candidate.path] = now
                    previous_state.last_changed = now
                    previous_state.change_count += 1
                    previous_state.sample_invalidated = True
                return
        if not self._passes_filesystem_filters(candidate):
            self._log_candidate_ignored(candidate.path, "filtered_out")
            return
        with self._lock:
            previous = self._pending.get(candidate.path)
            previous_state = self._pending_states.get(candidate.path)
            if previous is not None and not force:
                metadata_changed = previous.size != candidate.size or previous.mtime != candidate.mtime
                if metadata_changed:
                    self._pending[candidate.path] = replace(candidate, sample_digest=previous.sample_digest)
                    self._stable_since[candidate.path] = now
                    state = previous_state or _PendingCandidateState(first_seen=now, last_changed=now)
                    self._pending_states[candidate.path] = state
                    state.last_changed = now
                    state.event_type = _prefer_event_type(state.event_type, event_type)
                    state.src_path = src_path or state.src_path
                    state.change_count += 1
                    state.sample_invalidated = True
                    state.from_temporary_download = state.from_temporary_download or _is_temporary_download_path(src_path)
                    if previous.size != candidate.size:
                        state.size_change_count += 1
                    if _looks_like_copy_final_mtime(previous.mtime, candidate.mtime, now):
                        state.saw_copy_final_attributes = True
                    state.filter_revision = filter_revision
                    return
                if previous_state is not None:
                    previous_state.event_type = _prefer_event_type(previous_state.event_type, event_type)
                    previous_state.src_path = src_path or previous_state.src_path
                    previous_state.from_temporary_download = previous_state.from_temporary_download or _is_temporary_download_path(src_path)
                    if event_type == "modified":
                        self._stable_since[candidate.path] = now
                        previous_state.last_changed = now
                        previous_state.change_count += 1
                        previous_state.sample_invalidated = True
                return
        candidate = _candidate_with_sample_digest(candidate)
        if candidate is None:
            self._log_candidate_ignored(path, "sample_unreadable")
            return
        partial_probe = self.state.partial_probe_for(candidate.path)
        if partial_probe is not None and not force:
            sampled = _candidate_with_sample_digest(candidate)
            if sampled is not None and _probe_matches_candidate(partial_probe, sampled):
                self._log_candidate_ignored(candidate.path, "partial_snapshot_quarantined")
                return
            self.state.clear_partial_probe(candidate.path)
            if sampled is not None:
                candidate = sampled
        with self._lock:
            previous = self._pending.get(candidate.path)
            previous_state = self._pending_states.get(candidate.path)
            if (
                previous is not None
                and previous.size == candidate.size
                and previous.mtime == candidate.mtime
                and not force
            ):
                if previous_state is not None:
                    previous_state.event_type = _prefer_event_type(previous_state.event_type, event_type)
                    previous_state.src_path = src_path or previous_state.src_path
                    previous_state.from_temporary_download = previous_state.from_temporary_download or _is_temporary_download_path(src_path)
                    previous_state.filter_revision = filter_revision
                return
            if previous is not None and force and previous_state is not None:
                previous_state.force = True
                previous_state.event_type = _prefer_event_type(previous_state.event_type, event_type)
                previous_state.src_path = src_path or previous_state.src_path
                previous_state.filter_revision = filter_revision
                return
            self._pending[candidate.path] = candidate
            if previous is None or previous.size != candidate.size or previous.mtime != candidate.mtime:
                self._stable_since[candidate.path] = now
                if previous_state is None:
                    self._pending_states[candidate.path] = _PendingCandidateState(
                        first_seen=now,
                        last_changed=now,
                        event_type=event_type,
                        src_path=src_path,
                        force=force,
                        from_temporary_download=_is_temporary_download_path(src_path),
                        filter_revision=filter_revision,
                    )
                else:
                    previous_state.last_changed = now
                    previous_state.event_type = _prefer_event_type(previous_state.event_type, event_type)
                    previous_state.src_path = src_path or previous_state.src_path
                    previous_state.force = previous_state.force or force
                    previous_state.change_count += 1
                    previous_state.from_temporary_download = previous_state.from_temporary_download or _is_temporary_download_path(src_path)
                    if previous is not None and previous.size != candidate.size:
                        previous_state.size_change_count += 1
                    if previous is not None and _looks_like_copy_final_mtime(previous.mtime, candidate.mtime, now):
                        previous_state.saw_copy_final_attributes = True
                    previous_state.filter_revision = filter_revision
        self.log.write(
            "candidate_queued",
            path=candidate.path,
            force=force,
            event_type=event_type,
            src_path=src_path,
            size=candidate.size,
            mtime=candidate.mtime,
            pending=self.pending_count,
        )

    def should_ignore_event_path(self, path: str) -> bool:
        if not path:
            return True
        return self._is_under_metadata_dir(path) or self._is_under_probe_root(path) or bool(self._output_suppression_reason(path))

    def _log_candidate_ignored(self, path: str, reason: str, **payload) -> None:
        normalized = os.path.normcase(os.path.abspath(str(path))) if path else ""
        self.log.write_throttled(
            "candidate_ignored",
            throttle_key=f"{normalized}|{reason}",
            interval_seconds=300.0,
            path=path,
            reason=reason,
            **payload,
        )

    def is_builtin_password_file(self, path: str) -> bool:
        if not path:
            return False
        return os.path.normcase(os.path.abspath(path)) == os.path.normcase(self.builtin_password_file)

    def enqueue_many(self, paths: Iterable[str]):
        for path in paths:
            self.enqueue(path)

    def notify_password_source_changed(self, reason: str, path: str = "") -> None:
        previous_signature = self._password_source_signature
        signature = self._refresh_password_sources()
        if reason in {"builtin_password_file", "clipboard"} and signature == previous_signature:
            return
        self._password_source_signature = signature
        generation = self.state.mark_password_source_changed(signature)
        self.log.write("password_source_changed", reason=reason, path=path, password_generation=generation)
        if path:
            self.notify_password_table_changed(path, bump_generation=False)
            return
        self._mark_all_password_failures_dirty()

    def notify_password_table_changed(self, path: str, *, bump_generation: bool = True) -> None:
        if bump_generation:
            self.notify_password_source_changed("directory_password_file", path)
            return
        directory = os.path.dirname(os.path.abspath(path))
        with self._lock:
            self._password_dirty_dirs[directory] = time.time()

    def notify_path_departed(self, path: str, *, recursive: bool = False) -> None:
        normalized = os.path.abspath(path)
        with self._lock:
            pending_paths = [
                candidate_path
                for candidate_path in self._pending
                if _paths_match(candidate_path, normalized, recursive=recursive)
            ]
            for candidate_path in pending_paths:
                self._pending.pop(candidate_path, None)
                self._stable_since.pop(candidate_path, None)
                self._pending_states.pop(candidate_path, None)
        forgotten = self.state.forget_path(normalized, recursive=recursive)
        self.log.write(
            "candidate_departed",
            path=normalized,
            recursive=recursive,
            forgotten=forgotten,
            pending_removed=len(pending_paths),
        )

    def _pop_ready(self, now: float) -> list[WatchCandidate]:
        ready: list[WatchCandidate] = []
        with self._lock:
            for path, candidate in list(self._pending.items()):
                refreshed = _candidate_for_event_path(path)
                if refreshed is None:
                    self._pending.pop(path, None)
                    self._stable_since.pop(path, None)
                    self._pending_states.pop(path, None)
                    continue
                stable_since = self._stable_since.setdefault(path, now)
                state = self._pending_states.setdefault(
                    path,
                    _PendingCandidateState(
                        first_seen=stable_since,
                        last_changed=stable_since,
                    ),
                )
                metadata_changed = refreshed.size != candidate.size or refreshed.mtime != candidate.mtime
                filter_revision = self._filter_revision
                if metadata_changed or state.filter_revision != filter_revision:
                    if not self._passes_filesystem_filters(refreshed):
                        self._pending.pop(path, None)
                        self._stable_since.pop(path, None)
                        self._pending_states.pop(path, None)
                        continue
                    state.filter_revision = filter_revision
                if metadata_changed:
                    self._pending[path] = replace(refreshed, sample_digest=candidate.sample_digest)
                    self._stable_since[path] = now
                    state.last_changed = now
                    state.change_count += 1
                    state.sample_invalidated = True
                    if refreshed.size != candidate.size:
                        state.size_change_count += 1
                    if _looks_like_copy_final_mtime(candidate.mtime, refreshed.mtime, now):
                        state.saw_copy_final_attributes = True
                    continue
                if self._candidate_ready_delay(state) <= 0 or now - stable_since >= self._candidate_ready_delay(state):
                    sampled = _candidate_with_sample_digest(refreshed)
                    if sampled is None:
                        self._stable_since[path] = now
                        continue
                    if sampled.sample_digest != candidate.sample_digest:
                        if state.sample_invalidated:
                            self._accept_ready_candidate(sampled, state, ready)
                            self._pending.pop(path, None)
                            self._stable_since.pop(path, None)
                            self._pending_states.pop(path, None)
                            continue
                        self._pending[path] = sampled
                        self._stable_since[path] = now
                        state.last_changed = now
                        state.change_count += 1
                        continue
                    self._accept_ready_candidate(sampled, state, ready)
                    self._pending.pop(path, None)
                    self._stable_since.pop(path, None)
                    self._pending_states.pop(path, None)
        return ready

    def _accept_ready_candidate(
        self,
        candidate: WatchCandidate,
        pending_state: _PendingCandidateState,
        ready: list[WatchCandidate],
    ) -> None:
        if not pending_state.force and self.state.snapshot_matches(
            candidate.path,
            candidate.size,
            candidate.mtime,
            candidate.sample_digest,
        ):
            self._log_candidate_ignored(
                candidate.path,
                "unchanged_input",
                size=candidate.size,
                mtime=candidate.mtime,
            )
            return
        self.state.observe_and_queue(
            candidate.path,
            candidate.size,
            candidate.mtime,
            candidate.sample_digest,
        )
        ready.append(candidate)

    def _process_password_dirty_dirs(self, now: float) -> None:
        ready_dirs: list[str] = []
        with self._lock:
            for directory, changed_at in list(self._password_dirty_dirs.items()):
                if now - changed_at >= self.password_retry_debounce_seconds:
                    ready_dirs.append(directory)
                    self._password_dirty_dirs.pop(directory, None)
        for directory in ready_dirs:
            entries = self.state.failed_password_entries_under(
                directory,
                include_subtree=self.password_retry_include_subtree,
            )
            for entry in entries:
                if os.path.exists(entry.path):
                    self.log.write("retry_password_failure", path=entry.path, directory=directory)
                    self.enqueue(entry.path, force=True)

    def _prepare_group_head(self, path: str) -> WatchCandidate | None:
        candidate = _candidate_for_event_path(path)
        if candidate is None or not self._passes_filesystem_filters(candidate):
            return None
        return _candidate_with_sample_digest(candidate)

    def _process_candidate(
        self,
        candidate: WatchCandidate,
        *,
        group: WatchGroupSnapshot | None = None,
    ) -> WatchRunResult:
        if self.runner_factory is None:
            raise RuntimeError("WatchScheduler requires a runner_factory.")
        self.log.write("processing_started", path=candidate.path, size=candidate.size, mtime=candidate.mtime)
        with self._password_source_lock:
            run_config = dict(self.config)
        output_root = self._output_root_for(candidate.path)
        run_config["output"] = {
            **(run_config.get("output", {}) if isinstance(run_config.get("output"), dict) else {}),
            "root": output_root,
            "common_root": self._common_root_for(candidate.path),
        }
        final_output_config = dict(run_config)
        final_output_config["output"] = dict(run_config["output"])
        predicted_final_dirs = self._predicted_output_dirs(candidate.path, final_output_config)
        probe_workspace = self._prepare_probe_workspace(candidate.path)
        run_config["output"] = {
            **run_config["output"],
            "root": probe_workspace,
            "common_root": final_output_config["output"]["common_root"],
        }
        run_config["post_extract"] = {
            **(run_config.get("post_extract", {}) if isinstance(run_config.get("post_extract"), dict) else {}),
            "defer_success_actions": True,
        }
        predicted_probe_dirs = self._predicted_output_dirs(candidate.path, run_config)
        self._activate_output_roots([probe_workspace, *predicted_probe_dirs])
        runner = self.runner_factory(run_config)
        try:
            summary = runner.run_targets([candidate.path])
        finally:
            self._release_output_roots([probe_workspace, *predicted_probe_dirs])
        self._remember_recent_passwords(getattr(runner, "recent_passwords", []))
        target_result = _target_result_for_path(summary, candidate.path)
        outcome_kind = _summary_outcome_kind(summary, target_result)
        probe_output_dirs = self._generated_output_dirs(runner, predicted_probe_dirs)

        if outcome_kind == OutcomeKind.PARTIAL_SUCCESS:
            verification = dict(getattr(target_result, "verification", {}) or {})
            signature = _verification_signature(verification)
            previous = self.state.partial_probe_for(candidate.path)
            snapshot = WatchInputSnapshot(
                path=candidate.path,
                size=candidate.size,
                mtime=candidate.mtime,
                sample_digest=candidate.sample_digest,
            )
            if previous is None or previous.fingerprint != snapshot.fingerprint:
                status = "awaiting_confirmation"
                retry_at = time.time() + self.partial_retry_seconds
                attempt_count = 1
                event = "partial_confirmation_scheduled"
            else:
                attempt_count = previous.attempt_count + 1
                retry_at = 0.0
                if previous.verification_signature == signature:
                    status = "quarantined_snapshot"
                    event = "partial_snapshot_quarantined"
                else:
                    status = "awaiting_input_change"
                    event = "partial_result_changed"
            self.state.record_partial_probe(
                snapshot,
                verification_signature=signature,
                verification_payload=verification,
                retry_at=retry_at,
                status=status,
                attempt_count=attempt_count,
            )
            self._cleanup_probe_workspace(probe_workspace)
            self.log.write(
                event,
                path=candidate.path,
                status=status,
                attempt_count=attempt_count,
                retry_at=retry_at,
                verification_signature=signature,
            )
            return WatchRunResult(processed=1)

        failed = list(summary.failed_tasks)
        if failed:
            error = failed[0] if failed else "watch extraction failed"
            failures = list(getattr(summary, "failures", []) or [])
            failure_payloads = [_failure_to_dict(failure) for failure in failures]
            is_password_failure = any(getattr(failure, "is_password_failure", False) for failure in failures)
            is_missing_volume = any(
                _failure_contains(failure, FailureKind.MISSING_VOLUME)
                for failure in failures
            )
            blockers = []
            if is_missing_volume:
                blockers.append(BLOCKER_MISSING_VOLUME)
            if is_password_failure:
                blockers.append(BLOCKER_PASSWORD)
            status = (
                "failed_password"
                if is_password_failure
                else "suspended_missing_volume"
                if is_missing_volume
                else "failed_terminal"
            )
            payload = failure_payloads[0] if failure_payloads else {}
            payload = {**payload, "blockers": list(blockers)}
            if group is not None:
                if blockers:
                    self.state.record_group_suspended(group, blockers=blockers, failure_payload=payload)
                else:
                    self.state.record_group_terminal(group, status="failed_terminal", failure_payload=payload)
            self.state.mark(
                candidate.path,
                candidate.size,
                candidate.mtime,
                sample_digest=candidate.sample_digest,
                status=status,
                error=error,
                failure_payload=payload,
            )
            self.log.write(status, path=candidate.path, error=error, failures=failure_payloads)
            self._cleanup_probe_workspace(probe_workspace)
            return WatchRunResult(processed=1, failed=1, errors=failed)
        if _summary_processed_no_tasks(summary):
            if group is not None:
                self.state.record_group_terminal(group, status="ignored_no_tasks")
            self.state.mark(
                candidate.path,
                candidate.size,
                candidate.mtime,
                sample_digest=candidate.sample_digest,
                status="ignored_no_tasks",
            )
            self.log.write("no_tasks_found", path=candidate.path)
            self._cleanup_probe_workspace(probe_workspace)
            return WatchRunResult(processed=1)
        if outcome_kind != OutcomeKind.COMPLETE_SUCCESS:
            self._cleanup_probe_workspace(probe_workspace)
            error = "watch pipeline returned no complete target outcome"
            self.log.write("failed_terminal", path=candidate.path, error=error, failures=[])
            return WatchRunResult(processed=1, failed=1, errors=[error])

        generated_output_dirs, output_path_map = self._promote_probe_outputs(
            probe_output_dirs,
            predicted_final_dirs,
            probe_workspace,
        )
        apply_deferred = getattr(runner, "apply_deferred_postprocess", None)
        if callable(apply_deferred):
            apply_deferred(output_path_map)
        self.state.clear_partial_probe(candidate.path)
        self._remember_recent_output_roots(generated_output_dirs)
        self._remember_known_output_roots(generated_output_dirs)
        if group is not None:
            self.state.record_group_done(group)
        self.state.mark(
            candidate.path,
            candidate.size,
            candidate.mtime,
            sample_digest=candidate.sample_digest,
            status="done",
        )
        self.log.write("done", path=candidate.path, success_count=summary.success_count, output_dirs=generated_output_dirs)
        return WatchRunResult(processed=1, succeeded=summary.success_count)

    def _common_root_for(self, path: str) -> str:
        path = os.path.abspath(path)
        matched = _longest_matching_root(path, self.watch_roots)
        if matched and os.path.isdir(matched):
            return matched
        if matched and os.path.isfile(matched):
            return os.path.dirname(matched)
        return os.path.dirname(path)

    def _output_root_for(self, path: str) -> str:
        if not self._relative_out_dir:
            return self.out_dir
        return os.path.abspath(os.path.join(self._common_root_for(path), self.out_dir))

    def _probe_root_for(self, path: str) -> str:
        return os.path.join(self._common_root_for(path), ".sunpack_watch_probes")

    def _probe_roots(self) -> list[str]:
        roots = []
        for root in self.watch_roots:
            base = root if os.path.isdir(root) else os.path.dirname(root)
            roots.append(os.path.join(os.path.abspath(base), ".sunpack_watch_probes"))
        return _dedupe_paths(roots)

    def _is_under_probe_root(self, path: str) -> bool:
        normalized = os.path.abspath(path)
        return _is_under_any_root(normalized, self._probe_roots())

    def _recover_probe_workspaces(self) -> None:
        for root in self._probe_roots():
            shutil.rmtree(root, ignore_errors=True)

    def _prepare_probe_workspace(self, path: str) -> str:
        identity = hashlib.sha256(os.path.normcase(os.path.abspath(path)).encode("utf-8")).hexdigest()[:20]
        owner_dir = os.path.join(self._probe_root_for(path), identity)
        shutil.rmtree(owner_dir, ignore_errors=True)
        workspace = os.path.join(owner_dir, "work")
        os.makedirs(workspace, exist_ok=True)
        return workspace

    def _cleanup_probe_workspace(self, workspace: str) -> None:
        owner_dir = os.path.dirname(os.path.abspath(workspace))
        probe_root = os.path.dirname(owner_dir)
        shutil.rmtree(owner_dir, ignore_errors=True)
        try:
            os.rmdir(probe_root)
        except OSError:
            pass

    def _promote_probe_outputs(
        self,
        probe_outputs: list[str],
        predicted_final_dirs: list[str],
        workspace: str,
    ) -> tuple[list[str], dict[str, str]]:
        sources = [
            path
            for path in _dedupe_paths(probe_outputs)
            if os.path.isdir(path) and _is_relative_to(path, workspace)
        ]
        promoted: list[str] = []
        path_map: dict[str, str] = {}
        for index, source in enumerate(sources):
            if index < len(predicted_final_dirs):
                target = predicted_final_dirs[index]
            else:
                target = os.path.join(os.path.dirname(predicted_final_dirs[0]), os.path.basename(source))
            target = _next_nonexisting_path(target)
            os.makedirs(os.path.dirname(target), exist_ok=True)
            try:
                os.replace(source, target)
            except OSError as exc:
                if exc.errno != errno.EXDEV and getattr(exc, "winerror", None) != 17:
                    raise
                shutil.move(source, target)
            promoted.append(target)
            path_map[source] = target
        self._cleanup_probe_workspace(workspace)
        return promoted, path_map

    def _process_due_partial_probes(self, now: float) -> None:
        for probe in self.state.due_partial_probes(now):
            candidate = _candidate_for_event_path(probe.path)
            if candidate is None:
                self.state.clear_partial_probe(probe.path)
                continue
            sampled = _candidate_with_sample_digest(candidate)
            if sampled is None:
                continue
            if _probe_matches_candidate(probe, sampled):
                self.enqueue(sampled.path, force=True, event_type="partial_confirmation")
                continue
            self.state.clear_partial_probe(probe.path)
            self.enqueue(sampled.path, event_type="modified")

    def _is_under_watched_root(self, path: str) -> bool:
        return _longest_matching_root(path, self.watch_roots) is not None

    def _is_under_broad_output_root(self, path: str) -> bool:
        if not self.out_dir:
            return False
        if self._relative_out_dir:
            if self.out_dir in {"", "."}:
                return False
            normalized = os.path.abspath(path)
            return any(_is_relative_to(normalized, os.path.join(root, self.out_dir)) for root in self.watch_roots)
        if any(_is_relative_to(root, self.out_dir) for root in self.watch_roots):
            return False
        return _is_relative_to(os.path.abspath(path), self.out_dir)

    def _is_under_metadata_dir(self, path: str) -> bool:
        normalized = os.path.abspath(path)
        if normalized in self.metadata_files:
            return True
        return bool(self.metadata_dir and _is_relative_to(normalized, self.metadata_dir))

    def _passes_filesystem_filters(self, candidate: WatchCandidate) -> bool:
        if not self.filters:
            return True
        entry = _file_entry_from_watch_candidate(candidate)
        return bool(apply_ordered_filters_to_entries([entry], self.filters))

    def _candidate_ready_delay(self, state: _PendingCandidateState) -> float:
        if self.stable_seconds <= 0 or state.force:
            return 0.0
        if state.from_temporary_download or state.event_type == "moved":
            return self.fast_stable_seconds
        if state.saw_copy_final_attributes:
            return self.copy_final_stable_seconds
        if state.size_change_count > 0:
            return self.stable_seconds
        return self.new_file_stable_seconds

    def _output_suppression_reason(self, path: str) -> str:
        normalized = os.path.abspath(path)
        now = time.time()
        self._prune_recent_output_roots(now)
        with self._lock:
            active_roots = list(self._active_output_roots)
            recent_roots = [root for root, expires_at in self._recent_output_roots.items() if expires_at > now]
        if _is_under_any_root(normalized, active_roots):
            return "under_active_output_root"
        if _is_under_any_root(normalized, recent_roots):
            return "under_recent_output_root"
        if _is_under_any_root(normalized, self._known_output_roots):
            return "under_known_output_root"
        return ""

    def _predicted_output_dirs(self, path: str, run_config: dict) -> list[str]:
        try:
            task = ArchiveTask(
                fact_bag=FactBag(),
                score=0,
                main_path=os.path.abspath(path),
                all_parts=[os.path.abspath(path)],
            )
            return _dedupe_paths([default_output_dir_for_task(task, run_config.get("output", {}))])
        except Exception:
            return []

    def _generated_output_dirs(self, runner, predicted: list[str]) -> list[str]:
        roots: list[str] = []
        context = getattr(runner, "context", None)
        flatten_candidates = getattr(context, "flatten_candidates", None)
        if flatten_candidates:
            roots.extend(str(path) for path in flatten_candidates if path)
        recovered_outputs = getattr(context, "recovered_outputs", None)
        if recovered_outputs:
            for item in recovered_outputs:
                if isinstance(item, dict) and item.get("out_dir"):
                    roots.append(str(item["out_dir"]))
        roots.extend(predicted)
        return _dedupe_paths(roots)

    def _activate_output_roots(self, roots: list[str]) -> None:
        if not roots:
            return
        with self._lock:
            for root in _dedupe_paths(roots):
                self._active_output_roots[root] = self._active_output_roots.get(root, 0) + 1

    def _release_output_roots(self, roots: list[str]) -> None:
        if not roots:
            return
        with self._lock:
            for root in _dedupe_paths(roots):
                count = self._active_output_roots.get(root, 0)
                if count <= 1:
                    self._active_output_roots.pop(root, None)
                else:
                    self._active_output_roots[root] = count - 1
        self._remember_recent_output_roots(roots)

    def _remember_recent_output_roots(self, roots: list[str]) -> None:
        if not roots or self.output_suppression_seconds <= 0:
            return
        expires_at = time.time() + self.output_suppression_seconds
        with self._lock:
            for root in _dedupe_paths(roots):
                self._recent_output_roots[root] = max(expires_at, self._recent_output_roots.get(root, 0.0))

    def _remember_known_output_roots(self, roots: list[str]) -> None:
        if not roots:
            return
        with self._lock:
            self._known_output_roots = _dedupe_paths([*self._known_output_roots, *roots])
        self.state.remember_output_roots(roots)

    def _prune_recent_output_roots(self, now: float) -> None:
        with self._lock:
            for root, expires_at in list(self._recent_output_roots.items()):
                if expires_at <= now:
                    self._recent_output_roots.pop(root, None)

    def _refresh_password_sources(self) -> str:
        builtin_passwords = dedupe_passwords([*self._configured_builtin_passwords, *get_builtin_passwords()])
        user_passwords = dedupe_passwords([*self._recent_passwords, *self._configured_user_passwords])
        signature = _password_source_signature(
            self._configured_user_passwords,
            builtin_passwords,
        )
        with self._password_source_lock:
            self.config["user_passwords"] = user_passwords
            self.config["builtin_passwords"] = builtin_passwords
        return signature

    def _remember_recent_passwords(self, passwords: Iterable[str] | None) -> None:
        incoming = dedupe_passwords([str(value) for value in list(passwords or []) if str(value)])
        updated = dedupe_passwords([*incoming, *self._recent_passwords])
        if updated == self._recent_passwords:
            return
        self._recent_passwords = updated
        self.notify_password_source_changed("recent_password")

    def _mark_all_password_failures_dirty(self) -> None:
        now = time.time()
        with self._lock:
            for entry in self.state.entries.values():
                if entry.status == "failed_password":
                    self._password_dirty_dirs[os.path.dirname(entry.path)] = now


class _WatchEventHandler(FileSystemEventHandler):
    def __init__(self, scheduler: WatchScheduler):
        self.scheduler = scheduler

    def on_created(self, event: FileSystemEvent):
        self._handle(event, "created")

    def on_modified(self, event: FileSystemEvent):
        self._handle(event, "modified")

    def on_deleted(self, event: FileSystemEvent):
        self._handle_departure(event)

    def on_moved(self, event: FileSystemEvent):
        src_path = getattr(event, "src_path", "")
        if src_path:
            self._handle_departure_path(
                src_path,
                is_directory=bool(getattr(event, "is_directory", False)),
            )
        dest_path = getattr(event, "dest_path", "")
        if dest_path:
            self._handle_path(dest_path, event_type="moved", src_path=src_path)

    def _handle_departure(self, event: FileSystemEvent) -> None:
        src_path = getattr(event, "src_path", "")
        if src_path:
            self._handle_departure_path(
                src_path,
                is_directory=bool(getattr(event, "is_directory", False)),
            )

    def _handle_departure_path(self, path: str, *, is_directory: bool) -> None:
        if self.scheduler.is_builtin_password_file(path):
            self.scheduler.notify_password_source_changed("builtin_password_file", path="")
            return
        if is_directory_password_file(path, self.scheduler.config):
            self.scheduler.notify_password_table_changed(path)
            return
        self.scheduler.notify_path_departed(path, recursive=is_directory)

    def _handle(self, event: FileSystemEvent, event_type: str):
        if getattr(event, "is_directory", False):
            return
        src_path = getattr(event, "src_path", "")
        if src_path:
            self._handle_path(src_path, event_type=event_type)

    def _handle_path(self, path: str, *, event_type: str = "unknown", src_path: str = ""):
        if self.scheduler.is_builtin_password_file(path):
            self.scheduler.notify_password_source_changed("builtin_password_file", path="")
            return
        if self.scheduler.should_ignore_event_path(path):
            return
        if is_directory_password_file(path, self.scheduler.config):
            self.scheduler.notify_password_table_changed(path)
            return
        self.scheduler.enqueue(path, event_type=event_type, src_path=src_path)


def _candidate_for_event_path(path: str) -> WatchCandidate | None:
    if not path:
        return None
    return _watch_candidate_for_path(path)


def _candidate_with_sample_digest(candidate: WatchCandidate) -> WatchCandidate | None:
    digest = _sample_file_digest(candidate.path, candidate.size)
    if digest is None:
        return None
    return replace(candidate, sample_digest=digest)


def _sample_file_digest(path: str, size: int) -> str | None:
    window_size = 32 * 1024
    sample_count = 8
    try:
        with open(path, "rb") as handle:
            if size <= window_size * sample_count:
                offsets = [0]
                read_sizes = [max(0, size)]
            else:
                max_offset = size - window_size
                offsets = sorted({(max_offset * index) // (sample_count - 1) for index in range(sample_count)})
                read_sizes = [window_size] * len(offsets)
            digest = hashlib.blake2s(digest_size=16)
            digest.update(int(size).to_bytes(8, "little", signed=False))
            for offset, read_size in zip(offsets, read_sizes):
                handle.seek(offset)
                data = handle.read(read_size)
                if len(data) != read_size:
                    return None
                digest.update(int(offset).to_bytes(8, "little", signed=False))
                digest.update(data)
    except (OSError, OverflowError):
        return None
    return digest.hexdigest()


def _file_entry_from_watch_candidate(candidate: WatchCandidate) -> FileEntry:
    path = Path(candidate.path)
    return FileEntry(
        path=path,
        is_dir=False,
        size=int(candidate.size),
        mtime_ns=int(candidate.mtime * 1_000_000_000),
    )

def _longest_matching_root(path: str, roots: list[str]) -> str | None:
    matches = [root for root in roots if _is_relative_to(path, root)]
    if not matches:
        return None
    return max(matches, key=len)


def _is_relative_to(path: str, root: str) -> bool:
    try:
        Path(path).resolve().relative_to(Path(root).resolve())
        return True
    except ValueError:
        return False


def _paths_match(path: str, expected: str, *, recursive: bool) -> bool:
    normalized = os.path.abspath(path)
    expected = os.path.abspath(expected)
    return os.path.normcase(normalized) == os.path.normcase(expected) or (
        recursive and _is_relative_to(normalized, expected)
    )


def _is_under_any_root(path: str, roots: list[str]) -> bool:
    return any(_is_relative_to(path, root) for root in roots if root)


def _is_temporary_download_path(path: str) -> bool:
    if not path:
        return False
    name = os.path.basename(str(path)).lower()
    suffixes = (
        ".baiduyun.p.downloading",
        ".downloading",
        ".crdownload",
        ".part",
        ".tmp",
        ".download",
        ".partial",
        ".!qb",
        ".!ut",
    )
    return name.endswith(suffixes)


def _probe_matches_candidate(probe, candidate: WatchCandidate) -> bool:
    return bool(
        int(getattr(probe, "size", -1)) == int(candidate.size)
        and float(getattr(probe, "mtime", -1.0)) == float(candidate.mtime)
        and str(getattr(probe, "sample_digest", "")) == str(candidate.sample_digest)
    )


def _target_result_for_path(summary, path: str):
    expected = os.path.normcase(os.path.abspath(path))
    for item in list(getattr(summary, "target_results", []) or []):
        raw_path = item.get("input_path", "") if isinstance(item, dict) else getattr(item, "input_path", "")
        if raw_path and os.path.normcase(os.path.abspath(str(raw_path))) == expected:
            return item
    return None


def _summary_outcome_kind(summary, target_result) -> OutcomeKind:
    raw = (
        target_result.get("outcome_kind")
        if isinstance(target_result, dict)
        else getattr(target_result, "outcome_kind", None)
    ) if target_result is not None else None
    if isinstance(raw, OutcomeKind):
        return raw
    if raw:
        try:
            return OutcomeKind(str(raw))
        except ValueError:
            pass
    if int(getattr(summary, "partial_success_count", 0) or 0) > 0:
        return OutcomeKind.PARTIAL_SUCCESS
    if int(getattr(summary, "success_count", 0) or 0) > 0:
        return OutcomeKind.COMPLETE_SUCCESS
    return OutcomeKind.FAILURE


def _verification_signature(payload: dict) -> str:
    coverage = payload.get("archive_coverage") if isinstance(payload.get("archive_coverage"), dict) else {}
    files = []
    for item in payload.get("files") or []:
        if not isinstance(item, dict):
            continue
        files.append({
            "archive_path": str(item.get("archive_path") or ""),
            "status": str(item.get("status") or ""),
            "bytes_written": int(item.get("bytes_written", 0) or 0),
            "expected_size": item.get("expected_size"),
            "crc_expected": item.get("crc_expected"),
            "crc_actual": item.get("crc_actual"),
            "failure_stage": str(item.get("failure_stage") or ""),
            "failure_kind": str(item.get("failure_kind") or ""),
        })
    canonical = {
        "assessment_status": str(payload.get("assessment_status") or ""),
        "source_integrity": str(payload.get("source_integrity") or ""),
        "decision_hint": str(payload.get("decision_hint") or ""),
        "completeness": round(float(payload.get("completeness", 0.0) or 0.0), 9),
        "recoverable_upper_bound": round(float(payload.get("recoverable_upper_bound", 0.0) or 0.0), 9),
        "coverage": {
            key: coverage.get(key)
            for key in (
                "expected_files", "matched_files", "complete_files", "partial_files",
                "failed_files", "missing_files", "unverified_files", "expected_bytes",
                "matched_bytes", "complete_bytes",
            )
        },
        "repair_hints": dict(payload.get("repair_hints") or {}),
        "files": sorted(files, key=lambda item: (item["archive_path"], item["status"])),
    }
    return hashlib.sha256(json.dumps(canonical, sort_keys=True, ensure_ascii=False, default=str).encode("utf-8")).hexdigest()


def _next_nonexisting_path(path: str) -> str:
    if not os.path.exists(path):
        return path
    base = f"{path}_extracted"
    if not os.path.exists(base):
        return base
    index = 2
    while os.path.exists(f"{base}_{index}"):
        index += 1
    return f"{base}_{index}"


def _prefer_event_type(current: str, incoming: str) -> str:
    order = {"unknown": 0, "initial_scan": 1, "modified": 2, "created": 3, "moved": 4, "recovery": 5}
    return incoming if order.get(incoming, 0) >= order.get(current, 0) else current


def _looks_like_copy_final_mtime(previous_mtime: float, current_mtime: float, now: float) -> bool:
    if current_mtime <= 0:
        return False
    if current_mtime < previous_mtime - 1.0:
        return True
    return current_mtime < now - 60.0 and previous_mtime > now - 60.0


def _dedupe_paths(paths: Iterable[str]) -> list[str]:
    output: list[str] = []
    seen: set[str] = set()
    for path in paths:
        value = str(path or "").strip()
        if not value:
            continue
        normalized = os.path.abspath(value)
        key = os.path.normcase(normalized)
        if key in seen:
            continue
        seen.add(key)
        output.append(normalized)
    return output


def _password_source_signature(
    user_passwords: list[str],
    builtin_passwords: list[str],
) -> str:
    payload = json.dumps(
        [user_passwords, builtin_passwords],
        ensure_ascii=False,
        separators=(",", ":"),
    ).encode("utf-8")
    return hashlib.sha256(payload).hexdigest()


def _failure_to_dict(failure) -> dict:
    if hasattr(failure, "to_dict"):
        try:
            return failure.to_dict()
        except Exception:
            return {}
    return {}


def _failure_contains(failure, kind: FailureKind) -> bool:
    contains = getattr(failure, "contains", None)
    if callable(contains):
        try:
            return bool(contains(kind))
        except Exception:
            pass
    return getattr(failure, "kind", None) == kind


def _summary_processed_no_tasks(summary) -> bool:
    return (
        int(getattr(summary, "success_count", 0) or 0) <= 0
        and not list(getattr(summary, "failed_tasks", []) or [])
        and not list(getattr(summary, "processed_keys", []) or [])
        and not list(getattr(summary, "recovered_outputs", []) or [])
    )
