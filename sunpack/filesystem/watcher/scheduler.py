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
from sunpack.contracts.pipeline import PipelineTarget
from sunpack.filesystem.directory_scanner import apply_ordered_filters_to_entries
from sunpack.filesystem.filters import build_filters
from sunpack.filesystem.watcher.log import WatchLogStore
from sunpack.filesystem.watcher.group_dispatch import NullWatchGroupResolver, plan_watch_dispatches
from sunpack.filesystem.watcher.group_models import (
    BLOCKER_MISSING_VOLUME,
    BLOCKER_PASSWORD,
    WatchGroupSnapshot,
)
from sunpack.filesystem.watcher.quiet_policy import AdaptiveQuietPolicy, AdaptiveQuietTracker
from sunpack.filesystem.watcher.scanner import WatchCandidate, scan_watch_candidates
from sunpack.filesystem.watcher.scanner import _candidate_for as _watch_candidate_for_path
from sunpack.filesystem.watcher.state import WatchStateStore
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
class _ActiveCandidateState:
    last_event_at: float
    quiet_seconds: float
    filtered_size: int
    filtered_mtime: float
    generation: int = 1
    force: bool = False
    event_requires_attempt: bool = False
    filter_revision: int = 0


@dataclass
class _ActivePipelineRequest:
    candidate: WatchCandidate
    group: WatchGroupSnapshot | None
    handle: object
    probe_workspace: str
    predicted_probe_dirs: list[str]
    predicted_final_dirs: list[str]


class WatchScheduler:
    def __init__(
        self,
        config: dict,
        watch_roots: list[str],
        *,
        out_dir: str,
        state_path: str,
        interval_seconds: float | None = None,
        quiet_seconds: float | None = None,
        recursive: bool | None = None,
        initial_scan: bool | None = None,
        observer_stop_timeout_seconds: float | None = None,
        pipeline_engine=None,
        group_coordinator=None,
    ):
        self.config = config
        watch_config = dict(DEFAULT_WATCH_CONFIG)
        if isinstance(config.get("watch"), dict):
            watch_config.update(config["watch"])
        self.watch_roots = [os.path.abspath(path) for path in watch_roots]
        expanded_out_dir = os.path.expanduser(out_dir)
        self._relative_out_dir = not os.path.isabs(expanded_out_dir)
        self.out_dir = os.path.normpath(expanded_out_dir) if self._relative_out_dir else os.path.abspath(expanded_out_dir)
        self.interval_seconds = max(0.1, float(DEFAULT_WATCH_CONFIG["interval_seconds"] if interval_seconds is None else interval_seconds))
        configured_cold_start = watch_config.get(
            "cold_start_seconds",
            watch_config.get("quiet_seconds", DEFAULT_WATCH_CONFIG["cold_start_seconds"]),
        )
        self.cold_start_seconds = max(
            0.0,
            float(configured_cold_start if quiet_seconds is None else quiet_seconds),
        )
        self.quiet_seconds = self.cold_start_seconds
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
        self._active_states: dict[str, _ActiveCandidateState] = {}
        self._quiet_trackers: dict[str, AdaptiveQuietTracker] = {}
        self._password_dirty_dirs: dict[str, float] = {}
        self._active_output_roots: dict[str, int] = {}
        self._recent_output_roots: dict[str, float] = {}
        self._known_output_roots: list[str] = self.state.generated_output_roots()
        self._observer = Observer()
        self._started = False
        if pipeline_engine is None:
            raise ValueError("WatchScheduler requires a PipelineEngine")
        self.pipeline_engine = pipeline_engine
        quiet_min_seconds = max(
            0.0,
            float(watch_config.get("quiet_min_seconds", DEFAULT_WATCH_CONFIG["quiet_min_seconds"])),
        )
        quiet_max_seconds = (
            0.0
            if self.cold_start_seconds <= 0.0
            else max(
                self.cold_start_seconds,
                quiet_min_seconds,
                float(watch_config.get("quiet_max_seconds", DEFAULT_WATCH_CONFIG["quiet_max_seconds"])),
            )
        )
        if self.cold_start_seconds <= 0.0:
            quiet_min_seconds = 0.0
        self._quiet_policy = AdaptiveQuietPolicy(
            initial_seconds=self.cold_start_seconds,
            minimum_seconds=quiet_min_seconds,
            maximum_seconds=quiet_max_seconds,
        )
        self.output_suppression_seconds = max(0.0, float(watch_config["output_suppression_seconds"]))
        self.password_retry_debounce_seconds = max(0.0, float(watch_config["password_retry_debounce_seconds"]))
        self.password_retry_include_subtree = bool(watch_config["password_retry_include_subtree"])
        self._configured_user_passwords = dedupe_passwords(list(config.get("user_passwords") or []))
        self._configured_builtin_passwords = dedupe_passwords(list(config.get("builtin_passwords") or []))
        self.builtin_password_file = os.path.abspath(str(builtin_passwords_module.builtin_password_path()))
        self._recent_passwords: list[str] = []
        self._password_source_signature = self._refresh_password_sources()
        if self.state.record_password_source_signature(self._password_source_signature):
            self._mark_all_password_failures_dirty()
        self._clipboard_monitor = ClipboardPasswordMonitor(
            on_passwords_changed=self.notify_password_source_changed,
            enabled=bool(watch_config["clipboard_monitor_enabled"]),
            max_entries=int(watch_config["clipboard_builtin_max_entries"]),
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
                self.enqueue(snapshot.path, force=snapshot.force, event_type="recovery")
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
            cold_start_seconds=self.cold_start_seconds,
            quiet_min_seconds=self._quiet_policy.minimum_seconds,
            quiet_max_seconds=self._quiet_policy.maximum_seconds,
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
                time.sleep(self.next_delay_seconds())
        finally:
            self.stop()

    def run_once(self) -> WatchRunResult:
        now = time.time()
        self._process_password_dirty_dirs(now)
        ready = self._pop_ready(time.time())
        with self._lock:
            active_paths = {os.path.normcase(os.path.abspath(path)) for path in self._pending}
        dispatches, waiting = plan_watch_dispatches(
            ready,
            active_paths=active_paths,
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
        active_requests = [
            self._submit_candidate(dispatch.candidate, group=dispatch.group)
            for dispatch in dispatches
        ]
        result = WatchRunResult(pending=self.pending_count)
        for active_request in active_requests:
            single = self._complete_candidate(active_request)
            result.processed += single.processed
            result.succeeded += single.succeeded
            result.failed += single.failed
            result.errors.extend(single.errors)
        for candidate in ready:
            self.state.complete_work_if_matches(candidate)
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
        with self._lock:
            if not self._pending:
                return self.interval_seconds
            return max(
                0.0,
                min(
                    state.quiet_seconds - (now - state.last_event_at)
                    for state in self._active_states.values()
                ),
            )

    def enqueue(self, path: str, *, force: bool = False, event_type: str = "unknown", src_path: str = ""):
        if self.should_ignore_event_path(path):
            return
        if is_directory_password_file(path, self.config):
            self._log_candidate_ignored(path, "directory_password_file")
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
        now = time.time()
        with self._lock:
            state = self._active_states.get(candidate.path)
            if state is not None:
                quiet_seconds = self._observe_candidate_activity(candidate, now)
                self._pending[candidate.path] = candidate
                state.last_event_at = now
                state.quiet_seconds = quiet_seconds
                state.generation += 1
                state.force = state.force or force
                state.event_requires_attempt = state.event_requires_attempt or _event_requires_attempt(event_type)
                return
        if not self._passes_filesystem_filters(candidate):
            self._log_candidate_ignored(candidate.path, "filtered_out")
            return
        became_active = False
        active_quiet_seconds = self.cold_start_seconds
        with self._lock:
            active_quiet_seconds = self._observe_candidate_activity(candidate, now)
            self._pending[candidate.path] = candidate
            state = self._active_states.get(candidate.path)
            if state is None:
                became_active = True
                self._active_states[candidate.path] = _ActiveCandidateState(
                    last_event_at=now,
                    quiet_seconds=active_quiet_seconds,
                    filtered_size=candidate.size,
                    filtered_mtime=candidate.mtime,
                    force=force,
                    event_requires_attempt=_event_requires_attempt(event_type),
                    filter_revision=self._filter_revision,
                )
            else:
                state.last_event_at = now
                state.quiet_seconds = active_quiet_seconds
                state.generation += 1
                state.force = state.force or force
                state.event_requires_attempt = state.event_requires_attempt or _event_requires_attempt(event_type)
                state.filter_revision = self._filter_revision
        if became_active:
            self.state.queue_active(candidate, force=force or _event_requires_attempt(event_type))
            self.log.write(
                "candidate_active",
                path=candidate.path,
                force=force,
                event_type=event_type,
                src_path=src_path,
                size=candidate.size,
                mtime=candidate.mtime,
                quiet_seconds=active_quiet_seconds,
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
                self._active_states.pop(candidate_path, None)
            tracker_paths = [
                candidate_path
                for candidate_path in self._quiet_trackers
                if _paths_match(candidate_path, normalized, recursive=recursive)
            ]
            for candidate_path in tracker_paths:
                self._quiet_trackers.pop(candidate_path, None)
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
        due: list[tuple[str, WatchCandidate, int, bool, bool, int, int, float, float]] = []
        with self._lock:
            for path, candidate in self._pending.items():
                state = self._active_states[path]
                if now - state.last_event_at >= state.quiet_seconds:
                    due.append((
                        path,
                        candidate,
                        state.generation,
                        state.force,
                        state.event_requires_attempt,
                        state.filter_revision,
                        state.filtered_size,
                        state.filtered_mtime,
                        state.quiet_seconds,
                    ))

        for path, candidate, generation, force, event_requires_attempt, filter_revision, filtered_size, filtered_mtime, quiet_seconds in due:
            refreshed = _candidate_for_event_path(path)
            if refreshed is None:
                self._drop_active(path, generation)
                self.state.forget_path(path)
                continue
            filter_stale = (
                filter_revision != self._filter_revision
                or filtered_size != refreshed.size
                or filtered_mtime != refreshed.mtime
            )
            if filter_stale and not self._passes_filesystem_filters(refreshed):
                self._drop_active(path, generation)
                self.state.complete_work([path])
                continue
            if refreshed.size != candidate.size or refreshed.mtime != candidate.mtime:
                self._record_boundary_activity(path, generation, refreshed, now)
                continue
            identified = _candidate_with_file_identity(refreshed)
            if identified is None:
                self._record_boundary_activity(path, generation, refreshed, now)
                continue
            with self._lock:
                state = self._active_states.get(path)
                if state is None or state.generation != generation:
                    continue
                self._pending.pop(path, None)
                self._active_states.pop(path, None)
            if not force and not event_requires_attempt and self.state.snapshot_matches(
                identified.path,
                identified.size,
                identified.mtime,
                identified.file_id,
            ):
                self.state.complete_work([path])
                self._log_candidate_ignored(path, "unchanged_input", size=identified.size, mtime=identified.mtime)
                continue
            self.state.record_attempt(
                identified.path,
                identified.size,
                identified.mtime,
                identified.file_id,
            )
            self.log.write("candidate_quiet", path=path, generation=generation, quiet_seconds=quiet_seconds)
            ready.append(identified)
        return ready

    def _drop_active(self, path: str, generation: int) -> None:
        with self._lock:
            state = self._active_states.get(path)
            if state is None or state.generation != generation:
                return
            self._pending.pop(path, None)
            self._active_states.pop(path, None)

    def _record_boundary_activity(
        self,
        path: str,
        generation: int,
        candidate: WatchCandidate,
        now: float,
    ) -> None:
        with self._lock:
            state = self._active_states.get(path)
            if state is None or state.generation != generation:
                return
            self._pending[path] = candidate
            state.last_event_at = now
            state.quiet_seconds = self._observe_candidate_activity(candidate, now)
            state.generation += 1
            state.filter_revision = self._filter_revision
            state.filtered_size = candidate.size
            state.filtered_mtime = candidate.mtime

    def _observe_candidate_activity(self, candidate: WatchCandidate, now: float) -> float:
        tracker = self._quiet_trackers.get(candidate.path)
        if tracker is None:
            tracker = AdaptiveQuietTracker(self._quiet_policy)
            self._quiet_trackers[candidate.path] = tracker
        return tracker.observe(now, size=candidate.size, mtime=candidate.mtime)

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
        return _candidate_with_file_identity(candidate)

    def _submit_candidate(
        self,
        candidate: WatchCandidate,
        *,
        group: WatchGroupSnapshot | None = None,
    ) -> _ActivePipelineRequest:
        self.log.write("processing_started", path=candidate.path, size=candidate.size, mtime=candidate.mtime)
        with self._password_source_lock:
            run_config = dict(self.config)
            self.pipeline_engine.update_password_sources(
                user_passwords=run_config.get("user_passwords", []),
                builtin_passwords=run_config.get("builtin_passwords", []),
            )
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
        predicted_probe_dirs = self._predicted_output_dirs(candidate.path, run_config)
        self._activate_output_roots([probe_workspace, *predicted_probe_dirs])
        try:
            handle = self.pipeline_engine.submit(
                [PipelineTarget(candidate.path, output=run_config["output"])],
                defer_postprocess=True,
            )
        except Exception:
            self._release_output_roots([probe_workspace, *predicted_probe_dirs])
            self._cleanup_probe_workspace(probe_workspace)
            raise
        return _ActivePipelineRequest(
            candidate=candidate,
            group=group,
            handle=handle,
            probe_workspace=probe_workspace,
            predicted_probe_dirs=predicted_probe_dirs,
            predicted_final_dirs=predicted_final_dirs,
        )

    def _complete_candidate(self, request: _ActivePipelineRequest) -> WatchRunResult:
        candidate = request.candidate
        group = request.group
        try:
            response = request.handle.result()
        except Exception:
            self._cleanup_probe_workspace(request.probe_workspace)
            raise
        finally:
            self._release_output_roots([request.probe_workspace, *request.predicted_probe_dirs])
        summary = response.summary
        self._remember_recent_passwords(response.recent_passwords)
        target_result = _target_result_for_path(summary, candidate.path)
        outcome_kind = _summary_outcome_kind(summary, target_result)
        probe_output_dirs = _dedupe_paths([
            *response.artifacts.flatten_targets,
            *(
                str(item.get("out_dir") or "")
                for item in (getattr(summary, "recovered_outputs", []) or [])
                if isinstance(item, dict)
            ),
            *request.predicted_probe_dirs,
        ])

        if outcome_kind == OutcomeKind.PARTIAL_SUCCESS:
            self._cleanup_probe_workspace(request.probe_workspace)
            if group is not None:
                self.state.record_group_terminal(group, status="partial")
            self.state.mark(
                candidate.path,
                candidate.size,
                candidate.mtime,
                file_id=candidate.file_id,
                status="partial",
            )
            self.log.write("partial", path=candidate.path)
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
                file_id=candidate.file_id,
                status=status,
                error=error,
                failure_payload=payload,
            )
            self.log.write(status, path=candidate.path, error=error, failures=failure_payloads)
            self._cleanup_probe_workspace(request.probe_workspace)
            return WatchRunResult(processed=1, failed=1, errors=failed)
        if _summary_processed_no_tasks(summary):
            if group is not None:
                self.state.record_group_terminal(group, status="ignored_no_tasks")
            self.state.mark(
                candidate.path,
                candidate.size,
                candidate.mtime,
                file_id=candidate.file_id,
                status="ignored_no_tasks",
            )
            self.log.write("no_tasks_found", path=candidate.path)
            self._cleanup_probe_workspace(request.probe_workspace)
            return WatchRunResult(processed=1)
        if outcome_kind != OutcomeKind.COMPLETE_SUCCESS:
            self._cleanup_probe_workspace(request.probe_workspace)
            error = "watch pipeline returned no complete target outcome"
            if group is not None:
                self.state.record_group_terminal(group, status="failed_terminal")
            self.log.write("failed_terminal", path=candidate.path, error=error, failures=[])
            return WatchRunResult(processed=1, failed=1, errors=[error])

        generated_output_dirs, output_path_map = self._promote_probe_outputs(
            probe_output_dirs,
            request.predicted_final_dirs,
            request.probe_workspace,
        )
        request.handle.finalize(output_path_map)
        self._remember_recent_output_roots(generated_output_dirs)
        self._remember_known_output_roots(generated_output_dirs)
        if group is not None:
            self.state.record_group_done(group)
        self.state.mark(
            candidate.path,
            candidate.size,
            candidate.mtime,
            file_id=candidate.file_id,
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
            os.makedirs(root, exist_ok=True)
            _clear_directory_contents(root)

    def _prepare_probe_workspace(self, path: str) -> str:
        identity = hashlib.sha256(os.path.normcase(os.path.abspath(path)).encode("utf-8")).hexdigest()[:20]
        probe_root = self._probe_root_for(path)
        os.makedirs(probe_root, exist_ok=True)
        owner_dir = os.path.join(probe_root, identity)
        shutil.rmtree(owner_dir, ignore_errors=True)
        workspace = os.path.join(owner_dir, "work")
        os.makedirs(workspace, exist_ok=True)
        return workspace

    def _cleanup_probe_workspace(self, workspace: str) -> None:
        owner_dir = os.path.dirname(os.path.abspath(workspace))
        probe_root = os.path.dirname(owner_dir)
        shutil.rmtree(owner_dir, ignore_errors=True)
        os.makedirs(probe_root, exist_ok=True)

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


def _candidate_with_file_identity(candidate: WatchCandidate) -> WatchCandidate | None:
    try:
        stat = os.stat(candidate.path, follow_symlinks=False)
    except OSError:
        return None
    if int(stat.st_size) != candidate.size or abs(float(stat.st_mtime) - candidate.mtime) > 1e-6:
        return None
    file_id = f"{int(stat.st_dev)}:{int(stat.st_ino)}"
    return replace(candidate, file_id=file_id)


def _event_requires_attempt(event_type: str) -> bool:
    return event_type in {"created", "modified", "moved"}


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


def _clear_directory_contents(path: str) -> None:
    try:
        entries = list(os.scandir(path))
    except OSError:
        return
    for entry in entries:
        try:
            if entry.is_dir(follow_symlinks=False):
                shutil.rmtree(entry.path, ignore_errors=True)
            else:
                os.unlink(entry.path)
        except OSError:
            continue


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
