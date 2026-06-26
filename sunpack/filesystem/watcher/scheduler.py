from __future__ import annotations

import os
import threading
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Iterable

from sunpack.config.detection_view import directory_scan_is_recursive
from sunpack.config.fields.watch import DEFAULT_WATCH_CONFIG
from sunpack.contracts.detection import FactBag
from sunpack.contracts.filesystem import FileEntry
from sunpack.contracts.tasks import ArchiveTask
from sunpack.extraction.internal.workflow.output_paths import default_output_dir_for_task
from sunpack.filesystem.directory_scanner import apply_ordered_filters_to_entries
from sunpack.filesystem.filters import build_filters
from sunpack.filesystem.watcher.log import WatchLogStore
from sunpack.filesystem.watcher.scanner import WatchCandidate, scan_watch_candidates
from sunpack.filesystem.watcher.scanner import _candidate_for as _watch_candidate_for_path
from sunpack.filesystem.watcher.state import WatchStateStore
from sunpack.passwords.internal.builtin import get_builtin_passwords
from sunpack.passwords.internal.clipboard_monitor import ClipboardPasswordMonitor
from sunpack.passwords.internal.local_files import is_directory_password_file

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
    ):
        self.config = config
        self.watch_roots = [os.path.abspath(path) for path in watch_roots]
        self.out_dir = os.path.abspath(out_dir)
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
        self.filters = build_filters(config)
        self.state = WatchStateStore(state_path)
        log_path = Path(state_path).with_name("events.jsonl")
        self.log = WatchLogStore(str(log_path))
        state_parent = Path(state_path).parent
        self.metadata_dir = os.path.abspath(str(state_parent)) if state_parent.name == ".sunpack_watch" else ""
        self.metadata_files = {
            os.path.abspath(str(Path(state_path))),
            os.path.abspath(str(log_path)),
        }
        self._lock = threading.Lock()
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
        self._clipboard_monitor = ClipboardPasswordMonitor(
            on_passwords_changed=self.notify_password_source_changed,
            enabled=bool(watch_config.get("clipboard_monitor_enabled", False)),
            max_entries=int(watch_config.get("clipboard_builtin_max_entries", 30)),
        )

    def start(self):
        if self._started:
            return
        handler = _WatchEventHandler(self)
        for root in self.watch_roots:
            watch_path = root if os.path.isdir(root) else os.path.dirname(root)
            self._observer.schedule(handler, watch_path, recursive=self.recursive and os.path.isdir(root))
        self._observer.start()
        self._clipboard_monitor.start()
        self._started = True
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
        ready = self._pop_ready(now)
        result = WatchRunResult(pending=self.pending_count)
        for candidate in ready:
            single = self._process_candidate(candidate)
            result.processed += single.processed
            result.succeeded += single.succeeded
            result.failed += single.failed
            result.errors.extend(single.errors)
        result.pending = self.pending_count
        return result

    @property
    def pending_count(self) -> int:
        with self._lock:
            return len(self._pending)

    def next_delay_seconds(self) -> float:
        now = time.time()
        with self._lock:
            if not self._pending:
                return self.interval_seconds
            delays = []
            for path in self._pending:
                stable_since = self._stable_since.get(path, now)
                state = self._pending_states.get(path) or _PendingCandidateState(first_seen=stable_since, last_changed=stable_since)
                delays.append(max(0.0, self._candidate_ready_delay(state) - (now - stable_since)))
            next_ready = min(delays) if delays else self.pending_check_interval_seconds
        return max(0.0, min(self.pending_check_interval_seconds, next_ready))

    def enqueue(self, path: str, *, force: bool = False, event_type: str = "unknown", src_path: str = ""):
        if self.should_ignore_event_path(path):
            return
        if _is_temporary_download_path(path):
            self.log.write("candidate_ignored", path=path, reason="temporary_download_file")
            return
        candidate = _candidate_for_event_path(path)
        if candidate is None:
            self.log.write("candidate_ignored", path=path, reason="not_a_file_or_unreadable")
            return
        if not self._is_under_watched_root(candidate.path):
            self.log.write("candidate_ignored", path=candidate.path, reason="outside_watched_roots")
            return
        output_reason = self._output_suppression_reason(candidate.path)
        if output_reason:
            self.log.write("candidate_ignored", path=candidate.path, reason=output_reason)
            return
        if self._is_under_broad_output_root(candidate.path):
            self.log.write("candidate_ignored", path=candidate.path, reason="under_output_root")
            return
        if self._is_under_metadata_dir(candidate.path):
            self.log.write("candidate_ignored", path=candidate.path, reason="under_metadata_dir")
            return
        if not self._passes_filesystem_filters(candidate):
            self.log.write("candidate_ignored", path=candidate.path, reason="filtered_out")
            return
        if self.state.should_skip(candidate.path, candidate.size, candidate.mtime, force=force):
            self.log.write(
                "candidate_ignored",
                path=candidate.path,
                reason="already_processed",
                size=candidate.size,
                mtime=candidate.mtime,
            )
            return
        now = time.time()
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
        return self._is_under_metadata_dir(path) or bool(self._output_suppression_reason(path))

    def enqueue_many(self, paths: Iterable[str]):
        for path in paths:
            self.enqueue(path)

    def notify_password_source_changed(self, reason: str, path: str = "") -> None:
        self._reload_builtin_passwords()
        generation = self.state.mark_password_source_changed()
        self.log.write("password_source_changed", reason=reason, path=path, password_generation=generation)
        if path:
            self.notify_password_table_changed(path, bump_generation=False)
            return
        with self._lock:
            for entry in self.state.entries.values():
                if entry.status == "failed_password":
                    self._password_dirty_dirs[os.path.dirname(entry.path)] = time.time()

    def notify_password_table_changed(self, path: str, *, bump_generation: bool = True) -> None:
        if bump_generation:
            self.notify_password_source_changed("directory_password_file", path)
            return
        directory = os.path.dirname(os.path.abspath(path))
        with self._lock:
            self._password_dirty_dirs[directory] = time.time()

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
                if not self._passes_filesystem_filters(refreshed):
                    self._pending.pop(path, None)
                    self._stable_since.pop(path, None)
                    self._pending_states.pop(path, None)
                    continue
                if refreshed.size != candidate.size or refreshed.mtime != candidate.mtime:
                    self._pending[path] = refreshed
                    self._stable_since[path] = now
                    state = self._pending_states.setdefault(path, _PendingCandidateState(first_seen=now, last_changed=now))
                    state.last_changed = now
                    state.change_count += 1
                    if refreshed.size != candidate.size:
                        state.size_change_count += 1
                    if _looks_like_copy_final_mtime(candidate.mtime, refreshed.mtime, now):
                        state.saw_copy_final_attributes = True
                    continue
                stable_since = self._stable_since.setdefault(path, now)
                state = self._pending_states.setdefault(path, _PendingCandidateState(first_seen=stable_since, last_changed=stable_since))
                if self._candidate_ready_delay(state) <= 0 or now - stable_since >= self._candidate_ready_delay(state):
                    ready.append(refreshed)
                    self._pending.pop(path, None)
                    self._stable_since.pop(path, None)
                    self._pending_states.pop(path, None)
        return ready

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

    def _process_candidate(self, candidate: WatchCandidate) -> WatchRunResult:
        if self.runner_factory is None:
            raise RuntimeError("WatchScheduler requires a runner_factory.")
        self.log.write("processing_started", path=candidate.path, size=candidate.size, mtime=candidate.mtime)
        run_config = dict(self.config)
        run_config["output"] = {
            **(run_config.get("output", {}) if isinstance(run_config.get("output"), dict) else {}),
            "root": self.out_dir,
            "common_root": self._common_root_for(candidate.path),
        }
        predicted_output_dirs = self._predicted_output_dirs(candidate.path, run_config)
        self._activate_output_roots(predicted_output_dirs)
        runner = self.runner_factory(run_config)
        try:
            summary = runner.run_targets([candidate.path])
        finally:
            self._release_output_roots(predicted_output_dirs)
        generated_output_dirs = self._generated_output_dirs(runner, predicted_output_dirs)
        self._remember_recent_output_roots(generated_output_dirs)
        failed = list(summary.failed_tasks)
        if failed:
            error = failed[0] if failed else "watch extraction failed"
            failures = list(getattr(summary, "failures", []) or [])
            failure_payloads = [_failure_to_dict(failure) for failure in failures]
            is_password_failure = any(getattr(failure, "is_password_failure", False) for failure in failures)
            status = "failed_password" if is_password_failure else "failed_terminal"
            payload = failure_payloads[0] if failure_payloads else {}
            self.state.mark(
                candidate.path,
                candidate.size,
                candidate.mtime,
                status=status,
                output_dir=generated_output_dirs[0] if generated_output_dirs else "",
                generated_output_dirs=[],
                error=error,
                failure_payload=payload,
            )
            self.log.write(status, path=candidate.path, error=error, failures=failure_payloads)
            return WatchRunResult(processed=1, failed=1, errors=failed)
        if _summary_processed_no_tasks(summary):
            self.state.mark(
                candidate.path,
                candidate.size,
                candidate.mtime,
                status="ignored_no_tasks",
            )
            self.log.write("no_tasks_found", path=candidate.path)
            return WatchRunResult(processed=1)
        self._remember_known_output_roots(generated_output_dirs)
        self.state.mark(
            candidate.path,
            candidate.size,
            candidate.mtime,
            status="done",
            output_dir=generated_output_dirs[0] if generated_output_dirs else "",
            generated_output_dirs=generated_output_dirs,
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

    def _is_under_watched_root(self, path: str) -> bool:
        return _longest_matching_root(path, self.watch_roots) is not None

    def _is_under_broad_output_root(self, path: str) -> bool:
        if not self.out_dir:
            return False
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

    def _prune_recent_output_roots(self, now: float) -> None:
        with self._lock:
            for root, expires_at in list(self._recent_output_roots.items()):
                if expires_at <= now:
                    self._recent_output_roots.pop(root, None)

    def _reload_builtin_passwords(self) -> None:
        if "builtin_passwords" in self.config:
            self.config["builtin_passwords"] = get_builtin_passwords()


class _WatchEventHandler(FileSystemEventHandler):
    def __init__(self, scheduler: WatchScheduler):
        self.scheduler = scheduler

    def on_created(self, event: FileSystemEvent):
        self._handle(event, "created")

    def on_modified(self, event: FileSystemEvent):
        self._handle(event, "modified")

    def on_moved(self, event: FileSystemEvent):
        dest_path = getattr(event, "dest_path", "")
        if dest_path:
            self._handle_path(dest_path, event_type="moved", src_path=getattr(event, "src_path", ""))

    def _handle(self, event: FileSystemEvent, event_type: str):
        if getattr(event, "is_directory", False):
            return
        src_path = getattr(event, "src_path", "")
        if src_path:
            self._handle_path(src_path, event_type=event_type)

    def _handle_path(self, path: str, *, event_type: str = "unknown", src_path: str = ""):
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


def _is_under_any_root(path: str, roots: list[str]) -> bool:
    return any(_is_relative_to(path, root) for root in roots if root)


def _is_temporary_download_path(path: str) -> bool:
    if not path:
        return False
    name = os.path.basename(str(path)).lower()
    suffixes = (
        ".crdownload",
        ".part",
        ".tmp",
        ".download",
        ".partial",
        ".!qb",
        ".!ut",
    )
    return name.endswith(suffixes)


def _prefer_event_type(current: str, incoming: str) -> str:
    order = {"unknown": 0, "initial_scan": 1, "modified": 2, "created": 3, "moved": 4}
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


def _failure_to_dict(failure) -> dict:
    if hasattr(failure, "to_dict"):
        try:
            return failure.to_dict()
        except Exception:
            return {}
    return {}


def _summary_processed_no_tasks(summary) -> bool:
    return (
        int(getattr(summary, "success_count", 0) or 0) <= 0
        and not list(getattr(summary, "failed_tasks", []) or [])
        and not list(getattr(summary, "processed_keys", []) or [])
        and not list(getattr(summary, "recovered_outputs", []) or [])
    )
