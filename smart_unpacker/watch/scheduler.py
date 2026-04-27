from __future__ import annotations

import os
import threading
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Iterable

from smart_unpacker.watch.scanner import WatchCandidate, looks_like_archive, scan_watch_candidates
from smart_unpacker.watch.state import WatchStateStore

from watchdog.events import FileSystemEvent, FileSystemEventHandler
from watchdog.observers import Observer


@dataclass
class WatchRunResult:
    processed: int = 0
    succeeded: int = 0
    failed: int = 0
    pending: int = 0
    errors: list[str] = field(default_factory=list)


class WatchScheduler:
    def __init__(
        self,
        config: dict,
        watch_roots: list[str],
        *,
        out_dir: str,
        state_path: str,
        interval_seconds: float = 1.0,
        stable_seconds: float = 10.0,
        recursive: bool = True,
        initial_scan: bool = True,
        runner_factory=None,
    ):
        self.config = config
        self.watch_roots = [os.path.abspath(path) for path in watch_roots]
        self.out_dir = os.path.abspath(out_dir)
        self.interval_seconds = max(0.1, float(interval_seconds))
        self.stable_seconds = max(0.0, float(stable_seconds))
        self.recursive = recursive
        self.initial_scan = initial_scan
        self.state = WatchStateStore(state_path)
        self._lock = threading.Lock()
        self._pending: dict[str, WatchCandidate] = {}
        self._stable_since: dict[str, float] = {}
        self._observer = Observer()
        self._started = False
        self.runner_factory = runner_factory

    def start(self):
        if self._started:
            return
        handler = _ArchiveEventHandler(self)
        for root in self.watch_roots:
            watch_path = root if os.path.isdir(root) else os.path.dirname(root)
            self._observer.schedule(handler, watch_path, recursive=self.recursive and os.path.isdir(root))
        self._observer.start()
        self._started = True
        if self.initial_scan:
            for candidate in scan_watch_candidates(self.watch_roots, recursive=self.recursive):
                self.enqueue(candidate.path)

    def stop(self):
        if not self._started:
            return
        self._observer.stop()
        self._observer.join(timeout=5.0)
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

    def enqueue(self, path: str):
        candidate = _candidate_for_event_path(path)
        if candidate is None:
            return
        if not self._is_under_watched_root(candidate.path):
            return
        if self._is_under_output_root(candidate.path):
            return
        if self.state.is_done(candidate.path, candidate.size, candidate.mtime):
            return
        now = time.time()
        with self._lock:
            previous = self._pending.get(candidate.path)
            self._pending[candidate.path] = candidate
            if previous is None or previous.size != candidate.size or previous.mtime != candidate.mtime:
                self._stable_since[candidate.path] = now

    def enqueue_many(self, paths: Iterable[str]):
        for path in paths:
            self.enqueue(path)

    def _pop_ready(self, now: float) -> list[WatchCandidate]:
        ready: list[WatchCandidate] = []
        with self._lock:
            for path, candidate in list(self._pending.items()):
                refreshed = _candidate_for_event_path(path)
                if refreshed is None:
                    self._pending.pop(path, None)
                    self._stable_since.pop(path, None)
                    continue
                if refreshed.size != candidate.size or refreshed.mtime != candidate.mtime:
                    self._pending[path] = refreshed
                    self._stable_since[path] = now
                    continue
                stable_since = self._stable_since.setdefault(path, now)
                if self.stable_seconds <= 0 or now - stable_since >= self.stable_seconds:
                    ready.append(refreshed)
                    self._pending.pop(path, None)
                    self._stable_since.pop(path, None)
        return ready

    def _process_candidate(self, candidate: WatchCandidate) -> WatchRunResult:
        if self.runner_factory is None:
            raise RuntimeError("WatchScheduler requires a runner_factory.")
        run_config = dict(self.config)
        run_config["output"] = {
            **(run_config.get("output", {}) if isinstance(run_config.get("output"), dict) else {}),
            "root": self.out_dir,
            "common_root": self._common_root_for(candidate.path),
        }
        summary = self.runner_factory(run_config).run_targets([candidate.path])
        failed = list(summary.failed_tasks)
        if failed:
            error = failed[0] if failed else "watch extraction failed"
            self.state.mark(candidate.path, candidate.size, candidate.mtime, status="failed", output_dir=self.out_dir, error=error)
            return WatchRunResult(processed=1, failed=1, errors=failed)
        self.state.mark(candidate.path, candidate.size, candidate.mtime, status="done", output_dir=self.out_dir)
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

    def _is_under_output_root(self, path: str) -> bool:
        return _is_relative_to(os.path.abspath(path), self.out_dir)


class _ArchiveEventHandler(FileSystemEventHandler):
    def __init__(self, scheduler: WatchScheduler):
        self.scheduler = scheduler

    def on_created(self, event: FileSystemEvent):
        self._handle(event)

    def on_modified(self, event: FileSystemEvent):
        self._handle(event)

    def on_moved(self, event: FileSystemEvent):
        dest_path = getattr(event, "dest_path", "")
        if dest_path:
            self.scheduler.enqueue(dest_path)

    def _handle(self, event: FileSystemEvent):
        if getattr(event, "is_directory", False):
            return
        src_path = getattr(event, "src_path", "")
        if src_path:
            self.scheduler.enqueue(src_path)


def _candidate_for_event_path(path: str) -> WatchCandidate | None:
    if not path or not looks_like_archive(path):
        return None
    try:
        stat = os.stat(path)
    except OSError:
        return None
    if stat.st_size <= 0:
        return None
    return WatchCandidate(path=os.path.abspath(path), size=int(stat.st_size), mtime=float(stat.st_mtime))


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

