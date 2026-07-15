from __future__ import annotations

from dataclasses import asdict, dataclass, field
import json
import os
import time
from pathlib import Path
from typing import Any, Iterable

from .group_models import (
    BLOCKER_MISSING_VOLUME,
    WatchGroupSnapshot,
    WatchGroupState,
)
from sunpack.support.collections import dedupe_normalized_paths


STATE_VERSION = 10
LOADABLE_STATE_VERSIONS = {9, STATE_VERSION}


@dataclass
class WatchInputSnapshot:
    path: str
    size: int
    mtime: float
    file_id: str = ""
    change_usn: int = 0
    force: bool = False

    @property
    def fingerprint(self) -> str:
        base = f"{self.path}|{self.size}|{self.mtime:.6f}"
        return f"{base}|{self.file_id}|{self.change_usn}"


@dataclass
class WatchStateEntry:
    """Latest retry-blocking failure for one input path."""

    path: str
    size: int
    mtime: float
    file_id: str = ""
    change_usn: int = 0
    status: str = "pending"
    last_error: str = ""
    attempt_count: int = 0
    failure_kind: str = ""
    failure_stage: str = ""
    failure_payload: dict[str, Any] = field(default_factory=dict)
    last_attempt_at: float = 0.0
    password_generation: int = 0

    @property
    def fingerprint(self) -> str:
        base = f"{self.path}|{self.size}|{self.mtime:.6f}"
        return f"{base}|{self.file_id}|{self.change_usn}"


class WatchStateStore:
    """Persistent input snapshot, crash queue, and retry blockers for watch mode."""

    def __init__(self, path: str):
        self.path = Path(path)
        self.snapshots: dict[str, WatchInputSnapshot] = {}
        self.pending_work: dict[str, WatchInputSnapshot] = {}
        self.entries: dict[str, WatchStateEntry] = {}
        self.groups: dict[str, WatchGroupState] = {}
        self.owned_output_roots: list[str] = []
        self.password_generation = 0
        self.password_source_signature = ""
        self.load()

    def load(self) -> None:
        if not self.path.exists():
            return
        try:
            payload = json.loads(self.path.read_text(encoding="utf-8"))
        except Exception:
            return
        if not isinstance(payload, dict) or payload.get("version") not in LOADABLE_STATE_VERSIONS:
            return
        try:
            self.password_generation = max(0, int(payload.get("password_generation", 0)))
        except (TypeError, ValueError):
            self.password_generation = 0
        self.password_source_signature = str(payload.get("password_source_signature") or "")
        self.snapshots = self._load_records(payload.get("snapshots"), WatchInputSnapshot)
        self.pending_work = self._load_records(payload.get("pending_work"), WatchInputSnapshot)
        self.entries = self._load_records(payload.get("entries"), WatchStateEntry)
        self.groups = self._load_records(payload.get("groups"), WatchGroupState, normalize_keys=False)
        roots = payload.get("owned_output_roots")
        self.owned_output_roots = dedupe_normalized_paths(roots if isinstance(roots, list) else [])

    @staticmethod
    def _load_records(payload, record_type, *, normalize_keys: bool = True) -> dict:
        result = {}
        if not isinstance(payload, dict):
            return result
        for key, value in payload.items():
            if not isinstance(value, dict):
                continue
            try:
                record = record_type(**value)
            except TypeError:
                continue
            record_key = _path_key(record.path) if normalize_keys and hasattr(record, "path") else str(key)
            result[record_key] = record
        return result

    def save(self) -> None:
        self.path.parent.mkdir(parents=True, exist_ok=True)
        payload: dict[str, Any] = {
            "version": STATE_VERSION,
            "password_generation": self.password_generation,
            "password_source_signature": self.password_source_signature,
            "snapshots": {key: asdict(value) for key, value in self.snapshots.items()},
            "pending_work": {key: asdict(value) for key, value in self.pending_work.items()},
            "entries": {key: asdict(value) for key, value in self.entries.items()},
            "groups": {key: asdict(value) for key, value in self.groups.items()},
            "owned_output_roots": list(self.owned_output_roots),
        }
        temp = self.path.with_name(f".{self.path.name}.tmp")
        temp.write_text(json.dumps(payload, ensure_ascii=False, indent=2), encoding="utf-8")
        os.replace(temp, self.path)

    def snapshot_matches(
        self,
        path: str,
        size: int,
        mtime: float,
        file_id: str = "",
        change_usn: int = 0,
    ) -> bool:
        snapshot = self.snapshots.get(_path_key(path))
        return bool(
            snapshot
            and snapshot.size == size
            and snapshot.mtime == mtime
            and snapshot.file_id == file_id
            and snapshot.change_usn == int(change_usn)
        )

    def queue_active(self, candidate, *, force: bool = False) -> None:
        snapshot = WatchInputSnapshot(
            path=os.path.abspath(candidate.path),
            size=int(candidate.size),
            mtime=float(candidate.mtime),
            file_id=str(getattr(candidate, "file_id", "") or ""),
            change_usn=int(getattr(candidate, "change_usn", 0) or 0),
            force=bool(force),
        )
        self.pending_work[_path_key(candidate.path)] = snapshot
        self.save()

    def record_attempt(
        self,
        path: str,
        size: int,
        mtime: float,
        file_id: str = "",
        change_usn: int = 0,
    ) -> None:
        snapshot = WatchInputSnapshot(
            path=os.path.abspath(path),
            size=size,
            mtime=mtime,
            file_id=file_id,
            change_usn=int(change_usn),
            force=False,
        )
        key = _path_key(path)
        self.snapshots[key] = snapshot
        self.pending_work[key] = snapshot
        self.save()

    def pending_snapshots(self) -> list[WatchInputSnapshot]:
        return list(self.pending_work.values())

    def complete_work(self, paths: Iterable[str]) -> None:
        changed = False
        for path in paths:
            changed = self.pending_work.pop(_path_key(path), None) is not None or changed
        if changed:
            self.save()

    def complete_work_if_matches(self, candidate) -> None:
        key = _path_key(candidate.path)
        pending = self.pending_work.get(key)
        if pending is None:
            return
        if (
            pending.size != int(candidate.size)
            or pending.mtime != float(candidate.mtime)
            or pending.file_id != str(candidate.file_id or "")
            or pending.change_usn != int(candidate.change_usn)
        ):
            return
        self.pending_work.pop(key, None)
        self.save()

    def forget_path(self, path: str, *, recursive: bool = False) -> bool:
        normalized = os.path.abspath(path)
        keys = {
            key
            for collection in (self.snapshots, self.pending_work, self.entries)
            for key in collection
            if _path_matches(key, normalized, recursive=recursive)
        }
        changed = False
        for key in keys:
            changed = self.snapshots.pop(key, None) is not None or changed
            changed = self.pending_work.pop(key, None) is not None or changed
            changed = self.entries.pop(key, None) is not None or changed
        for group_id, group in list(self.groups.items()):
            members = [group.head_path, *group.member_paths]
            if any(_path_matches(member, normalized, recursive=recursive) for member in members if member):
                self.groups.pop(group_id, None)
                changed = True
        retained_roots = [
            root
            for root in self.owned_output_roots
            if not _paths_overlap_for_departure(root, normalized, recursive=recursive)
        ]
        if retained_roots != self.owned_output_roots:
            self.owned_output_roots = retained_roots
            changed = True
        if changed:
            self.save()
        return changed

    def latest_entry_for_path(self, path: str) -> WatchStateEntry | None:
        return self.entries.get(_path_key(path))

    def clear_entries(self, paths: Iterable[str]) -> None:
        changed = False
        for path in paths:
            changed = self.entries.pop(_path_key(path), None) is not None or changed
        if changed:
            self.save()

    def mark_password_source_changed(self, signature: str | None = None) -> int:
        if signature is not None:
            self.password_source_signature = signature
        self.password_generation += 1
        self.save()
        return self.password_generation

    def record_password_source_signature(self, signature: str) -> bool:
        signature = str(signature or "")
        previous = self.password_source_signature
        changed = bool(previous and previous != signature)
        if not previous and any(entry.status == "failed_password" for entry in self.entries.values()):
            changed = True
        self.password_source_signature = signature
        if changed:
            self.password_generation += 1
        if previous != signature or changed:
            self.save()
        return changed

    def failed_password_entries_under(self, directory: str, *, include_subtree: bool = True) -> list[WatchStateEntry]:
        root = Path(directory).resolve()
        result: list[WatchStateEntry] = []
        for entry in self.entries.values():
            if entry.status != "failed_password":
                continue
            try:
                parent = Path(entry.path).resolve().parent
                if include_subtree:
                    parent.relative_to(root)
                elif parent != root:
                    continue
            except ValueError:
                continue
            result.append(entry)
        return result

    def mark(
        self,
        path: str,
        size: int,
        mtime: float,
        *,
        file_id: str = "",
        change_usn: int = 0,
        status: str,
        error: str = "",
        failure_payload: dict[str, Any] | None = None,
    ) -> None:
        key = _path_key(path)
        previous = self.entries.get(key)
        payload = dict(failure_payload or {})
        blockers = {str(value) for value in payload.get("blockers") or []}
        if status not in {"failed_password", "suspended_missing_volume"} and not blockers:
            changed = self.entries.pop(key, None) is not None
            if changed:
                self.save()
            return
        self.entries[key] = WatchStateEntry(
            path=os.path.abspath(path),
            size=size,
            mtime=mtime,
            file_id=file_id,
            change_usn=int(change_usn),
            status=status,
            last_error=error,
            attempt_count=(previous.attempt_count + 1) if previous else 1,
            failure_kind=str(payload.get("kind") or ""),
            failure_stage=str(payload.get("stage") or ""),
            failure_payload=payload,
            last_attempt_at=time.time(),
            password_generation=self.password_generation,
        )
        self.save()

    def group_state(self, group_id: str) -> WatchGroupState | None:
        return self.groups.get(group_id)

    def record_group_waiting(self, snapshot: WatchGroupSnapshot) -> None:
        previous = self.groups.get(snapshot.group_id)
        blockers = set(previous.blockers if previous else [])
        blockers.add(BLOCKER_MISSING_VOLUME)
        self.groups[snapshot.group_id] = self._group_record(
            snapshot,
            previous=previous,
            status="suspended",
            blockers=sorted(blockers),
            last_attempted_fingerprint=snapshot.fingerprint,
            password_generation=previous.password_generation if previous else self.password_generation,
            failure_payload={
                "kind": BLOCKER_MISSING_VOLUME,
                "stage": "relation",
                "message": snapshot.missing_reason or "split archive is missing its first or an intermediate volume",
                "details": {"missing_indices": list(snapshot.missing_indices)},
            },
        )
        self.save()

    def record_group_attempt(self, snapshot: WatchGroupSnapshot) -> None:
        previous = self.groups.get(snapshot.group_id)
        self.groups[snapshot.group_id] = self._group_record(
            snapshot,
            previous=previous,
            status="running",
            blockers=list(previous.blockers if previous else []),
            last_attempted_fingerprint=snapshot.fingerprint,
            password_generation=previous.password_generation if previous else self.password_generation,
            failure_payload=dict(previous.failure_payload if previous else {}),
            increment_attempt=True,
        )
        self.save()

    def record_group_suspended(
        self,
        snapshot: WatchGroupSnapshot,
        *,
        blockers: list[str],
        failure_payload: dict[str, Any] | None = None,
    ) -> None:
        previous = self.groups.get(snapshot.group_id)
        self.groups[snapshot.group_id] = self._group_record(
            snapshot,
            previous=previous,
            status="suspended",
            blockers=sorted(set(blockers)),
            last_attempted_fingerprint=snapshot.fingerprint,
            password_generation=self.password_generation,
            failure_payload=dict(failure_payload or {}),
        )
        self.save()

    def record_group_terminal(
        self,
        snapshot: WatchGroupSnapshot,
        *,
        status: str,
        failure_payload: dict[str, Any] | None = None,
    ) -> None:
        previous = self.groups.get(snapshot.group_id)
        self.groups[snapshot.group_id] = self._group_record(
            snapshot,
            previous=previous,
            status=status,
            blockers=[],
            last_attempted_fingerprint=snapshot.fingerprint,
            password_generation=self.password_generation,
            failure_payload=dict(failure_payload or {}),
        )
        self.save()

    def record_group_done(self, snapshot: WatchGroupSnapshot) -> None:
        self.record_group_terminal(snapshot, status="done")

    def _group_record(
        self,
        snapshot: WatchGroupSnapshot,
        *,
        previous: WatchGroupState | None,
        status: str,
        blockers: list[str],
        last_attempted_fingerprint: str,
        password_generation: int,
        failure_payload: dict[str, Any],
        increment_attempt: bool = False,
    ) -> WatchGroupState:
        return WatchGroupState(
            group_id=snapshot.group_id,
            directory=snapshot.directory,
            logical_name=snapshot.logical_name,
            split_family=snapshot.split_family,
            head_path=snapshot.head_path,
            member_paths=list(snapshot.member_paths),
            status=status,
            blockers=list(blockers),
            relation_fingerprint=snapshot.fingerprint,
            last_attempted_fingerprint=last_attempted_fingerprint,
            password_generation=password_generation,
            missing_reason=snapshot.missing_reason,
            missing_indices=list(snapshot.missing_indices),
            failure_payload=dict(failure_payload),
            attempt_count=(previous.attempt_count if previous else 0) + (1 if increment_attempt else 0),
            updated_at=time.time(),
        )

    def generated_output_roots(self) -> list[str]:
        return list(self.owned_output_roots)

    def remember_output_roots(self, roots: Iterable[str]) -> None:
        updated = _compact_paths([*self.owned_output_roots, *roots])
        if updated != self.owned_output_roots:
            self.owned_output_roots = updated
            self.save()


def _path_key(path: str) -> str:
    return os.path.normcase(os.path.abspath(path))


def _compact_paths(paths: Iterable[str]) -> list[str]:
    compacted: list[str] = []
    for path in sorted(dedupe_normalized_paths(paths), key=len):
        key = _path_key(path)
        if any(_is_path_under(key, _path_key(root)) for root in compacted):
            continue
        compacted = [root for root in compacted if not _is_path_under(_path_key(root), key)]
        compacted.append(path)
    return compacted


def _path_matches(path: str, expected: str, *, recursive: bool) -> bool:
    normalized = _path_key(path)
    expected_key = _path_key(expected)
    return normalized == expected_key or (recursive and _is_path_under(normalized, expected_key))


def _is_path_under(path: str, root: str) -> bool:
    try:
        return os.path.commonpath([path, root]) == root
    except ValueError:
        return False


def _paths_overlap_for_departure(path: str, departed: str, *, recursive: bool) -> bool:
    path_key = _path_key(path)
    departed_key = _path_key(departed)
    return path_key == departed_key or (recursive and _is_path_under(path_key, departed_key))
