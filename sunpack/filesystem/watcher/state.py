from __future__ import annotations

from dataclasses import dataclass, asdict, field
import json
import os
import time
from pathlib import Path
from typing import Any

from .group_models import (
    BLOCKER_MISSING_VOLUME,
    WatchGroupSnapshot,
    WatchGroupState,
)


@dataclass
class WatchStateEntry:
    path: str
    size: int
    mtime: float
    sample_digest: str = ""
    status: str = "pending"
    output_dir: str = ""
    generated_output_dirs: list[str] = field(default_factory=list)
    tracked_output_dirs: list[str] = field(default_factory=list)
    output_tracking_initialized: bool = False
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
        return f"{base}|{self.sample_digest}" if self.sample_digest else base


class WatchStateStore:
    def __init__(self, path: str):
        self.path = Path(path)
        self.entries: dict[str, WatchStateEntry] = {}
        self._latest_entries_by_path: dict[str, WatchStateEntry] = {}
        self.groups: dict[str, WatchGroupState] = {}
        self.invalidated_paths: set[str] = set()
        self.password_generation = 0
        self.password_source_signature = ""
        self.load()

    def load(self):
        if not self.path.exists():
            return
        try:
            payload = json.loads(self.path.read_text(encoding="utf-8"))
        except Exception:
            return
        if not isinstance(payload, dict) or payload.get("version") != 5:
            return
        entries = payload.get("entries") if isinstance(payload, dict) else {}
        groups = payload.get("groups") if isinstance(payload, dict) else {}
        invalidated_paths = payload.get("invalidated_paths") if isinstance(payload, dict) else []
        try:
            self.password_generation = max(0, int(payload.get("password_generation", 0))) if isinstance(payload, dict) else 0
        except (TypeError, ValueError):
            self.password_generation = 0
        self.password_source_signature = str(payload.get("password_source_signature") or "") if isinstance(payload, dict) else ""
        if isinstance(invalidated_paths, list):
            self.invalidated_paths = {
                os.path.normcase(os.path.abspath(str(path)))
                for path in invalidated_paths
                if str(path or "").strip()
            }
        if not isinstance(entries, dict):
            return
        for key, value in entries.items():
            if not isinstance(value, dict):
                continue
            try:
                entry = WatchStateEntry(**value)
                self.entries[key] = entry
                self._remember_latest_entry(entry)
            except TypeError:
                continue
        if isinstance(groups, dict):
            for key, value in groups.items():
                if not isinstance(value, dict):
                    continue
                try:
                    self.groups[key] = WatchGroupState(**value)
                except TypeError:
                    continue

    def save(self):
        self.path.parent.mkdir(parents=True, exist_ok=True)
        payload: dict[str, Any] = {
            "version": 5,
            "password_generation": self.password_generation,
            "password_source_signature": self.password_source_signature,
            "invalidated_paths": sorted(self.invalidated_paths),
            "entries": {key: asdict(value) for key, value in self.entries.items()},
            "groups": {key: asdict(value) for key, value in self.groups.items()},
        }
        temp = self.path.with_name(f".{self.path.name}.tmp")
        temp.write_text(json.dumps(payload, ensure_ascii=False, indent=2), encoding="utf-8")
        os.replace(temp, self.path)

    def key_for(self, path: str, size: int, mtime: float, sample_digest: str = "") -> str:
        base_key = f"{os.path.abspath(path)}|{size}|{mtime:.6f}"
        return f"{base_key}|{sample_digest}" if sample_digest else base_key

    def is_done(self, path: str, size: int, mtime: float, sample_digest: str = "") -> bool:
        entry = self.entries.get(self.key_for(path, size, mtime, sample_digest))
        return bool(entry and entry.status == "done" and self._can_skip_entry(entry))

    def should_skip(
        self,
        path: str,
        size: int,
        mtime: float,
        sample_digest: str = "",
        *,
        force: bool = False,
    ) -> bool:
        normalized_path = os.path.normcase(os.path.abspath(path))
        if normalized_path in self.invalidated_paths:
            return False
        entry = self.entries.get(self.key_for(path, size, mtime, sample_digest))
        if entry is None:
            return False
        if entry.status == "done":
            if self._done_outputs_exist(entry):
                return True
            self.invalidate_path(path)
            return False
        if entry.status in {"failed_terminal", "ignored_no_tasks"}:
            return True
        if entry.status == "failed_password":
            if force:
                return False
            return entry.password_generation >= self.password_generation
        return False

    def invalidate_path(self, path: str, *, recursive: bool = False) -> bool:
        normalized = os.path.normcase(os.path.abspath(path))
        matched_paths = {
            key
            for key in self._latest_entries_by_path
            if key == normalized or (recursive and _is_path_under(key, normalized))
        }
        for key, entry in self._latest_entries_by_path.items():
            if entry.status != "done":
                continue
            output_roots = (
                entry.tracked_output_dirs
                if entry.output_tracking_initialized
                else entry.generated_output_dirs or ([entry.output_dir] if entry.output_dir else [])
            )
            if any(
                _output_path_affected(normalized, output_root, recursive=recursive)
                for output_root in output_roots
            ):
                matched_paths.add(key)
        changed = False
        for key in matched_paths:
            if key not in self.invalidated_paths:
                self.invalidated_paths.add(key)
                changed = True
        for group in self.groups.values():
            member_paths = [group.head_path, *group.member_paths]
            if not any(
                os.path.normcase(os.path.abspath(candidate)) in matched_paths
                or _path_matches(candidate, normalized, recursive=recursive)
                for candidate in member_paths
                if candidate
            ):
                continue
            if group.status != "waiting" or group.last_attempted_fingerprint or group.blockers:
                group.status = "waiting"
                group.blockers = []
                group.last_attempted_fingerprint = ""
                group.updated_at = time.time()
                changed = True
        if changed:
            self.save()
        return changed

    def _can_skip_entry(self, entry: WatchStateEntry) -> bool:
        normalized = os.path.normcase(os.path.abspath(entry.path))
        return normalized not in self.invalidated_paths and self._done_outputs_exist(entry)

    @staticmethod
    def _done_outputs_exist(entry: WatchStateEntry) -> bool:
        outputs = (
            entry.tracked_output_dirs
            if entry.output_tracking_initialized
            else entry.generated_output_dirs or ([entry.output_dir] if entry.output_dir else [])
        )
        outputs = _dedupe_paths(outputs)
        return not outputs or all(os.path.exists(path) for path in outputs)

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

    def group_state(self, group_id: str) -> WatchGroupState | None:
        return self.groups.get(group_id)

    def latest_entry_for_path(self, path: str) -> WatchStateEntry | None:
        normalized = os.path.normcase(os.path.abspath(path))
        return self._latest_entries_by_path.get(normalized)

    def _remember_latest_entry(self, entry: WatchStateEntry) -> None:
        key = os.path.normcase(os.path.abspath(entry.path))
        previous = self._latest_entries_by_path.get(key)
        if previous is None or entry.last_attempt_at >= previous.last_attempt_at:
            self._latest_entries_by_path[key] = entry

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

    def mark(
        self,
        path: str,
        size: int,
        mtime: float,
        *,
        sample_digest: str = "",
        status: str,
        output_dir: str = "",
        generated_output_dirs: list[str] | None = None,
        error: str = "",
        failure_payload: dict[str, Any] | None = None,
    ):
        key = self.key_for(path, size, mtime, sample_digest)
        previous = self.entries.get(key)
        payload = dict(failure_payload or {})
        normalized_output_dirs = _dedupe_paths(generated_output_dirs or ([output_dir] if output_dir else []))
        entry = WatchStateEntry(
            path=os.path.abspath(path),
            size=size,
            mtime=mtime,
            sample_digest=sample_digest,
            status=status,
            output_dir=output_dir,
            generated_output_dirs=normalized_output_dirs,
            tracked_output_dirs=[path for path in normalized_output_dirs if os.path.exists(path)] if status == "done" else [],
            output_tracking_initialized=status == "done",
            last_error=error,
            attempt_count=(previous.attempt_count + 1) if previous else 1,
            failure_kind=str(payload.get("kind") or ""),
            failure_stage=str(payload.get("stage") or ""),
            failure_payload=payload,
            last_attempt_at=time.time(),
            password_generation=self.password_generation,
        )
        self.entries[key] = entry
        self._remember_latest_entry(entry)
        self.invalidated_paths.discard(os.path.normcase(os.path.abspath(path)))
        self.save()

    def generated_output_roots(self) -> list[str]:
        roots: list[str] = []
        for entry in self.entries.values():
            if entry.status != "done":
                continue
            roots.extend(entry.generated_output_dirs or ([entry.output_dir] if entry.output_dir else []))
        return _dedupe_paths(roots)


def _dedupe_paths(paths: list[str]) -> list[str]:
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


def _path_matches(path: str, expected: str, *, recursive: bool) -> bool:
    normalized = os.path.normcase(os.path.abspath(path))
    return normalized == expected or (recursive and _is_path_under(normalized, expected))


def _is_path_under(path: str, root: str) -> bool:
    try:
        return os.path.commonpath([path, root]) == root
    except ValueError:
        return False


def _output_path_affected(path: str, output_root: str, *, recursive: bool) -> bool:
    root = os.path.normcase(os.path.abspath(output_root))
    return (
        path == root
        or _is_path_under(path, root)
        or (recursive and _is_path_under(root, path))
    )
