from __future__ import annotations

from dataclasses import dataclass, asdict, field
import json
import os
import time
from pathlib import Path
from typing import Any


@dataclass
class WatchStateEntry:
    path: str
    size: int
    mtime: float
    status: str = "pending"
    output_dir: str = ""
    last_error: str = ""
    attempt_count: int = 0
    failure_kind: str = ""
    failure_stage: str = ""
    failure_payload: dict[str, Any] = field(default_factory=dict)
    last_attempt_at: float = 0.0
    password_generation: int = 0

    @property
    def fingerprint(self) -> str:
        return f"{self.path}|{self.size}|{self.mtime:.6f}"


class WatchStateStore:
    def __init__(self, path: str):
        self.path = Path(path)
        self.entries: dict[str, WatchStateEntry] = {}
        self.password_generation = 0
        self.load()

    def load(self):
        if not self.path.exists():
            return
        try:
            payload = json.loads(self.path.read_text(encoding="utf-8"))
        except Exception:
            return
        entries = payload.get("entries") if isinstance(payload, dict) else {}
        try:
            self.password_generation = max(0, int(payload.get("password_generation", 0))) if isinstance(payload, dict) else 0
        except (TypeError, ValueError):
            self.password_generation = 0
        if not isinstance(entries, dict):
            return
        for key, value in entries.items():
            if not isinstance(value, dict):
                continue
            try:
                self.entries[key] = WatchStateEntry(**value)
            except TypeError:
                continue

    def save(self):
        self.path.parent.mkdir(parents=True, exist_ok=True)
        payload: dict[str, Any] = {
            "version": 2,
            "password_generation": self.password_generation,
            "entries": {key: asdict(value) for key, value in self.entries.items()},
        }
        temp = self.path.with_name(f".{self.path.name}.tmp")
        temp.write_text(json.dumps(payload, ensure_ascii=False, indent=2), encoding="utf-8")
        os.replace(temp, self.path)

    def key_for(self, path: str, size: int, mtime: float) -> str:
        return f"{os.path.abspath(path)}|{size}|{mtime:.6f}"

    def is_done(self, path: str, size: int, mtime: float) -> bool:
        entry = self.entries.get(self.key_for(path, size, mtime))
        return bool(entry and entry.status == "done")

    def should_skip(self, path: str, size: int, mtime: float, *, force: bool = False) -> bool:
        entry = self.entries.get(self.key_for(path, size, mtime))
        if entry is None:
            return False
        if entry.status in {"done", "failed_terminal"}:
            return True
        if entry.status == "failed_password":
            if force:
                return False
            return entry.password_generation >= self.password_generation
        return False

    def mark_password_source_changed(self) -> int:
        self.password_generation += 1
        self.save()
        return self.password_generation

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
        status: str,
        output_dir: str = "",
        error: str = "",
        failure_payload: dict[str, Any] | None = None,
    ):
        key = self.key_for(path, size, mtime)
        previous = self.entries.get(key)
        payload = dict(failure_payload or {})
        self.entries[key] = WatchStateEntry(
            path=os.path.abspath(path),
            size=size,
            mtime=mtime,
            status=status,
            output_dir=output_dir,
            last_error=error,
            attempt_count=(previous.attempt_count + 1) if previous else 1,
            failure_kind=str(payload.get("kind") or ""),
            failure_stage=str(payload.get("stage") or ""),
            failure_payload=payload,
            last_attempt_at=time.time(),
            password_generation=self.password_generation,
        )
        self.save()
