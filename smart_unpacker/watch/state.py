from __future__ import annotations

from dataclasses import dataclass, asdict
import json
import os
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

    @property
    def fingerprint(self) -> str:
        return f"{self.path}|{self.size}|{self.mtime:.6f}"


class WatchStateStore:
    def __init__(self, path: str):
        self.path = Path(path)
        self.entries: dict[str, WatchStateEntry] = {}
        self.load()

    def load(self):
        if not self.path.exists():
            return
        try:
            payload = json.loads(self.path.read_text(encoding="utf-8"))
        except Exception:
            return
        entries = payload.get("entries") if isinstance(payload, dict) else {}
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
            "version": 1,
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

    def mark(self, path: str, size: int, mtime: float, *, status: str, output_dir: str = "", error: str = ""):
        key = self.key_for(path, size, mtime)
        previous = self.entries.get(key)
        self.entries[key] = WatchStateEntry(
            path=os.path.abspath(path),
            size=size,
            mtime=mtime,
            status=status,
            output_dir=output_dir,
            last_error=error,
            attempt_count=(previous.attempt_count + 1) if previous else 1,
        )
        self.save()
