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
    sample_digest: str = ""
    status: str = "pending"
    output_dir: str = ""
    generated_output_dirs: list[str] = field(default_factory=list)
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
        entries = payload.get("entries") if isinstance(payload, dict) else {}
        try:
            self.password_generation = max(0, int(payload.get("password_generation", 0))) if isinstance(payload, dict) else 0
        except (TypeError, ValueError):
            self.password_generation = 0
        self.password_source_signature = str(payload.get("password_source_signature") or "") if isinstance(payload, dict) else ""
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
            "version": 4,
            "password_generation": self.password_generation,
            "password_source_signature": self.password_source_signature,
            "entries": {key: asdict(value) for key, value in self.entries.items()},
        }
        temp = self.path.with_name(f".{self.path.name}.tmp")
        temp.write_text(json.dumps(payload, ensure_ascii=False, indent=2), encoding="utf-8")
        os.replace(temp, self.path)

    def key_for(self, path: str, size: int, mtime: float, sample_digest: str = "") -> str:
        legacy_key = self._legacy_key_for(path, size, mtime)
        return f"{legacy_key}|{sample_digest}" if sample_digest else legacy_key

    def _legacy_key_for(self, path: str, size: int, mtime: float) -> str:
        return f"{os.path.abspath(path)}|{size}|{mtime:.6f}"

    def is_done(self, path: str, size: int, mtime: float, sample_digest: str = "") -> bool:
        entry = self.entries.get(self.key_for(path, size, mtime, sample_digest))
        return bool(entry and entry.status == "done")

    def should_skip(
        self,
        path: str,
        size: int,
        mtime: float,
        sample_digest: str = "",
        *,
        force: bool = False,
    ) -> bool:
        entry = self.entries.get(self.key_for(path, size, mtime, sample_digest))
        if entry is None:
            return False
        if entry.status in {"done", "failed_terminal", "ignored_no_tasks"}:
            return True
        if entry.status == "failed_password":
            if force:
                return False
            return entry.password_generation >= self.password_generation
        return False

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
        self.entries[key] = WatchStateEntry(
            path=os.path.abspath(path),
            size=size,
            mtime=mtime,
            sample_digest=sample_digest,
            status=status,
            output_dir=output_dir,
            generated_output_dirs=_dedupe_paths(generated_output_dirs or ([output_dir] if output_dir else [])),
            last_error=error,
            attempt_count=(previous.attempt_count + 1) if previous else 1,
            failure_kind=str(payload.get("kind") or ""),
            failure_stage=str(payload.get("stage") or ""),
            failure_payload=payload,
            last_attempt_at=time.time(),
            password_generation=self.password_generation,
        )
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
