from __future__ import annotations

import hashlib
import json
import logging
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from smart_unpacker.contracts.archive_input import ArchiveInputDescriptor
from smart_unpacker.contracts.tasks import ArchiveTask
from smart_unpacker.extraction.result import ExtractionResult
from smart_unpacker.repair.result import RepairResult


LOGGER = logging.getLogger(__name__)

TERMINAL_REPAIR_STATUSES = {"unrepairable", "unsupported", "needs_password", "skipped"}
TERMINAL_FAILURE_FLAGS = {
    "wrong_password",
    "missing_volume",
    "unsupported_method",
    "output_filesystem",
    "process_failure",
}


@dataclass(frozen=True)
class RepairLoopLimits:
    max_rounds: int = 3
    max_seconds: float = 120.0
    max_generated_files: int = 16
    max_generated_bytes: int = 2048 * 1024 * 1024

    @classmethod
    def from_config(cls, config: dict[str, Any]) -> "RepairLoopLimits":
        return cls(
            max_rounds=max(0, int(config.get("max_repair_rounds_per_task", 3) or 0)),
            max_seconds=max(0.0, float(config.get("max_repair_seconds_per_task", 120.0) or 0.0)),
            max_generated_files=max(0, int(config.get("max_repair_generated_files_per_task", 16) or 0)),
            max_generated_bytes=int(max(0.0, float(config.get("max_repair_generated_mb_per_task", 2048.0) or 0.0)) * 1024 * 1024),
        )


class RepairLoopState:
    def __init__(self, task: ArchiveTask, limits: RepairLoopLimits):
        self.task = task
        self.limits = limits
        self.started_at = float(task.fact_bag.get("repair.loop.started_at", 0.0) or 0.0)
        if self.started_at <= 0.0:
            self.started_at = time.monotonic()
            task.fact_bag.set("repair.loop.started_at", self.started_at)
        self._ensure_initial_digest()

    def can_attempt(self, *, trigger: str, failure: ExtractionResult | None = None) -> bool:
        if self.terminal_reason:
            return False
        if failure is not None:
            reason = terminal_failure_reason(failure)
            if reason:
                self.stop(reason, trigger=trigger)
                return False
        if self.round_count >= self.limits.max_rounds:
            self.stop("max_repair_rounds_reached", trigger=trigger)
            return False
        if self.limits.max_seconds > 0 and self._elapsed_seconds() > self.limits.max_seconds:
            self.stop("max_repair_seconds_reached", trigger=trigger)
            return False
        if self.limits.max_generated_files > 0 and self.generated_file_count >= self.limits.max_generated_files:
            self.stop("max_repair_generated_files_reached", trigger=trigger)
            return False
        if self.limits.max_generated_bytes > 0 and self.generated_bytes >= self.limits.max_generated_bytes:
            self.stop("max_repair_generated_bytes_reached", trigger=trigger)
            return False
        return True

    def record_result(self, result: RepairResult | None, *, trigger: str) -> bool:
        if result is None:
            return False

        previous_digest = self.current_digest
        round_payload = {
            "round": self.round_count + 1,
            "trigger": trigger,
            "input_digest": previous_digest,
            "status": result.status,
            "module": result.module_name,
            "actions": list(result.actions),
            "message": result.message,
        }
        self._add_generated_paths(result)

        if result.status in TERMINAL_REPAIR_STATUSES:
            self._append_round(round_payload)
            self.stop(f"repair_{result.status}", trigger=trigger, result=result)
            return False
        if not result.ok:
            self._append_round(round_payload)
            return False

        next_digest = input_digest(self.task)
        round_payload["output_digest"] = next_digest
        signature = _action_signature(result, previous_digest)
        if signature in self.seen_action_signatures:
            round_payload["exit_reason"] = "repeated_repair_action"
            self._append_round(round_payload)
            self.stop("repeated_repair_action", trigger=trigger, result=result)
            return False
        self._add_seen_action_signature(signature)

        if next_digest in self.seen_input_digests:
            round_payload["exit_reason"] = "repeated_repair_input"
            self._append_round(round_payload)
            self.stop("repeated_repair_input", trigger=trigger, result=result)
            return False
        self._add_seen_input_digest(next_digest)
        self.task.fact_bag.set("repair.loop.current_digest", next_digest)
        self._append_round(round_payload)
        return True

    @property
    def terminal_reason(self) -> str:
        return str(self.task.fact_bag.get("repair.loop.terminal_reason") or "")

    @property
    def round_count(self) -> int:
        rounds = self.task.fact_bag.get("repair.loop.rounds")
        return len(rounds) if isinstance(rounds, list) else 0

    @property
    def current_digest(self) -> str:
        digest = str(self.task.fact_bag.get("repair.loop.current_digest") or "")
        if digest:
            return digest
        digest = input_digest(self.task)
        self.task.fact_bag.set("repair.loop.current_digest", digest)
        return digest

    @property
    def seen_input_digests(self) -> list[str]:
        values = self.task.fact_bag.get("repair.loop.seen_input_digests")
        return [str(item) for item in values] if isinstance(values, list) else []

    @property
    def seen_action_signatures(self) -> list[str]:
        values = self.task.fact_bag.get("repair.loop.seen_action_signatures")
        return [str(item) for item in values] if isinstance(values, list) else []

    @property
    def generated_file_count(self) -> int:
        return int(self.task.fact_bag.get("repair.loop.generated_file_count", 0) or 0)

    @property
    def generated_bytes(self) -> int:
        return int(self.task.fact_bag.get("repair.loop.generated_bytes", 0) or 0)

    def stop(self, reason: str, *, trigger: str = "", result: RepairResult | None = None) -> None:
        if self.terminal_reason:
            return
        self.task.fact_bag.set("repair.loop.terminal_reason", reason)
        payload = {
            "reason": reason,
            "trigger": trigger,
            "rounds": self.round_count,
        }
        if result is not None:
            payload.update({"status": result.status, "module": result.module_name, "message": result.message})
        self.task.fact_bag.set("repair.loop.terminal", payload)
        LOGGER.warning("archive repair loop stopped: %s", payload)

    def _ensure_initial_digest(self) -> None:
        if not self.seen_input_digests:
            digest = input_digest(self.task)
            self.task.fact_bag.set("repair.loop.current_digest", digest)
            self.task.fact_bag.set("repair.loop.seen_input_digests", [digest])

    def _append_round(self, payload: dict[str, Any]) -> None:
        rounds = self.task.fact_bag.get("repair.loop.rounds")
        items = list(rounds) if isinstance(rounds, list) else []
        items.append(dict(payload))
        self.task.fact_bag.set("repair.loop.rounds", items)

    def _add_seen_input_digest(self, digest: str) -> None:
        values = self.seen_input_digests
        values.append(digest)
        self.task.fact_bag.set("repair.loop.seen_input_digests", _dedupe(values))

    def _add_seen_action_signature(self, signature: str) -> None:
        values = self.seen_action_signatures
        values.append(signature)
        self.task.fact_bag.set("repair.loop.seen_action_signatures", _dedupe(values))

    def _add_generated_paths(self, result: RepairResult) -> None:
        paths = set(result.workspace_paths or [])
        repaired_input = result.repaired_input if isinstance(result.repaired_input, dict) else {}
        repaired_path = repaired_input.get("path") or repaired_input.get("archive_path") or repaired_input.get("entry_path")
        if repaired_path:
            paths.add(str(repaired_path))
        file_count = self.generated_file_count
        byte_count = self.generated_bytes
        for path in sorted(paths):
            try:
                item = Path(path)
                if item.is_file():
                    file_count += 1
                    byte_count += item.stat().st_size
            except OSError:
                continue
        self.task.fact_bag.set("repair.loop.generated_file_count", file_count)
        self.task.fact_bag.set("repair.loop.generated_bytes", byte_count)

    def _elapsed_seconds(self) -> float:
        return time.monotonic() - self.started_at


def terminal_failure_reason(result: ExtractionResult) -> str:
    diagnostics = result.diagnostics if isinstance(result.diagnostics, dict) else {}
    worker_result = diagnostics.get("result") if isinstance(diagnostics.get("result"), dict) else {}
    native = worker_result.get("diagnostics") if isinstance(worker_result.get("diagnostics"), dict) else {}
    flags = set()
    for payload in (worker_result, diagnostics, native):
        if not isinstance(payload, dict):
            continue
        for flag in TERMINAL_FAILURE_FLAGS:
            if payload.get(flag):
                flags.add(flag)
        failure_kind = str(payload.get("failure_kind") or "")
        failure_stage = str(payload.get("failure_stage") or "")
        if failure_kind == "output_filesystem":
            flags.add("output_filesystem")
        if failure_stage.startswith("worker_") or failure_kind.startswith("process_"):
            flags.add("process_failure")
    text = str(result.error or "").lower()
    if "password" in text or "密码" in text:
        flags.add("wrong_password")
    if "volume" in text or "分卷" in text:
        flags.add("missing_volume")
    if "unsupported" in text:
        flags.add("unsupported_method")
    for flag in TERMINAL_FAILURE_FLAGS:
        if flag in flags:
            return flag
    return ""


def input_digest(task: ArchiveTask) -> str:
    raw = task.fact_bag.get("archive.input")
    descriptor = _descriptor_from_task(task, raw)
    descriptor_payload = descriptor.to_dict() if descriptor is not None else {}
    h = hashlib.sha256()
    h.update(_stable_json(descriptor_payload).encode("utf-8"))
    if descriptor is None:
        for path in list(task.all_parts or [task.main_path]):
            _hash_path(h, path)
    elif descriptor.open_mode == "file":
        _hash_path(h, descriptor.entry_path)
    elif descriptor.open_mode == "file_range":
        for part in descriptor.parts:
            if part.range is not None:
                _hash_range(h, part.range.path, part.range.start, part.range.end)
            else:
                _hash_path(h, part.path)
    elif descriptor.open_mode == "concat_ranges":
        for item in descriptor.ranges:
            _hash_range(h, item.path, item.start, item.end)
    else:
        for part in descriptor.parts:
            _hash_path(h, part.path)
    return h.hexdigest()


def _descriptor_from_task(task: ArchiveTask, raw: Any) -> ArchiveInputDescriptor | None:
    if not isinstance(raw, dict):
        return None
    archive_path = str(task.main_path or "")
    part_paths = list(task.all_parts or [])
    try:
        if raw.get("kind") == "archive_input" or raw.get("open_mode"):
            return ArchiveInputDescriptor.from_dict(raw, archive_path=archive_path, part_paths=part_paths)
        return ArchiveInputDescriptor.from_legacy(raw, archive_path=archive_path, part_paths=part_paths)
    except (TypeError, ValueError):
        return None


def _hash_path(h: Any, path: str) -> None:
    text = str(path or "")
    h.update(b"\0path\0")
    h.update(text.encode("utf-8", errors="surrogatepass"))
    try:
        item = Path(text)
        h.update(str(item.stat().st_size).encode("ascii"))
        with item.open("rb") as handle:
            for chunk in iter(lambda: handle.read(1024 * 1024), b""):
                h.update(chunk)
    except OSError:
        h.update(b"\0missing\0")


def _hash_range(h: Any, path: str, start: int, end: int | None) -> None:
    text = str(path or "")
    start = max(0, int(start or 0))
    h.update(b"\0range\0")
    h.update(text.encode("utf-8", errors="surrogatepass"))
    h.update(str(start).encode("ascii"))
    h.update(str(end).encode("ascii") if end is not None else b"")
    try:
        item = Path(text)
        size = item.stat().st_size
        stop = size if end is None else min(size, max(start, int(end)))
        with item.open("rb") as handle:
            handle.seek(start)
            remaining = max(0, stop - start)
            while remaining:
                chunk = handle.read(min(1024 * 1024, remaining))
                if not chunk:
                    break
                h.update(chunk)
                remaining -= len(chunk)
    except OSError:
        h.update(b"\0missing\0")


def _action_signature(result: RepairResult, input_digest_value: str) -> str:
    payload = {
        "input": input_digest_value,
        "module": result.module_name,
        "actions": list(result.actions),
        "status": result.status,
    }
    return hashlib.sha256(_stable_json(payload).encode("utf-8")).hexdigest()


def _stable_json(value: Any) -> str:
    return json.dumps(value, ensure_ascii=True, sort_keys=True, separators=(",", ":"), default=str)


def _dedupe(values: list[str]) -> list[str]:
    output: list[str] = []
    seen: set[str] = set()
    for value in values:
        if value in seen:
            continue
        seen.add(value)
        output.append(value)
    return output
