from __future__ import annotations

import hashlib
import json
import logging
import shutil
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from packrelic.contracts.archive_state import ArchiveState
from packrelic.contracts.archive_input import ArchiveInputDescriptor
from packrelic.contracts.tasks import ArchiveTask
from packrelic.extraction.result import ExtractionResult
from packrelic.repair.result import RepairResult
from packrelic.support.archive_state_view import archive_state_to_bytes


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
        round_number = self.round_count + 1
        round_payload = {
            "round": round_number,
            "trigger": trigger,
            "input_digest": previous_digest,
            "status": result.status,
            "module": result.module_name,
            "actions": list(result.actions),
            "format": result.format,
            "confidence": float(result.confidence or 0.0),
            "partial": bool(result.partial),
            "message": result.message,
            "workspace_paths": list(result.workspace_paths),
        }

        if result.status in TERMINAL_REPAIR_STATUSES:
            self._add_generated_paths(result)
            self._append_round(round_payload)
            self.stop(f"repair_{result.status}", trigger=trigger, result=result)
            return False
        if not result.ok:
            self._add_generated_paths(result)
            self._append_round(round_payload)
            return False

        snapshot_path = self._snapshot_repaired_file(result, round_number)
        if snapshot_path:
            round_payload["output_path"] = snapshot_path
            round_payload["workspace_paths"] = _dedupe([*round_payload["workspace_paths"], snapshot_path])
        self._add_generated_paths(result, extra_paths=[snapshot_path] if snapshot_path else [])

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
        LOGGER.info("archive repair round completed: %s", round_payload)
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

    def _snapshot_repaired_file(self, result: RepairResult, round_number: int) -> str:
        repaired_input = result.repaired_input if isinstance(result.repaired_input, dict) else {}
        kind = str(repaired_input.get("kind") or "file").lower()
        source_path = str(repaired_input.get("path") or repaired_input.get("archive_path") or "")
        if kind != "file" or not source_path:
            return ""
        source = Path(source_path)
        if not source.is_file():
            return ""
        target = self._round_snapshot_path(source, result, round_number)
        if source.resolve() != target.resolve():
            target.parent.mkdir(parents=True, exist_ok=True)
            shutil.copyfile(source, target)
        format_hint = str(repaired_input.get("format_hint") or repaired_input.get("format") or result.format or "")
        self.task.set_archive_state(ArchiveState.from_archive_input(ArchiveInputDescriptor.from_dict({
            "kind": "archive_input",
            "entry_path": str(target),
            "open_mode": "file",
            "format_hint": format_hint,
            "logical_name": str(self.task.logical_name or ""),
            "parts": [{"path": str(target), "role": "main"}],
            "analysis": {
                "source": "repair_loop",
                "module": result.module_name,
                "actions": list(result.actions),
                "round": int(round_number),
            },
        })))
        return str(target)

    def _round_snapshot_path(self, source: Path, result: RepairResult, round_number: int) -> Path:
        module = _safe_name(result.module_name or "repair")
        suffix = source.suffix
        if not suffix:
            suffix = _suffix_for_format(result.format)
        filename = f"round_{round_number:02d}_{module}{suffix}"
        target = source.parent / filename
        if not target.exists() or target.resolve() == source.resolve():
            return target
        index = 2
        while True:
            candidate = source.parent / f"round_{round_number:02d}_{module}_{index}{suffix}"
            if not candidate.exists():
                return candidate
            index += 1

    def _add_generated_paths(self, result: RepairResult, *, extra_paths: list[str] | None = None) -> None:
        paths = set(result.workspace_paths or [])
        paths.update(str(path) for path in (extra_paths or []) if path)
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
    damage_signals = False
    password_signals = False
    for payload in (worker_result, diagnostics, native):
        if not isinstance(payload, dict):
            continue
        for flag in TERMINAL_FAILURE_FLAGS:
            if flag == "wrong_password" and payload.get(flag):
                password_signals = True
                continue
            if payload.get(flag):
                flags.add(flag)
        failure_kind = str(payload.get("failure_kind") or "")
        failure_stage = str(payload.get("failure_stage") or "")
        if payload.get("damaged") or payload.get("checksum_error") or failure_kind in {
            "corrupted_data",
            "data_error",
            "checksum_error",
            "crc_error",
        }:
            damage_signals = True
        if failure_kind == "output_filesystem":
            flags.add("output_filesystem")
        if failure_stage.startswith("worker_") or failure_kind.startswith("process_"):
            flags.add("process_failure")
    text = str(result.error or "").lower()
    is_split = len(result.all_parts or []) > 1 or _looks_like_split_name(result.archive)
    if password_signals and not (is_split and damage_signals):
        flags.add("wrong_password")
    if ("password" in text or "密码" in text) and not (is_split and damage_signals):
        flags.add("wrong_password")
    if "volume" in text or "分卷" in text:
        flags.add("missing_volume")
    if "unsupported" in text:
        flags.add("unsupported_method")
    for flag in TERMINAL_FAILURE_FLAGS:
        if flag in flags:
            return flag
    return ""


def _looks_like_split_name(path: str) -> bool:
    name = Path(str(path or "")).name.lower()
    return name.endswith(".001") or ".part1." in name or ".part01." in name


def input_digest(task: ArchiveTask) -> str:
    try:
        state = task.archive_state()
    except (TypeError, ValueError):
        state = None
    if state is not None:
        return _state_digest(state)
    raw = task.fact_bag.get("archive.input")
    descriptor = _descriptor_from_task(task, raw)
    h = hashlib.sha256()
    h.update(_stable_json(_descriptor_shape(descriptor)).encode("utf-8"))
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


def _state_digest(state: ArchiveState) -> str:
    h = hashlib.sha256()
    h.update(b"\0archive_state\0")
    h.update(_stable_json(_state_shape(state)).encode("utf-8"))
    try:
        h.update(archive_state_to_bytes(state))
    except (OSError, ValueError):
        h.update(b"\0unreadable_state\0")
        h.update(_stable_json(state.to_dict()).encode("utf-8"))
    return h.hexdigest()


def _state_shape(state: ArchiveState) -> dict[str, Any]:
    descriptor = state.to_archive_input_descriptor()
    return {
        "source": _descriptor_shape(descriptor),
        "format_hint": state.format_hint or state.source.format_hint,
        "logical_name": state.logical_name,
        "patches": [patch.to_dict() for patch in state.patches],
        "patch_digest": state.effective_patch_digest(),
    }


def _descriptor_shape(descriptor: ArchiveInputDescriptor | None) -> dict[str, Any]:
    if descriptor is None:
        return {"open_mode": "task_paths"}
    return {
        "open_mode": descriptor.open_mode,
        "format_hint": descriptor.format_hint,
        "parts": [
            {
                "role": part.role,
                "volume_number": part.volume_number,
                "start": part.range.start if part.range is not None else None,
                "end": part.range.end if part.range is not None else None,
            }
            for part in descriptor.parts
        ],
        "ranges": [
            {"start": item.start, "end": item.end}
            for item in descriptor.ranges
        ],
        "segment": descriptor.segment.to_dict() if descriptor.segment is not None else None,
    }


def _descriptor_from_task(task: ArchiveTask, raw: Any) -> ArchiveInputDescriptor | None:
    if not isinstance(raw, dict):
        return None
    archive_path = str(task.main_path or "")
    part_paths = list(task.all_parts or [])
    try:
        if raw.get("kind") == "archive_input" or raw.get("open_mode"):
            return ArchiveInputDescriptor.from_dict(raw, archive_path=archive_path, part_paths=part_paths)
        return ArchiveInputDescriptor.from_source_input(raw, archive_path=archive_path, part_paths=part_paths)
    except (TypeError, ValueError):
        return None


def _hash_path(h: Any, path: str) -> None:
    text = str(path or "")
    h.update(b"\0path\0")
    try:
        item = Path(text)
        h.update(str(item.stat().st_size).encode("ascii"))
        with item.open("rb") as handle:
            for chunk in iter(lambda: handle.read(1024 * 1024), b""):
                h.update(chunk)
    except OSError:
        h.update(b"\0missing\0")
        h.update(text.encode("utf-8", errors="surrogatepass"))


def _hash_range(h: Any, path: str, start: int, end: int | None) -> None:
    text = str(path or "")
    start = max(0, int(start or 0))
    h.update(b"\0range\0")
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
        h.update(text.encode("utf-8", errors="surrogatepass"))


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


def _safe_name(value: str) -> str:
    text = "".join(ch if ch.isalnum() or ch in "-_." else "_" for ch in str(value or "repair"))
    return text.strip("._") or "repair"


def _suffix_for_format(value: str) -> str:
    fmt = str(value or "").lower().lstrip(".")
    return {
        "7z": ".7z",
        "bzip2": ".bz2",
        "gzip": ".gz",
        "rar": ".rar",
        "tar": ".tar",
        "xz": ".xz",
        "zip": ".zip",
        "zstd": ".zst",
    }.get(fmt, ".bin")


def _dedupe(values: list[str]) -> list[str]:
    output: list[str] = []
    seen: set[str] = set()
    for value in values:
        if value in seen:
            continue
        seen.add(value)
        output.append(value)
    return output
