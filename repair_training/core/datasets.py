from __future__ import annotations

import hashlib
import json
from pathlib import Path
from typing import Any, Callable


SPLITS = ("train", "valid", "test")


def read_jsonl(path: str | Path) -> list[dict[str, Any]]:
    output: list[dict[str, Any]] = []
    path = Path(path)
    if not path.is_file():
        return output
    with path.open("r", encoding="utf-8") as handle:
        for line in handle:
            if not line.strip():
                continue
            row = json.loads(line)
            if isinstance(row, dict):
                output.append(row)
    return output


def write_json(path: str | Path, payload: Any) -> None:
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(payload, ensure_ascii=False, indent=2, sort_keys=True, default=str), encoding="utf-8")


def write_jsonl(path: str | Path, rows: list[dict[str, Any]]) -> None:
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", encoding="utf-8") as handle:
        for row in rows:
            handle.write(json.dumps(row, ensure_ascii=False, sort_keys=True, default=str) + "\n")


def split_rows(
    rows: list[dict[str, Any]],
    *,
    key_fn: Callable[[dict[str, Any]], str] | None = None,
    valid_ratio: float = 0.1,
    test_ratio: float = 0.1,
) -> dict[str, list[dict[str, Any]]]:
    key_fn = key_fn or row_group_key
    valid_cut = max(0.0, min(1.0, 1.0 - float(valid_ratio or 0.0) - float(test_ratio or 0.0)))
    test_cut = max(valid_cut, min(1.0, 1.0 - float(test_ratio or 0.0)))
    output = {split: [] for split in SPLITS}
    for row in rows:
        bucket = _bucket(key_fn(row))
        if bucket < valid_cut:
            output["train"].append(row)
        elif bucket < test_cut:
            output["valid"].append(row)
        else:
            output["test"].append(row)
    if rows and not output["train"]:
        output["train"] = list(rows)
    return output


def row_group_key(row: dict[str, Any]) -> str:
    source = row.get("source_identity") if isinstance(row.get("source_identity"), dict) else {}
    for value in (
        source.get("source_archive_id"),
        source.get("clean_sha256"),
        row.get("sample_id"),
        row.get("episode_id"),
        row.get("state_digest"),
    ):
        text = str(value or "")
        if text:
            return text
    return hashlib.sha256(json.dumps(row, sort_keys=True, default=str).encode("utf-8")).hexdigest()


def action_query_id(row: dict[str, Any]) -> str:
    return "|".join([
        str(row.get("episode_id") or ""),
        str(row.get("state_digest") or ""),
        str(row.get("round_index") or 0),
    ])


def group_sizes(rows: list[dict[str, Any]], *, key_fn: Callable[[dict[str, Any]], str] | None = None) -> list[int]:
    key_fn = key_fn or action_query_id
    sizes: list[int] = []
    current = None
    count = 0
    for row in rows:
        key = key_fn(row)
        if current is None:
            current = key
        if key != current:
            sizes.append(count)
            current = key
            count = 0
        count += 1
    if count:
        sizes.append(count)
    return sizes


def sort_for_groups(rows: list[dict[str, Any]], *, key_fn: Callable[[dict[str, Any]], str] | None = None) -> list[dict[str, Any]]:
    key_fn = key_fn or action_query_id
    return sorted(rows, key=lambda row: (key_fn(row), str(row.get("action_type") or ""), str(row.get("candidate_id") or "")))


def sha256_file(path: str | Path) -> str:
    h = hashlib.sha256()
    with Path(path).open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            h.update(chunk)
    return h.hexdigest()


def _bucket(key: str) -> float:
    digest = hashlib.sha256(str(key or "").encode("utf-8")).hexdigest()
    return int(digest[:12], 16) / float(0xFFFFFFFFFFFF)
