from __future__ import annotations

from pathlib import Path
from typing import Any

from sunpack.repair.model.diagnosis.graph_builder import build_sample_with_plugin
from sunpack.repair.model.diagnosis.graph_registry import (
    UnsupportedDiagnosisGraphFormat,
    get_diagnosis_graph_plugin,
)
from sunpack.repair.model.diagnosis.graph_schema import DiagnosisGraphSample
from sunpack.repair.model.formats import normalize_format_name


def build_diagnosis_graph_sample(row: dict[str, Any]) -> DiagnosisGraphSample:
    return build_diagnosis_graph_sample_for_format(detect_graph_format(row), row)


def build_diagnosis_graph_sample_for_format(format_name: str, row: dict[str, Any]) -> DiagnosisGraphSample:
    normalized = normalize_format_name(format_name)
    plugin = get_diagnosis_graph_plugin(normalized)
    return build_sample_with_plugin(row, plugin=plugin)


def detect_graph_format(row: dict[str, Any]) -> str:
    payload = row.get("knowledge_payload") if isinstance(row.get("knowledge_payload"), dict) else row
    for value in (
        row.get("format"),
        _nested(payload, "analysis", "summary", "format"),
        _nested(payload, "source", "input", "format_hint"),
    ):
        normalized = _normalize_detected(value)
        if normalized:
            return normalized
    format_payload = payload.get("format") if isinstance(payload.get("format"), dict) else {}
    keys = [str(key) for key in format_payload if key]
    if len(keys) == 1:
        normalized = _normalize_detected(keys[0])
        if normalized:
            return normalized
    for path in (
        _nested(payload, "source", "input", "entry_path"),
        _nested(payload, "source", "input", "path"),
        _nested(payload, "source", "input", "parts", 0, "path"),
    ):
        normalized = _format_from_path(path)
        if normalized:
            return normalized
    raise UnsupportedDiagnosisGraphFormat("cannot detect diagnosis graph format from row")


def _normalize_detected(value: Any) -> str:
    text = str(value or "").strip().lower().lstrip(".")
    if not text:
        return ""
    if text in {"zip", "7z", "7zip", "seven_zip", "seven-zip", "rar", "tar", "gzip", "gz", "bzip2", "bz2", "xz", "zstd", "zst"}:
        return normalize_format_name(text)
    return ""


def _format_from_path(value: Any) -> str:
    suffix = Path(str(value or "")).suffix.lower().lstrip(".")
    return _normalize_detected(suffix)


def _nested(value: Any, *path: Any) -> Any:
    cur = value
    for part in path:
        if isinstance(part, int):
            if isinstance(cur, list) and 0 <= part < len(cur):
                cur = cur[part]
                continue
            return None
        if isinstance(cur, dict) and part in cur:
            cur = cur[part]
            continue
        return None
    return cur
