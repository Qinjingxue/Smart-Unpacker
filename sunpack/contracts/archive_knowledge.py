from __future__ import annotations

from copy import deepcopy
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any


@dataclass
class ArchiveKnowledge:
    data: dict[str, Any] = field(default_factory=dict)

    @classmethod
    def from_any(cls, raw: Any | None) -> "ArchiveKnowledge":
        if isinstance(raw, ArchiveKnowledge):
            return cls(raw.to_dict())
        if isinstance(raw, dict):
            return cls(_jsonable(raw))
        return cls()

    def to_dict(self) -> dict[str, Any]:
        return _jsonable(self.data)

    def revision(self) -> int:
        meta = self.data.get("_meta")
        if not isinstance(meta, dict):
            return 0
        try:
            return int(meta.get("revision", 0) or 0)
        except (TypeError, ValueError):
            return 0

    def source_identity(self) -> dict[str, Any]:
        state = self.get("archive.state", {})
        source = self.get("source.input", {})
        if isinstance(state, dict):
            patch_digest = state.get("patch_digest") or state.get("effective_patch_digest")
            if patch_digest:
                return {
                    "kind": "archive_state",
                    "patch_digest": str(patch_digest),
                    "format_hint": state.get("format_hint") or (source or {}).get("format_hint") if isinstance(source, dict) else state.get("format_hint"),
                }
        if isinstance(source, dict):
            return {
                "kind": str(source.get("kind") or source.get("open_mode") or "file"),
                "path": str(source.get("path") or source.get("entry_path") or ""),
                "format_hint": source.get("format_hint") or source.get("format"),
            }
        return {}

    def get(self, path: str, default: Any = None) -> Any:
        current: Any = self.data
        for part in _parts(path):
            if not isinstance(current, dict) or part not in current:
                return default
            current = current[part]
        return current

    def set(
        self,
        path: str,
        value: Any,
        *,
        source_layer: str = "",
        source_module: str = "",
        round: int | None = None,
        source_digest: str = "",
        patch_digest: str = "",
        confidence: float | None = None,
        timestamp: str | None = None,
    ) -> "ArchiveKnowledge":
        if not path:
            return self
        current = self.data
        parts = _parts(path)
        for part in parts[:-1]:
            current = current.setdefault(part, {})
            if not isinstance(current, dict):
                return self
        current[parts[-1]] = _jsonable(value)
        provenance = _provenance(
            source_layer=source_layer,
            source_module=source_module,
            round=round,
            source_digest=source_digest,
            patch_digest=patch_digest,
            confidence=confidence,
            timestamp=timestamp,
        )
        if provenance:
            self.add_evidence(path, value, provenance=provenance)
        return self

    def merge(self, *payloads: Any, source_layer: str = "", source_module: str = "") -> "ArchiveKnowledge":
        for payload in payloads:
            raw = payload.to_dict() if isinstance(payload, ArchiveKnowledge) else payload
            if isinstance(raw, dict):
                _deep_merge(self.data, _jsonable(raw))
        if source_layer or source_module:
            self.add_evidence("knowledge.merge", True, provenance=_provenance(source_layer=source_layer, source_module=source_module))
        return self

    def add_flags(self, namespace: str, flags: list[str] | tuple[str, ...] | set[str], *, source_layer: str = "", source_module: str = "") -> "ArchiveKnowledge":
        key = f"{namespace}.flags" if namespace else "flags"
        current = [str(item) for item in self.get(key, []) or [] if str(item)]
        merged = _dedupe([*current, *[str(item) for item in flags if str(item)]])
        return self.set(key, merged, source_layer=source_layer, source_module=source_module)

    def flags(self, namespace: str = "") -> list[str]:
        if namespace:
            return [str(item) for item in self.get(f"{namespace}.flags", []) or [] if str(item)]
        output: list[str] = []
        self._collect_flags(self.data, output)
        return _dedupe(output)

    def features(self, prefix: str = "") -> dict[str, Any]:
        value = self.get(prefix) if prefix else self.data
        return _jsonable(value) if isinstance(value, dict) else {}

    def add_evidence(self, path: str, value: Any, *, provenance: dict[str, Any] | None = None) -> "ArchiveKnowledge":
        evidence = list(self.data.setdefault("_evidence", []))
        item = {"path": str(path), "value": _compact_evidence_value(value)}
        if provenance:
            item["provenance"] = _jsonable(provenance)
        evidence.append(item)
        self.data["_evidence"] = evidence[-500:]
        return self

    def history(self, namespace: str = "") -> list[dict[str, Any]]:
        raw = self.get(f"{namespace}.history" if namespace else "history", [])
        return [dict(item) for item in raw if isinstance(item, dict)] if isinstance(raw, list) else []

    def mirror_fact_bag(self, facts: dict[str, Any], *, source_layer: str = "fact_bag") -> "ArchiveKnowledge":
        for key, value in facts.items():
            if key in {"archive.knowledge", "archive.state"}:
                continue
            self.set(key, value, source_layer=source_layer)
        return self

    def _collect_flags(self, value: Any, output: list[str]) -> None:
        if isinstance(value, dict):
            for key, item in value.items():
                if key == "flags" and isinstance(item, list):
                    output.extend(str(flag) for flag in item if str(flag))
                else:
                    self._collect_flags(item, output)


def merge_knowledge(*payloads: Any) -> dict[str, Any]:
    knowledge = ArchiveKnowledge()
    for payload in payloads:
        if payload:
            knowledge.merge(payload)
    return knowledge.to_dict()


def project_knowledge_sources(knowledge: Any) -> list[dict[str, Any]]:
    raw = ArchiveKnowledge.from_any(knowledge).to_dict()
    if not raw:
        return []
    sources = [raw]
    for key in ("filesystem", "relations", "detection", "analysis", "extraction", "verification", "repair", "policy", "format"):
        value = raw.get(key)
        if isinstance(value, dict):
            sources.append(value)
    zip_payload = raw.get("format", {}).get("zip") if isinstance(raw.get("format"), dict) else None
    if isinstance(zip_payload, dict):
        sources.append(zip_payload)
    return sources


def _parts(path: str) -> list[str]:
    return [part for part in str(path or "").split(".") if part]


def _provenance(
    *,
    source_layer: str = "",
    source_module: str = "",
    round: int | None = None,
    source_digest: str = "",
    patch_digest: str = "",
    confidence: float | None = None,
    timestamp: str | None = None,
) -> dict[str, Any]:
    payload: dict[str, Any] = {}
    if source_layer:
        payload["source_layer"] = source_layer
    if source_module:
        payload["source_module"] = source_module
    if round is not None:
        payload["round"] = int(round)
    if source_digest:
        payload["source_digest"] = source_digest
    if patch_digest:
        payload["patch_digest"] = patch_digest
    if confidence is not None:
        payload["confidence"] = float(confidence)
    if payload:
        payload["timestamp"] = timestamp or datetime.now(timezone.utc).isoformat()
    return payload


def _deep_merge(target: dict[str, Any], source: dict[str, Any]) -> dict[str, Any]:
    for key, value in source.items():
        if isinstance(value, dict) and isinstance(target.get(key), dict):
            _deep_merge(target[key], value)
        elif isinstance(value, list) and isinstance(target.get(key), list):
            target[key] = _merge_lists(target[key], value)
        else:
            target[key] = deepcopy(value)
    return target


def _merge_lists(left: list[Any], right: list[Any]) -> list[Any]:
    output: list[Any] = []
    seen: set[str] = set()
    for item in [*left, *right]:
        key = repr(_jsonable(item))
        if key in seen:
            continue
        seen.add(key)
        output.append(_jsonable(item))
    return output


def _dedupe(values: list[str]) -> list[str]:
    output: list[str] = []
    seen: set[str] = set()
    for value in values:
        if value in seen:
            continue
        seen.add(value)
        output.append(value)
    return output


def _jsonable(value: Any) -> Any:
    if isinstance(value, ArchiveKnowledge):
        return value.to_dict()
    if isinstance(value, dict):
        return {str(key): _jsonable(item) for key, item in value.items()}
    if isinstance(value, (list, tuple, set)):
        return [_jsonable(item) for item in value]
    if isinstance(value, (str, int, float, bool)) or value is None:
        return value
    if hasattr(value, "to_dict"):
        try:
            return _jsonable(value.to_dict())
        except Exception:
            return str(value)
    return str(value)


def _compact_evidence_value(value: Any) -> Any:
    if isinstance(value, ArchiveKnowledge):
        return {"kind": "archive_knowledge", "revision": value.revision(), "source_identity": value.source_identity()}
    if isinstance(value, dict):
        output: dict[str, Any] = {}
        for key, item in value.items():
            text_key = str(key)
            if text_key in {"archive_state", "candidate_features", "candidate_log", "workspace_paths"}:
                output[text_key] = _compact_large_value(text_key, item)
            elif text_key in {"stdout", "stderr"} and isinstance(item, str):
                output[text_key] = item[:4000]
            else:
                output[text_key] = _compact_evidence_value(item)
        return output
    if isinstance(value, (list, tuple, set)):
        values = list(value)
        compacted = [_compact_evidence_value(item) for item in values[:50]]
        if len(values) > 50:
            compacted.append({"truncated_count": len(values) - 50})
        return compacted
    return _jsonable(value)


def _compact_large_value(key: str, value: Any) -> Any:
    if isinstance(value, dict):
        return {
            "kind": key,
            "keys": sorted(str(item) for item in value.keys())[:50],
            "sha256": _stable_repr_digest(value),
        }
    if isinstance(value, list):
        return {"kind": key, "count": len(value), "sha256": _stable_repr_digest(value)}
    return _jsonable(value)


def _stable_repr_digest(value: Any) -> str:
    import hashlib
    import json

    try:
        payload = json.dumps(_jsonable(value), ensure_ascii=False, sort_keys=True, default=str)
    except Exception:
        payload = repr(value)
    return hashlib.sha256(payload.encode("utf-8", errors="replace")).hexdigest()
