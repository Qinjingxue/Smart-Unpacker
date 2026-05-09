from __future__ import annotations

from datetime import datetime, timezone
from typing import Any

from sunpack.contracts.archive_knowledge import ArchiveKnowledge


def ensure_knowledge(target: Any) -> ArchiveKnowledge:
    if isinstance(target, ArchiveKnowledge):
        return target
    if hasattr(target, "knowledge") and callable(target.knowledge):
        return target.knowledge()
    return ArchiveKnowledge.from_any(target)


def commit_task_knowledge(task: Any, knowledge: ArchiveKnowledge | dict[str, Any]) -> ArchiveKnowledge:
    payload = ensure_knowledge(knowledge)
    if hasattr(task, "set_knowledge") and callable(task.set_knowledge):
        task.set_knowledge(payload)
    return payload


def write_value(
    target: Any,
    path: str,
    value: Any,
    *,
    source_layer: str,
    source_module: str = "",
    round: int | None = None,
    source_digest: str = "",
    patch_digest: str = "",
    confidence: float | None = None,
) -> ArchiveKnowledge:
    knowledge = ensure_knowledge(target)
    knowledge.set(
        path,
        value,
        source_layer=source_layer,
        source_module=source_module,
        round=round,
        source_digest=source_digest,
        patch_digest=patch_digest,
        confidence=confidence,
    )
    return knowledge


def write_payload(
    target: Any,
    namespace: str,
    payload: dict[str, Any],
    *,
    source_layer: str,
    source_module: str = "",
    round: int | None = None,
    source_digest: str = "",
    patch_digest: str = "",
    confidence: float | None = None,
) -> ArchiveKnowledge:
    knowledge = ensure_knowledge(target)
    for key, value in dict(payload or {}).items():
        if value in (None, "", [], {}):
            continue
        write_value(
            knowledge,
            f"{namespace}.{key}" if namespace else str(key),
            value,
            source_layer=source_layer,
            source_module=source_module,
            round=round,
            source_digest=source_digest,
            patch_digest=patch_digest,
            confidence=confidence,
        )
    return knowledge


def write_flags(
    target: Any,
    namespace: str,
    flags: list[str] | tuple[str, ...] | set[str],
    *,
    source_layer: str,
    source_module: str = "",
    round: int | None = None,
    source_digest: str = "",
    patch_digest: str = "",
    confidence: float | None = None,
) -> ArchiveKnowledge:
    knowledge = ensure_knowledge(target)
    knowledge.add_flags(
        namespace,
        [str(flag) for flag in flags or [] if str(flag)],
        source_layer=source_layer,
        source_module=source_module,
    )
    if round is not None or source_digest or patch_digest or confidence is not None:
        write_evidence(
            knowledge,
            path=f"{namespace}.flags",
            value=[str(flag) for flag in flags or [] if str(flag)],
            source_layer=source_layer,
            source_module=source_module,
            confidence=confidence,
        )
    return knowledge


def append_history(
    target: Any,
    path: str,
    item: dict[str, Any],
    *,
    source_layer: str,
    source_module: str = "",
    max_items: int = 200,
) -> ArchiveKnowledge:
    knowledge = ensure_knowledge(target)
    history = knowledge.get(path)
    values = list(history) if isinstance(history, list) else []
    values.append(_jsonable(item))
    knowledge.set(
        path,
        values[-max_items:],
        source_layer=source_layer,
        source_module=source_module,
    )
    return knowledge


def write_evidence(
    target: Any,
    *,
    path: str,
    value: Any,
    source_layer: str,
    source_module: str = "",
    confidence: float | None = None,
) -> ArchiveKnowledge:
    knowledge = ensure_knowledge(target)
    evidence = knowledge.get("_evidence")
    rows = list(evidence) if isinstance(evidence, list) else []
    provenance: dict[str, Any] = {
        "source_layer": source_layer,
        "timestamp": datetime.now(timezone.utc).isoformat(),
    }
    if source_module:
        provenance["source_module"] = source_module
    if confidence is not None:
        provenance["confidence"] = float(confidence)
    rows.append({"path": path, "value": _jsonable(value), "provenance": provenance})
    knowledge.set("_evidence", rows[-500:])
    return knowledge


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
