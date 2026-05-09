from __future__ import annotations

from typing import Any

from sunpack.contracts.archive_knowledge import ArchiveKnowledge


def task_knowledge(task: Any) -> ArchiveKnowledge:
    if hasattr(task, "knowledge") and callable(task.knowledge):
        return task.knowledge()
    return ArchiveKnowledge()


def get(task_or_knowledge: Any, path: str, default: Any = None) -> Any:
    knowledge = task_or_knowledge if isinstance(task_or_knowledge, ArchiveKnowledge) else task_knowledge(task_or_knowledge)
    value = knowledge.get(path, default)
    return default if value is None else value


def source_input(task: Any) -> dict[str, Any]:
    return _dict(get(task, "source.input", {}))


def source_derivation(task: Any) -> dict[str, Any]:
    payload = _dict(get(task, "source.derivation", {}))
    if payload:
        return payload
    training = {
        "damage_profile": get(task, "repair_training.damage_profile"),
        "sample_id": get(task, "repair_training.sample_id"),
        "zip_structure_features": get(task, "repair_training.zip_structure_features"),
        "zip_container_tags": get(task, "repair_training.zip_container_tags"),
    }
    return {key: value for key, value in training.items() if value not in (None, "", [], {})}


def analysis_prepass(task: Any) -> dict[str, Any]:
    return _dict(get(task, "analysis.prepass", {}))


def analysis_fuzzy_profile(task: Any) -> dict[str, Any]:
    fuzzy = _dict(get(task, "analysis.fuzzy", {}))
    profile = fuzzy.get("binary_profile") if isinstance(fuzzy.get("binary_profile"), dict) else fuzzy
    return _dict(profile)


def analysis_evidences(task: Any) -> list[dict[str, Any]]:
    value = get(task, "analysis.evidences", [])
    return [dict(item) for item in value if isinstance(item, dict)] if isinstance(value, list) else []


def selected_format(task: Any) -> str:
    return str(get(task, "analysis.selected_format", "") or get(task, "analysis.summary.format", "") or "")


def zip_structure_features(task: Any) -> dict[str, Any]:
    return (
        _dict(get(task, "format.zip.structure", {}))
        or _dict(source_derivation(task).get("zip_structure_features"))
        or _dict(get(task, "repair_training.zip_structure_features", {}))
    )


def zip_container_tags(task: Any) -> list[str]:
    value = get(task, "format.zip.container_tags", [])
    if not value:
        value = source_derivation(task).get("zip_container_tags", [])
    if not value:
        value = get(task, "repair_training.zip_container_tags", [])
    return [str(item) for item in value if str(item)] if isinstance(value, list) else []


def damage_profile(task: Any) -> str:
    return str(source_derivation(task).get("damage_profile") or get(task, "repair_training.damage_profile", "") or "")


def extraction_failure(task: Any) -> dict[str, Any]:
    return _dict(get(task, "extraction.failure", {}))


def extraction_diagnostics(task: Any) -> dict[str, Any]:
    return _dict(get(task, "extraction.diagnostics", {}))


def verification_summary(task: Any) -> dict[str, Any]:
    return _dict(get(task, "verification.summary", {}))


def repair_history_items(task: Any) -> list[dict[str, Any]]:
    value = get(task, "repair.history.items", [])
    if not value:
        value = get(task, "repair.history", [])
    return [dict(item) for item in value if isinstance(item, dict)] if isinstance(value, list) else []


def repair_history_payload(task: Any) -> dict[str, Any]:
    return _dict(get(task, "repair.history", {}))


def repair_attempts(task: Any) -> int:
    try:
        return int(get(task, "repair.attempts", 0) or 0)
    except (TypeError, ValueError):
        return 0


def archive_password(task: Any) -> str | None:
    value = get(task, "archive.password")
    return str(value) if value is not None else None


def resource_health(task: Any) -> dict[str, Any]:
    return _dict(get(task, "resource.health", {}))


def resource_analysis(task: Any) -> dict[str, Any]:
    return _dict(get(task, "resource.analysis", {}))


def resource_tokens(task: Any) -> dict[str, Any]:
    return _dict(get(task, "resource.tokens", {}))


def resource_token_cost(task: Any) -> int:
    try:
        return int(get(task, "resource.token_cost", 0) or 0)
    except (TypeError, ValueError):
        return 0


def resource_profile_key(task: Any) -> str:
    return str(get(task, "resource.profile_key", "") or "")


def _dict(value: Any) -> dict[str, Any]:
    return dict(value) if isinstance(value, dict) else {}
