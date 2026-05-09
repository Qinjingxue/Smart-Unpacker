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
    return _dict(get(task, "source.derivation", {}))


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


def analysis_selected_segment(task: Any) -> dict[str, Any]:
    return _dict(get(task, "analysis.selected_segment", {}))


def analysis_status(task: Any) -> str:
    return str(get(task, "analysis.status", "") or get(task, "analysis.summary.status", "") or "")


def analysis_error(task: Any) -> str:
    return str(get(task, "analysis.error", "") or get(task, "analysis.summary.error", "") or "")


def zip_structure_features(task: Any) -> dict[str, Any]:
    return _dict(get(task, "format.zip.structure", {})) or _dict(source_derivation(task).get("zip_structure_features"))


def zip_container_tags(task: Any) -> list[str]:
    value = get(task, "format.zip.container_tags", [])
    if not value:
        value = source_derivation(task).get("zip_container_tags", [])
    return [str(item) for item in value if str(item)] if isinstance(value, list) else []


def damage_profile(task: Any) -> str:
    return str(source_derivation(task).get("damage_profile") or "")


def sample_id(task: Any) -> str:
    return str(source_derivation(task).get("sample_id") or get(task, "training.sample_id", "") or "")


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


def repair_loop(task: Any) -> dict[str, Any]:
    return _dict(get(task, "repair.loop", {}))


def repair_candidate_log(task: Any) -> list[dict[str, Any]]:
    value = get(task, "repair.candidate_log", [])
    return [dict(item) for item in value if isinstance(item, dict)] if isinstance(value, list) else []


def repair_candidate_log_path(task: Any) -> str:
    return str(get(task, "repair.candidate_log_path", "") or "")


def archive_metadata(task: Any) -> dict[str, Any]:
    return _dict(get(task, "archive.metadata", {}))


def archive_repaired(task: Any) -> bool:
    return bool(get(task, "archive.repaired", False))


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
