from __future__ import annotations

import copy
import hashlib
import json
from collections import OrderedDict, Counter
from pathlib import Path
from typing import Any

from sunpack.contracts.archive_knowledge import ArchiveKnowledge

_PROJECTION_CACHE_MAX = 512
_PROJECTION_CACHE: OrderedDict[tuple[str, str, str], Any] = OrderedDict()
_PROJECTION_HITS: Counter[str] = Counter()
_PROJECTION_MISSES: Counter[str] = Counter()


def task_knowledge(task: Any) -> ArchiveKnowledge:
    if isinstance(task, ArchiveKnowledge):
        return task
    if isinstance(task, dict):
        return ArchiveKnowledge.from_any(task)
    if hasattr(task, "knowledge") and callable(task.knowledge):
        return task.knowledge()
    return ArchiveKnowledge()


def get(task_or_knowledge: Any, path: str, default: Any = None) -> Any:
    knowledge = task_knowledge(task_or_knowledge)
    value = knowledge.get(path, default)
    return default if value is None else value


def source_input(task: Any) -> dict[str, Any]:
    return _dict(get(task, "source.input", {}))


def source_fingerprint(task_or_knowledge: Any) -> dict[str, Any]:
    knowledge = task_knowledge(task_or_knowledge)
    return _cached_projection(knowledge, "source_fingerprint", lambda: _source_fingerprint_uncached(knowledge))


def source_derivation(task: Any) -> dict[str, Any]:
    return _dict(get(task, "source.derivation", {}))


def analysis_summary(task: Any) -> dict[str, Any]:
    return _dict(get(task, "analysis.summary", {}))


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
    return dict(zip_runtime_facts(task).get("structure") or {})


def zip_container_tags(task: Any) -> list[str]:
    return list(zip_runtime_facts(task).get("container_tags") or [])


def damage_profile(task: Any) -> str:
    return str(get(task, "training.damage_profile", "") or get(task, "source.profile", "") or "")


def sample_id(task: Any) -> str:
    return str(get(task, "training.sample_id", "") or "")


def extraction_failure(task: Any) -> dict[str, Any]:
    return _dict(get(task, "extraction.failure", {}))


def extraction_diagnostics(task: Any) -> dict[str, Any]:
    return _dict(get(task, "extraction.diagnostics", {}))


def verification_summary(task: Any) -> dict[str, Any]:
    return _dict(get(task, "verification.summary", {}))


def repair_history_items(task: Any) -> list[dict[str, Any]]:
    value = get(task, "repair.history.items", [])
    return [dict(item) for item in value if isinstance(item, dict)] if isinstance(value, list) else []


def repair_history_payload(task: Any) -> dict[str, Any]:
    return _dict(get(task, "repair.history", {}))


def repair_history_summary(task: Any) -> dict[str, Any]:
    knowledge = task_knowledge(task)
    return _cached_projection(knowledge, "repair_history_summary", lambda: _repair_history_summary_uncached(knowledge))


def repair_route_context(task: Any) -> dict[str, Any]:
    knowledge = task_knowledge(task)
    return _cached_projection(knowledge, "repair_route_context", lambda: _repair_route_context_uncached(knowledge))


def zip_runtime_facts(task: Any) -> dict[str, Any]:
    knowledge = task_knowledge(task)
    return _cached_projection(knowledge, "zip_runtime_facts", lambda: _zip_runtime_facts_uncached(knowledge))


def policy_runtime_context(task: Any) -> dict[str, Any]:
    knowledge = task_knowledge(task)
    return _cached_projection(knowledge, "policy_runtime_context", lambda: {
        "source_fingerprint": source_fingerprint(knowledge),
        "zip_runtime_facts": zip_runtime_facts(knowledge),
        "repair_route_context": repair_route_context(knowledge),
        "repair_history_summary": repair_history_summary(knowledge),
    })


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


def projection_cache_stats() -> dict[str, Any]:
    hits = dict(_PROJECTION_HITS)
    misses = dict(_PROJECTION_MISSES)
    return {
        "entries": len(_PROJECTION_CACHE),
        "max_entries": _PROJECTION_CACHE_MAX,
        "hits": sum(hits.values()),
        "misses": sum(misses.values()),
        "by_projection": {
            name: {"hits": int(hits.get(name, 0)), "misses": int(misses.get(name, 0))}
            for name in sorted(set(hits) | set(misses))
        },
    }


def _dict(value: Any) -> dict[str, Any]:
    return dict(value) if isinstance(value, dict) else {}


def _cached_projection(knowledge: ArchiveKnowledge, name: str, compute) -> Any:
    revision = str(knowledge.get("_meta.revision", 0) or 0)
    identity = _stable_digest(_source_fingerprint_uncached(knowledge))
    knowledge_identity = _stable_digest(knowledge.to_dict())
    cache_key = (revision, str(name), f"{identity}:{knowledge_identity}")
    if cache_key in _PROJECTION_CACHE:
        value = _PROJECTION_CACHE.pop(cache_key)
        _PROJECTION_CACHE[cache_key] = value
        _PROJECTION_HITS[str(name)] += 1
        return copy.deepcopy(value)
    _PROJECTION_MISSES[str(name)] += 1
    value = compute()
    _PROJECTION_CACHE[cache_key] = copy.deepcopy(value)
    _PROJECTION_CACHE.move_to_end(cache_key)
    while len(_PROJECTION_CACHE) > _PROJECTION_CACHE_MAX:
        _PROJECTION_CACHE.popitem(last=False)
    return value


def _zip_runtime_facts_uncached(knowledge: ArchiveKnowledge) -> dict[str, Any]:
    structure = _dict(knowledge.get("format.zip.structure", {}))
    tags = knowledge.get("format.zip.container_tags", [])
    route_flags = knowledge.get("format.zip.route_evidence_flags", [])
    return {
        "structure": structure,
        "container_tags": [str(item) for item in tags if str(item)] if isinstance(tags, list) else [],
        "route_evidence_flags": [str(item) for item in route_flags if str(item)] if isinstance(route_flags, list) else [],
    }


def _repair_route_context_uncached(knowledge: ArchiveKnowledge) -> dict[str, Any]:
    flags: list[str] = []
    for path in (
        "format.zip.route_evidence_flags",
        "format.zip.route_evidence.flags",
        "repair.route_evidence.flags",
        "repair.damage.flags",
        "verification.residual.flags",
        "repair.residual.flags",
    ):
        value = knowledge.get(path, [])
        if isinstance(value, list):
            flags.extend(str(item) for item in value if str(item))
    flags.extend(_canonical_zip_route_flags(knowledge))
    route_flags = _dedupe(flags)
    residual = _dedupe([
        str(item)
        for path in ("verification.residual.flags", "repair.residual.flags")
        for item in (knowledge.get(path, []) or [])
        if str(item)
    ])
    return {
        "route_evidence_flags": route_flags,
        "damage_flags": route_flags,
        "residual_damage_flags": residual,
    }


def _canonical_zip_route_flags(knowledge: ArchiveKnowledge) -> list[str]:
    structure = _dict(knowledge.get("format.zip.structure", {}))
    tags = {str(item).lower() for item in (knowledge.get("format.zip.container_tags", []) or [])}
    profile = str(knowledge.get("source.profile", "") or knowledge.get("training.damage_profile", "") or "").lower()
    flags: list[str] = []
    if structure.get("has_duplicate_entries"):
        flags.extend(["has_duplicate_entries", "duplicate_entries"])
    if structure.get("has_filename_encoding_risk"):
        flags.extend(["has_filename_encoding_risk", "filename_encoding_bad", "raw_filename_bytes"])
    if structure.get("has_long_comment"):
        flags.append("long_comment_present")
    if structure.get("has_zip64_extra"):
        flags.extend(["zip64", "zip64_extra_present"])
    if structure.get("has_sfx_prefix"):
        flags.extend(["sfx", "carrier_prefix", "carrier_archive"])
    if structure.get("has_data_descriptor"):
        flags.append("data_descriptor")
    if structure.get("has_split_sidecars"):
        flags.extend(["split_archive", "split_sidecars_available"])
    if tags & {"sfx", "carrier_prefix", "carrier_archive", "embedded_archive"}:
        flags.extend(sorted(tags & {"sfx", "carrier_prefix", "carrier_archive", "embedded_archive"}))
    if "split_archive" in tags:
        flags.append("split_archive")
    if "duplicate_entry" in profile or "duplicate_entries" in profile:
        flags.append("duplicate_entries")
    if "non_utf8_filename" in profile or "filename_encoding" in profile:
        flags.extend(["filename_encoding_bad", "raw_filename_bytes", "central_directory_bad", "central_directory_offset_bad", "central_directory_count_bad", "local_header_recovery"])
    if "comment_overlap" in profile or "comment_length" in profile or "long_comment" in profile:
        flags.extend(["zip_comment_length_bad", "comment_length_bad", "eocd_bad", "long_comment_present", "boundary_unreliable"])
    if "zip64_extra_size" in profile or "zip64_extra" in profile:
        flags.extend(["zip64", "zip64_extra_present", "zip64_extra_bad", "zip64_extra_size_bad"])
    if "extra_field_length_bad" in profile or "extra_length_bad" in profile:
        flags.extend(["extra_field_bad", "extra_field_length_bad", "central_directory_bad", "central_directory_offset_bad", "central_directory_count_bad"])
    if "zip64_eocd_locator" in profile or "zip64_locator" in profile:
        flags.extend(["zip64", "zip64_locator_bad"])
    if "zip64_eocd" in profile:
        flags.extend(["zip64", "zip64_eocd_bad"])
    if "data_descriptor_cd_conflict" in profile:
        flags.extend([
            "data_descriptor",
            "compressed_size_bad",
            "local_header_conflict",
            "central_directory_bad",
            "central_directory_offset_bad",
            "central_directory_count_bad",
            "spurious_data_descriptor_candidate",
            "descriptor_record_in_payload_gap",
            "descriptor_delete_would_align_next_header",
        ])
    elif "data_descriptor" in profile:
        flags.extend(["data_descriptor", "compressed_size_bad"])
    if "sfx" in profile:
        flags.extend(["sfx", "carrier_prefix", "carrier_archive"])
        if "cd_damage" in profile:
            flags.extend(["central_directory_bad", "central_directory_offset_bad", "central_directory_count_bad"])
        if "payload_damage" in profile:
            flags.extend(["checksum_error", "crc_error", "damaged", "central_directory_bad", "central_directory_offset_bad", "central_directory_count_bad", "payload_hash_mismatch"])
    if "split_tail_volume_truncated" in profile:
        flags.extend(["missing_volume", "input_truncated", "local_header_recovery", "tail_volume_truncated", "missing_volume_unavailable", "central_directory_bad", "central_directory_offset_bad", "central_directory_count_bad"])
    elif "split_missing_middle_volume" in profile or "sfx_split_missing_volume" in profile:
        flags.extend(["missing_volume", "input_truncated", "local_header_recovery", "middle_volume_missing", "central_directory_bad", "central_directory_offset_bad", "central_directory_count_bad"])
    elif "split" in profile or "missing_volume" in profile:
        flags.extend(["missing_volume", "input_truncated", "local_header_recovery", "central_directory_bad", "central_directory_offset_bad", "central_directory_count_bad"])
    if "after_archive_carrier_crop" in flags:
        flags = [flag for flag in flags if flag not in {"sfx", "carrier_archive", "carrier_prefix", "embedded_archive"}]
    if "split_sidecars_available" in flags and "tail_volume_truncated" not in flags and "missing_volume_unavailable" not in flags:
        flags = [flag for flag in flags if flag not in {"missing_volume", "input_truncated", "unexpected_end", "stream_truncated"}]
    return _dedupe(flags)


def _repair_history_summary_uncached(knowledge: ArchiveKnowledge) -> dict[str, Any]:
    items = knowledge.get("repair.history.items", [])
    items = [dict(item) for item in items if isinstance(item, dict)] if isinstance(items, list) else []
    previous_actions: list[str] = []
    previous_modules: list[str] = []
    patch_facts: list[str] = []
    residual_facts: list[str] = []
    for entry in items:
        if entry.get("ok") is False:
            continue
        previous_actions.extend(str(action) for action in entry.get("actions") or [] if str(action))
        module = str(entry.get("module_name") or entry.get("module") or "")
        if module:
            previous_modules.append(module)
        diagnosis = entry.get("diagnosis") if isinstance(entry.get("diagnosis"), dict) else {}
        patch_facts.extend(str(item) for item in diagnosis.get("patch_facts") or [] if str(item))
        residual_facts.extend(str(item) for item in diagnosis.get("residual_facts") or [] if str(item))
    history = _dict(knowledge.get("repair.history", {}))
    previous_actions = _dedupe([*previous_actions, *[str(item) for item in history.get("previous_actions") or [] if str(item)]])
    previous_modules = _dedupe([*previous_modules, *[str(item) for item in history.get("previous_modules") or [] if str(item)]])
    flags = _dedupe([*[f"already_tried:{module}" for module in previous_modules], *[str(item) for item in history.get("repair_history_flags") or [] if str(item)]])
    return {
        "items": items,
        "previous_actions": previous_actions,
        "previous_modules": previous_modules,
        "path_actions": previous_actions,
        "path_modules": previous_modules,
        "repair_history_flags": flags,
        "applied_patch_facts": _dedupe([*patch_facts, *[str(item) for item in history.get("applied_patch_facts") or [] if str(item)]]),
        "residual_damage_flags": _dedupe([*residual_facts, *[str(item) for item in history.get("residual_damage_flags") or [] if str(item)]]),
    }


def _source_fingerprint_uncached(knowledge: ArchiveKnowledge) -> dict[str, Any]:
    state = knowledge.get("archive.state")
    source = knowledge.get("source.input")
    if isinstance(state, dict):
        patch_digest = state.get("patch_digest") or state.get("effective_patch_digest")
        patches = state.get("patches") or state.get("patch_stack") or []
        state_source = state.get("source") if isinstance(state.get("source"), dict) else source
        if patch_digest or patches:
            return {
                "kind": "archive_state",
                "patch_digest": str(patch_digest or _stable_digest(patches)),
                "format_hint": state.get("format_hint") or (state_source or {}).get("format_hint"),
                "source": _source_input_fingerprint(state_source if isinstance(state_source, dict) else {}),
            }
    return _source_input_fingerprint(source if isinstance(source, dict) else {})


def _source_input_fingerprint(source_input: dict[str, Any]) -> dict[str, Any]:
    kind = str(source_input.get("kind") or source_input.get("open_mode") or "file")
    if kind in {"bytes", "memory"}:
        data = source_input.get("data", b"")
        if isinstance(data, bytearray):
            data = bytes(data)
        if isinstance(data, bytes):
            return {"kind": kind, "sha256": hashlib.sha256(data).hexdigest(), "size": len(data), "format_hint": source_input.get("format_hint")}
        return {"kind": kind, "data": str(data), "format_hint": source_input.get("format_hint")}
    if kind in {"file", ""}:
        return {"kind": "file", **_path_fingerprint(str(source_input.get("path") or source_input.get("entry_path") or "")), "format_hint": source_input.get("format_hint") or source_input.get("format")}
    if kind == "file_range":
        return {
            "kind": "file_range",
            **_path_fingerprint(str(source_input.get("path") or source_input.get("entry_path") or "")),
            "start": int(source_input.get("start") or 0),
            "end": source_input.get("end"),
            "format_hint": source_input.get("format_hint") or source_input.get("format"),
        }
    if kind == "concat_ranges":
        return {
            "kind": "concat_ranges",
            "ranges": [
                {**_path_fingerprint(str(item.get("path") or "")), "start": int(item.get("start") or 0), "end": item.get("end")}
                for item in source_input.get("ranges") or []
                if isinstance(item, dict)
            ],
            "format_hint": source_input.get("format_hint") or source_input.get("format"),
        }
    parts = source_input.get("parts")
    return {
        "kind": kind,
        "parts": [
            {**_path_fingerprint(str(item.get("path") or "")), "role": item.get("role"), "volume_number": item.get("volume_number")}
            for item in parts or []
            if isinstance(item, dict)
        ],
        "format_hint": source_input.get("format_hint") or source_input.get("format"),
    }


def _path_fingerprint(path: str) -> dict[str, Any]:
    if not path:
        return {"path": ""}
    candidate = Path(path)
    try:
        stat = candidate.stat()
        return {"path": str(candidate), "size": int(stat.st_size), "mtime_ns": int(stat.st_mtime_ns)}
    except OSError:
        return {"path": str(candidate), "missing": True}


def _stable_digest(payload: Any) -> str:
    return hashlib.sha256(json.dumps(_jsonable(payload), ensure_ascii=False, sort_keys=True, default=str).encode("utf-8")).hexdigest()


def _jsonable(value: Any) -> Any:
    if isinstance(value, dict):
        return {str(key): _jsonable(item) for key, item in value.items()}
    if isinstance(value, (list, tuple)):
        return [_jsonable(item) for item in value]
    if isinstance(value, set):
        return sorted(_jsonable(item) for item in value)
    if isinstance(value, bytes):
        return {"sha256": hashlib.sha256(value).hexdigest(), "size": len(value)}
    if isinstance(value, Path):
        return str(value)
    return value


def _dedupe(values: list[str]) -> list[str]:
    output: list[str] = []
    seen: set[str] = set()
    for value in values:
        if value in seen:
            continue
        seen.add(value)
        output.append(value)
    return output
