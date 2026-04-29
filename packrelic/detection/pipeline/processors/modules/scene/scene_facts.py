import os
from typing import Any, Dict

from packrelic.detection.pipeline.processors.context import FactProcessorContext
from packrelic.detection.pipeline.processors.identity import file_identity_for_context
from packrelic.detection.pipeline.processors.registry import register_processor
from packrelic.detection.scene.context import context_from_marker_candidates
from packrelic.detection.scene.definitions import scene_rules
from packrelic.support.global_cache_manager import cached_value, file_identity, stable_fingerprint


def _scene_rules(config: dict[str, Any] | None) -> list[dict[str, Any]]:
    return scene_rules(config)


def collect_scene_context_from_markers(marker_candidates: list[dict], config: dict[str, Any] | None = None) -> Dict[str, Any]:
    return context_from_marker_candidates(marker_candidates, _scene_rules(config))


def _get_scene_rule(scene_type: str, rules: list[dict[str, Any]]) -> Dict[str, Any]:
    for rule in rules:
        if rule.get("scene_type") == scene_type:
            return rule
    return {}


def _is_under_prefix(rel_path: str, prefixes: list) -> bool:
    return any(rel_path == prefix or rel_path.startswith(prefix + "/") for prefix in prefixes)


def analyze_scene_path(context: FactProcessorContext) -> dict[str, Any]:
    path = context.fact_bag.get("file.path") or ""
    key = (
        file_identity_for_context(context, path),
        stable_fingerprint(context.fact_config or {}),
        stable_fingerprint(context.fact_bag.get("scene.context") or {}),
        bool(context.fact_bag.get("relation.is_split_related")),
        bool(context.fact_bag.get("file.is_split_candidate")),
    )
    return cached_value("scene_path_analysis", key, lambda: _analyze_scene_path_uncached(context, path))


def _analyze_scene_path_uncached(context: FactProcessorContext, path: str) -> dict[str, Any]:
    scene_ctx = context.fact_bag.get("scene.context")
    if not isinstance(scene_ctx, dict):
        marker_candidates = context.fact_bag.get("scene.directory_markers") or []
        scene_ctx = context_from_marker_candidates(marker_candidates, _scene_rules(context.fact_config))

    scene_type = scene_ctx.get("scene_type", "generic")
    match_strength = scene_ctx.get("match_strength", "none")
    result = {
        "context": scene_ctx,
        "scene_type": scene_type,
        "match_strength": match_strength,
        "relative_path": "",
        "is_runtime_exact_path": False,
        "is_protected_exact_path": False,
        "is_protected_prefix_path": False,
        "is_protected_path": False,
        "protected_archive_ext_match": False,
        "is_runtime_resource_archive": False,
    }

    if not path or scene_type == "generic":
        return result

    scene_dir = scene_ctx.get("target_dir")
    try:
        rel_path = os.path.relpath(path, scene_dir).replace("\\", "/")
    except (TypeError, ValueError):
        return result

    rules = _scene_rules(context.fact_config)
    rule = _get_scene_rule(scene_type, rules)
    if not rule:
        return result

    ext = os.path.splitext(path)[1].lower()
    is_runtime_exact = rel_path in rule.get("runtime_exact_paths", [])
    is_protected_exact = rel_path in rule.get("protected_exact_paths", [])
    is_protected_prefix = _is_under_prefix(rel_path, rule.get("protected_prefixes", []))
    is_protected_path = is_protected_exact or is_protected_prefix
    protected_archive_ext_match = ext in {str(item).lower() for item in rule.get("protected_archive_exts", [])}
    is_split_related = bool(
        context.fact_bag.get("relation.is_split_related")
        or context.fact_bag.get("file.is_split_candidate")
    )
    is_runtime_resource_archive = bool(
        scene_type != "generic"
        and not is_runtime_exact
        and is_protected_path
        and (protected_archive_ext_match or is_split_related)
    )

    result.update({
        "relative_path": rel_path,
        "is_runtime_exact_path": is_runtime_exact,
        "is_protected_exact_path": is_protected_exact,
        "is_protected_prefix_path": is_protected_prefix,
        "is_protected_path": is_protected_path,
        "protected_archive_ext_match": protected_archive_ext_match,
        "is_runtime_resource_archive": is_runtime_resource_archive,
    })
    return result


def _scene_analysis_value(context: FactProcessorContext, key: str):
    return analyze_scene_path(context).get(key)


SCENE_OUTPUT_SCHEMAS = {
    "scene.context": {
        "type": "dict",
        "description": "Detected directory scene, including scene_type, target_dir, match_strength, and markers.",
    },
    "scene.relative_path": {
        "type": "str",
        "description": "Candidate path relative to the detected scene root.",
    },
    "scene.scene_type": {
        "type": "str",
        "description": "Detected scene type for the candidate path.",
    },
    "scene.match_strength": {
        "type": "str",
        "description": "Detected scene match strength.",
    },
    "scene.is_runtime_exact_path": {
        "type": "bool",
        "description": "Whether the candidate is a scene runtime exact path.",
    },
    "scene.is_protected_exact_path": {
        "type": "bool",
        "description": "Whether the candidate matches a protected exact scene path.",
    },
    "scene.is_protected_prefix_path": {
        "type": "bool",
        "description": "Whether the candidate is under a protected scene prefix.",
    },
    "scene.is_protected_path": {
        "type": "bool",
        "description": "Whether the candidate is in a protected scene path.",
    },
    "scene.protected_archive_ext_match": {
        "type": "bool",
        "description": "Whether the candidate extension is protected as a scene archive resource.",
    },
    "scene.is_runtime_resource_archive": {
        "type": "bool",
        "description": "Whether the candidate is a protected scene runtime resource archive.",
    },
}


@register_processor(
    "scene_facts",
    input_facts={"file.path", "scene.directory_markers"},
    output_facts=set(SCENE_OUTPUT_SCHEMAS),
    schemas=SCENE_OUTPUT_SCHEMAS,
)
def process_scene_fact(context: FactProcessorContext):
    output_fact = context.output_fact
    if output_fact == "scene.context":
        return collect_scene_context_from_markers(context.fact_bag.get("scene.directory_markers") or [], context.fact_config)
    if output_fact == "scene.relative_path":
        return str(_scene_analysis_value(context, "relative_path") or "")
    if output_fact == "scene.scene_type":
        return str(_scene_analysis_value(context, "scene_type") or "generic")
    if output_fact == "scene.match_strength":
        return str(_scene_analysis_value(context, "match_strength") or "none")
    if output_fact == "scene.is_runtime_exact_path":
        return bool(_scene_analysis_value(context, "is_runtime_exact_path"))
    if output_fact == "scene.is_protected_exact_path":
        return bool(_scene_analysis_value(context, "is_protected_exact_path"))
    if output_fact == "scene.is_protected_prefix_path":
        return bool(_scene_analysis_value(context, "is_protected_prefix_path"))
    if output_fact == "scene.is_protected_path":
        return bool(_scene_analysis_value(context, "is_protected_path"))
    if output_fact == "scene.protected_archive_ext_match":
        return bool(_scene_analysis_value(context, "protected_archive_ext_match"))
    if output_fact == "scene.is_runtime_resource_archive":
        return bool(_scene_analysis_value(context, "is_runtime_resource_archive"))
    return None
