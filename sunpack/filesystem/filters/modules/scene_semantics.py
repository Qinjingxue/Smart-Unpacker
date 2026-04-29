from dataclasses import dataclass
from pathlib import Path
from typing import Any

from sunpack_native import scene_semantics_filter_entries as _NATIVE_SCENE_SEMANTICS_FILTER_ENTRIES

from sunpack.contracts.filesystem import FileEntry
from sunpack.filesystem.filters import register_filter
from sunpack.filesystem.filters.base import ScanCandidate, ScanDecision, keep


SCENE_FACT_KEYS = {
    "context",
    "relative_path",
    "scene_type",
    "match_strength",
    "is_runtime_exact_path",
    "is_protected_exact_path",
    "is_protected_prefix_path",
    "is_protected_path",
    "protected_archive_ext_match",
    "is_runtime_resource_archive",
}


def annotate_scene_metadata(
    entries: list[FileEntry],
    root_path: Path,
    config: dict[str, Any] | None,
) -> list[FileEntry]:
    scene_config = config or {}
    kept_paths = _NATIVE_SCENE_SEMANTICS_FILTER_ENTRIES(
        str(root_path),
        [
            {
                "path": str(entry.path),
                "is_dir": entry.is_dir,
            }
            for entry in entries
        ],
        scene_rules(scene_config),
        scene_prune_dir_globs(scene_config),
        scene_path_globs(scene_config),
    )
    kept_keys = {_normalized_path(path).lower() for path in kept_paths}
    return [entry for entry in entries if _normalized_path(entry.path).lower() in kept_keys]


def detect_scene_context_for_directory(
    target_dir: str,
    *,
    entries: list[FileEntry] | None = None,
) -> dict[str, Any]:
    normalized_target = _normalized_path(target_dir)
    default = {
        "target_dir": normalized_target,
        "scene_type": "generic",
        "match_strength": "none",
        "markers": [],
    }
    if not entries:
        return default

    best = default
    for entry in entries:
        metadata = entry.metadata or {}
        scene = metadata.get("scene") if isinstance(metadata, dict) else None
        context = scene.get("context") if isinstance(scene, dict) else None
        if not isinstance(context, dict):
            continue
        if _normalized_path(context.get("target_dir")) != normalized_target:
            continue
        if context.get("scene_type") == "generic":
            continue
        if context.get("match_strength") == "strong":
            return context
        best = context
    return best


def is_strong_scene_context(context: dict[str, Any]) -> bool:
    return context.get("scene_type") != "generic" and context.get("match_strength") == "strong"


def _normalized_path(path: Any) -> str:
    return str(path or "").replace("\\", "/").rstrip("/")


def scene_rules(config: dict[str, Any] | None = None) -> list[dict[str, Any]]:
    rules = (config or {}).get("scene_rules")
    return rules if isinstance(rules, list) else []


def scene_prune_dir_globs(config: dict[str, Any] | None = None) -> list[str]:
    globs = (config or {}).get("prune_dir_globs")
    if not isinstance(globs, list):
        return []
    return [str(item) for item in globs if isinstance(item, str) and item.strip()]


def scene_path_globs(config: dict[str, Any] | None = None) -> list[str]:
    globs = (config or {}).get("path_globs")
    if not isinstance(globs, list):
        return []
    return [str(item) for item in globs if isinstance(item, str) and item.strip()]




@dataclass
class SceneSemanticsScanFilter:
    name = "scene_semantics"
    stage = "path"
    config: dict[str, Any]

    @classmethod
    def from_config(cls, config: dict[str, Any]):
        return cls(config=dict(config))

    def evaluate(self, candidate: ScanCandidate) -> ScanDecision:
        return keep()


register_filter(SceneSemanticsScanFilter.name, SceneSemanticsScanFilter)
