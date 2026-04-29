from dataclasses import dataclass
from pathlib import Path
from typing import Any

from sunpack_native import scene_semantics_payloads as _NATIVE_SCENE_SEMANTICS_PAYLOADS

from sunpack.contracts.filesystem import FileEntry
from sunpack.filesystem.filters import register_filter
from sunpack.filesystem.filters.base import ScanCandidate, ScanDecision, keep, prune, reject


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
    payloads = _NATIVE_SCENE_SEMANTICS_PAYLOADS(
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
    )
    scene_root_keys = {
        _normalized_path(path).lower()
        for path, payload in (payloads.items() if isinstance(payloads, dict) else [])
        if isinstance(payload, dict) and payload.get("prune_scene_subtree")
    }
    annotated: list[FileEntry] = []
    for entry in entries:
        if _under_or_same_key(entry.path, scene_root_keys):
            continue
        scene_payload = payloads.get(_normalized_path(entry.path)) if isinstance(payloads, dict) else None
        if not isinstance(scene_payload, dict):
            annotated.append(entry)
            continue
        metadata = dict(entry.metadata or {})
        metadata["scene"] = scene_payload
        annotated.append(FileEntry(
            path=entry.path,
            is_dir=entry.is_dir,
            size=entry.size,
            mtime_ns=entry.mtime_ns,
            metadata=metadata,
        ))
    return annotated


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


def _under_or_same_key(path: Any, parent_keys: set[str]) -> bool:
    if not parent_keys:
        return False
    key = _normalized_path(path).lower()
    if key in parent_keys:
        return True
    parts = key.split("/")
    for index in range(len(parts) - 1, 0, -1):
        if "/".join(parts[:index]) in parent_keys:
            return True
    return False


def scene_rules(config: dict[str, Any] | None = None) -> list[dict[str, Any]]:
    rules = (config or {}).get("scene_rules")
    return rules if isinstance(rules, list) else []


def scene_prune_dir_globs(config: dict[str, Any] | None = None) -> list[str]:
    globs = (config or {}).get("prune_dir_globs")
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
        metadata = candidate.metadata or {}
        scene = metadata.get("scene") if isinstance(metadata, dict) else None
        if candidate.kind == "dir" and isinstance(scene, dict) and scene.get("prune_scene_subtree"):
            return prune("scene directory subtree")
        if self.config.get("protect_runtime_resources", True) and candidate.kind == "file":
            if isinstance(scene, dict) and scene.get("is_runtime_resource_archive"):
                return reject("scene runtime resource archive")
        return keep()


register_filter(SceneSemanticsScanFilter.name, SceneSemanticsScanFilter)
