from typing import Any

from sunpack.detection.scene.context import context_from_markers
from sunpack.detection.scene.definitions import RECOMMENDED_SCENE_RULES_PAYLOAD
from sunpack.detection.scene.markers import collect_scene_markers_from_snapshot
from sunpack.contracts.filesystem import DirectorySnapshot
from sunpack.filesystem.directory_scanner import DirectoryScanner
from sunpack.support.global_cache_manager import cached_value, directory_identity, stable_fingerprint
from sunpack.support.path_keys import normalized_path, path_key


def detect_scene_context_for_directory(
    target_dir: str,
    rules: list[dict[str, Any]] | None = None,
    snapshot: DirectorySnapshot | None = None,
) -> dict[str, Any]:
    effective_rules = rules or RECOMMENDED_SCENE_RULES_PAYLOAD
    norm_target = normalized_path(target_dir)
    key = (
        _snapshot_directory_identity(snapshot, norm_target) if snapshot is not None else directory_identity(norm_target),
        stable_fingerprint(effective_rules),
    )
    return cached_value(
        "scene_context_for_directory",
        key,
        lambda: context_from_markers(
            norm_target,
            collect_scene_markers_from_snapshot(snapshot or DirectoryScanner(norm_target).scan(), effective_rules),
            effective_rules,
        ),
    )


def is_strong_scene_context(context: dict[str, Any]) -> bool:
    return context.get("scene_type") != "generic" and context.get("match_strength") == "strong"


def _snapshot_directory_identity(snapshot: DirectorySnapshot, directory: str):
    root_key = path_key(directory)
    entries = []
    for entry in snapshot.entries:
        if path_key(entry.path.parent) != root_key:
            continue
        entries.append((
            entry.path.name.lower(),
            bool(entry.is_dir),
            int(entry.size or 0),
            int(entry.mtime_ns or 0),
        ))
    return root_key, len(entries), tuple(sorted(entries))
