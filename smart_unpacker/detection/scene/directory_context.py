import os
from typing import Any

from smart_unpacker.detection.scene.context import context_from_markers
from smart_unpacker.detection.scene.definitions import RECOMMENDED_SCENE_RULES_PAYLOAD
from smart_unpacker.detection.scene.markers import collect_scene_markers_from_snapshot
from smart_unpacker.contracts.filesystem import DirectorySnapshot
from smart_unpacker.filesystem.directory_scanner import DirectoryScanner
from smart_unpacker.support.external_command_cache import cached_value, directory_identity, stable_fingerprint


def detect_scene_context_for_directory(
    target_dir: str,
    rules: list[dict[str, Any]] | None = None,
    snapshot: DirectorySnapshot | None = None,
) -> dict[str, Any]:
    effective_rules = rules or RECOMMENDED_SCENE_RULES_PAYLOAD
    norm_target = os.path.normpath(target_dir)
    key = (directory_identity(norm_target), stable_fingerprint(effective_rules))
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
