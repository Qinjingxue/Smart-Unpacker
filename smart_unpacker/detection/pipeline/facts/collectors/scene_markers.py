import os

from smart_unpacker.detection.pipeline.facts.registry import register_batch_fact, register_fact
from smart_unpacker.detection.scene.definitions import scene_rules
from smart_unpacker.detection.scene.markers import collect_scene_markers_from_directory, collect_scene_markers_from_snapshot
from smart_unpacker.support.external_command_cache import cached_value, directory_identity, stable_fingerprint


@register_fact(
    "scene.directory_markers",
    type="list[dict]",
    description="Directory-level scene marker candidates collected from the candidate directory and parent directories.",
    context=True,
)
def collect_scene_directory_markers(context) -> list[dict]:
    base_path = context.fact_bag.get("file.path") or context.base_path
    rules = scene_rules(context.fact_config)
    start_dir = os.path.dirname(os.path.abspath(base_path)) if os.path.isfile(base_path) else os.path.abspath(base_path)
    max_depth = int((context.fact_config or {}).get("scene_context_max_parent_depth", 4))
    directories = candidate_directories(start_dir, max_depth)
    key = (tuple(directory_identity(directory) for directory in directories), stable_fingerprint(rules))
    return cached_value("scene_marker_candidates", key, lambda: _collect_scene_marker_candidates(directories, rules))


@register_batch_fact("scene.directory_markers")
def collect_scene_directory_markers_batch(context):
    fact_config = _merged_fact_config(context.fact_configs)
    rules = scene_rules(fact_config)
    rules_key = stable_fingerprint(rules)
    max_depth = int(fact_config.get("scene_context_max_parent_depth", 4))
    directory_markers: dict[tuple[str, str], list[str]] = {}

    for bag in context.fact_bags:
        base_path = bag.get("file.path") or ""
        if not base_path:
            continue
        start_dir = os.path.dirname(os.path.abspath(base_path)) if os.path.isfile(base_path) else os.path.abspath(base_path)
        candidates = []
        for directory in candidate_directories(start_dir, max_depth):
            normalized = os.path.normpath(directory)
            cache_key = (os.path.normcase(normalized), rules_key)
            markers = directory_markers.get(cache_key)
            if markers is None:
                markers = cached_scene_markers_for_directory(normalized, rules)
                directory_markers[cache_key] = markers
            candidates.append({
                "target_dir": normalized,
                "markers": markers,
            })
        bag.set(context.fact_name, candidates)


def _merged_fact_config(fact_configs: dict[str, dict]) -> dict:
    merged = {}
    for config in fact_configs.values():
        merged.update(config)
    return merged


def _collect_scene_marker_candidates(directories: list[str], rules: list[dict]) -> list[dict]:
    candidates = []
    for directory in directories:
        candidates.append({
            "target_dir": os.path.normpath(directory),
            "markers": cached_scene_markers_for_directory(directory, rules),
        })
    return candidates


def cached_scene_markers_for_directory(directory: str, rules: list[dict], snapshot=None) -> list[str]:
    identity = directory_identity(directory)
    rules_fingerprint = stable_fingerprint(rules)
    return cached_value(
        "scene_directory_markers",
        (identity, rules_fingerprint),
        lambda: _collect_scene_markers_for_directory(directory, rules, snapshot=snapshot),
    )


def _collect_scene_markers_for_directory(directory: str, rules: list[dict], snapshot=None) -> list[str]:
    if snapshot is not None:
        return sorted(collect_scene_markers_from_snapshot(snapshot, rules))
    return sorted(collect_scene_markers_from_directory(directory, rules))


def candidate_directories(start_dir: str, max_depth: int) -> list[str]:
    directories = []
    current = os.path.abspath(start_dir)
    depth = 0
    while current and depth <= max_depth:
        directories.append(current)
        parent = os.path.dirname(current)
        if parent == current:
            break
        current = parent
        depth += 1
    return directories
