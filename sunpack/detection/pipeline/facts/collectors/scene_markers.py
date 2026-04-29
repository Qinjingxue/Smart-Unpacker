import os

from sunpack.detection.pipeline.facts.registry import register_batch_fact, register_fact
from sunpack.detection.scene.definitions import scene_rules
from sunpack.detection.scene.markers import collect_scene_markers_from_directory, collect_scene_markers_from_snapshot
from sunpack.support.global_cache_manager import cached_value, directory_identity, stable_fingerprint
from sunpack.support.path_keys import normalized_path, path_key


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
    scan_session = getattr(context, "scan_session", None)
    directories = _directories_within_scan_scope(scan_session, candidate_directories(start_dir, max_depth))
    snapshots = {
        directory: _scene_snapshot_for_directory(scan_session, directory, rules)
        for directory in directories
    } if scan_session is not None else {}
    if scan_session is not None:
        identities = tuple(
            _snapshot_directory_identity(snapshots.get(directory), directory)
            if snapshots.get(directory) is not None
            else scan_session.directory_identity_for_path(directory)
            for directory in directories
        )
    else:
        identities = tuple(directory_identity(directory) for directory in directories)
    key = (identities, stable_fingerprint(rules))
    return cached_value(
        "scene_marker_candidates",
        key,
        lambda: _collect_scene_marker_candidates(directories, rules, snapshots=snapshots),
    )


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
        for directory in _directories_within_scan_scope(context.scan_session, candidate_directories(start_dir, max_depth)):
            normalized = normalized_path(directory)
            cache_key = (path_key(normalized), rules_key)
            markers = directory_markers.get(cache_key)
            if markers is None:
                snapshot = _scene_snapshot_for_directory(context.scan_session, normalized, rules)
                markers = cached_scene_markers_for_directory(normalized, rules, snapshot=snapshot)
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


def _collect_scene_marker_candidates(directories: list[str], rules: list[dict], snapshots: dict[str, object] | None = None) -> list[dict]:
    candidates = []
    for directory in directories:
        candidates.append({
            "target_dir": normalized_path(directory),
            "markers": cached_scene_markers_for_directory(directory, rules, snapshot=(snapshots or {}).get(directory)),
        })
    return candidates


def cached_scene_markers_for_directory(directory: str, rules: list[dict], snapshot=None) -> list[str]:
    identity = _snapshot_directory_identity(snapshot, directory) if snapshot is not None else directory_identity(directory)
    rules_fingerprint = stable_fingerprint(rules)
    return cached_value(
        "scene_directory_markers",
        (identity, rules_fingerprint),
        lambda: _collect_scene_markers_for_directory(directory, rules, snapshot=snapshot),
    )


def _collect_scene_markers_for_directory(directory: str, rules: list[dict], snapshot=None) -> list[str]:
    if snapshot is not None:
        return sorted(collect_scene_markers_from_snapshot(snapshot, rules))
    return sorted(collect_scene_markers_from_directory(directory, rules, max_depth=_scene_snapshot_depth(rules)))


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


def _directories_within_scan_scope(scan_session, directories: list[str]) -> list[str]:
    if scan_session is None or not hasattr(scan_session, "is_within_scan_scope"):
        return directories
    return [
        directory
        for directory in directories
        if scan_session.is_within_scan_scope(directory)
    ]


def _scene_snapshot_for_directory(scan_session, directory: str, rules: list[dict]):
    if scan_session is None:
        return None
    try:
        if hasattr(scan_session, "scene_snapshot_for_directory"):
            return scan_session.scene_snapshot_for_directory(directory, max_depth=_scene_snapshot_depth(rules))
        return scan_session.shallow_snapshot_for_directory(directory, max_depth=_scene_snapshot_depth(rules))
    except Exception:
        return None


def _scene_snapshot_depth(rules: list[dict]) -> int:
    depth = 1
    for rule in rules:
        for rel_path in (rule.get("nested_path_markers") or {}):
            parts = [part for part in str(rel_path or "").replace("\\", "/").split("/") if part]
            depth = max(depth, len(parts))
    return depth


def _snapshot_directory_identity(snapshot, directory: str):
    root_key = path_key(directory)
    entries = []
    for entry in getattr(snapshot, "entries", []) or []:
        if path_key(entry.path.parent) != root_key:
            continue
        entries.append((
            entry.path.name.lower(),
            bool(entry.is_dir),
            int(entry.size or 0),
            int(entry.mtime_ns or 0),
        ))
    return root_key, len(entries), tuple(sorted(entries))
