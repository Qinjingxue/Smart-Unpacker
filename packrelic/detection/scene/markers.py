from dataclasses import dataclass, field
from fnmatch import fnmatch

from packrelic.contracts.filesystem import DirectorySnapshot
from packrelic.filesystem.directory_scanner import DirectoryScanner
from packrelic.support.path_keys import path_key, relative_os_path


@dataclass
class SceneSnapshotIndex:
    root_key: str
    path_keys: set[str] = field(default_factory=set)
    child_dirs_by_parent: dict[str, set[str]] = field(default_factory=dict)
    top_level_dirs: set[str] = field(default_factory=set)
    top_level_files: set[str] = field(default_factory=set)


def collect_scene_markers_from_snapshot(snapshot: DirectorySnapshot, rules: list[dict]) -> set[str]:
    markers: set[str] = set()
    index = _snapshot_index(snapshot)
    top_level_dirs = index.top_level_dirs
    top_level_files = index.top_level_files
    top_level_exes = {name for name in top_level_files if name.endswith(".exe")}

    for rule in rules:
        for name in top_level_dirs:
            if name in rule.get("top_level_dir_markers", {}):
                markers.add(rule["top_level_dir_markers"][name])
        for name in top_level_files:
            if name in rule.get("top_level_file_markers", {}):
                markers.add(rule["top_level_file_markers"][name])
            for pattern, marker in rule.get("top_level_glob_markers", ()):
                if fnmatch(name, pattern):
                    markers.add(marker)
        for rel_path, marker in rule.get("nested_path_markers", {}).items():
            if _snapshot_has_relative_path(index, snapshot, rel_path):
                markers.add(marker)

    if "www" in top_level_dirs:
        runtime_dirs = {"js", "data", "img", "audio", "fonts", "movies"}
        present_runtime_dirs = len(runtime_dirs & _snapshot_child_dirs(index, snapshot, "www"))
        if present_runtime_dirs >= 2:
            markers.add("runtime_exe" if top_level_exes else "www_runtime_layout")
    www_child_dirs = _snapshot_child_dirs(index, snapshot, "www")
    if "js" in www_child_dirs:
        markers.add("js_dir")
    if "data" in www_child_dirs:
        markers.add("data_dir")
    if "img" in www_child_dirs:
        markers.add("img_dir")
    if "audio" in www_child_dirs:
        markers.add("audio_dir")
    if "fonts" in www_child_dirs:
        markers.add("fonts_dir")
    if top_level_exes:
        markers.add("runtime_exe")
    if "resources" in top_level_dirs and top_level_exes:
        markers.add("electron_runtime_layout")
    if "package.nw" in top_level_files and top_level_exes:
        markers.add("nwjs_runtime_layout")
    if "game" in top_level_dirs and ("renpy" in top_level_dirs or "lib" in top_level_dirs):
        markers.add("renpy_runtime_layout")
    if top_level_exes and any(name.endswith(".pck") for name in top_level_files):
        markers.add("godot_runtime_layout")

    return markers


def collect_scene_markers_from_directory(directory: str, rules: list[dict]) -> set[str]:
    snapshot = DirectoryScanner(directory, config={}).scan()
    return collect_scene_markers_from_snapshot(snapshot, rules)


def _snapshot_index(snapshot: DirectorySnapshot) -> SceneSnapshotIndex:
    root_key = path_key(snapshot.root_path)
    index = SceneSnapshotIndex(root_key=root_key)
    for entry in snapshot.entries:
        entry_path_key = path_key(entry.path)
        parent_key = path_key(entry.path.parent)
        index.path_keys.add(entry_path_key)
        if entry.is_dir:
            index.child_dirs_by_parent.setdefault(parent_key, set()).add(entry.path.name.lower())
            if parent_key == root_key:
                index.top_level_dirs.add(entry.path.name.lower())
        elif parent_key == root_key:
            index.top_level_files.add(entry.path.name.lower())
    return index


def _snapshot_has_relative_path(index: SceneSnapshotIndex, snapshot: DirectorySnapshot, rel_path: str) -> bool:
    target = path_key(snapshot.root_path / _relative_path(rel_path))
    return target in index.path_keys


def _snapshot_child_dirs(index: SceneSnapshotIndex, snapshot: DirectorySnapshot, child_name: str) -> set[str]:
    child_key = path_key(snapshot.root_path / child_name)
    return index.child_dirs_by_parent.get(child_key, set())


def _relative_path(rel_path: str):
    return relative_os_path(rel_path)
