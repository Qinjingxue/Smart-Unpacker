import os
from dataclasses import dataclass, field
from fnmatch import fnmatch

from smart_unpacker.contracts.filesystem import DirectorySnapshot


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
    markers: set[str] = set()
    top_level_dirs, top_level_files = _top_level_entries(directory)
    top_level_exes = {name for name in top_level_files if name.endswith(".exe")}

    for rule in rules:
        dir_markers = {str(name).lower(): marker for name, marker in rule.get("top_level_dir_markers", {}).items()}
        file_markers = {str(name).lower(): marker for name, marker in rule.get("top_level_file_markers", {}).items()}
        for name in top_level_dirs:
            if name in dir_markers:
                markers.add(dir_markers[name])
        for name in top_level_files:
            if name in file_markers:
                markers.add(file_markers[name])
            for pattern, marker in rule.get("top_level_glob_markers", ()):
                if fnmatch(name, str(pattern).lower()):
                    markers.add(marker)
        for rel_path, marker in rule.get("nested_path_markers", {}).items():
            if _relative_path_exists(directory, rel_path):
                markers.add(marker)

    www_child_dirs = _direct_child_dirs(directory, "www")
    if "www" in top_level_dirs:
        runtime_dirs = {"js", "data", "img", "audio", "fonts", "movies"}
        present_runtime_dirs = len(runtime_dirs & www_child_dirs)
        if present_runtime_dirs >= 2:
            markers.add("runtime_exe" if top_level_exes else "www_runtime_layout")
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


def _snapshot_index(snapshot: DirectorySnapshot) -> SceneSnapshotIndex:
    root_key = _path_key(snapshot.root_path)
    index = SceneSnapshotIndex(root_key=root_key)
    for entry in snapshot.entries:
        path_key = _path_key(entry.path)
        parent_key = _path_key(entry.path.parent)
        index.path_keys.add(path_key)
        if entry.is_dir:
            index.child_dirs_by_parent.setdefault(parent_key, set()).add(entry.path.name.lower())
            if parent_key == root_key:
                index.top_level_dirs.add(entry.path.name.lower())
        elif parent_key == root_key:
            index.top_level_files.add(entry.path.name.lower())
    return index


def _snapshot_has_relative_path(index: SceneSnapshotIndex, snapshot: DirectorySnapshot, rel_path: str) -> bool:
    target = os.path.normcase(os.path.normpath(snapshot.root_path / _relative_path(rel_path)))
    return target in index.path_keys


def _snapshot_child_dirs(index: SceneSnapshotIndex, snapshot: DirectorySnapshot, child_name: str) -> set[str]:
    child_key = _path_key(snapshot.root_path / child_name)
    return index.child_dirs_by_parent.get(child_key, set())


def _path_key(path) -> str:
    return os.path.normcase(os.path.normpath(path))


def _relative_path(rel_path: str):
    return os.path.join(*rel_path.split("/"))


def _top_level_entries(directory: str) -> tuple[set[str], set[str]]:
    dirs: set[str] = set()
    files: set[str] = set()
    try:
        with os.scandir(directory) as entries:
            for entry in entries:
                name = entry.name.lower()
                try:
                    if entry.is_dir():
                        dirs.add(name)
                    elif entry.is_file():
                        files.add(name)
                except OSError:
                    continue
    except OSError:
        return set(), set()
    return dirs, files


def _direct_child_dirs(directory: str, child_name: str) -> set[str]:
    child_dir = os.path.join(directory, child_name)
    dirs: set[str] = set()
    try:
        with os.scandir(child_dir) as entries:
            for entry in entries:
                try:
                    if entry.is_dir():
                        dirs.add(entry.name.lower())
                except OSError:
                    continue
    except OSError:
        return set()
    return dirs


def _relative_path_exists(directory: str, rel_path: str) -> bool:
    try:
        return os.path.exists(os.path.join(directory, _relative_path(rel_path)))
    except OSError:
        return False
