from pathlib import Path
import re

from sunpack_native import scan_directory_entries as _NATIVE_SCAN_DIRECTORY_ENTRIES

from sunpack.contracts.filesystem import DirectorySnapshot, FileEntry
from sunpack.config.detection_view import DIRECTORY_SCAN_CURRENT_DIR_ONLY, directory_scan_mode
from sunpack.filesystem.filters import build_filters
from sunpack.filesystem.filters.base import ScanCandidate, ScanFilter
from sunpack.filesystem.filters.modules.scene_semantics import (
    annotate_scene_metadata,
    scene_path_globs,
    scene_prune_dir_globs,
)


class DirectoryScanner:
    def __init__(self, root_path: str, max_depth: int | None = None, filters: list[ScanFilter] | None = None, config: dict | None = None):
        self.root_path = Path(root_path)
        self.config = config or {}
        self._custom_filters = filters is not None
        self.max_depth = self._effective_max_depth(max_depth, config)
        self.filters = list(filters) if filters is not None else build_filters(config)

    def _effective_max_depth(self, max_depth: int | None, config: dict | None) -> int | None:
        if max_depth is not None:
            return max_depth
        mode = directory_scan_mode(config or {})
        if mode == DIRECTORY_SCAN_CURRENT_DIR_ONLY:
            return 0
        return None

    def scan(self) -> DirectorySnapshot:
        return self._scan_native()

    def _scan_native(self) -> DirectorySnapshot | None:
        options = self._native_scan_options()
        if options is None:
            raise RuntimeError("Native directory scan requires built-in filesystem filters only")
        rows = _NATIVE_SCAN_DIRECTORY_ENTRIES(
            str(self.root_path),
            self.max_depth,
            options["patterns"],
            options["prune_dirs"],
            options["blocked_extensions"],
            options["min_size"],
        )

        root_path = self.root_path.parent if self.root_path.is_file() else self.root_path
        entries = [
            FileEntry(
                path=Path(row.get("path")),
                is_dir=bool(row.get("is_dir")),
                size=row.get("size"),
                mtime_ns=row.get("mtime_ns"),
            )
            for row in rows
            if isinstance(row, dict) and row.get("path")
        ]
        entries = self._apply_ordered_filters(entries)
        return DirectorySnapshot(root_path=root_path, entries=entries)

    def _native_scan_options(self) -> dict | None:
        if self._custom_filters:
            return None

        patterns: list[str] = []
        prune_dirs: list[str] = []
        blocked_extensions: list[str] = []
        min_size = None
        seen_scene_semantics = False

        for scan_filter in self.filters:
            name = getattr(scan_filter, "name", "")
            stage = getattr(scan_filter, "stage", "")
            if name == "scene_semantics":
                scene_config = getattr(scan_filter, "config", {}) or {}
                prune_dirs.extend(_dir_glob_to_regex(item) for item in scene_prune_dir_globs(scene_config))
                patterns.extend(_path_glob_to_regex(item) for item in scene_path_globs(scene_config))
                seen_scene_semantics = True
                continue
            if name == "blacklist" and stage == "path":
                if not seen_scene_semantics:
                    blocked_extensions.extend(getattr(scan_filter, "blocked_extensions", []) or [])
                continue
            if name in {"size_minimum", "size_range"} and stage == "size":
                if seen_scene_semantics:
                    break
                value = getattr(scan_filter, "min_inspection_size_bytes", None)
                if value is not None:
                    try:
                        min_size = max(int(value), int(min_size or 0))
                    except (TypeError, ValueError):
                        return None
                continue
            if name in {"whitelist", "mtime_range"}:
                break
            return None

        return {
            "patterns": patterns,
            "prune_dirs": prune_dirs,
            "blocked_extensions": blocked_extensions,
            "min_size": min_size,
        }

    def _apply_ordered_filters(self, entries: list[FileEntry]) -> list[FileEntry]:
        if not self.filters:
            return entries

        current = entries
        for scan_filter in self.filters:
            if getattr(scan_filter, "name", "") == "scene_semantics":
                current = annotate_scene_metadata(
                    current,
                    self.root_path.parent if self.root_path.is_file() else self.root_path,
                    getattr(scan_filter, "config", {}) or {},
                )
            current = apply_filter_to_entries(current, scan_filter)
        return current

    @staticmethod
    def _under_any(path: Path, parents: list[Path]) -> bool:
        return _under_any(path, parents)


def apply_ordered_filters_to_entries(entries: list[FileEntry], filters: list[ScanFilter]) -> list[FileEntry]:
    if not filters:
        return entries

    current = entries
    for scan_filter in filters:
        current = apply_filter_to_entries(current, scan_filter)
    return current


def apply_filter_to_entries(entries: list[FileEntry], scan_filter: ScanFilter) -> list[FileEntry]:
    kept: list[FileEntry] = []
    pruned_dir_keys: set[str] = set()
    for entry in sorted(entries, key=lambda item: (len(item.path.parts), str(item.path).lower())):
        if _under_any_key(entry.path, pruned_dir_keys):
            continue
        decision = scan_filter.evaluate(ScanCandidate(
            path=entry.path,
            kind="dir" if entry.is_dir else "file",
            size=entry.size,
            mtime_ns=entry.mtime_ns,
            metadata=entry.metadata,
        ))
        if decision.prune_dir and entry.is_dir:
            pruned_dir_keys.add(_path_key(entry.path))
        if decision.reject_entry:
            continue
        kept.append(entry)
    return kept


def _under_any(path: Path, parents: list[Path]) -> bool:
    for parent in parents:
        try:
            path.relative_to(parent)
        except ValueError:
            continue
        return path != parent
    return False


def _under_any_key(path: Path, parent_keys: set[str]) -> bool:
    if not parent_keys:
        return False
    current = path.parent
    while current != current.parent:
        if _path_key(current) in parent_keys:
            return True
        current = current.parent
    return _path_key(current) in parent_keys


def _path_key(path: Path) -> str:
    return str(path).replace("\\", "/").rstrip("/").lower()


def _dir_glob_to_regex(pattern: str) -> str:
    pattern = _normalize_glob(pattern)
    if not pattern:
        return r"a\A"
    return f"^{_glob_segment_to_regex(pattern)}$"


def _path_glob_to_regex(pattern: str) -> str:
    pattern = _normalize_glob(pattern)
    if not pattern:
        return r"a\A"
    if pattern.endswith("/**"):
        base = pattern[:-3].rstrip("/")
        if not base:
            return r".*"
        return f"(^|/){_glob_path_to_regex(base)}($|/.*)"
    return f"(^|/){_glob_path_to_regex(pattern)}($|/.*)?"


def _normalize_glob(pattern: str) -> str:
    return str(pattern or "").strip().replace("\\", "/").strip("/")


def _glob_segment_to_regex(pattern: str) -> str:
    return "".join(_glob_char_to_regex(char, slash=False) for char in pattern)


def _glob_path_to_regex(pattern: str) -> str:
    return "".join(_glob_char_to_regex(char, slash=True) for char in pattern)


def _glob_char_to_regex(char: str, *, slash: bool) -> str:
    if char == "*":
        return ".*" if slash else r"[^/]*"
    if char == "?":
        return "." if slash else r"[^/]"
    return re.escape(char)
