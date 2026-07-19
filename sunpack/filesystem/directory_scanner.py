from pathlib import Path
import re

from sunpack_native import (
    filter_inventory_file_indices as _NATIVE_FILTER_INVENTORY_FILE_INDICES,
    scan_directory_snapshot as _NATIVE_SCAN_DIRECTORY_SNAPSHOT,
)

from sunpack.contracts.filesystem import DirectorySnapshot, FileEntry
from sunpack.config.detection_view import directory_scan_is_recursive
from sunpack.filesystem.filters import build_filters
from sunpack.filesystem.filters.base import ScanCandidate, ScanFilter
from sunpack.filesystem.filters.modules.directory_prune import (
    path_globs as directory_path_globs,
    prune_dir_globs as directory_prune_dir_globs,
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
        if not directory_scan_is_recursive(config or {}):
            return 0
        return None

    def scan(self) -> DirectorySnapshot:
        return self._scan_native()

    @classmethod
    def snapshot_from_entries(
        cls,
        root_path: str,
        entries: list[FileEntry],
        *,
        config: dict | None = None,
        start_filter: str | None = None,
        stop_before_filter: str | None = None,
    ) -> DirectorySnapshot:
        """Apply the normal ordered filters to an already collected file table."""
        scanner = cls(root_path, config=config)
        return DirectorySnapshot.from_entries(
            root_path=scanner.root_path,
            entries=scanner._apply_ordered_filters(
                list(entries),
                start_filter=start_filter,
                stop_before_filter=stop_before_filter,
            ),
        )

    @classmethod
    def inventory_file_indices(
        cls,
        root_path: str,
        paths: list[str],
        sizes: list[int],
        *,
        config: dict | None = None,
    ) -> list[int]:
        scanner = cls(root_path, config=config)
        options = scanner._native_inventory_filter_options()
        if options is None:
            return list(range(len(paths)))
        return list(_NATIVE_FILTER_INVENTORY_FILE_INDICES(
            str(scanner.root_path),
            paths,
            sizes,
            options["patterns"],
            options["prune_dir_globs"],
            options["blocked_extensions"],
            options["blocked_file_names"],
            options["size_ranges"],
            options["whitelist_rules"],
        ))

    def _native_inventory_filter_options(self) -> dict | None:
        return self._native_filter_options()

    def _scan_native(self) -> DirectorySnapshot | None:
        options = self._native_scan_options()
        if options is None:
            raise RuntimeError("Native directory scan requires built-in filesystem filters only")
        native_snapshot = _NATIVE_SCAN_DIRECTORY_SNAPSHOT(
            str(self.root_path),
            self.max_depth,
            options["patterns"],
            options["prune_dir_globs"],
            options["blocked_extensions"],
            options["blocked_file_names"],
            options["size_ranges"],
            options["mtime_ranges"],
            options["whitelist_rules"],
        )
        root_path = self.root_path.parent if self.root_path.is_file() else self.root_path
        return DirectorySnapshot.from_native(root_path, native_snapshot)

    def _native_scan_options(self) -> dict | None:
        return self._native_filter_options()

    def _native_filter_options(self) -> dict | None:
        if self._custom_filters:
            return None

        patterns: list[str] = []
        prune_dir_globs: list[str] = []
        blocked_extensions: list[str] = []
        blocked_file_names: list[str] = []
        size_ranges: list[tuple] = []
        mtime_ranges: list[tuple] = []
        whitelist_rules: list[tuple] = []
        for scan_filter in self.filters:
            name = getattr(scan_filter, "name", "")
            stage = getattr(scan_filter, "stage", "")
            if name == "directory_prune":
                prune_config = getattr(scan_filter, "config", {}) or {}
                prune_dir_globs.extend(directory_prune_dir_globs(prune_config))
                patterns.extend(_path_glob_to_regex(item) for item in directory_path_globs(prune_config))
                continue
            if name == "blacklist" and stage == "path":
                blocked_extensions.extend(getattr(scan_filter, "blocked_extensions", []) or [])
                blocked_file_names.extend(getattr(scan_filter, "blocked_files", []) or [])
                continue
            if name == "size_range" and stage == "size":
                value_range = getattr(scan_filter, "value_range", None)
                if value_range is None:
                    return None
                size_ranges.append(_numeric_range_tuple(value_range))
                continue
            if name == "whitelist":
                whitelist_rules.append((
                    list(getattr(scan_filter, "path_patterns", []) or []),
                    list(getattr(scan_filter, "prune_dirs", []) or []),
                    list(getattr(scan_filter, "file_patterns", []) or []),
                    list(getattr(scan_filter, "allowed_extensions", []) or []),
                ))
                continue
            if name == "mtime_range":
                value_range = getattr(scan_filter, "value_range", None)
                if value_range is None:
                    return None
                mtime_ranges.append(_numeric_range_tuple(value_range))
                continue
            return None

        return {
            "patterns": patterns,
            "prune_dir_globs": prune_dir_globs,
            "blocked_extensions": blocked_extensions,
            "blocked_file_names": blocked_file_names,
            "size_ranges": size_ranges,
            "mtime_ranges": mtime_ranges,
            "whitelist_rules": whitelist_rules,
        }

    def _apply_ordered_filters(
        self,
        entries: list[FileEntry],
        *,
        start_filter: str | None = None,
        stop_before_filter: str | None = None,
    ) -> list[FileEntry]:
        if not self.filters:
            return entries

        current = entries
        started = start_filter is None
        for scan_filter in self.filters:
            name = getattr(scan_filter, "name", "")
            if not started:
                if name != start_filter:
                    continue
                started = True
            if stop_before_filter is not None and name == stop_before_filter:
                break
            if name == "directory_prune":
                continue
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


def _numeric_range_tuple(value_range) -> tuple:
    return tuple(
        getattr(value_range, field, None)
        for field in ("gt", "gte", "lt", "lte", "eq")
    )
