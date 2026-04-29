from pathlib import Path

from sunpack_native import scan_directory_entries as _NATIVE_SCAN_DIRECTORY_ENTRIES

from sunpack.contracts.filesystem import DirectorySnapshot, FileEntry
from sunpack.config.detection_view import DIRECTORY_SCAN_CURRENT_DIR_ONLY, directory_scan_mode
from sunpack.filesystem.filters import build_filters
from sunpack.filesystem.filters.base import ScanCandidate, ScanFilter


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

        for scan_filter in self.filters:
            name = getattr(scan_filter, "name", "")
            stage = getattr(scan_filter, "stage", "")
            if name == "blacklist" and stage == "path":
                patterns.extend(getattr(scan_filter, "patterns", []) or [])
                prune_dirs.extend(getattr(scan_filter, "prune_dirs", []) or [])
                blocked_extensions.extend(getattr(scan_filter, "blocked_extensions", []) or [])
                continue
            if name in {"size_minimum", "size_range"} and stage == "size":
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
        return apply_ordered_filters_to_entries(entries, self.filters)

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
    pruned_dirs: list[Path] = []
    for entry in sorted(entries, key=lambda item: (len(item.path.parts), str(item.path).lower())):
        if _under_any(entry.path, pruned_dirs):
            continue
        decision = scan_filter.evaluate(ScanCandidate(
            path=entry.path,
            kind="dir" if entry.is_dir else "file",
            size=entry.size,
            mtime_ns=entry.mtime_ns,
        ))
        if decision.prune_dir and entry.is_dir:
            pruned_dirs.append(entry.path)
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
