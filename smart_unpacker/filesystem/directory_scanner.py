import os
from pathlib import Path
from typing import List

from smart_unpacker.contracts.filesystem import DirectorySnapshot, FileEntry
from smart_unpacker.config.detection_view import DIRECTORY_SCAN_CURRENT_DIR_ONLY, directory_scan_mode
from smart_unpacker.filesystem.filters import build_filters
from smart_unpacker.filesystem.filters.base import ScanCandidate, ScanFilter

try:
    from smart_unpacker_native import scan_directory_entries as _NATIVE_SCAN_DIRECTORY_ENTRIES
except ImportError:
    _NATIVE_SCAN_DIRECTORY_ENTRIES = None


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

    def _filters_for_stage(self, stage: str):
        return [scan_filter for scan_filter in self.filters if getattr(scan_filter, "stage", None) == stage]

    def _accepted(self, candidate: ScanCandidate, stage: str) -> tuple[bool, bool]:
        prune_dir = False
        for scan_filter in self._filters_for_stage(stage):
            decision = scan_filter.evaluate(candidate)
            prune_dir = prune_dir or bool(decision.prune_dir)
            if decision.reject_entry:
                return False, prune_dir
        return True, prune_dir

    def _file_entry(self, path: Path) -> FileEntry | None:
        candidate = ScanCandidate(path=path, kind="file")
        accepted, _ = self._accepted(candidate, "path")
        if not accepted:
            return None
        try:
            stat = path.stat()
        except OSError:
            entry = FileEntry(path=path, is_dir=False)
            candidate = ScanCandidate(path=path, kind="file")
        else:
            entry = FileEntry(path=path, is_dir=False, size=stat.st_size, mtime_ns=stat.st_mtime_ns)
            candidate = ScanCandidate(path=path, kind="file", size=stat.st_size, mtime_ns=stat.st_mtime_ns)
        for stage in ("size", "mtime", "final"):
            accepted, _ = self._accepted(candidate, stage)
            if not accepted:
                return None
        return entry

    def _dir_entry(self, path: Path) -> tuple[FileEntry | None, bool]:
        candidate = ScanCandidate(path=path, kind="dir")
        accepted, prune_dir = self._accepted(candidate, "path")
        if not accepted:
            return None, prune_dir
        for stage in ("size", "mtime", "final"):
            accepted, stage_prune = self._accepted(candidate, stage)
            prune_dir = prune_dir or stage_prune
            if not accepted:
                return None, prune_dir
        return FileEntry(path=path, is_dir=True), prune_dir

    def scan(self) -> DirectorySnapshot:
        native_snapshot = self._scan_native()
        if native_snapshot is not None:
            return native_snapshot
        return self._scan_python()

    def _scan_python(self) -> DirectorySnapshot:
        entries: List[FileEntry] = []
        
        if not self.root_path.exists():
            return DirectorySnapshot(root_path=self.root_path, entries=[])

        if self.root_path.is_file():
            entry = self._file_entry(self.root_path)
            if entry is not None:
                entries.append(entry)
            return DirectorySnapshot(root_path=self.root_path.parent, entries=entries)

        try:
            for root, dirs, files in os.walk(str(self.root_path)):
                root_p = Path(root)
                if self.max_depth is not None:
                    try:
                        depth = len(root_p.relative_to(self.root_path).parts)
                    except ValueError:
                        depth = 0
                    if depth >= self.max_depth:
                        dirs[:] = []
                kept_dirs = []
                for d in list(dirs):
                    entry, prune = self._dir_entry(root_p / d)
                    if entry is not None:
                        entries.append(entry)
                    if not prune:
                        kept_dirs.append(d)
                dirs[:] = kept_dirs
                for f in files:
                    entry = self._file_entry(root_p / f)
                    if entry is not None:
                        entries.append(entry)
        except OSError:
            pass

        return DirectorySnapshot(root_path=self.root_path, entries=entries)

    def _scan_native(self) -> DirectorySnapshot | None:
        if _NATIVE_SCAN_DIRECTORY_ENTRIES is None or self._native_scan_disabled():
            return None
        options = self._native_scan_options()
        if options is None:
            return None
        try:
            rows = _NATIVE_SCAN_DIRECTORY_ENTRIES(
                str(self.root_path),
                self.max_depth,
                options["patterns"],
                options["prune_dirs"],
                options["blocked_extensions"],
                options["min_size"],
            )
        except Exception:
            return None

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
            if name == "size_minimum" and stage == "size":
                value = getattr(scan_filter, "min_inspection_size_bytes", None)
                if value is not None:
                    try:
                        min_size = int(value)
                    except (TypeError, ValueError):
                        return None
                continue
            return None

        return {
            "patterns": patterns,
            "prune_dirs": prune_dirs,
            "blocked_extensions": blocked_extensions,
            "min_size": min_size,
        }

    def _native_scan_disabled(self) -> bool:
        value = os.environ.get("SMART_UNPACKER_DISABLE_NATIVE_DIRECTORY_SCAN", "")
        return value.strip().lower() in {"1", "true", "yes", "on"}
