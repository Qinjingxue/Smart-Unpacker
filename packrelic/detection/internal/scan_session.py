from typing import Any, List

from packrelic_native import batch_file_head_facts as _native_batch_file_head_facts

from packrelic.contracts.detection import FactBag
from packrelic.contracts.filesystem import DirectorySnapshot
from packrelic.detection.internal.target_groups import relation_group_to_fact_bag
from packrelic.filesystem.directory_scanner import DirectoryScanner
from packrelic.relations import CandidateGroup, RelationsScheduler
from packrelic.support.path_keys import normalized_path, path_key, safe_relative_path


class DetectionScanSession:
    """Directory-scoped cache for candidate construction."""

    def __init__(self, relations: RelationsScheduler | None = None, config: dict | None = None):
        self.relations = relations or RelationsScheduler()
        self.config = config or {}
        self._snapshots: dict[str, DirectorySnapshot] = {}
        self._scene_snapshots: dict[str, DirectorySnapshot] = {}
        self._relation_groups: dict[str, List[CandidateGroup]] = {}
        self._fact_bags: dict[str, List[FactBag]] = {}
        self._file_head_facts: dict[str, dict[str, Any]] = {}
        self._directory_identities: dict[str, tuple[str, int, tuple]] = {}
        self._scan_roots: list[str] = []

    def set_scan_roots(self, roots: list[str]) -> None:
        self._scan_roots = []
        seen: set[str] = set()
        for root in roots:
            normalized = normalized_path(root)
            key = path_key(normalized)
            if not normalized or key in seen:
                continue
            seen.add(key)
            self._scan_roots.append(normalized)

    def is_within_scan_scope(self, path: str) -> bool:
        if not self._scan_roots:
            return True
        path = normalized_path(path)
        path_scope_key = path_key(path)
        for root in self._scan_roots:
            if path_scope_key == path_key(root) or safe_relative_path(path, root) is not None:
                return True
        return False

    def snapshot_for_directory(self, directory: str) -> DirectorySnapshot:
        return self._snapshot_for_directory(directory, max_depth=None)

    def shallow_snapshot_for_directory(self, directory: str, max_depth: int) -> DirectorySnapshot:
        full_key = self._snapshot_key(directory, max_depth=None)
        if full_key in self._snapshots:
            return self._snapshots[full_key]
        return self._snapshot_for_directory(directory, max_depth=max_depth)

    def scene_snapshot_for_directory(self, directory: str, max_depth: int) -> DirectorySnapshot:
        key = self._snapshot_key(directory, max_depth)
        if key not in self._scene_snapshots:
            self._scene_snapshots[key] = DirectoryScanner(directory, max_depth=max_depth, config={}).scan()
        return self._scene_snapshots[key]

    def _snapshot_for_directory(self, directory: str, max_depth: int | None) -> DirectorySnapshot:
        key = self._snapshot_key(directory, max_depth)
        if key not in self._snapshots:
            self._snapshots[key] = DirectoryScanner(directory, max_depth=max_depth, config=self.config).scan()
        return self._snapshots[key]

    def relation_groups_for_directory(self, directory: str) -> List[CandidateGroup]:
        key = self._directory_key(directory)
        if key not in self._relation_groups:
            snapshot = self.snapshot_for_directory(directory)
            self._relation_groups[key] = self.relations.build_candidate_groups(snapshot)
        return self._relation_groups[key]

    def fact_bags_for_directory(self, directory: str) -> List[FactBag]:
        key = self._directory_key(directory)
        if key not in self._fact_bags:
            self._fact_bags[key] = [
                relation_group_to_fact_bag(group)
                for group in self.relation_groups_for_directory(directory)
            ]
        return self._fact_bags[key]

    def logical_name_for_archive(self, filename: str) -> str:
        return self.relations.logical_name_for_archive(filename)

    def file_head_facts_for_paths(self, paths: list[str], *, magic_size: int = 16) -> dict[str, dict[str, Any]]:
        requested = [normalized_path(path) for path in paths if path]
        missing = [
            path for path in requested
            if self._file_head_fetch_needed(path, magic_size=magic_size)
        ]
        if missing:
            rows = _native_batch_file_head_facts(missing, max(0, int(magic_size or 0)))
            seen = set()
            for row in rows:
                if not isinstance(row, dict) or not row.get("path"):
                    continue
                key = path_key(row.get("path"))
                seen.add(key)
                self._file_head_facts[key] = {
                    "path": str(row.get("path") or ""),
                    "exists": bool(row.get("exists")),
                    "is_file": bool(row.get("is_file")),
                    "size": row.get("size"),
                    "mtime_ns": row.get("mtime_ns"),
                    "magic": row.get("magic") if isinstance(row.get("magic"), bytes) else b"",
                }
            for path in missing:
                key = path_key(path)
                if key not in seen:
                    self._file_head_facts[key] = {
                        "path": path,
                        "exists": False,
                        "is_file": False,
                        "size": None,
                        "mtime_ns": None,
                        "magic": b"",
                    }
        return {
            path_key(path): dict(self._file_head_facts.get(path_key(path), {}))
            for path in requested
        }

    def file_head_facts_for_path(self, path: str, *, magic_size: int = 16) -> dict[str, Any]:
        return self.file_head_facts_for_paths([path], magic_size=magic_size).get(path_key(path), {})

    def file_identity_for_path(self, path: str) -> tuple[str, int, int]:
        key = path_key(path)
        facts = self.file_head_facts_for_path(path, magic_size=0)
        size = facts.get("size")
        mtime_ns = facts.get("mtime_ns")
        if isinstance(size, int) and isinstance(mtime_ns, int):
            return key, size, mtime_ns
        return key, 0, 0

    def directory_identity_for_path(self, directory: str) -> tuple[str, int, tuple]:
        key = self._directory_key(directory)
        if key not in self._directory_identities:
            snapshot = self.shallow_snapshot_for_directory(directory, max_depth=0)
            entries = []
            for entry in snapshot.entries:
                if path_key(entry.path.parent) != key:
                    continue
                entries.append((
                    entry.path.name.lower(),
                    bool(entry.is_dir),
                    int(entry.size or 0),
                    int(entry.mtime_ns or 0),
                ))
            self._directory_identities[key] = (key, len(entries), tuple(sorted(entries)))
        return self._directory_identities[key]

    def _directory_key(self, directory: str) -> str:
        return path_key(directory)

    def _snapshot_key(self, directory: str, max_depth: int | None) -> str:
        return f"{self._directory_key(directory)}::{max_depth}"

    def _file_head_fetch_needed(self, path: str, *, magic_size: int) -> bool:
        facts = self._file_head_facts.get(path_key(path))
        if facts is None:
            return True
        return bool(magic_size > 0 and facts.get("is_file") and not facts.get("magic"))
