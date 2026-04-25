import os
from typing import List

from smart_unpacker.contracts.detection import FactBag
from smart_unpacker.contracts.filesystem import DirectorySnapshot
from smart_unpacker.detection.internal.target_groups import relation_group_to_fact_bag
from smart_unpacker.filesystem.directory_scanner import DirectoryScanner
from smart_unpacker.relations.scheduler import CandidateGroup, RelationsScheduler


class DetectionScanSession:
    """Directory-scoped cache for candidate construction."""

    def __init__(self, relations: RelationsScheduler | None = None, config: dict | None = None):
        self.relations = relations or RelationsScheduler()
        self.config = config or {}
        self._snapshots: dict[str, DirectorySnapshot] = {}
        self._relation_groups: dict[str, List[CandidateGroup]] = {}
        self._fact_bags: dict[str, List[FactBag]] = {}

    def snapshot_for_directory(self, directory: str) -> DirectorySnapshot:
        return self._snapshot_for_directory(directory, max_depth=None)

    def shallow_snapshot_for_directory(self, directory: str, max_depth: int) -> DirectorySnapshot:
        full_key = self._snapshot_key(directory, max_depth=None)
        if full_key in self._snapshots:
            return self._snapshots[full_key]
        return self._snapshot_for_directory(directory, max_depth=max_depth)

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
        return self.relations.get_logical_name(filename, is_archive=True)

    def _directory_key(self, directory: str) -> str:
        return os.path.normcase(os.path.normpath(directory))

    def _snapshot_key(self, directory: str, max_depth: int | None) -> str:
        return f"{self._directory_key(directory)}::{max_depth}"
