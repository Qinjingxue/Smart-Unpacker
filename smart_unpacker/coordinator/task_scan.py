import os
from typing import Any, Dict, List

from smart_unpacker.config.detection_view import detection_config, rule_pipeline_config
from smart_unpacker.coordinator.context import RunContext
from smart_unpacker.detection import DetectionScheduler
from smart_unpacker.contracts.tasks import ArchiveTask
from smart_unpacker.relations.internal.group_builder import RelationsGroupBuilder


STANDARD_ARCHIVE_EXTS = {".7z", ".zip", ".rar", ".gz", ".bz2", ".xz"}


class ArchiveTaskScanner:
    def __init__(self, config: Dict[str, Any], context: RunContext):
        self.config = config
        self.detector = DetectionScheduler(config)
        self.context = context
        self._relations = RelationsGroupBuilder()

    def scan_root(self, scan_root: str) -> List[ArchiveTask]:
        return self.scan_targets([scan_root])

    def scan_targets(self, scan_roots: List[str]) -> List[ArchiveTask]:
        if self._detection_pipeline_disabled():
            return self._scan_standard_archive_targets(scan_roots)

        tasks: List[ArchiveTask] = []
        for detection in self.detector.detect_targets(scan_roots):
            bag = detection.fact_bag
            if not bag.get("candidate.entry_path"):
                continue

            decision = detection.decision
            if decision.should_extract:
                task = ArchiveTask.from_fact_bag(bag, decision.total_score, decision=decision)
                if task.key in self.context.processed_keys:
                    continue
                tasks.append(task)
        return tasks

    def _scan_standard_archive_targets(self, scan_roots: List[str]) -> List[ArchiveTask]:
        tasks: List[ArchiveTask] = []
        for bag in self.detector.build_candidate_fact_bags(scan_roots):
            main_path = bag.get("candidate.entry_path")
            if not main_path or not self._is_standard_archive_candidate(main_path, bag):
                continue
            task = ArchiveTask.from_fact_bag(bag, score=0)
            if task.key in self.context.processed_keys:
                continue
            tasks.append(task)
        return tasks

    def _detection_pipeline_disabled(self) -> bool:
        detector_config = detection_config(self.config)
        if self._has_enabled_modules(detector_config.get("fact_collectors")):
            return False
        if self._has_enabled_modules(detector_config.get("processors")):
            return False
        pipeline = rule_pipeline_config(self.config)
        for layer in ("precheck", "scoring", "confirmation"):
            if self._has_enabled_modules(pipeline.get(layer)):
                return False
        return True

    def _has_enabled_modules(self, modules_config) -> bool:
        if not isinstance(modules_config, list):
            return False
        return any(isinstance(item, dict) and item.get("enabled", False) for item in modules_config)

    def _is_standard_archive_candidate(self, path: str, bag) -> bool:
        name = os.path.basename(path).lower()
        ext = os.path.splitext(name)[1]
        if ext in STANDARD_ARCHIVE_EXTS:
            return True
        if self._relations.detect_split_role(name) == "first":
            return True
        if ext == ".exe" and bag.get("relation.is_split_exe_companion"):
            return True
        return False
