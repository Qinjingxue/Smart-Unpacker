import os
from typing import Any

from packrelic.config.detection_view import detection_config, rule_pipeline_config
from packrelic.contracts.detection import FactBag
from packrelic.contracts.tasks import ArchiveTask
from packrelic.detection.scheduler import DetectionScheduler
from packrelic.relations.scheduler import RelationsScheduler


STANDARD_ARCHIVE_EXTS = {".7z", ".zip", ".rar", ".tar", ".gz", ".bz2", ".xz", ".zst"}


class ArchiveTaskProvider:
    """Public detection facade that turns detection decisions into archive tasks."""

    def __init__(self, config: dict[str, Any]):
        self.config = config
        self.detector = DetectionScheduler(config)
        self._relations = RelationsScheduler()
        self.failed_candidates: list[str] = []

    def scan_targets(self, scan_roots: list[str], processed_keys: set[str] | None = None) -> list[ArchiveTask]:
        processed_keys = processed_keys or set()
        self.failed_candidates = []
        if self._detection_pipeline_disabled():
            return self._scan_standard_archive_targets(scan_roots, processed_keys)

        tasks: list[ArchiveTask] = []
        fact_bags = self._filter_incomplete_split_groups(self.detector.build_candidate_fact_bags(scan_roots))
        for detection in self.detector.evaluate_bags(fact_bags):
            bag = detection.fact_bag
            if not bag.get("candidate.entry_path"):
                continue

            decision = detection.decision
            if decision.should_extract:
                task = ArchiveTask.from_fact_bag(bag, decision.total_score, decision=decision)
                if task.key in processed_keys:
                    continue
                tasks.append(task)
        return tasks

    def _scan_standard_archive_targets(
        self,
        scan_roots: list[str],
        processed_keys: set[str],
    ) -> list[ArchiveTask]:
        tasks: list[ArchiveTask] = []
        for bag in self._filter_incomplete_split_groups(self.detector.build_candidate_fact_bags(scan_roots)):
            main_path = bag.get("candidate.entry_path")
            if not main_path or not self._is_standard_archive_candidate(main_path, bag):
                continue
            task = ArchiveTask.from_fact_bag(bag, score=0)
            if task.key in processed_keys:
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

    def _filter_incomplete_split_groups(self, bags: list[FactBag]) -> list[FactBag]:
        filtered = []
        seen_failures = set()
        for bag in bags:
            if bag.get("relation.split_group_complete") is False:
                message = self._incomplete_split_failure_message(bag)
                if message not in seen_failures:
                    seen_failures.add(message)
                    self.failed_candidates.append(message)
                continue
            filtered.append(bag)
        return filtered

    def _incomplete_split_failure_message(self, bag: FactBag) -> str:
        path = bag.get("candidate.entry_path") or bag.get("file.path") or ""
        name = os.path.basename(path) or str(bag.get("candidate.logical_name") or "split archive")
        return f"{name} [分卷缺失或不完整]"
