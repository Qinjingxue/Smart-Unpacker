import os
from typing import Any

from sunpack.config.detection_view import detection_config, rule_pipeline_config
from sunpack.contracts.detection import FactBag
from sunpack.contracts.failures import FailureInfo
from sunpack.contracts.tasks import ArchiveTask
from sunpack.detection.knowledge import write_detection_task
from sunpack.detection.scheduler import DetectionScheduler
from sunpack.detection.options import DetectionOptions
from sunpack.coordinator.scan_session import DetectionScanSession
from sunpack.coordinator.target_scan import build_fact_bags_for_targets
from sunpack.filesystem.knowledge import write_filesystem_task
from sunpack.relations.knowledge import write_relation_task
from sunpack.relations.scheduler import RelationsScheduler


STANDARD_ARCHIVE_EXTS = {".7z", ".zip", ".rar", ".tar", ".gz", ".bz2", ".xz", ".zst"}


class ArchiveTaskProvider:
    """Public detection facade that turns detection decisions into archive tasks."""

    def __init__(self, config: dict[str, Any], detection_options: DetectionOptions | None = None):
        self.config = config
        self.detection_options = detection_options or DetectionOptions()
        self.detector = DetectionScheduler(config, options=self.detection_options)
        self._relations = RelationsScheduler()
        self.failed_candidates: list[str] = []
        self.failed_candidate_failures: list[FailureInfo] = []

    def scan_targets(
        self,
        scan_roots: list[str],
        processed_keys: set[str] | None = None,
        scan_session: DetectionScanSession | None = None,
        *,
        is_recursive_scan: bool = False,
    ) -> list[ArchiveTask]:
        processed_keys = processed_keys or set()
        self.failed_candidates = []
        self.failed_candidate_failures = []
        if self._detection_pipeline_disabled():
            return self._scan_standard_archive_targets(scan_roots, processed_keys, scan_session=scan_session)

        tasks: list[ArchiveTask] = []
        for detection in self.detect_targets(scan_roots, scan_session=scan_session, is_recursive_scan=is_recursive_scan):
            bag = detection.fact_bag
            if not bag.get("candidate.entry_path"):
                continue

            decision = detection.decision
            if decision.should_extract:
                task = ArchiveTask.from_fact_bag(bag, decision.total_score, decision=decision)
                _write_initial_task_knowledge(task)
                if task.key in processed_keys:
                    continue
                tasks.append(task)
        return tasks

    def task_from_candidate_bag(self, bag: FactBag) -> ArchiveTask | None:
        """Re-enter detection for one Relations hypothesis."""
        if not bag.get("candidate.entry_path"):
            return None
        if self._detection_pipeline_disabled():
            task = ArchiveTask.from_fact_bag(bag, score=0)
        else:
            decision = self.detector.evaluate_bag(bag)
            if not decision.should_extract:
                return None
            task = ArchiveTask.from_fact_bag(bag, decision.total_score, decision=decision)
        _write_initial_task_knowledge(task)
        return task

    def resolve_volume_once_in_directory(
        self,
        current_paths: list[str],
        *,
        format_hint: str = "",
    ):
        return self._relations.resolve_volume_once_in_directory(
            current_paths,
            format_hint=format_hint,
        )

    def _scan_standard_archive_targets(
        self,
        scan_roots: list[str],
        processed_keys: set[str],
        *,
        scan_session: DetectionScanSession | None = None,
    ) -> list[ArchiveTask]:
        tasks: list[ArchiveTask] = []
        scan_session = scan_session or DetectionScanSession(config=self.config)
        candidate_bags = build_fact_bags_for_targets(scan_roots, session=scan_session, config=self.config)
        for bag in self._filter_incomplete_split_groups(candidate_bags):
            main_path = bag.get("candidate.entry_path")
            if not main_path or not self._is_standard_archive_candidate(main_path, bag):
                continue
            task = ArchiveTask.from_fact_bag(bag, score=0)
            _write_initial_task_knowledge(task)
            if task.key in processed_keys:
                continue
            tasks.append(task)
        return tasks

    def detect_targets(
        self,
        scan_roots: list[str],
        *,
        scan_session: DetectionScanSession | None = None,
        is_recursive_scan: bool = False,
    ):
        scan_session = scan_session or DetectionScanSession(config=self.config)
        candidate_bags = build_fact_bags_for_targets(scan_roots, session=scan_session, config=self.config)
        fact_bags = self._filter_incomplete_split_groups(candidate_bags)
        if self.detection_options.deep_scan:
            return self.detector.evaluate_bags(fact_bags, scan_session=scan_session)

        # Establish strict precheck outcomes first.  Candidates that survive
        # are eligible for the existing embedded-scan policy before fuzzy
        # scoring gets a chance to accept one incidental archive signature.
        _precheck_decisions, surviving = self.detector.evaluate_precheck_pool(
            fact_bags,
            scan_session=scan_session,
        )
        ratio = self._embedded_deep_scan_single_candidate_ratio()
        if ratio > 0.0:
            selected = (
                _select_single_candidate_ratio(surviving, ratio)
                if is_recursive_scan
                else surviving
            )
            for bag in selected:
                bag.set("candidate.embedded_payload_precheck_enabled", True)
                bag.unset("embedded_archive.analysis")

        # Re-running precheck is cheap because its facts are already cached.
        # Selected survivors now enter embedded_payload_identity first; a
        # failed embedded scan passes through to the unchanged scoring layer.
        return self.detector.evaluate_bags(fact_bags, scan_session=scan_session)

    def _embedded_deep_scan_single_candidate_ratio(self) -> float:
        embedded_config = self.config.get("embedded_scan")
        if isinstance(embedded_config, dict) and not bool(embedded_config.get("enabled", True)):
            return 0.0
        pipeline = rule_pipeline_config(self.config)
        precheck = pipeline.get("precheck") if isinstance(pipeline.get("precheck"), list) else []
        for item in precheck:
            if not isinstance(item, dict) or item.get("name") != "embedded_payload_identity":
                continue
            if item.get("enabled", False) is False:
                return 0.0
            value = item.get("deep_scan_single_candidate_ratio", 0.3)
            try:
                return min(1.0, max(0.0, float(value)))
            except (TypeError, ValueError):
                return 0.0
        return 0.0

    def _detection_pipeline_disabled(self) -> bool:
        if self.detection_options.deep_scan:
            return False
        detector_config = detection_config(self.config)
        if detector_config.get("enabled") is False:
            return True
        if self._has_enabled_modules(detector_config.get("fact_collectors")):
            return False
        if self._has_enabled_modules(detector_config.get("processors")):
            return False
        pipeline = rule_pipeline_config(self.config)
        for layer in ("precheck", "scoring"):
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
        """Preserve relation hints without treating filename inference as failure evidence."""
        return list(bags)


def _write_initial_task_knowledge(task: ArchiveTask) -> None:
    write_filesystem_task(task)
    write_relation_task(task)
    write_detection_task(task)


def _select_single_candidate_ratio(fact_bags: list[FactBag], ratio: float) -> list[FactBag]:
    """Select every logical candidate whose size reaches the configured share."""
    sized = [
        (size, str(bag.get("file.path") or ""), bag)
        for bag in fact_bags
        if (size := _logical_candidate_size(bag)) > 0
    ]
    if not sized or ratio <= 0.0:
        return []
    sized.sort(key=lambda item: (-item[0], os.path.normcase(os.path.normpath(item[1]))))
    total_size = sum(size for size, _path, _bag in sized)
    threshold = total_size * min(1.0, ratio)
    return [bag for size, _path, bag in sized if size >= threshold]


def _logical_candidate_size(bag: FactBag) -> int:
    paths = bag.get("candidate.member_paths")
    if isinstance(paths, list) and len(paths) > 1:
        total = 0
        seen: set[str] = set()
        for raw_path in paths:
            if not isinstance(raw_path, str) or not raw_path:
                continue
            normalized = os.path.normcase(os.path.normpath(raw_path))
            if normalized in seen:
                continue
            seen.add(normalized)
            try:
                total += os.path.getsize(raw_path)
            except OSError:
                continue
        if total > 0:
            return total
    size = bag.get("file.size")
    return int(size) if isinstance(size, int) and size > 0 else 0
