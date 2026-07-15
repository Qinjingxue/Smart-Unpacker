import os
from copy import deepcopy
from typing import Any

from sunpack.config.detection_view import detection_config, rule_pipeline_config
from sunpack.contracts.detection import FactBag
from sunpack.contracts.failures import FailureInfo, FailureKind
from sunpack.contracts.tasks import ArchiveTask
from sunpack.detection.knowledge import write_detection_task
from sunpack.detection.scheduler import DetectionScheduler
from sunpack.analysis.stage import ArchiveAnalysisStage
from sunpack.coordinator.scan_session import DetectionScanSession
from sunpack.coordinator.target_scan import build_fact_bags_for_targets
from sunpack.filesystem.knowledge import write_filesystem_task
from sunpack.relations.knowledge import write_relation_task
from sunpack.relations.scheduler import RelationsScheduler
from sunpack.i18n import I18nContext


STANDARD_ARCHIVE_EXTS = {".7z", ".zip", ".rar", ".tar", ".gz", ".bz2", ".xz", ".zst"}


class ArchiveTaskProvider:
    """Public detection facade that turns detection decisions into archive tasks."""

    def __init__(self, config: dict[str, Any], analysis_stage: ArchiveAnalysisStage | None = None):
        self.config = config
        cli_config = config.get("cli") if isinstance(config.get("cli"), dict) else {}
        self.i18n = I18nContext(cli_config.get("language"))
        self.detector = DetectionScheduler(config)
        self._relations = RelationsScheduler()
        self.analysis_stage = analysis_stage or ArchiveAnalysisStage(config)
        rescue_config = deepcopy(config)
        detector_config = detection_config(config)
        rescue_prepass = rescue_config.setdefault("analysis", {}).setdefault("prepass", {})
        rescue_prepass.setdefault("full_scan_max_bytes", int(detector_config.get("content_structure_rescue_full_scan_max_bytes", 64 * 1024 * 1024) or 0))
        rescue_prepass.setdefault("deep_scan", bool(detector_config.get("content_structure_rescue_deep_scan", False)))
        deep_rescue_config = deepcopy(rescue_config)
        rescue_fuzzy = rescue_config.setdefault("analysis", {}).setdefault("fuzzy", {})
        rescue_fuzzy.setdefault(
            "enabled",
            bool(detector_config.get("content_structure_rescue_fuzzy", False)),
        )
        self.rescue_analysis_stage = ArchiveAnalysisStage(
            rescue_config,
            executor_pool=self.analysis_stage.executor_pool,
            module_executor_pool=self.analysis_stage.module_executor_pool,
            workload_executor=self.analysis_stage.workload_executor,
        )
        self.deep_rescue_analysis_stage = ArchiveAnalysisStage(
            deep_rescue_config,
            executor_pool=self.analysis_stage.executor_pool,
            module_executor_pool=self.analysis_stage.module_executor_pool,
            workload_executor=self.analysis_stage.workload_executor,
        )
        self.failed_candidates: list[str] = []
        self.failed_candidate_failures: list[FailureInfo] = []

    def scan_targets(
        self,
        scan_roots: list[str],
        processed_keys: set[str] | None = None,
        scan_session: DetectionScanSession | None = None,
    ) -> list[ArchiveTask]:
        processed_keys = processed_keys or set()
        self.failed_candidates = []
        self.failed_candidate_failures = []
        if self._detection_pipeline_disabled():
            return self._scan_standard_archive_targets(scan_roots, processed_keys, scan_session=scan_session)

        tasks: list[ArchiveTask] = []
        for detection in self.detect_targets(scan_roots, scan_session=scan_session):
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
    ):
        scan_session = scan_session or DetectionScanSession(config=self.config)
        candidate_bags = build_fact_bags_for_targets(scan_roots, session=scan_session, config=self.config)
        fact_bags = self._filter_incomplete_split_groups(candidate_bags)
        detections = self.detector.evaluate_bags(fact_bags, scan_session=scan_session)
        rescue_rows = []
        for index, detection in enumerate(detections):
            if self._structure_rescue_eligible(detection.fact_bag, detection.decision):
                rescue_rows.append((index, ArchiveTask.from_fact_bag(
                    detection.fact_bag,
                    score=detection.decision.total_score,
                    decision=detection.decision,
                )))
        reports = self._analyze_rescue_batch([task for _index, task in rescue_rows])
        reports_by_index = {
            index: report
            for (index, _task), report in zip(rescue_rows, reports)
        }
        return [
            type(detection)(
                fact_bag=detection.fact_bag,
                decision=self._refine_with_structure_rescue(
                    detection.fact_bag,
                    detection.decision,
                    report=reports_by_index.get(index),
                ),
            )
            for index, detection in enumerate(detections)
        ]

    def _analyze_rescue_batch(self, tasks: list[ArchiveTask]):
        if not tasks:
            return []
        analyze_reports = getattr(self.rescue_analysis_stage, "analyze_reports", None)
        if callable(analyze_reports):
            reports = list(analyze_reports(tasks))
        else:
            reports = [self.rescue_analysis_stage.analyze_task(task) for task in tasks]
        deep_rows = [
            (index, task)
            for index, (task, report) in enumerate(zip(tasks, reports))
            if self._requires_deep_structure_rescue(task.fact_bag, report)
        ]
        if deep_rows:
            deep_analyze = getattr(self.deep_rescue_analysis_stage, "analyze_reports", None)
            deep_tasks = [task for _index, task in deep_rows]
            deep_reports = (
                list(deep_analyze(deep_tasks))
                if callable(deep_analyze)
                else [self.deep_rescue_analysis_stage.analyze_task(task) for task in deep_tasks]
            )
            for (index, _task), report in zip(deep_rows, deep_reports):
                reports[index] = report
        return reports

    @staticmethod
    def _requires_deep_structure_rescue(bag: FactBag, report) -> bool:
        if report is not None and list(getattr(report, "selected", []) or []):
            return False
        return bool(
            bag.get("relation.is_split_related")
            or bag.get("relation.is_split_member")
            or bag.get("relation.is_split_exe_companion")
            or bag.get("relation.is_disguised_split_exe_companion")
            or int(bag.get("relation.split_member_count") or 0) > 1
        )

    def _structure_rescue_eligible(self, bag: FactBag, decision) -> bool:
        if decision.should_extract or decision.discarded_at in {"precheck", "confirmation"}:
            return False
        # Extensions are deliberately excluded from this gate: SunPack's inputs
        # frequently have missing, misleading, or arbitrary suffixes. Every
        # undecided candidate receives the cheap signature/structure rescue pass.
        return bool(bag.get("candidate.entry_path") or bag.get("file.path"))

    def _refine_with_structure_rescue(self, bag: FactBag, decision, *, report=None):
        if decision.should_extract or decision.discarded_at in {"precheck", "confirmation"}:
            return decision
        path = str(bag.get("candidate.entry_path") or bag.get("file.path") or "")
        if not path:
            return decision
        if report is None:
            return decision
        task = ArchiveTask.from_fact_bag(bag, score=decision.total_score, decision=decision)
        self.analysis_stage.remember_report(task, report)
        candidates = list(report.selected)
        if not candidates:
            candidates = [item for item in report.evidences if item.segments and bool(item.details.get("password_required"))]
        if not candidates:
            return decision
        selected = max(candidates, key=lambda item: float(item.confidence or 0.0))
        first_segment = selected.segments[0] if selected.segments else None
        evidence = {
            "has_extractable": bool(report.has_extractable or selected.details.get("password_required")),
            "prepass": dict(report.prepass or {}),
            "read_bytes": int(report.read_bytes or 0),
            "selected": {
                "format": selected.format,
                "confidence": float(selected.confidence or 0.0),
                "start_offset": int(first_segment.start_offset or 0) if first_segment is not None else 0,
                "details": dict(selected.details or {}),
            },
        }
        return self.detector.refine_with_structure(bag, decision, evidence)

    def _detection_pipeline_disabled(self) -> bool:
        detector_config = detection_config(self.config)
        if detector_config.get("enabled") is False:
            return True
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
                    self.failed_candidate_failures.append(FailureInfo(
                        kind=FailureKind.MISSING_VOLUME,
                        stage="relation",
                        message=message,
                        message_key="failure.incomplete_split_suffix",
                        user_action="Wait for or provide the missing split archive volumes.",
                        details={
                            "path": str(bag.get("candidate.entry_path") or bag.get("file.path") or ""),
                            "split_family": str(bag.get("relation.split_family") or ""),
                            "missing_reason": str(bag.get("relation.split_missing_reason") or ""),
                            "missing_indices": list(bag.get("relation.split_missing_indices") or []),
                        },
                    ))
                continue
            filtered.append(bag)
        return filtered

    def _incomplete_split_failure_message(self, bag: FactBag) -> str:
        path = bag.get("candidate.entry_path") or bag.get("file.path") or ""
        name = os.path.basename(path) or str(bag.get("candidate.logical_name") or "split archive")
        return self.i18n.t("failure.incomplete_split_suffix", name=name)


def _write_initial_task_knowledge(task: ArchiveTask) -> None:
    write_filesystem_task(task)
    write_relation_task(task)
    write_detection_task(task)
