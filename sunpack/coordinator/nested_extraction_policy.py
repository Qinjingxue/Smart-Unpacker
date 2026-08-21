from __future__ import annotations

from dataclasses import dataclass
import os
from typing import Any

from sunpack_native import authorize_nested_candidates as _NATIVE_AUTHORIZE_NESTED_CANDIDATES

from sunpack.config.detection_view import rule_pipeline_config
from sunpack.contracts.detection import FactBag
from sunpack.contracts.tasks import ArchiveTask
from sunpack.coordinator.scan_session import DetectionScanSession
from sunpack.support.path_keys import normalized_path, safe_relative_path


EMBEDDED_SCAN_ALLOWED_FACT = "candidate.embedded_scan_allowed"
DEFAULT_DEEP_SCAN_SINGLE_CANDIDATE_RATIO = 0.3


@dataclass(frozen=True)
class NestedAuthorizationBatch:
    allowed_tasks: list[ArchiveTask]
    skipped: list[dict[str, Any]]


@dataclass(frozen=True)
class EmbeddedScanPlan:
    """Candidate-level embedded-scan permissions for one detection round."""

    recursive: bool
    allowed_bag_ids: frozenset[int]
    reason: str

    def allows(self, bag: FactBag) -> bool:
        return id(bag) in self.allowed_bag_ids

    def apply(self, fact_bags: list[FactBag]) -> None:
        """Materialize permissions before precheck starts."""

        for bag in fact_bags:
            bag.set(EMBEDDED_SCAN_ALLOWED_FACT, self.allows(bag))


class NestedExtractionPolicy:
    """Authorize detected archive tasks from raw filesystem context in one batch."""

    def __init__(self, config: dict[str, Any]):
        self.root_config = config
        raw = config.get("nested_extraction_policy", {})
        self.config = raw if isinstance(raw, dict) else {}

    def plan_embedded_scan(
        self,
        fact_bags: list[FactBag],
        *,
        is_recursive_scan: bool,
    ) -> EmbeddedScanPlan:
        """Authorize embedded analysis once, before the detection pipeline.

        Initial scans are allowed to inspect every candidate. Later recursive
        scans use the configured logical-candidate byte ratio. The rule and
        processor layers only consume the resulting fact; they do not make a
        second policy decision.
        """

        if not self._shared_embedded_scan_enabled():
            return EmbeddedScanPlan(
                recursive=is_recursive_scan,
                allowed_bag_ids=frozenset(),
                reason="shared_embedded_scan_disabled",
            )

        if not is_recursive_scan:
            return EmbeddedScanPlan(
                recursive=False,
                allowed_bag_ids=frozenset(id(bag) for bag in fact_bags),
                reason="initial_scan_all_candidates",
            )

        ratio = self._recursive_embedded_candidate_ratio()
        selected = select_single_candidate_ratio(fact_bags, ratio)
        return EmbeddedScanPlan(
            recursive=True,
            allowed_bag_ids=frozenset(id(bag) for bag in selected),
            reason=(
                "recursive_candidate_ratio"
                if selected
                else "recursive_candidate_ratio_selected_none"
            ),
        )

    def _shared_embedded_scan_enabled(self) -> bool:
        embedded_config = self.root_config.get("embedded_scan")
        if isinstance(embedded_config, dict):
            return bool(embedded_config.get("enabled", True))
        return True

    def _recursive_embedded_candidate_ratio(self) -> float:
        pipeline = rule_pipeline_config(self.root_config)
        precheck = pipeline.get("precheck") if isinstance(pipeline.get("precheck"), list) else []
        for item in precheck:
            if not isinstance(item, dict) or item.get("name") != "embedded_payload_identity":
                continue
            if item.get("enabled", False) is False:
                return 0.0
            value = item.get(
                "deep_scan_single_candidate_ratio",
                DEFAULT_DEEP_SCAN_SINGLE_CANDIDATE_RATIO,
            )
            try:
                return min(1.0, max(0.0, float(value)))
            except (TypeError, ValueError):
                return 0.0
        return 0.0

    def authorize_batch(
        self,
        tasks: list[ArchiveTask],
        scan_roots: list[str],
        scan_session: DetectionScanSession | None,
        *,
        round_index: int,
    ) -> NestedAuthorizationBatch:
        # The first round is the user's requested discovery scope.  This policy
        # only governs archives discovered from extraction output in later rounds.
        if not tasks or round_index <= 1 or not self.config.get("enabled", True):
            return NestedAuthorizationBatch(list(tasks), [])
        if scan_session is None:
            raise RuntimeError("Nested extraction authorization requires the detection scan session")

        directory_roots = sorted(
            {
                normalized_path(os.path.abspath(root))
                for root in scan_roots
                if root and os.path.isdir(root)
            },
            key=lambda value: len(value),
            reverse=True,
        )

        allowed_ids: set[int] = set()
        grouped: dict[str, list[ArchiveTask]] = {}
        skipped: list[dict[str, Any]] = []
        for task in tasks:
            root = next(
                (
                    candidate_root
                    for candidate_root in directory_roots
                    if safe_relative_path(task.main_path, candidate_root) is not None
                ),
                None,
            )
            if root is None:
                skipped.append({
                    "path": task.main_path,
                    "task_key": task.key,
                    "round": round_index,
                    "policy": "nested_extraction_policy",
                    "allowed": False,
                    "reason": "outside_scan_root",
                })
                continue
            grouped.setdefault(root, []).append(task)

        for root, root_tasks in grouped.items():
            snapshot = scan_session.snapshot_for_directory(root)
            candidates = [
                (
                    task.main_path,
                    list(task.all_parts or [task.main_path]),
                )
                for task in root_tasks
            ]
            rows = list(_NATIVE_AUTHORIZE_NESTED_CANDIDATES(
                snapshot.raw_native_snapshot,
                root,
                candidates,
                float(self.config.get("byte_ratio_exponent", 1.0)),
                float(self.config.get("project_ratio_exponent", 1.0)),
                float(self.config.get("authorization_bias", 0.0)),
                float(self.config.get("minimum_authorization_score", 0.85)),
                float(self.config.get("minimum_archive_byte_ratio", 0.1)),
                int(self.config.get("hard_maximum_other_projects", 1000)),
            ))
            if len(rows) != len(root_tasks):
                raise RuntimeError("Native nested extraction authorization returned an invalid row count")
            for task, raw_row in zip(root_tasks, rows):
                row = dict(raw_row)
                if row.get("allowed"):
                    allowed_ids.add(id(task))
                    continue
                skipped.append({
                    "path": task.main_path,
                    "task_key": task.key,
                    "round": round_index,
                    "policy": "nested_extraction_policy",
                    **row,
                })

        return NestedAuthorizationBatch(
            allowed_tasks=[task for task in tasks if id(task) in allowed_ids],
            skipped=skipped,
        )


def select_single_candidate_ratio(fact_bags: list[FactBag], ratio: float) -> list[FactBag]:
    """Select logical candidates meeting a share of the recursive byte pool."""

    sized = [
        (size, str(bag.get("file.path") or ""), bag)
        for bag in fact_bags
        if (size := logical_candidate_size(bag)) > 0
    ]
    if not sized or ratio <= 0.0:
        return []
    sized.sort(key=lambda item: (-item[0], os.path.normcase(os.path.normpath(item[1]))))
    total_size = sum(size for size, _path, _bag in sized)
    threshold = total_size * min(1.0, ratio)
    return [bag for size, _path, bag in sized if size >= threshold]


def logical_candidate_size(bag: FactBag) -> int:
    """Return one logical size, counting split members once."""

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
