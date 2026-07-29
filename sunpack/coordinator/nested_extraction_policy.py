from __future__ import annotations

from dataclasses import dataclass
import os
from typing import Any

from sunpack_native import authorize_nested_candidates as _NATIVE_AUTHORIZE_NESTED_CANDIDATES

from sunpack.contracts.tasks import ArchiveTask
from sunpack.coordinator.scan_session import DetectionScanSession
from sunpack.support.path_keys import normalized_path, safe_relative_path


@dataclass(frozen=True)
class NestedAuthorizationBatch:
    allowed_tasks: list[ArchiveTask]
    skipped: list[dict[str, Any]]


class NestedExtractionPolicy:
    """Authorize detected archive tasks from raw filesystem context in one batch."""

    def __init__(self, config: dict[str, Any]):
        raw = config.get("nested_extraction_policy", {})
        self.config = raw if isinstance(raw, dict) else {}

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
