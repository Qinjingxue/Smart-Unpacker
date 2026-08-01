from __future__ import annotations

import json
import threading
from collections import OrderedDict

from sunpack.analysis.result import ArchiveAnalysisReport
from sunpack.contracts.tasks import ArchiveTask
from sunpack.repair_inspection.request import RepairInspectionRequest
from sunpack.support import archive_knowledge_projection as knowledge_view


class RepairInspectionCache:
    def __init__(self, max_entries: int = 512):
        self.max_entries = max(0, int(max_entries or 0))
        self._items: OrderedDict[tuple, ArchiveAnalysisReport] = OrderedDict()
        self._lock = threading.Lock()

    def key(self, task: ArchiveTask, request: RepairInspectionRequest) -> tuple:
        state = task.archive_state()
        source = knowledge_view.source_fingerprint(task)
        return (
            "inspection",
            json.dumps(source, ensure_ascii=False, sort_keys=True, default=str),
            state.effective_patch_digest(),
            tuple(sorted(item.value for item in request.capabilities)),
            json.dumps(request.initial_prepass or {}, ensure_ascii=False, sort_keys=True, default=str),
        )

    def get(self, key: tuple) -> ArchiveAnalysisReport | None:
        with self._lock:
            value = self._items.get(key)
            if value is not None:
                self._items.move_to_end(key)
            return value

    def put(self, key: tuple, report: ArchiveAnalysisReport) -> None:
        if self.max_entries <= 0:
            return
        with self._lock:
            self._items[key] = report
            self._items.move_to_end(key)
            while len(self._items) > self.max_entries:
                self._items.popitem(last=False)

    def clear(self) -> None:
        with self._lock:
            self._items.clear()
