from __future__ import annotations

from types import SimpleNamespace

import repair_training.policy.teacher as teacher_module
import sunpack.repair.search.recovery as recovery_module
from repair_training.policy.teacher import _RuntimeTeacherContext
from sunpack.contracts.archive_knowledge import ArchiveKnowledge
from sunpack.repair.job import RepairJob


class _FakeTask:
    def __init__(self):
        self._knowledge = ArchiveKnowledge({"source": {"input": {"path": "state.zip"}}})

    def knowledge(self) -> ArchiveKnowledge:
        return self._knowledge


def test_teacher_refresh_reads_archive_task_knowledge_via_current_api(tmp_path, monkeypatch):
    task = _FakeTask()
    monkeypatch.setattr(
        teacher_module,
        "ArchiveStateByteView",
        lambda state: SimpleNamespace(materialize=lambda path: tmp_path / "state.zip"),
    )
    monkeypatch.setattr(recovery_module, "task_for_materialized_recovery_state", lambda *args: task)
    monkeypatch.setattr(teacher_module, "write_zip_runtime_evidence_facts", lambda task: None)

    context = _RuntimeTeacherContext.__new__(_RuntimeTeacherContext)
    context.budget = {"teacher_refresh_analysis": True}
    context.workspace_root = tmp_path
    context.repair_inspection_service = SimpleNamespace(
        refresh_task=lambda task: task.knowledge().set("inspection.summary", {"format": "zip", "confidence": 1.0})
    )
    job = RepairJob(source_input={"kind": "file", "path": "original.zip"}, format="zip", archive_key="sample")
    recovery = SimpleNamespace(
        verification={"content_integrity": "payload_damaged", "container_integrity": "unknown"},
        extraction={"failure_kind": "data_error"},
    )

    refreshed = context._job_with_refreshed_knowledge(job, object(), recovery=recovery, step=1)

    assert refreshed is not job
    assert refreshed.knowledge["inspection"]["summary"]["format"] == "zip"
    assert refreshed.knowledge["verification"]["summary"]["content_integrity"] == "payload_damaged"
    assert refreshed.knowledge["extraction"]["failure"]["failure_kind"] == "data_error"
