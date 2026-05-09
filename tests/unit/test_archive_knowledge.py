from pathlib import Path

from sunpack.contracts.archive_input import ArchiveInputDescriptor
from sunpack.contracts.archive_knowledge import ArchiveKnowledge
from sunpack.contracts.archive_state import ArchiveState, PatchOperation, PatchPlan
from sunpack.contracts.detection import FactBag
from sunpack.contracts.tasks import ArchiveTask
from sunpack.repair.job import RepairJob
from sunpack.repair.context import normalize_zip_runtime_route_evidence
from sunpack.repair.policy.runtime_features import runtime_context_from_job
from sunpack.support import archive_knowledge_projection as knowledge_view
from sunpack.support.archive_knowledge_writer import commit_task_knowledge


def test_archive_knowledge_namespace_merge_flags_and_roundtrip():
    knowledge = ArchiveKnowledge()
    knowledge.set("format.zip.structure.has_sfx_prefix", True, source_layer="analysis", source_module="zip_probe")
    knowledge.add_flags("repair.route_evidence", ["sfx", "carrier_prefix"], source_layer="repair")
    knowledge.merge({"verification": {"summary": {"completeness": 0.5}}})

    payload = ArchiveKnowledge.from_any(knowledge.to_dict()).to_dict()

    assert payload["format"]["zip"]["structure"]["has_sfx_prefix"] is True
    assert payload["repair"]["route_evidence"]["flags"] == ["sfx", "carrier_prefix"]
    assert payload["verification"]["summary"]["completeness"] == 0.5
    assert payload["_evidence"]
    assert "sfx" in ArchiveKnowledge.from_any(payload).flags()


def test_archive_task_state_job_knowledge_flow(tmp_path):
    archive_path = tmp_path / "sample.zip"
    archive_path.write_bytes(b"PK\x05\x06" + b"\0" * 18)
    bag = FactBag()
    bag.set("candidate.entry_path", str(archive_path))
    bag.set("analysis.selected_format", "zip")
    task = ArchiveTask(fact_bag=bag, score=1, main_path=str(archive_path)).ensure_archive_state()

    knowledge = task.knowledge()
    knowledge.set("format.zip.structure.has_data_descriptor", True, source_layer="analysis")
    task.set_knowledge(knowledge)

    state = task.archive_state()
    job = RepairJob(source_input=state.to_archive_input_descriptor().to_source_input(), format="zip", archive_state=state, knowledge=task.knowledge().to_dict())
    context = runtime_context_from_job(job)

    assert state.knowledge["format"]["zip"]["structure"]["has_data_descriptor"] is True
    assert context["knowledge_projection"]["has_archive_knowledge"] is True
    assert knowledge_view.zip_runtime_facts(ArchiveKnowledge.from_any(job.knowledge))["structure"]["has_data_descriptor"] is True
    route_payload = normalize_zip_runtime_route_evidence({"archive_knowledge": job.knowledge})
    assert "data_descriptor" in route_payload["route_evidence_flags"]


def test_archive_state_keeps_knowledge_with_virtual_patch(tmp_path):
    archive_path = tmp_path / "sample.zip"
    archive_path.write_bytes(b"abcdef")
    descriptor = ArchiveInputDescriptor(entry_path=str(archive_path), open_mode="file", format_hint="zip")
    patch = PatchPlan(
        id="p1",
        operations=[PatchOperation.replace_bytes(offset=0, data=b"Z")],
        provenance={"module": "test"},
        confidence=1.0,
    )

    state = ArchiveState.from_archive_input(
        descriptor,
        patches=[patch],
        knowledge={"repair": {"patch_facts": {"flags": ["fixed_field=test"]}}},
    )
    restored = ArchiveState.from_dict(state.to_dict(), archive_path=str(archive_path))

    assert restored.effective_patch_digest() == state.effective_patch_digest()
    assert restored.knowledge["repair"]["patch_facts"]["flags"] == ["fixed_field=test"]


def test_policy_runtime_context_prefers_archive_knowledge():
    job = RepairJob(
        source_input={},
        format="zip",
        damage_flags=[],
        knowledge={
            "source": {"input": {"kind": "file", "format_hint": "zip"}},
            "format": {"zip": {"structure": {"has_data_descriptor": True}}},
            "verification": {"summary": {"decision_hint": "repair", "completeness": 0.25}},
            "repair": {"history": {"residual_damage_flags": ["exact_match_failed"]}},
        },
    )

    context = runtime_context_from_job(job)

    assert context["job_summary"]["route_evidence_flags"] == ["data_descriptor"]
    assert context["verification_summary"]["decision_hint"] == "repair"
    assert context["verification_summary"]["completeness"] == 0.25
    assert context["job_summary"]["residual_damage_flags"] == ["exact_match_failed"]


def test_archive_knowledge_commit_revision_and_projection_cache_invalidation(tmp_path):
    archive_path = tmp_path / "sample.zip"
    archive_path.write_bytes(b"abc")
    task = ArchiveTask.from_fact_bag(_fact_bag_for_path(archive_path), score=1)

    first_revision = int(task.knowledge().get("_meta.revision", 0) or 0)
    first = knowledge_view.source_fingerprint(task)
    second = knowledge_view.source_fingerprint(task)
    assert first == second

    knowledge = task.knowledge()
    knowledge.set("format.zip.structure.has_data_descriptor", True, source_layer="test")
    commit_task_knowledge(task, knowledge)

    assert int(task.knowledge().get("_meta.revision", 0) or 0) > first_revision
    assert knowledge_view.zip_runtime_facts(task)["structure"]["has_data_descriptor"] is True


def test_zip_runtime_facts_do_not_read_source_derivation_legacy_zip_fields():
    knowledge = ArchiveKnowledge()
    knowledge.set("source.derivation", {"zip_structure_features": {"has_data_descriptor": True}, "zip_container_tags": ["data_descriptor"]})

    facts = knowledge_view.zip_runtime_facts(knowledge)

    assert facts["structure"] == {}
    assert facts["container_tags"] == []
    assert knowledge_view.repair_route_context(knowledge)["route_evidence_flags"] == []


def test_repair_route_context_and_history_summary_are_canonical():
    knowledge = ArchiveKnowledge()
    knowledge.set("format.zip.route_evidence_flags", ["data_descriptor"])
    knowledge.add_flags("repair.damage", ["central_directory_bad", "data_descriptor"])
    knowledge.add_flags("verification.residual", ["payload_hash_mismatch"])
    knowledge.set("repair.history.items", [
        {"ok": True, "module_name": "zip_fix_cd_offset", "actions": ["fix_cd_offset"], "diagnosis": {"patch_facts": ["fixed_field=cd_offset"]}}
    ])

    route = knowledge_view.repair_route_context(knowledge)
    history = knowledge_view.repair_history_summary(knowledge)

    assert route["route_evidence_flags"] == ["data_descriptor", "central_directory_bad", "payload_hash_mismatch"]
    assert route["residual_damage_flags"] == ["payload_hash_mismatch"]
    assert history["previous_modules"] == ["zip_fix_cd_offset"]
    assert "already_tried:zip_fix_cd_offset" in history["repair_history_flags"]


def _fact_bag_for_path(path: Path) -> FactBag:
    bag = FactBag()
    bag.set("candidate.entry_path", str(path))
    bag.set("candidate.member_paths", [str(path)])
    bag.set("file.detected_ext", "zip")
    return bag
