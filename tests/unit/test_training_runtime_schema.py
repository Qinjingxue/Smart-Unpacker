import json

import pytest

from sunpack.contracts.archive_input import ArchiveInputDescriptor
from sunpack.contracts.archive_state import ArchiveState, PatchOperation, PatchPlan
from sunpack.repair.candidate import CandidateValidation, RepairCandidate
from sunpack.repair.job import RepairJob
from sunpack.repair.policy.training_runtime import (
    archive_state_for_job,
    build_damage_analysis_request,
    build_repair_action_request,
    candidate_snapshot,
    request_to_dict,
    validate_policy_candidates,
)
from repair_training.schemas import (
    TrainingAction,
    TrainingCandidateSnapshot,
    TrainingEpisode,
    TrainingTransition,
    TrainingVerificationSnapshot,
)


def test_training_episode_schema_round_trip_with_archive_state_digest(tmp_path):
    source = tmp_path / "source.zip"
    source.write_bytes(b"abcdef")
    descriptor = ArchiveInputDescriptor.from_parts(archive_path=str(source), format_hint="zip")
    state = ArchiveState.from_archive_input(descriptor)
    episode = TrainingEpisode(
        episode_id="e1",
        format="zip",
        source_identity={"path": str(source)},
        corrupted_input=descriptor.to_source_input(),
        initial_state=state.to_dict(),
        initial_state_digest=state.effective_patch_digest(),
        transitions=[
            TrainingTransition(
                round_index=1,
                state_digest=state.effective_patch_digest(),
                patch_depth=0,
                candidate_snapshots=[TrainingCandidateSnapshot(candidate_id="c1", module_name="zip_fix", format="zip")],
                available_actions=[
                    TrainingAction(action_type="apply_patch", candidate_id="c1"),
                    TrainingAction(action_type="stop"),
                ],
                selected_action=TrainingAction(action_type="apply_patch", candidate_id="c1"),
                next_state_digest="next",
                verification_before=TrainingVerificationSnapshot(score=0.1),
                verification_after=TrainingVerificationSnapshot(score=0.9),
                reward=0.8,
            )
        ],
    )

    restored = TrainingEpisode.from_dict(episode.to_dict())

    assert restored.to_dict() == episode.to_dict()
    assert restored.initial_state_digest == state.effective_patch_digest()


def test_training_action_validation_and_control_action_normalization():
    with pytest.raises(ValueError):
        TrainingAction(action_type="apply_patch")

    assert TrainingAction(action_type="undo_patch", candidate_id="ignored").candidate_id == ""
    assert TrainingAction(action_type="stop", candidate_id="ignored").candidate_id == ""
    assert TrainingAction(action_type="give_up", candidate_id="ignored").candidate_id == ""


def test_training_runtime_adapter_builds_requests_and_snapshots(tmp_path):
    source = tmp_path / "source.zip"
    source.write_bytes(b"abcdef")
    descriptor = ArchiveInputDescriptor.from_parts(archive_path=str(source), format_hint="zip")
    root = ArchiveState.from_archive_input(descriptor)
    patch = PatchPlan(
        module="zip_fix_cd_offset",
        format="zip",
        operations=[PatchOperation.replace_bytes(offset=0, data=b"Z", expected=b"a")],
        confidence=0.8,
    )
    repaired = root.push_patch(patch)
    candidate = RepairCandidate(
        module_name="zip_fix_cd_offset",
        format="zip",
        repaired_input={"kind": "archive_state"},
        confidence=0.8,
        validations=[CandidateValidation(name="smoke", accepted=True, score=0.9)],
        plan={"archive_state": repaired.to_dict(), "patch_plan": patch.to_dict()},
    )
    job = RepairJob(
        source_input=descriptor.to_source_input(),
        format="zip",
        archive_state=root,
        knowledge={"source": {"input": descriptor.to_source_input()}, "analysis": {"summary": {"format": "zip", "confidence": 0.5}}},
    )

    assert archive_state_for_job(job) is root
    damage_request = build_damage_analysis_request(job, root, diagnosis={"format": "zip"}, round_index=2)
    action_request = build_repair_action_request(job, root, [candidate], {"damage_labels": ["central_directory_offset_bad"]}, round_index=2)
    snapshot = candidate_snapshot(candidate, index=0)
    validated = validate_policy_candidates({}, [candidate])

    assert damage_request.round_index == 2
    assert damage_request.runtime_context["archive_state"]["patch_digest"] == root.effective_patch_digest()
    damage_payload = request_to_dict(build_damage_analysis_request(job, repaired, diagnosis={"format": "zip"}, round_index=3))
    assert damage_payload["archive_state"]["patch_digest"] == repaired.effective_patch_digest()
    assert "patches" not in json.dumps(damage_payload["archive_state"], sort_keys=True)
    assert "data_b64" not in json.dumps(damage_payload, sort_keys=True)
    assert "expected_b64" not in json.dumps(damage_payload, sort_keys=True)
    assert action_request.candidate_payloads[0]["candidate_id"] == snapshot["candidate_id"]
    assert action_request.candidate_payloads[0]["damage_analysis"]["damage_labels"] == ["central_directory_offset_bad"]
    assert snapshot["patch_depth"] == 1
    assert snapshot["patch_operation_count"] == 1
    assert snapshot["last_patch_module"] == "zip_fix_cd_offset"
    assert snapshot["has_archive_state_plan"] is True
    assert validated[0] is candidate
