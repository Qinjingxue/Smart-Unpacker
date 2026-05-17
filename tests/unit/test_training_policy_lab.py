import json
from pathlib import Path

from repair_training.collect_episodes import collect_episode
from repair_training.schemas import (
    TrainingAction,
    TrainingCandidateSnapshot,
    TrainingEpisode,
    TrainingTransition,
    TrainingVerificationSnapshot,
)
from repair_training.taxonomy import normalize_damage_record
from repair_training.value_labeler import label_episode_values
from sunpack.contracts.archive_input import ArchiveInputDescriptor
from sunpack.contracts.archive_state import ArchiveState, PatchOperation, PatchPlan
from sunpack.repair.candidate import CandidateValidation, RepairCandidate, RepairCandidateBatch
from sunpack.repair.policy.recovery_evaluator import RecoveryEvaluator, snapshot_from_verification
from sunpack.repair.job import RepairJob
from sunpack.verification.result import ArchiveCoverageSummary, VerificationResult


def test_zip_taxonomy_normalizes_eocd_count_and_compound_zip64_tail():
    target = normalize_damage_record({
        "format": "zip",
        "damage_profile": "compound_zip64_locator_extra_trailing_junk",
        "damage_layer": "compound",
        "expected_min_steps": 3,
        "expected_route_facts": ["zip64", "trailing_junk"],
        "corruption_plan": [
            {"zone": "zip.eocd.entry_count_total", "offset": 10, "size": 2, "name": "count_bad"},
            {"zone": "archive.tail", "offset": 99, "size": 42, "name": "tail_junk"},
            {"zone": "zip.extra.zip64.length", "offset": 20, "size": 2, "name": "zip64_extra"},
        ],
    })

    labels = {label.label: label for label in target.labels}

    assert "central_directory_count" in labels
    assert any(label.family == "boundary" for label in target.labels)
    assert any(label.family == "zip64" for label in target.labels)
    assert all(label.expected_min_steps == 3 for label in target.labels)


def test_seven_zip_taxonomy_routes_common_families():
    target = normalize_damage_record({
        "format": "seven_zip",
        "damage_profile": "seven_zip_stream_crc_bad",
        "runtime_damage_flags": ["stream_crc_bad", "next_header_crc_bad", "encoded_header_present", "split_sidecars_available"],
        "corruption_plan": [
            {"zone": "7z.stream_crc", "name": "crc"},
            {"zone": "7z.next_header_crc", "name": "next"},
            {"zone": "7z.encoded_header", "name": "encoded"},
            {"zone": "7z.split.volume", "name": "split"},
        ],
    })

    families = {label.family for label in target.labels}

    assert {"crc", "next_header", "encoded_header", "split_volume"}.issubset(families)


def test_unknown_taxonomy_preserves_raw_metadata():
    target = normalize_damage_record({"format": "zip", "damage_profile": "mystery_profile"})

    assert target.labels[0].family == "unknown"
    assert target.labels[0].metadata["damage_profile"] == "mystery_profile"


def test_recovery_evaluator_scores_verification_and_oracle(tmp_path):
    source = tmp_path / "broken.zip"
    source.write_bytes(b"abc")
    state = ArchiveState.from_archive_input(ArchiveInputDescriptor.from_parts(archive_path=str(source), format_hint="zip"))
    snapshot = snapshot_from_verification(
        state,
        None,
        VerificationResult(
            completeness=0.2,
            output_quality_score=0.8,
            archive_coverage=ArchiveCoverageSummary(completeness=0.75, expected_files=4, complete_files=3),
        ),
    )
    oracle = snapshot_from_verification(
        state,
        None,
        VerificationResult(completeness=1.0),
        oracle={"expected_hashes": 4, "matched_hashes": 1},
        mode="training_oracle",
    )

    assert snapshot.score == 0.75
    assert snapshot.complete_files == 3
    assert oracle.score == 0.25
    assert oracle.metadata["score_source"] == "oracle"


def test_policy_light_ignores_pure_native_validation_score(tmp_path):
    source = tmp_path / "broken.zip"
    source.write_bytes(b"abc")
    descriptor = ArchiveInputDescriptor.from_parts(archive_path=str(source), format_hint="zip")
    state = ArchiveState.from_archive_input(descriptor)
    patch = PatchPlan(
        module="zip_fix_cd_offset",
        format="zip",
        operations=[PatchOperation.append_bytes(b"fixed")],
        confidence=0.9,
    )
    repaired = state.push_patch(patch)
    candidate = RepairCandidate(
        module_name="zip_fix_cd_offset",
        format="zip",
        repaired_input={"kind": "archive_state"},
        confidence=0.9,
        validations=[CandidateValidation(name="native", accepted=True, score=0.9)],
        plan={"archive_state": repaired.to_dict(), "patch_plan": patch.to_dict()},
    )

    snapshot = RecoveryEvaluator().evaluate_candidate(
        RepairJob(source_input={"path": str(source)}, format="zip"),
        candidate,
        mode="policy_light",
    )

    assert snapshot.score == 0.0
    assert snapshot.metadata["score_source"] == "none"


def test_recovery_evaluator_reads_verification_summary_from_job_knowledge(tmp_path):
    source = tmp_path / "observed.zip"
    source.write_bytes(b"abc")
    state = ArchiveState.from_archive_input(ArchiveInputDescriptor.from_parts(archive_path=str(source), format_hint="zip"))
    job = RepairJob(
        source_input={"path": str(source), "format_hint": "zip"},
        format="zip",
        knowledge={
            "verification": {
                "summary": {
                    "assessment_status": "partial",
                    "decision_hint": "accept_partial",
                    "completeness": 0.8,
                    "archive_coverage": {"completeness": 0.8, "complete_files": 4, "expected_files": 5},
                }
            }
        },
    )

    snapshot = RecoveryEvaluator().evaluate_state(job, state, mode="policy_light")

    assert snapshot.score == 0.8
    assert snapshot.complete_files == 4
    assert snapshot.metadata["score_source"] == "archive_coverage"


def test_recovery_evaluator_failure_snapshot_is_stable(monkeypatch, tmp_path):
    source = tmp_path / "broken.zip"
    source.write_bytes(b"abc")
    state = ArchiveState.from_archive_input(ArchiveInputDescriptor.from_parts(archive_path=str(source), format_hint="zip"))
    evaluator = RecoveryEvaluator()
    monkeypatch.setattr(evaluator, "_evaluate_state", lambda *args, **kwargs: (_ for _ in ()).throw(RuntimeError("boom")))

    snapshot = evaluator.evaluate_state(RepairJob(source_input={"path": str(source)}, format="zip"), state)

    assert snapshot.status == "evaluation_failed"
    assert snapshot.score == 0.0
    assert snapshot.metadata["error"] == "boom"


def test_episode_collector_emits_patch_state_episode(tmp_path):
    source = tmp_path / "broken.zip"
    source.write_bytes(b"abcdef")
    descriptor = ArchiveInputDescriptor.from_parts(archive_path=str(source), format_hint="zip")
    root = ArchiveState.from_archive_input(descriptor)
    patch = PatchPlan(
        module="zip_fix_cd_offset",
        format="zip",
        operations=[PatchOperation.replace_bytes(offset=0, data=b"Z", expected=b"a")],
        confidence=0.9,
    )
    repaired = root.push_patch(patch)
    candidate = RepairCandidate(
        module_name="zip_fix_cd_offset",
        format="zip",
        repaired_input={"kind": "archive_state"},
        confidence=0.9,
        validations=[CandidateValidation(name="test", accepted=True, score=0.9)],
        plan={"archive_state": repaired.to_dict(), "patch_plan": patch.to_dict()},
    )
    scheduler = _FakeScheduler(candidate)
    record = {
        "format": "zip",
        "sample_id": "case1",
        "damaged_input": descriptor.to_source_input(),
        "damaged_path": str(source),
        "runtime_damage_flags": ["central_directory_offset_bad"],
        "corruption_plan": [{"zone": "zip.eocd.cd_offset", "offset": 1, "size": 2}],
    }

    episode, stats = collect_episode(record, scheduler=scheduler, max_depth=1, max_states=4)
    restored = TrainingEpisode.from_dict(episode.to_dict())

    assert restored.episode_id == "case1"
    assert restored.initial_state_digest == root.effective_patch_digest()
    assert stats["candidate_count"] >= 1
    assert any(t.selected_action and t.selected_action.action_type == "expand_edge" for t in restored.transitions)
    assert any(t.selected_action and t.selected_action.action_type == "stop_signal" for t in restored.transitions)
    assert any(t.candidate_snapshots for t in restored.transitions)
    first_apply = next(t for t in restored.transitions if t.selected_action and t.selected_action.action_type == "expand_edge")
    assert first_apply.verification_after.details["recovery_snapshot"]["score"] == 0.0
    assert first_apply.verification_after.details["recovery_snapshot"]["metadata"]["score_source"] == "none"
    assert "recovery_score" not in first_apply.candidate_snapshots[0].metadata
    assert "score_source" not in first_apply.candidate_snapshots[0].metadata
    assert first_apply.candidate_snapshots[0].patch_digest == ""
    serialized = json.dumps(episode.to_dict(), sort_keys=True)
    assert "data_b64" not in serialized
    assert "expected_b64" not in serialized
    assert "patches" not in json.dumps(first_apply.damage_analysis_request.get("archive_state") or {}, sort_keys=True)
    assert len(serialized.encode("utf-8")) < 150_000


def test_value_labeler_propagates_delayed_reward_to_early_actions():
    episode = _chain_episode([
        ("root", "a", "A", 0.0, -0.1),
        ("a", "b", "B", -0.1, -0.2),
        ("b", "c", "C", -0.2, 1.0),
    ])

    rows, _ = label_episode_values(episode, gamma=0.85, step_cost=0.0)
    by_state = {row["state_digest"]: row for row in rows if row["action_type"] == "expand_edge"}

    assert by_state["root"]["long_term_value"] > 0
    assert by_state["a"]["long_term_value"] > 0
    assert by_state["b"]["immediate_reward"] == 1.2
    assert by_state["b"]["long_term_value"] > by_state["b"]["immediate_reward"]


def test_value_labeler_prefers_undo_when_child_state_is_worse():
    episode = TrainingEpisode(
        episode_id="undo",
        format="zip",
        source_identity={},
        corrupted_input={},
        initial_state_digest="root",
        transitions=[
            _edge("child", "worse", "bad", 0.1, 0.0),
            TrainingTransition(
                round_index=1,
                state_digest="child",
                patch_depth=1,
                available_actions=[TrainingAction(action_type="checkout_node")],
                selected_action=TrainingAction(action_type="checkout_node", metadata={"target_state_digest": "root"}),
                next_state_digest="root",
                verification_before=TrainingVerificationSnapshot(score=0.1),
                verification_after=TrainingVerificationSnapshot(score=0.5),
            ),
        ],
    )

    rows, _ = label_episode_values(episode, gamma=0.0, step_cost=0.0)
    undo = next(row for row in rows if row["action_type"] == "checkout_node")

    assert undo["is_best_action"] is True
    assert undo["long_term_value"] > 0


def test_value_labeler_stop_and_give_up_terminal_choices():
    stop_episode = TrainingEpisode(
        episode_id="stop",
        format="zip",
        source_identity={},
        corrupted_input={},
        transitions=[
            TrainingTransition(
                round_index=0,
                state_digest="good",
                patch_depth=1,
                selected_action=TrainingAction(action_type="stop_signal"),
                verification_before=TrainingVerificationSnapshot(score=0.95),
                verification_after=TrainingVerificationSnapshot(score=0.95),
                terminal=True,
            )
        ],
    )
    give_up_episode = TrainingEpisode(
        episode_id="give_up",
        format="zip",
        source_identity={},
        corrupted_input={},
        transitions=[
            TrainingTransition(
                round_index=0,
                state_digest="empty",
                patch_depth=0,
                selected_action=TrainingAction(action_type="exhaust_branch"),
                verification_before=TrainingVerificationSnapshot(score=0.0),
                verification_after=TrainingVerificationSnapshot(score=0.0),
                terminal=True,
            )
        ],
    )

    stop_rows, _ = label_episode_values(stop_episode)
    give_up_rows, _ = label_episode_values(give_up_episode)

    assert stop_rows[0]["is_best_action"] is True
    assert stop_rows[0]["long_term_value"] > 0
    assert give_up_rows[0]["is_best_action"] is True
    assert give_up_rows[0]["long_term_value"] == -0.01


def test_value_labeler_cli_outputs_action_and_damage_rows(tmp_path):
    episodes = tmp_path / "episodes.jsonl"
    episode = _chain_episode([("root", "fixed", "fix", 0.0, 1.0)])
    episodes.write_text(json.dumps(episode.to_dict(), sort_keys=True) + "\n", encoding="utf-8")

    from repair_training.value_labeler import main

    assert main(["--episodes", str(episodes), "--output-dir", str(tmp_path)]) == 0
    action_rows = [json.loads(line) for line in (tmp_path / "action_policy_rows.jsonl").read_text(encoding="utf-8").splitlines()]
    value_rows = [json.loads(line) for line in (tmp_path / "state_value_rows.jsonl").read_text(encoding="utf-8").splitlines()]
    damage_rows = [json.loads(line) for line in (tmp_path / "damage_rows.jsonl").read_text(encoding="utf-8").splitlines()]

    assert action_rows
    assert value_rows
    assert damage_rows
    assert any(row["is_best_action"] for row in action_rows)
    assert "state_value" not in action_rows[0]
    assert "current_recovery" in action_rows[0]
    assert not {"next_recovery", "recovery_delta", "score_source", "next_state_digest"} & set(action_rows[0])
    apply_row = next(row for row in action_rows if row["action_type"] == "expand_edge")
    candidate_keys = set(apply_row["candidate_snapshot"])
    candidate_metadata_keys = set((apply_row["candidate_snapshot"].get("metadata") or {}))
    assert not {
        "patch_digest",
        "patch_depth",
        "patch_count",
        "last_patch_module",
        "has_archive_state_plan",
        "branchable",
        "recovery_snapshot",
        "recovery_score",
        "recovery_delta",
        "verification_summary",
        "score_source",
    } & candidate_keys
    assert not {"recovery_score", "score_source", "verification_summary"} & candidate_metadata_keys


class _FakeScheduler:
    config = {}

    def __init__(self, candidate):
        self.candidate = candidate

    def generate_repair_candidates(self, job, lazy=True):
        if job.archive_state and job.archive_state.patch_depth() == 0:
            return RepairCandidateBatch(candidates=[self.candidate], diagnosis={"format": "zip"})
        return RepairCandidateBatch(candidates=[], diagnosis={"format": "zip"})


def _chain_episode(edges):
    transitions = []
    for source, target, candidate_id, before, after in edges:
        transitions.append(_edge(source, target, candidate_id, before, after))
    transitions.append(TrainingTransition(
        round_index=len(edges),
        state_digest=edges[-1][1],
        patch_depth=len(edges),
        selected_action=TrainingAction(action_type="stop_signal"),
        verification_before=TrainingVerificationSnapshot(score=edges[-1][4]),
        verification_after=TrainingVerificationSnapshot(score=edges[-1][4]),
        terminal=True,
    ))
    return TrainingEpisode(
        episode_id="chain",
        format="zip",
        source_identity={},
        corrupted_input={},
        initial_state_digest=edges[0][0],
        transitions=transitions,
    )


def _edge(source, target, candidate_id, before, after):
    return TrainingTransition(
        round_index=0,
        state_digest=source,
        patch_depth=0,
        candidate_snapshots=[TrainingCandidateSnapshot(candidate_id=candidate_id, module_name=candidate_id, format="zip")],
        available_actions=[TrainingAction(action_type="expand_edge", candidate_id=candidate_id)],
        selected_action=TrainingAction(action_type="expand_edge", candidate_id=candidate_id),
        next_state_digest=target,
        verification_before=TrainingVerificationSnapshot(score=before),
        verification_after=TrainingVerificationSnapshot(score=after),
    )
