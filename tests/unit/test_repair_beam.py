from sunpack.contracts.archive_input import ArchiveInputDescriptor
from sunpack.contracts.archive_state import ArchiveState, PatchOperation, PatchPlan
from sunpack.coordinator.repair_beam import RepairBeamLoop, RepairBeamState
from sunpack.repair.candidate import CandidateValidation, RepairCandidate, RepairCandidateBatch


def test_repair_beam_expands_candidates_and_keeps_top_states():
    scheduler = _FakeCandidateScheduler([
        _candidate("low", confidence=0.3),
        _candidate("middle", confidence=0.6),
        _candidate("high", confidence=0.75),
    ])
    loop = RepairBeamLoop(
        scheduler,
        beam_width=2,
        max_analyze_candidates=3,
        analyze=lambda candidate: {"confidence": 0.95 if candidate.module_name == "middle" else 0.1},
    )

    round_result = loop.expand_round([
        RepairBeamState(
            source_input={"kind": "file", "path": "broken.zip"},
            format="zip",
            confidence=0.7,
            damage_flags=["damaged"],
            archive_key="broken",
        )
    ], round_index=1)

    assert len(round_result.candidates) == 3
    assert len(round_result.states_out) == 2
    assert round_result.states_out[0].history[-1]["module"] == "middle"
    assert round_result.states_out[1].history[-1]["module"] == "high"


def test_repair_beam_deduplicates_equivalent_state_outputs():
    scheduler = _FakeCandidateScheduler([
        _candidate("first", confidence=0.8, path="same.zip"),
        _candidate("second", confidence=0.8, path="same.zip"),
    ])
    loop = RepairBeamLoop(scheduler, beam_width=4, max_analyze_candidates=4)

    round_result = loop.expand_round([
        RepairBeamState(source_input={"kind": "file", "path": "broken.zip"}, format="zip", archive_key="broken")
    ], round_index=1)

    assert len(round_result.states_out) == 1


def test_repair_beam_preserves_password_context_across_jobs_and_states():
    scheduler = _FakeCandidateScheduler([
        _candidate("with_password", confidence=0.8),
    ])
    loop = RepairBeamLoop(scheduler, beam_width=1, max_analyze_candidates=1)

    round_result = loop.expand_round([
        RepairBeamState(
            source_input={"kind": "file", "path": "encrypted.zip"},
            format="zip",
            archive_key="encrypted",
            password="secret",
        )
    ], round_index=1)

    assert scheduler.jobs[0].password == "secret"
    assert round_result.states_out[0].password == "secret"
    assert round_result.states_out[0].source_input["password"] == "secret"


def test_repair_beam_ranks_verification_completeness_over_module_confidence():
    scheduler = _FakeCandidateScheduler([
        _candidate("confident_but_incomplete", confidence=0.95),
        _candidate("less_confident_complete", confidence=0.45),
    ])
    loop = RepairBeamLoop(
        scheduler,
        beam_width=2,
        max_analyze_candidates=2,
        max_assess_candidates=2,
        assess=lambda item: {
            "assessment_status": "complete" if item.candidate.module_name == "less_confident_complete" else "partial",
            "decision_hint": "accept" if item.candidate.module_name == "less_confident_complete" else "repair",
            "completeness": 1.0 if item.candidate.module_name == "less_confident_complete" else 0.35,
            "recoverable_upper_bound": 1.0,
            "source_integrity": "complete",
        },
    )

    round_result = loop.expand_round([
        RepairBeamState(source_input={"kind": "file", "path": "broken.zip"}, format="zip", archive_key="broken")
    ], round_index=1)

    assert round_result.states_out[0].history[-1]["module"] == "less_confident_complete"
    assert round_result.states_out[0].completeness == 1.0
    assert round_result.accepted_states[0].decision_hint == "accept"


def test_repair_beam_verified_low_confidence_beats_unverified_high_confidence():
    scheduler = _FakeCandidateScheduler([
        _candidate("unverified_high_confidence", confidence=0.95),
        _verified_candidate("verified_low_confidence", confidence=0.2),
    ])
    loop = RepairBeamLoop(
        scheduler,
        beam_width=1,
        max_analyze_candidates=1,
        max_assess_candidates=1,
    )

    round_result = loop.expand_round([
        RepairBeamState(source_input={"kind": "file", "path": "broken.zip"}, format="zip", archive_key="broken")
    ], round_index=1)

    assert len(round_result.candidates) == 1
    assert round_result.candidates[0].candidate.module_name == "verified_low_confidence"
    assert round_result.states_out[0].history[-1]["module"] == "verified_low_confidence"


def test_repair_beam_run_stops_on_accepted_state():
    scheduler = _FakeCandidateScheduler([
        _candidate("complete", confidence=0.5),
        _candidate("partial", confidence=0.9),
    ])
    loop = RepairBeamLoop(
        scheduler,
        beam_width=2,
        max_analyze_candidates=2,
        max_assess_candidates=2,
        assess=lambda item: {
            "assessment_status": "complete" if item.candidate.module_name == "complete" else "partial",
            "decision_hint": "accept" if item.candidate.module_name == "complete" else "repair",
            "completeness": 1.0 if item.candidate.module_name == "complete" else 0.5,
            "recoverable_upper_bound": 1.0,
        },
    )

    result = loop.run([
        RepairBeamState(source_input={"kind": "file", "path": "broken.zip"}, format="zip", archive_key="broken")
    ], max_rounds=3)

    assert len(result.rounds) == 1
    assert result.best_state is not None
    assert result.best_state.history[-1]["module"] == "complete"


def test_repair_beam_does_not_stop_on_accept_partial_before_next_round_improves():
    scheduler = _SequencedCandidateScheduler([
        [_candidate("partial_round_1", confidence=0.9)],
        [_candidate("complete_round_2", confidence=0.3)],
    ])

    def assess(item):
        complete = item.candidate.module_name == "complete_round_2"
        return {
            "assessment_status": "complete" if complete else "partial",
            "decision_hint": "accept" if complete else "accept_partial",
            "completeness": 1.0 if complete else 0.6,
            "recoverable_upper_bound": 1.0,
        }

    result = RepairBeamLoop(
        scheduler,
        beam_width=1,
        max_analyze_candidates=1,
        max_assess_candidates=1,
        assess=assess,
    ).run([
        RepairBeamState(source_input={"kind": "file", "path": "broken.zip"}, format="zip", archive_key="broken")
    ], max_rounds=2)

    assert len(result.rounds) == 2
    assert result.best_state is not None
    assert result.best_state.history[-1]["module"] == "complete_round_2"


def test_repair_beam_builds_from_repair_config():
    scheduler = _FakeCandidateScheduler([_candidate("one", confidence=0.5)])

    loop = RepairBeamLoop.from_config(
        scheduler,
        {
            "beam": {
                "beam_width": 3,
                "max_candidates_per_state": 2,
                "max_analyze_candidates": 5,
                "max_assess_candidates": 4,
                "min_improvement": 0.2,
            }
        },
    )

    assert loop.beam_width == 3
    assert loop.max_candidates_per_state == 2
    assert loop.max_analyze_candidates == 5
    assert loop.max_assess_candidates == 4
    assert loop.min_improvement == 0.2


def test_repair_beam_materializes_only_assessment_window():
    calls = []
    scheduler = _FakeLazyCandidateScheduler([
        _lazy_candidate("first", confidence=0.9, calls=calls),
        _lazy_candidate("second", confidence=0.8, calls=calls),
        _lazy_candidate("third", confidence=0.7, calls=calls),
    ])
    loop = RepairBeamLoop(
        scheduler,
        beam_width=3,
        max_analyze_candidates=3,
        max_assess_candidates=1,
        assess=lambda item: {"assessment_status": "partial", "decision_hint": "repair", "completeness": 0.5},
    )

    round_result = loop.expand_round([
        RepairBeamState(source_input={"kind": "file", "path": "broken.zip"}, format="zip", archive_key="broken")
    ], round_index=1)

    assert calls == ["first"]
    assert len(round_result.states_out) == 1
    assert round_result.states_out[0].source_input["path"] == "first.zip"


def test_repair_beam_keeps_three_patch_plan_branches_virtual_without_copying_archive(tmp_path):
    source = tmp_path / "broken.zip"
    source.write_bytes(b"abcdef")
    workspace = tmp_path / "repair-workspace"
    workspace.mkdir()
    calls = []
    scheduler = _FakeLazyCandidateScheduler([
        _lazy_patch_candidate("trim_tail", source, calls=calls, patch=PatchOperation(op="truncate", offset=5), workspace=workspace),
        _lazy_patch_candidate("rewrite_byte", source, calls=calls, patch=PatchOperation.replace_bytes(offset=1, data=b"Z"), workspace=workspace),
        _lazy_patch_candidate("append_marker", source, calls=calls, patch=PatchOperation.append_bytes(b"!"), workspace=workspace),
    ])
    loop = RepairBeamLoop(
        scheduler,
        beam_width=3,
        max_analyze_candidates=3,
        max_assess_candidates=3,
        assess=lambda item: {"assessment_status": "partial", "decision_hint": "repair", "completeness": 0.5},
    )

    round_result = loop.expand_round([
        RepairBeamState(source_input={"kind": "file", "path": str(source), "format_hint": "zip"}, format="zip", archive_key="broken")
    ], round_index=1)

    assert calls == ["trim_tail", "rewrite_byte", "append_marker"]
    assert len(round_result.states_out) == 3
    assert all(state.source_input["kind"] == "archive_state" for state in round_result.states_out)
    assert all(state.archive_state["patches"] for state in round_result.states_out)
    assert not list(workspace.iterdir())
    assert source.read_bytes() == b"abcdef"


class _FakeCandidateScheduler:
    def __init__(self, candidates):
        self.candidates = candidates
        self.jobs = []

    def generate_repair_candidates(self, job):
        self.jobs.append(job)
        return RepairCandidateBatch(candidates=list(self.candidates), diagnosis={"format": job.format, "confidence": job.confidence})


class _SequencedCandidateScheduler:
    def __init__(self, rounds):
        self.rounds = list(rounds)
        self.jobs = []

    def generate_repair_candidates(self, job):
        self.jobs.append(job)
        index = min(len(self.jobs) - 1, len(self.rounds) - 1)
        return RepairCandidateBatch(candidates=list(self.rounds[index]), diagnosis={"format": job.format, "confidence": job.confidence})


class _FakeLazyCandidateScheduler:
    def __init__(self, candidates):
        self.candidates = candidates
        self.lazy_flags = []

    def generate_repair_candidates(self, job, *, lazy=False):
        self.lazy_flags.append(lazy)
        return RepairCandidateBatch(candidates=list(self.candidates), diagnosis={"format": job.format, "confidence": job.confidence})


def _candidate(module_name, *, confidence, path=None):
    return RepairCandidate(
        module_name=module_name,
        format="zip",
        repaired_input={"kind": "file", "path": path or f"{module_name}.zip", "format_hint": "zip"},
        confidence=confidence,
        actions=[module_name],
        validations=[CandidateValidation(name="module_result", accepted=True, score=confidence)],
    )


def _verified_candidate(module_name, *, confidence, path=None):
    return RepairCandidate(
        module_name=module_name,
        format="zip",
        repaired_input={"kind": "file", "path": path or f"{module_name}.zip", "format_hint": "zip"},
        confidence=confidence,
        actions=[module_name],
        validations=[
            CandidateValidation(name="module_result", accepted=True, score=confidence),
            CandidateValidation(
                name="native_candidate_validation",
                accepted=True,
                score=1.0,
                details={
                    "probe": {"is_archive": True, "is_broken": False},
                    "test": {"ok": True},
                    "dry_run": {"ok": True, "files_written": 1, "bytes_written": 12},
                    "resource_analysis": {"ok": True},
                    "archive_coverage": {"completeness": 1.0},
                },
            ),
        ],
    )


def _lazy_candidate(module_name, *, confidence, calls):
    def materialize():
        calls.append(module_name)
        return _candidate(module_name, confidence=confidence)

    return RepairCandidate(
        module_name=module_name,
        format="zip",
        repaired_input={},
        confidence=confidence,
        actions=["plan_repair", module_name],
        validations=[CandidateValidation(name="repair_plan", accepted=True, score=confidence)],
        materializer=materialize,
        materialized=False,
        plan={"module": module_name},
    )


def _lazy_patch_candidate(module_name, source, *, calls, patch, workspace):
    def materialize():
        calls.append(module_name)
        descriptor = ArchiveInputDescriptor.from_parts(archive_path=str(source), format_hint="zip")
        state = ArchiveState.from_archive_input(
            descriptor,
            patches=[PatchPlan(operations=[patch], provenance={"module": module_name}, confidence=0.8)],
        )
        return RepairCandidate(
            module_name=module_name,
            format="zip",
            repaired_input={
                "kind": "archive_state",
                "patch_digest": state.effective_patch_digest(),
                "format_hint": "zip",
            },
            confidence=0.8,
            actions=[module_name],
            validations=[CandidateValidation(name="module_result", accepted=True, score=0.8)],
            materialized=True,
            workspace_paths=[],
            plan={"archive_state": state.to_dict(), "workspace": str(workspace)},
        )

    return RepairCandidate(
        module_name=module_name,
        format="zip",
        repaired_input={},
        confidence=0.8,
        actions=["plan_repair", module_name],
        validations=[CandidateValidation(name="repair_plan", accepted=True, score=0.8)],
        materializer=materialize,
        materialized=False,
        plan={"module": module_name, "workspace": str(workspace), "lazy": True},
    )
