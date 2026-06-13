from pathlib import Path

from sunpack.contracts.archive_input import ArchiveInputDescriptor
from sunpack.contracts.archive_state import ArchiveState, PatchOperation, PatchPlan
from sunpack.repair.candidate import RepairCandidate
from sunpack.repair.job import RepairJob
from sunpack.repair.policy.graph import PolicyRepairGraph
from sunpack.repair.policy.recovery_evaluator import PolicyRecoverySnapshot


def test_policy_graph_initialize_creates_root_node(tmp_path: Path):
    job = _job(tmp_path)
    graph = PolicyRepairGraph.initialize(job, PolicyRecoverySnapshot(score=0.25, status="partial"))

    node = graph.graph.current_node()

    assert node is not None
    assert node.patch_status == "root"
    assert node.archive_state is not None
    assert node.recovery["score"] == 0.25
    assert graph.graph.best_node_id == node.node_id


def test_policy_graph_forward_success_creates_applied_node_and_expanded_edge(tmp_path: Path):
    job = _job(tmp_path)
    graph = PolicyRepairGraph.initialize(job, PolicyRecoverySnapshot(score=0.0))
    candidate = _patch_candidate("zip_fix_cd", job.archive_state, b"fixed")
    edge = graph.register_proposals([{"candidate_id": "c1", "module_name": "zip_fix_cd"}], step=1)[0]

    op = graph.forward(candidate_id="c1", module_name="zip_fix_cd", materialized_candidate=candidate, step=1)

    assert op.patch_status == "applied"
    assert graph.graph.current_node_id == op.node_id
    assert graph.graph.nodes[op.node_id].parent_id
    assert graph.graph.edges[edge.edge_id].status == "expanded"
    assert op.archive_state is not None
    assert op.archive_state.patch_depth() == 1


def test_policy_graph_forward_failure_creates_empty_failed_patch_node(tmp_path: Path):
    job = _job(tmp_path)
    graph = PolicyRepairGraph.initialize(job, PolicyRecoverySnapshot(score=0.0))
    graph.register_proposals([{"candidate_id": "c1", "module_name": "zip_fix_cd"}], step=1)
    root_digest = graph.graph.current_node().patch_digest

    op = graph.forward(
        candidate_id="c1",
        module_name="zip_fix_cd",
        materialized_candidate=None,
        failure={"failure_reason": "materialization_failed", "diagnostics": {"x": 1}},
        step=1,
    )

    node = graph.graph.nodes[op.node_id]
    assert op.patch_status == "empty_failed"
    assert node.patch_status == "empty_failed"
    assert node.failure_reason == "materialization_failed"
    assert op.archive_state is not None
    assert op.archive_state.patch_depth() == 1
    assert op.archive_state.effective_patch_digest() != root_digest
    assert list(graph.graph.edges.values())[0].status == "expanded_failed"


def test_policy_graph_repeated_empty_forward_reuses_existing_node(tmp_path: Path):
    job = _job(tmp_path)
    graph = PolicyRepairGraph.initialize(job, PolicyRecoverySnapshot(score=0.0))
    failure = {"failure_reason": "materialization_failed"}
    graph.register_proposals([{"candidate_id": "c1", "module_name": "zip_fix_cd"}], step=1)
    first = graph.forward(candidate_id="c1", module_name="zip_fix_cd", materialized_candidate=None, failure=failure, step=1)
    graph.undo(step=2)
    graph.register_proposals([{"candidate_id": "c2", "module_name": "zip_fix_cd"}], step=2)

    second = graph.forward(candidate_id="c2", module_name="zip_fix_cd", materialized_candidate=None, failure=failure, step=2)

    assert second.node_id == first.node_id
    assert second.patch_status == "repeated"
    assert len(graph.graph.nodes) == 2


def test_policy_graph_undo_and_stop_best(tmp_path: Path):
    job = _job(tmp_path)
    graph = PolicyRepairGraph.initialize(job, PolicyRecoverySnapshot(score=0.1, status="partial"))
    root_id = graph.graph.current_node_id
    graph.register_proposals([{"candidate_id": "c1", "module_name": "zip_fix_cd"}], step=1)
    child = graph.forward(candidate_id="c1", module_name="zip_fix_cd", materialized_candidate=None, failure={"failure_reason": "failed"}, step=1)
    graph.graph.nodes[child.node_id].recovery = {"score": 0.8, "status": "partial"}

    undo = graph.undo(step=2)
    stop = graph.stop_best()

    assert undo.node_id == root_id
    assert graph.graph.current_node_id == root_id
    assert stop.node_id == child.node_id
    assert stop.archive_state is not None


def test_policy_graph_fresh_first_after_undo_uses_exploration_stats(tmp_path: Path):
    job = _job(tmp_path)
    graph = PolicyRepairGraph.initialize(job, PolicyRecoverySnapshot(score=0.1, status="partial"))
    root_id = graph.graph.current_node_id
    graph.register_proposals([{"candidate_id": "c1", "module_name": "zip_fix_cd", "route_family": "cd"}], step=1)
    child = graph.forward(candidate_id="c1", module_name="zip_fix_cd", materialized_candidate=None, failure={"failure_reason": "failed"}, step=1)

    undo = graph.undo(step=2)
    proposals = graph.register_proposals([
        {"candidate_id": "c1", "module_name": "zip_fix_cd", "route_family": "cd"},
        {"candidate_id": "c2", "module_name": "zip_fix_cd_alt", "route_family": "cd"},
    ], step=2)
    parent = graph.graph.nodes[root_id]

    assert undo.node_id == root_id
    assert undo.diagnostics["from_node_id"] == child.node_id
    assert [edge.candidate_id for edge in proposals] == ["c2"]
    assert parent.exploration["outgoing_action_count"] == 2
    assert parent.exploration["expanded_action_count"] == 1
    assert parent.exploration["fresh_action_count"] == 1
    assert parent.exploration["exhaustion_ratio"] == 0.5
    assert next(iter(graph.graph.edges.values())).exploration["undo_count_after_attempt"] == 1


def test_policy_graph_fresh_first_hides_same_module_retry_until_exhausted(tmp_path: Path):
    job = _job(tmp_path)
    graph = PolicyRepairGraph.initialize(job, PolicyRecoverySnapshot(score=0.1, status="partial"))
    graph.register_proposals([{"candidate_id": "c1", "module_name": "zip_fix_cd", "route_family": "cd"}], step=1)
    graph.forward(candidate_id="c1", module_name="zip_fix_cd", materialized_candidate=None, failure={"failure_reason": "failed"}, step=1)
    graph.undo(step=2)

    proposals = graph.register_proposals([
        {"candidate_id": "c2", "module_name": "zip_fix_cd", "route_family": "cd"},
        {"candidate_id": "c3", "module_name": "zip_fix_other", "route_family": "other"},
    ], step=2)

    assert [edge.candidate_id for edge in proposals] == ["c3"]


def test_policy_graph_fresh_first_hides_branch_module_retry_until_exhausted(tmp_path: Path):
    job = _job(tmp_path)
    graph = PolicyRepairGraph.initialize(job, PolicyRecoverySnapshot(score=0.1, status="partial"))
    graph.register_proposals([{"candidate_id": "c1", "module_name": "zip_fix_cd", "route_family": "cd"}], step=1)
    first = graph.forward(candidate_id="c1", module_name="zip_fix_cd", materialized_candidate=_patch_candidate("zip_fix_cd", job.archive_state, b"one"), step=1)
    assert first.archive_state is not None

    proposals = graph.register_proposals([
        {"candidate_id": "c2", "module_name": "zip_fix_cd", "route_family": "cd"},
        {"candidate_id": "c3", "module_name": "zip_fix_other", "route_family": "other"},
    ], step=2)

    assert [edge.candidate_id for edge in proposals] == ["c3"]


def test_policy_graph_reopens_attempted_candidate_after_exhaustion(tmp_path: Path):
    job = _job(tmp_path)
    graph = PolicyRepairGraph.initialize(job, PolicyRecoverySnapshot(score=0.1, status="partial"))
    graph.register_proposals([{"candidate_id": "c1", "module_name": "zip_fix_cd", "route_family": "cd"}], step=1)
    graph.forward(candidate_id="c1", module_name="zip_fix_cd", materialized_candidate=None, failure={"failure_reason": "failed"}, step=1)
    graph.undo(step=2)

    proposals = graph.register_proposals([{
        "candidate_id": "c1",
        "module_name": "zip_fix_cd",
        "route_family": "cd",
    }], step=3)

    assert [edge.candidate_id for edge in proposals] == ["c1"]
    assert proposals[0].exploration["reopened_after_exhaustion"] is True
    assert graph.graph.current_node().exploration["fresh_action_count"] == 0
    assert graph.graph.current_node().exploration["reopened_action_count"] == 1


def test_policy_graph_stop_readiness_tracks_stale_best_updates(tmp_path: Path):
    job = _job(tmp_path)
    graph = PolicyRepairGraph.initialize(job, PolicyRecoverySnapshot(score=0.1, status="partial"))
    graph.register_proposals([{"candidate_id": "c1", "module_name": "zip_fix_cd"}], step=1)
    child = graph.forward(candidate_id="c1", module_name="zip_fix_cd", materialized_candidate=None, failure={"failure_reason": "failed"}, step=1)

    improved = graph.observe_current_recovery({"score": 0.4, "status": "partial"}, min_improvement=0.0)
    stale = graph.observe_current_recovery({"score": 0.2, "status": "partial"}, min_improvement=0.0)
    readiness = graph.stop_readiness(stale_patience=1)

    assert improved["steps_since_best_update"] == 0
    assert graph.graph.best_node_id == child.node_id
    assert stale["steps_since_best_update"] == 1
    assert readiness["should_force_stop"] is True
    assert readiness["force_stop_reason"] == "graph_stale_best"


def _job(tmp_path: Path) -> RepairJob:
    source = tmp_path / "source.zip"
    source.write_bytes(b"broken")
    state = ArchiveState.from_archive_input(ArchiveInputDescriptor.from_parts(archive_path=str(source), format_hint="zip"))
    return RepairJob(
        source_input={"kind": "file", "path": str(source), "format_hint": "zip"},
        archive_state=state,
        format="zip",
        archive_key="source",
        workspace=str(tmp_path / "repair"),
        extraction_failure={"status": "failed"},
        knowledge={"repair": {"history": {"items": []}}},
    )


def _patch_candidate(module: str, base: ArchiveState, replacement: bytes) -> RepairCandidate:
    patch = PatchPlan(
        module=module,
        format="zip",
        operations=[
            PatchOperation(op="truncate", offset=0, size=Path(base.source.entry_path).stat().st_size),
            PatchOperation.append_bytes(replacement),
        ],
        confidence=0.8,
    )
    state = base.push_patch(patch)
    return RepairCandidate(
        module_name=module,
        format="zip",
        repaired_input={"kind": "archive_state", "patch_digest": state.effective_patch_digest(), "format_hint": "zip"},
        confidence=0.8,
        actions=[module],
        plan={"archive_state": state.to_dict(), "patch_plan": patch.to_dict()},
    )
