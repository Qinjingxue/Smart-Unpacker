from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Literal


POLICY_GRAPH_ROW_SCHEMA = "repair_policy_graph_row_v2"
POLICY_TRANSITION_ROW_SCHEMA = "repair_policy_transition_row_v2"
POLICY_WORLD_ROW_SCHEMA = "repair_policy_world_row_v2"
ActionType = Literal["stop", "undo", "module"]
WorldTask = Literal["transition", "masked_graph", "ranking"]


@dataclass(frozen=True)
class PolicyAction:
    action_type: ActionType
    action_id: str
    module_name: str = ""
    score: float = 0.0
    action_q_value: float = 0.0
    action_prior: float = 0.0
    q_source: str = ""
    q_horizon: int = 0
    action_regret: float = 0.0
    is_teacher_evaluated: bool = False
    best_action_set_member: bool = False
    q_bucket: str = ""
    features: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        return {
            "action_type": self.action_type,
            "action_id": self.action_id,
            "module_name": self.module_name,
            "score": float(self.score or 0.0),
            "action_q_value": float(self.action_q_value or 0.0),
            "action_prior": float(self.action_prior or 0.0),
            "q_source": self.q_source,
            "q_horizon": int(self.q_horizon or 0),
            "action_regret": float(self.action_regret or 0.0),
            "is_teacher_evaluated": bool(self.is_teacher_evaluated),
            "best_action_set_member": bool(self.best_action_set_member),
            "q_bucket": self.q_bucket,
            "features": dict(self.features or {}),
        }


@dataclass(frozen=True)
class PolicyGraphTrainingSample:
    sample_id: str
    format: str
    graph: dict[str, Any]
    current_node_id: str
    best_node_id: str
    actions: list[PolicyAction]
    memory: list[dict[str, Any]] = field(default_factory=list)
    diagnosis_hgt: dict[str, Any] = field(default_factory=dict)
    current_recovery: dict[str, Any] = field(default_factory=dict)
    best_recovery: dict[str, Any] = field(default_factory=dict)
    final_best_recovery: float = 0.0
    has_promising_future: bool = False
    stop_regret: float = 0.0
    branch_bad: bool = False
    best_elsewhere: bool = False
    untried_promising_sibling_count: int = 0
    teacher_budget: dict[str, Any] = field(default_factory=dict)
    teacher_trace_id: str = ""
    source: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        return {
            "schema_version": POLICY_GRAPH_ROW_SCHEMA,
            "sample_id": self.sample_id,
            "format": self.format,
            "graph": dict(self.graph or {}),
            "current_node_id": self.current_node_id,
            "best_node_id": self.best_node_id,
            "actions": [action.to_dict() for action in self.actions],
            "memory": [dict(item) for item in self.memory],
            "diagnosis_hgt": dict(self.diagnosis_hgt or {}),
            "current_recovery": dict(self.current_recovery or {}),
            "best_recovery": dict(self.best_recovery or {}),
            "final_best_recovery": float(self.final_best_recovery or 0.0),
            "has_promising_future": bool(self.has_promising_future),
            "stop_regret": float(self.stop_regret or 0.0),
            "branch_bad": bool(self.branch_bad),
            "best_elsewhere": bool(self.best_elsewhere),
            "untried_promising_sibling_count": int(self.untried_promising_sibling_count or 0),
            "teacher_budget": dict(self.teacher_budget or {}),
            "teacher_trace_id": self.teacher_trace_id,
            "source": dict(self.source or {}),
        }


def sample_from_dict(row: dict[str, Any]) -> PolicyGraphTrainingSample:
    actions = []
    for raw in row.get("actions") or row.get("available_actions") or []:
        if not isinstance(raw, dict):
            continue
        action_type = _action_type(raw)
        if action_type not in {"stop", "undo", "module"}:
            continue
        actions.append(PolicyAction(
            action_type=action_type,  # type: ignore[arg-type]
            action_id=str(raw.get("action_id") or raw.get("candidate_id") or action_type),
            module_name=str(raw.get("module_name") or raw.get("module") or ""),
            score=_float(raw.get("score")),
            action_q_value=_float(raw.get("action_q_value", raw.get("q_value"))),
            action_prior=_float(raw.get("action_prior", raw.get("prior"))),
            q_source=str(raw.get("q_source") or ""),
            q_horizon=int(_float(raw.get("q_horizon"))),
            action_regret=_float(raw.get("action_regret")),
            is_teacher_evaluated=bool(raw.get("is_teacher_evaluated", False)),
            best_action_set_member=bool(raw.get("best_action_set_member", False)),
            q_bucket=str(raw.get("q_bucket") or ""),
            features=dict(raw.get("features") or {}),
        ))
    return PolicyGraphTrainingSample(
        sample_id=str(row.get("sample_id") or row.get("query_id") or ""),
        format=str(row.get("format") or "zip"),
        graph=dict(row.get("graph") or {}),
        current_node_id=str(row.get("current_node_id") or ""),
        best_node_id=str(row.get("best_node_id") or ""),
        actions=actions,
        memory=[dict(item) for item in row.get("memory") or [] if isinstance(item, dict)],
        diagnosis_hgt=dict(row.get("diagnosis_hgt") or {}),
        current_recovery=dict(row.get("current_recovery") or {}),
        best_recovery=dict(row.get("best_recovery") or {}),
        final_best_recovery=_float(row.get("final_best_recovery")),
        has_promising_future=bool(row.get("has_promising_future", False)),
        stop_regret=_float(row.get("stop_regret")),
        branch_bad=bool(row.get("branch_bad", False)),
        best_elsewhere=bool(row.get("best_elsewhere", False)),
        untried_promising_sibling_count=int(_float(row.get("untried_promising_sibling_count"))),
        teacher_budget=dict(row.get("teacher_budget") or {}),
        teacher_trace_id=str(row.get("teacher_trace_id") or ""),
        source=dict(row.get("source") or {}),
    )


@dataclass(frozen=True)
class PolicyGraphTransitionSample:
    sample_id: str
    format: str
    graph_before: dict[str, Any]
    current_node_id: str
    best_node_id: str
    available_actions: list[PolicyAction]
    chosen_action: PolicyAction
    graph_after: dict[str, Any]
    observed_delta: dict[str, Any] = field(default_factory=dict)
    action_q_values: dict[str, float] = field(default_factory=dict)
    episode_id: str = ""
    step_index: int = 0
    exploration_policy: str = ""
    source: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        return {
            "schema_version": POLICY_TRANSITION_ROW_SCHEMA,
            "sample_id": self.sample_id,
            "format": self.format,
            "graph_before": dict(self.graph_before or {}),
            "current_node_id": self.current_node_id,
            "best_node_id": self.best_node_id,
            "available_actions": [action.to_dict() for action in self.available_actions],
            "chosen_action": self.chosen_action.to_dict(),
            "graph_after": dict(self.graph_after or {}),
            "observed_delta": dict(self.observed_delta or {}),
            "action_q_values": dict(self.action_q_values or {}),
            "episode_id": self.episode_id,
            "step_index": int(self.step_index or 0),
            "exploration_policy": self.exploration_policy,
            "source": dict(self.source or {}),
        }


@dataclass(frozen=True)
class PolicyMaskedGraphSample:
    sample_id: str
    format: str
    graph: dict[str, Any]
    masked_graph: dict[str, Any]
    mask_targets: dict[str, Any]
    current_node_id: str = ""
    best_node_id: str = ""
    source: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        return {
            "schema_version": POLICY_WORLD_ROW_SCHEMA,
            "task": "masked_graph",
            "sample_id": self.sample_id,
            "format": self.format,
            "graph": dict(self.graph or {}),
            "masked_graph": dict(self.masked_graph or {}),
            "mask_targets": dict(self.mask_targets or {}),
            "current_node_id": self.current_node_id,
            "best_node_id": self.best_node_id,
            "source": dict(self.source or {}),
        }


@dataclass(frozen=True)
class PolicyWorldTrainingSample:
    task: WorldTask
    sample_id: str
    format: str
    graph: dict[str, Any]
    current_node_id: str = ""
    best_node_id: str = ""
    actions: list[PolicyAction] = field(default_factory=list)
    chosen_action: PolicyAction | None = None
    graph_after: dict[str, Any] = field(default_factory=dict)
    observed_delta: dict[str, Any] = field(default_factory=dict)
    masked_graph: dict[str, Any] = field(default_factory=dict)
    mask_targets: dict[str, Any] = field(default_factory=dict)
    ranking_sample: PolicyGraphTrainingSample | None = None
    source: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        payload = {
            "schema_version": POLICY_WORLD_ROW_SCHEMA,
            "task": self.task,
            "sample_id": self.sample_id,
            "format": self.format,
            "graph": dict(self.graph or {}),
            "current_node_id": self.current_node_id,
            "best_node_id": self.best_node_id,
            "actions": [action.to_dict() for action in self.actions],
            "chosen_action": self.chosen_action.to_dict() if self.chosen_action is not None else {},
            "graph_after": dict(self.graph_after or {}),
            "observed_delta": dict(self.observed_delta or {}),
            "masked_graph": dict(self.masked_graph or {}),
            "mask_targets": dict(self.mask_targets or {}),
            "source": dict(self.source or {}),
        }
        if self.ranking_sample is not None:
            payload["ranking_sample"] = self.ranking_sample.to_dict()
        return payload


def transition_sample_from_dict(row: dict[str, Any]) -> PolicyGraphTransitionSample:
    actions = [_policy_action_from_dict(raw) for raw in row.get("available_actions") or row.get("actions") or [] if isinstance(raw, dict)]
    chosen_raw = row.get("chosen_action") if isinstance(row.get("chosen_action"), dict) else {}
    return PolicyGraphTransitionSample(
        sample_id=str(row.get("sample_id") or ""),
        format=str(row.get("format") or "zip"),
        graph_before=dict(row.get("graph_before") or row.get("graph") or {}),
        current_node_id=str(row.get("current_node_id") or ""),
        best_node_id=str(row.get("best_node_id") or ""),
        available_actions=actions,
        chosen_action=_policy_action_from_dict(chosen_raw or {"action_type": "stop", "action_id": "stop"}),
        graph_after=dict(row.get("graph_after") or {}),
        observed_delta=dict(row.get("observed_delta") or {}),
        action_q_values={str(key): _float(value) for key, value in (row.get("action_q_values") or {}).items()} if isinstance(row.get("action_q_values"), dict) else {},
        episode_id=str(row.get("episode_id") or ""),
        step_index=int(_float(row.get("step_index"))),
        exploration_policy=str(row.get("exploration_policy") or ""),
        source=dict(row.get("source") or {}),
    )


def world_sample_from_dict(row: dict[str, Any]) -> PolicyWorldTrainingSample:
    task = str(row.get("task") or "ranking")
    if task not in {"transition", "masked_graph", "ranking"}:
        task = "ranking"
    ranking = row.get("ranking_sample") if isinstance(row.get("ranking_sample"), dict) else None
    return PolicyWorldTrainingSample(
        task=task,  # type: ignore[arg-type]
        sample_id=str(row.get("sample_id") or ""),
        format=str(row.get("format") or "zip"),
        graph=dict(row.get("graph") or row.get("graph_before") or {}),
        current_node_id=str(row.get("current_node_id") or ""),
        best_node_id=str(row.get("best_node_id") or ""),
        actions=[_policy_action_from_dict(raw) for raw in row.get("actions") or row.get("available_actions") or [] if isinstance(raw, dict)],
        chosen_action=_policy_action_from_dict(row.get("chosen_action")) if isinstance(row.get("chosen_action"), dict) else None,
        graph_after=dict(row.get("graph_after") or {}),
        observed_delta=dict(row.get("observed_delta") or {}),
        masked_graph=dict(row.get("masked_graph") or {}),
        mask_targets=dict(row.get("mask_targets") or {}),
        ranking_sample=sample_from_dict(ranking) if ranking else None,
        source=dict(row.get("source") or {}),
    )


def _policy_action_from_dict(raw: dict[str, Any]) -> PolicyAction:
    action_type = _action_type(raw)
    if action_type not in {"stop", "undo", "module"}:
        action_type = "module" if raw.get("module_name") or raw.get("module") else "stop"
    return PolicyAction(
        action_type=action_type,  # type: ignore[arg-type]
        action_id=str(raw.get("action_id") or raw.get("candidate_id") or action_type),
        module_name=str(raw.get("module_name") or raw.get("module") or ""),
        score=_float(raw.get("score")),
        action_q_value=_float(raw.get("action_q_value", raw.get("q_value"))),
        action_prior=_float(raw.get("action_prior", raw.get("prior"))),
        q_source=str(raw.get("q_source") or ""),
        q_horizon=int(_float(raw.get("q_horizon"))),
        action_regret=_float(raw.get("action_regret")),
        is_teacher_evaluated=bool(raw.get("is_teacher_evaluated", False)),
        best_action_set_member=bool(raw.get("best_action_set_member", False)),
        q_bucket=str(raw.get("q_bucket") or ""),
        features=dict(raw.get("features") or {}),
    )


def _action_type(raw: dict[str, Any]) -> str:
    text = str(raw.get("action_type") or raw.get("type") or "").strip().lower()
    if text == "module" or text.startswith("module:"):
        return "module"
    if text in {"undo", "stop"}:
        return text
    if raw.get("module_name") or raw.get("module"):
        return "module"
    return text


def _float(value: Any) -> float:
    try:
        return float(value)
    except (TypeError, ValueError):
        return 0.0
