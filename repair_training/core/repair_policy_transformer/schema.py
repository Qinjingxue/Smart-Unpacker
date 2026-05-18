from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Literal


POLICY_GRAPH_ROW_SCHEMA = "repair_policy_graph_row_v1"
ActionType = Literal["stop", "undo", "module"]


@dataclass(frozen=True)
class PolicyAction:
    action_type: ActionType
    action_id: str
    module_name: str = ""
    score: float = 0.0
    action_q_value: float = 0.0
    action_prior: float = 0.0
    features: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        return {
            "action_type": self.action_type,
            "action_id": self.action_id,
            "module_name": self.module_name,
            "score": float(self.score or 0.0),
            "action_q_value": float(self.action_q_value or 0.0),
            "action_prior": float(self.action_prior or 0.0),
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
        source=dict(row.get("source") or {}),
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

