from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Literal


TRAINING_EPISODE_SCHEMA_VERSION = 2
TrainingActionKind = Literal["expand_edge", "checkout_node", "stop_signal"]
_ACTION_KINDS = {"expand_edge", "checkout_node", "stop_signal"}


@dataclass(frozen=True)
class TrainingDamageLabel:
    label: str
    zone: dict[str, Any] = field(default_factory=dict)
    confidence: float = 1.0
    metadata: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        return {
            "label": self.label,
            "zone": dict(self.zone),
            "confidence": float(self.confidence or 0.0),
            "metadata": dict(self.metadata),
        }

    @classmethod
    def from_dict(cls, payload: dict[str, Any]) -> "TrainingDamageLabel":
        return cls(
            label=str(payload.get("label") or ""),
            zone=dict(payload.get("zone") or {}),
            confidence=_float(payload.get("confidence"), default=1.0),
            metadata=dict(payload.get("metadata") or {}),
        )


@dataclass(frozen=True)
class TrainingVerificationSnapshot:
    score: float = 0.0
    status: str = ""
    decision_hint: str = ""
    recovered_files: int = 0
    recovered_bytes: int = 0
    details: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        return {
            "score": float(self.score or 0.0),
            "status": self.status,
            "decision_hint": self.decision_hint,
            "recovered_files": int(self.recovered_files or 0),
            "recovered_bytes": int(self.recovered_bytes or 0),
            "details": dict(self.details),
        }

    @classmethod
    def from_dict(cls, payload: dict[str, Any] | None) -> "TrainingVerificationSnapshot":
        payload = payload if isinstance(payload, dict) else {}
        return cls(
            score=_float(payload.get("score")),
            status=str(payload.get("status") or ""),
            decision_hint=str(payload.get("decision_hint") or ""),
            recovered_files=_int(payload.get("recovered_files")),
            recovered_bytes=_int(payload.get("recovered_bytes")),
            details=dict(payload.get("details") or {}),
        )


@dataclass(frozen=True)
class TrainingCandidateSnapshot:
    candidate_id: str
    action_type: TrainingActionKind = "expand_edge"
    module_name: str = ""
    format: str = ""
    patch_depth: int = 0
    patch_digest: str = ""
    patch_operation_count: int = 0
    confidence: float = 0.0
    validation_summary: dict[str, Any] = field(default_factory=dict)
    metadata: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        return {
            "candidate_id": self.candidate_id,
            "action_type": self.action_type,
            "module_name": self.module_name,
            "format": self.format,
            "patch_depth": int(self.patch_depth or 0),
            "patch_digest": self.patch_digest,
            "patch_operation_count": int(self.patch_operation_count or 0),
            "confidence": float(self.confidence or 0.0),
            "validation_summary": dict(self.validation_summary),
            "metadata": dict(self.metadata),
        }

    @classmethod
    def from_dict(cls, payload: dict[str, Any]) -> "TrainingCandidateSnapshot":
        action_type = _action_kind(payload.get("action_type") or "expand_edge")
        return cls(
            candidate_id=str(payload.get("candidate_id") or ""),
            action_type=action_type,
            module_name=str(payload.get("module_name") or payload.get("module") or ""),
            format=str(payload.get("format") or ""),
            patch_depth=_int(payload.get("patch_depth")),
            patch_digest=str(payload.get("patch_digest") or ""),
            patch_operation_count=_int(payload.get("patch_operation_count")),
            confidence=_float(payload.get("confidence")),
            validation_summary=dict(payload.get("validation_summary") or {}),
            metadata=dict(payload.get("metadata") or {}),
        )


@dataclass(frozen=True)
class TrainingAction:
    action_type: TrainingActionKind
    candidate_id: str = ""
    reason: str = ""
    metadata: dict[str, Any] = field(default_factory=dict)

    def __post_init__(self) -> None:
        action = _action_kind(self.action_type)
        object.__setattr__(self, "action_type", action)
        if action == "expand_edge" and not str(self.candidate_id or ""):
            raise ValueError("expand_edge training action requires candidate_id")
        if action != "expand_edge" and self.candidate_id:
            object.__setattr__(self, "candidate_id", "")

    def to_dict(self) -> dict[str, Any]:
        return {
            "action_type": self.action_type,
            "candidate_id": self.candidate_id,
            "reason": self.reason,
            "metadata": dict(self.metadata),
        }

    @classmethod
    def from_dict(cls, payload: dict[str, Any]) -> "TrainingAction":
        return cls(
            action_type=_action_kind(payload.get("action_type")),
            candidate_id=str(payload.get("candidate_id") or ""),
            reason=str(payload.get("reason") or ""),
            metadata=dict(payload.get("metadata") or {}),
        )


@dataclass(frozen=True)
class TrainingTransition:
    round_index: int
    state_digest: str
    patch_depth: int
    damage_analysis_request: dict[str, Any] = field(default_factory=dict)
    damage_analysis_target: dict[str, Any] = field(default_factory=dict)
    candidate_snapshots: list[TrainingCandidateSnapshot] = field(default_factory=list)
    available_actions: list[TrainingAction] = field(default_factory=list)
    selected_action: TrainingAction | None = None
    next_state_digest: str = ""
    verification_before: TrainingVerificationSnapshot = field(default_factory=TrainingVerificationSnapshot)
    verification_after: TrainingVerificationSnapshot = field(default_factory=TrainingVerificationSnapshot)
    reward: float = 0.0
    terminal: bool = False
    node_id: str = ""
    parent_node_id: str = ""
    frontier_edge_id: str = ""
    graph_action: dict[str, Any] = field(default_factory=dict)
    graph_best_node_id: str = ""
    branch_status: str = ""

    def to_dict(self) -> dict[str, Any]:
        return {
            "round_index": int(self.round_index or 0),
            "state_digest": self.state_digest,
            "patch_depth": int(self.patch_depth or 0),
            "damage_analysis_request": dict(self.damage_analysis_request),
            "damage_analysis_target": dict(self.damage_analysis_target),
            "candidate_snapshots": [item.to_dict() for item in self.candidate_snapshots],
            "available_actions": [item.to_dict() for item in self.available_actions],
            "selected_action": self.selected_action.to_dict() if self.selected_action is not None else None,
            "next_state_digest": self.next_state_digest,
            "verification_before": self.verification_before.to_dict(),
            "verification_after": self.verification_after.to_dict(),
            "reward": float(self.reward or 0.0),
            "terminal": bool(self.terminal),
            "node_id": self.node_id,
            "parent_node_id": self.parent_node_id,
            "frontier_edge_id": self.frontier_edge_id,
            "graph_action": dict(self.graph_action),
            "graph_best_node_id": self.graph_best_node_id,
            "branch_status": self.branch_status,
        }

    @classmethod
    def from_dict(cls, payload: dict[str, Any]) -> "TrainingTransition":
        selected = payload.get("selected_action")
        return cls(
            round_index=_int(payload.get("round_index")),
            state_digest=str(payload.get("state_digest") or ""),
            patch_depth=_int(payload.get("patch_depth")),
            damage_analysis_request=dict(payload.get("damage_analysis_request") or {}),
            damage_analysis_target=dict(payload.get("damage_analysis_target") or {}),
            candidate_snapshots=[
                TrainingCandidateSnapshot.from_dict(item)
                for item in payload.get("candidate_snapshots") or []
                if isinstance(item, dict)
            ],
            available_actions=[
                TrainingAction.from_dict(item)
                for item in payload.get("available_actions") or []
                if isinstance(item, dict)
            ],
            selected_action=TrainingAction.from_dict(selected) if isinstance(selected, dict) else None,
            next_state_digest=str(payload.get("next_state_digest") or ""),
            verification_before=TrainingVerificationSnapshot.from_dict(payload.get("verification_before")),
            verification_after=TrainingVerificationSnapshot.from_dict(payload.get("verification_after")),
            reward=_float(payload.get("reward")),
            terminal=bool(payload.get("terminal")),
            node_id=str(payload.get("node_id") or ""),
            parent_node_id=str(payload.get("parent_node_id") or ""),
            frontier_edge_id=str(payload.get("frontier_edge_id") or ""),
            graph_action=dict(payload.get("graph_action") or {}),
            graph_best_node_id=str(payload.get("graph_best_node_id") or ""),
            branch_status=str(payload.get("branch_status") or ""),
        )


@dataclass(frozen=True)
class TrainingEpisode:
    episode_id: str
    format: str
    source_identity: dict[str, Any]
    corrupted_input: dict[str, Any]
    oracle_damage: list[TrainingDamageLabel] = field(default_factory=list)
    initial_state: dict[str, Any] = field(default_factory=dict)
    initial_state_digest: str = ""
    transitions: list[TrainingTransition] = field(default_factory=list)
    terminal: dict[str, Any] = field(default_factory=dict)
    metadata: dict[str, Any] = field(default_factory=dict)
    schema_version: int = TRAINING_EPISODE_SCHEMA_VERSION

    def to_dict(self) -> dict[str, Any]:
        return {
            "schema_version": int(self.schema_version or TRAINING_EPISODE_SCHEMA_VERSION),
            "episode_id": self.episode_id,
            "format": self.format,
            "source_identity": dict(self.source_identity),
            "corrupted_input": dict(self.corrupted_input),
            "oracle_damage": [item.to_dict() for item in self.oracle_damage],
            "initial_state": dict(self.initial_state),
            "initial_state_digest": self.initial_state_digest,
            "transitions": [item.to_dict() for item in self.transitions],
            "terminal": dict(self.terminal),
            "metadata": dict(self.metadata),
        }

    @classmethod
    def from_dict(cls, payload: dict[str, Any]) -> "TrainingEpisode":
        return cls(
            schema_version=_int(payload.get("schema_version"), default=TRAINING_EPISODE_SCHEMA_VERSION),
            episode_id=str(payload.get("episode_id") or ""),
            format=str(payload.get("format") or ""),
            source_identity=dict(payload.get("source_identity") or {}),
            corrupted_input=dict(payload.get("corrupted_input") or {}),
            oracle_damage=[
                TrainingDamageLabel.from_dict(item)
                for item in payload.get("oracle_damage") or []
                if isinstance(item, dict)
            ],
            initial_state=dict(payload.get("initial_state") or {}),
            initial_state_digest=str(payload.get("initial_state_digest") or ""),
            transitions=[
                TrainingTransition.from_dict(item)
                for item in payload.get("transitions") or []
                if isinstance(item, dict)
            ],
            terminal=dict(payload.get("terminal") or {}),
            metadata=dict(payload.get("metadata") or {}),
        )


def _action_kind(value: Any) -> TrainingActionKind:
    text = str(value or "")
    if text not in _ACTION_KINDS:
        raise ValueError(f"unsupported training action: {text}")
    return text  # type: ignore[return-value]


def _int(value: Any, *, default: int = 0) -> int:
    try:
        if value is None:
            return default
        return int(value)
    except Exception:
        return default


def _float(value: Any, *, default: float = 0.0) -> float:
    try:
        if value is None:
            return default
        return float(value)
    except Exception:
        return default
