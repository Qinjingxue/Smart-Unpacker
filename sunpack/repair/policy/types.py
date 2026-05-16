from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Literal, Protocol, runtime_checkable

from sunpack.contracts.archive_state import ArchiveState
from sunpack.repair.candidate import RepairCandidate
from sunpack.repair.job import RepairJob


PolicyCandidatePayload = dict[str, Any]
RepairActionKind = Literal["apply_patch", "undo_patch", "stop", "give_up"]


@dataclass(frozen=True)
class DamageAnalysisRequest:
    job: RepairJob
    format: str
    archive_state: ArchiveState | None = None
    runtime_context: dict[str, Any] = field(default_factory=dict)
    diagnosis: dict[str, Any] = field(default_factory=dict)
    knowledge_projection: dict[str, Any] = field(default_factory=dict)
    repair_history: dict[str, Any] = field(default_factory=dict)
    config: dict[str, Any] = field(default_factory=dict)
    round_index: int = 0


@dataclass(frozen=True)
class DamageAnalysisResult:
    format: str = ""
    damage_labels: list[str] = field(default_factory=list)
    damage_zones: list[dict[str, Any]] = field(default_factory=list)
    confidence: float = 0.0
    route_hints: list[str] = field(default_factory=list)
    blocking_reasons: list[str] = field(default_factory=list)
    metadata: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        return {
            "format": self.format,
            "damage_labels": list(self.damage_labels),
            "damage_zones": [dict(item) for item in self.damage_zones],
            "confidence": float(self.confidence or 0.0),
            "route_hints": list(self.route_hints),
            "blocking_reasons": list(self.blocking_reasons),
            "metadata": dict(self.metadata),
        }


@dataclass(frozen=True)
class RepairActionRequest:
    job: RepairJob
    format: str
    archive_state: ArchiveState | None
    candidates: list[RepairCandidate]
    candidate_payloads: list[PolicyCandidatePayload]
    damage_analysis: dict[str, Any] = field(default_factory=dict)
    current_recovery: dict[str, Any] = field(default_factory=dict)
    best_seen_recovery: dict[str, Any] = field(default_factory=dict)
    parent_recovery: dict[str, Any] = field(default_factory=dict)
    diagnosis: dict[str, Any] = field(default_factory=dict)
    repair_history: dict[str, Any] = field(default_factory=dict)
    config: dict[str, Any] = field(default_factory=dict)
    round_index: int = 0


@dataclass(frozen=True)
class RepairActionDecision:
    action: RepairActionKind = "give_up"
    selected_candidate_id: str = ""
    confidence: float | None = None
    provider_id: str = ""
    reason: str = ""
    metadata: dict[str, Any] = field(default_factory=dict)


@dataclass(frozen=True)
class RepairActionPrior:
    action: RepairActionKind = "give_up"
    candidate_id: str = ""
    prior_score: float = 0.0
    confidence: float | None = None
    provider_id: str = ""
    reason: str = ""
    metadata: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        return {
            "action": self.action,
            "candidate_id": self.candidate_id,
            "prior_score": float(self.prior_score or 0.0),
            "confidence": self.confidence,
            "provider_id": self.provider_id,
            "reason": self.reason,
            "metadata": dict(self.metadata),
        }


@dataclass(frozen=True)
class StateValueRequest:
    job: RepairJob
    format: str
    archive_state: ArchiveState | None = None
    damage_analysis: dict[str, Any] = field(default_factory=dict)
    current_recovery: dict[str, Any] = field(default_factory=dict)
    best_seen_recovery: dict[str, Any] = field(default_factory=dict)
    parent_recovery: dict[str, Any] = field(default_factory=dict)
    candidate_summaries: list[PolicyCandidatePayload] = field(default_factory=list)
    repair_history: dict[str, Any] = field(default_factory=dict)
    diagnosis: dict[str, Any] = field(default_factory=dict)
    config: dict[str, Any] = field(default_factory=dict)
    round_index: int = 0


@dataclass(frozen=True)
class StateValueResult:
    reachable_recovery_value: float = 0.0
    confidence: float | None = None
    provider_id: str = ""
    metadata: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        return {
            "reachable_recovery_value": float(self.reachable_recovery_value or 0.0),
            "confidence": self.confidence,
            "provider_id": self.provider_id,
            "metadata": dict(self.metadata),
        }


@runtime_checkable
class DamageAnalysisModel(Protocol):
    provider_id: str
    supported_formats: tuple[str, ...] | list[str]

    def available(self) -> bool:
        ...

    def analyze(self, request: DamageAnalysisRequest) -> DamageAnalysisResult | dict[str, Any] | None:
        ...


@runtime_checkable
class RepairActionModel(Protocol):
    provider_id: str
    supported_formats: tuple[str, ...] | list[str]

    def available(self) -> bool:
        ...

    def choose(self, request: RepairActionRequest) -> dict[str, Any] | list[dict[str, Any]] | None:
        ...


@runtime_checkable
class StateValueModel(Protocol):
    provider_id: str
    supported_formats: tuple[str, ...] | list[str]

    def available(self) -> bool:
        ...

    def estimate(self, request: StateValueRequest) -> StateValueResult | dict[str, Any] | float | None:
        ...
