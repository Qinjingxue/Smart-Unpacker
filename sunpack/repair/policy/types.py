from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Literal, Protocol, runtime_checkable

from sunpack.contracts.archive_state import ArchiveState
from sunpack.repair.candidate import RepairCandidate
from sunpack.repair.job import RepairJob


PolicyCandidatePayload = dict[str, Any]
RepairActionKind = Literal["apply_patch", "undo_patch", "stop", "give_up"]


@dataclass(frozen=True)
class RepairPolicyRequest:
    job: RepairJob
    format: str
    candidates: list[RepairCandidate]
    candidate_payloads: list[PolicyCandidatePayload]
    diagnosis: dict[str, Any] = field(default_factory=dict)
    config: dict[str, Any] = field(default_factory=dict)


@dataclass(frozen=True)
class RepairPolicyDecision:
    selected_candidate_id: str = ""
    confidence: float | None = None
    provider_id: str = ""
    reason: str = ""
    metadata: dict[str, Any] = field(default_factory=dict)


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

    def choose(self, request: RepairActionRequest) -> RepairActionDecision | dict[str, Any] | str | None:
        ...


@runtime_checkable
class RepairPolicyProvider(Protocol):
    provider_id: str
    supported_formats: tuple[str, ...] | list[str]

    def available(self) -> bool:
        ...

    def can_handle(self, request: RepairPolicyRequest) -> bool:
        ...

    def choose(self, request: RepairPolicyRequest) -> RepairPolicyDecision | dict[str, Any] | str | None:
        ...
