from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Protocol, runtime_checkable

from sunpack.repair.candidate import RepairCandidate
from sunpack.repair.job import RepairJob


PolicyCandidatePayload = dict[str, Any]


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
    selected_index: int | None = None
    confidence: float | None = None
    provider_id: str = ""
    reason: str = ""
    metadata: dict[str, Any] = field(default_factory=dict)


@runtime_checkable
class RepairPolicyProvider(Protocol):
    provider_id: str
    supported_formats: tuple[str, ...] | list[str]

    def available(self) -> bool:
        ...

    def can_handle(self, request: RepairPolicyRequest) -> bool:
        ...

    def choose(self, request: RepairPolicyRequest) -> RepairPolicyDecision | dict[str, Any] | str | int | None:
        ...
