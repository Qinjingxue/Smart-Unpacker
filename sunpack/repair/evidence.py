from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any


@dataclass(frozen=True)
class RepairAnalysisSegment:
    """Repair-owned projection of an analyzed archive segment."""

    start_offset: int
    end_offset: int | None = None
    confidence: float = 0.0
    role: str = "primary"
    damage_flags: list[str] = field(default_factory=list)
    evidence: list[str] = field(default_factory=list)


@dataclass(frozen=True)
class RepairAnalysisEvidence:
    """Stable repair input reconstructed from task knowledge facts."""

    format: str
    confidence: float = 0.0
    status: str = "not_found"
    segments: list[RepairAnalysisSegment] = field(default_factory=list)
    warnings: list[str] = field(default_factory=list)
    details: dict[str, Any] = field(default_factory=dict)
