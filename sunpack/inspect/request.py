from __future__ import annotations

from dataclasses import dataclass, field

from sunpack.analysis.request import AnalysisCapability, DEFAULT_ANALYSIS_CAPABILITIES


@dataclass(frozen=True, slots=True)
class InspectionRequest:
    """Repair-owned request for feedback about one archive state."""

    capabilities: frozenset[AnalysisCapability] = field(
        default_factory=lambda: DEFAULT_ANALYSIS_CAPABILITIES
    )
    initial_prepass: dict | None = None

    def __post_init__(self) -> None:
        object.__setattr__(
            self,
            "capabilities",
            frozenset(AnalysisCapability(item) for item in self.capabilities),
        )
        if self.initial_prepass is not None:
            object.__setattr__(self, "initial_prepass", dict(self.initial_prepass))
