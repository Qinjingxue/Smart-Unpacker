from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Protocol


@dataclass(frozen=True)
class RepairRuntimeStrategyDecision:
    mode: str
    selected_candidate_ids: list[str]
    beam_enabled: bool = False
    metadata: dict[str, Any] | None = None


class RepairRuntimeStrategy(Protocol):
    name: str

    def choose(self, *, state_id: str, candidate_payloads: list[dict[str, Any]], context: dict[str, Any] | None = None) -> RepairRuntimeStrategyDecision:
        ...


@dataclass
class TrainingExhaustiveStrategy:
    branch_top_k: int = 5
    name: str = "training_exhaustive"

    def choose(self, *, state_id: str, candidate_payloads: list[dict[str, Any]], context: dict[str, Any] | None = None) -> RepairRuntimeStrategyDecision:
        ordered = list(candidate_payloads or [])
        limit = max(1, int(self.branch_top_k or 1))
        return RepairRuntimeStrategyDecision(
            mode=self.name,
            selected_candidate_ids=[str(item.get("candidate_id") or "") for item in ordered[:limit] if str(item.get("candidate_id") or "")],
            beam_enabled=False,
            metadata={"state_id": state_id, "candidate_count": len(ordered), "branch_top_k": limit},
        )


@dataclass
class ModelSinglePathStrategy:
    provider: Any
    name: str = "model_single_path"

    def choose(self, *, state_id: str, candidate_payloads: list[dict[str, Any]], context: dict[str, Any] | None = None) -> RepairRuntimeStrategyDecision:
        request = {
            "state_id": state_id,
            "candidate_payloads": list(candidate_payloads or []),
            "context": dict(context or {}),
        }
        decision = self.provider.choose(request) if self.provider is not None else None
        if isinstance(decision, dict):
            selected = str(decision.get("selected_candidate_id") or "")
        else:
            selected = str(getattr(decision, "selected_candidate_id", "") or "")
        return RepairRuntimeStrategyDecision(
            mode=self.name,
            selected_candidate_ids=[selected] if selected else [],
            beam_enabled=False,
            metadata={"state_id": state_id, "provider_id": getattr(self.provider, "provider_id", "")},
        )


@dataclass
class SelectorBeamStrategy:
    name: str = "selector_beam"

    def choose(self, *, state_id: str, candidate_payloads: list[dict[str, Any]], context: dict[str, Any] | None = None) -> RepairRuntimeStrategyDecision:
        return RepairRuntimeStrategyDecision(
            mode=self.name,
            selected_candidate_ids=[],
            beam_enabled=True,
            metadata={"state_id": state_id, "candidate_count": len(candidate_payloads or [])},
        )
