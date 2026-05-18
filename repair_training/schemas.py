from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any


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


def _float(value: Any, *, default: float = 0.0) -> float:
    try:
        if value is None:
            return default
        return float(value)
    except Exception:
        return default
