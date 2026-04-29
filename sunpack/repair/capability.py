from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any


@dataclass(frozen=True)
class ModuleCapabilityDecision:
    name: str
    formats: tuple[str, ...] = ()
    stage: str = ""
    format_supported: bool = False
    selected: bool = False
    score: float = 0.0
    route_score: float = 0.0
    fine_score: float = 0.0
    reasons: list[str] = field(default_factory=list)
    declarative_reasons: list[str] = field(default_factory=list)
    policy_reasons: list[str] = field(default_factory=list)
    dynamic_reasons: list[str] = field(default_factory=list)
    execution_status: str = ""
    execution_message: str = ""
    execution_warnings: list[str] = field(default_factory=list)

    def as_dict(self) -> dict[str, Any]:
        return {
            "name": self.name,
            "formats": list(self.formats),
            "stage": self.stage,
            "format_supported": self.format_supported,
            "selected": self.selected,
            "score": self.score,
            "route_score": self.route_score,
            "fine_score": self.fine_score,
            "reasons": list(self.reasons),
            "declarative_reasons": list(self.declarative_reasons),
            "policy_reasons": list(self.policy_reasons),
            "dynamic_reasons": list(self.dynamic_reasons),
            "execution_status": self.execution_status,
            "execution_message": self.execution_message,
            "execution_warnings": list(self.execution_warnings),
        }


@dataclass(frozen=True)
class RepairCapabilityDecision:
    format: str
    categories: tuple[str, ...] = ()
    damage_flags: tuple[str, ...] = ()
    failure_stage: str = ""
    failure_kind: str = ""
    modules: list[ModuleCapabilityDecision] = field(default_factory=list)

    @property
    def selected_modules(self) -> list[str]:
        return [item.name for item in self.modules if item.selected]

    @property
    def format_supported_modules(self) -> list[str]:
        return [item.name for item in self.modules if item.format_supported]

    @property
    def automatic_unrepairable(self) -> bool:
        if self.selected_modules:
            return False
        supported = [item for item in self.modules if item.format_supported]
        if not supported:
            return False
        for item in supported:
            if item.policy_reasons:
                return False
            if not item.declarative_reasons:
                return False
        return True

    def message(self) -> str:
        if self.automatic_unrepairable:
            flags = ", ".join(self.damage_flags) or "none"
            categories = ", ".join(self.categories) or "none"
            return (
                "no enabled repair module declares support for this damage profile "
                f"(format={self.format}, categories={categories}, flags={flags})"
            )
        if not self.format_supported_modules:
            return "no repair module is registered for this diagnosis"
        return "no repair module is selectable for this diagnosis"

    def as_dict(self) -> dict[str, Any]:
        return {
            "format": self.format,
            "categories": list(self.categories),
            "damage_flags": list(self.damage_flags),
            "failure_stage": self.failure_stage,
            "failure_kind": self.failure_kind,
            "selected_modules": self.selected_modules,
            "format_supported_modules": self.format_supported_modules,
            "automatic_unrepairable": self.automatic_unrepairable,
            "message": self.message(),
            "modules": [item.as_dict() for item in self.modules],
        }
