from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Protocol

from sunpack.repair.candidate import RepairCandidate
from sunpack.repair.job import RepairJob
from sunpack.repair.policy.types import PolicyExplorationGraph


@dataclass(frozen=True)
class PolicyModuleProposal:
    action_id: str
    module_name: str
    payload: dict[str, Any] = field(default_factory=dict)
    candidate: RepairCandidate | None = field(default=None, compare=False, repr=False)

    def to_action_payload(self) -> dict[str, Any]:
        return {
            **dict(self.payload or {}),
            "action_type": "module",
            "action_id": self.action_id,
            "candidate_id": self.action_id,
            "module_name": self.module_name,
        }


@dataclass(frozen=True)
class ModuleMaterializationResult:
    candidate: RepairCandidate | None = None
    failure: dict[str, Any] = field(default_factory=dict)


class RepairFormatRuntimePlugin(Protocol):
    format_name: str

    def available_modules(
        self,
        *,
        scheduler: Any,
        job: RepairJob,
        diagnosis_hgt: dict[str, Any],
        graph: PolicyExplorationGraph,
    ) -> list[PolicyModuleProposal]:
        ...

    def build_module_job(
        self,
        *,
        job: RepairJob,
        module_name: str,
        graph: PolicyExplorationGraph,
    ) -> RepairJob:
        ...

    def materialize_module(
        self,
        *,
        scheduler: Any,
        proposal: PolicyModuleProposal,
        job: RepairJob,
    ) -> ModuleMaterializationResult:
        ...


_PLUGINS: dict[str, RepairFormatRuntimePlugin] = {}


def register_repair_format_plugin(plugin: RepairFormatRuntimePlugin) -> RepairFormatRuntimePlugin:
    _PLUGINS[_normalize_format(plugin.format_name)] = plugin
    return plugin


def get_repair_format_plugin(format_name: str) -> RepairFormatRuntimePlugin | None:
    _ensure_default_plugins()
    return _PLUGINS.get(_normalize_format(format_name))


def _ensure_default_plugins() -> None:
    if _PLUGINS:
        return
    from sunpack.repair.policy.formats.zip import ZipRepairFormatRuntimePlugin

    register_repair_format_plugin(ZipRepairFormatRuntimePlugin())


def _normalize_format(value: str) -> str:
    text = str(value or "").strip().lower().replace("-", "_")
    if text in {"zip", "pkzip"}:
        return "zip"
    if text in {"7z", "sevenzip", "seven_zip"}:
        return "seven_zip"
    return text
