from dataclasses import dataclass, field
from typing import Any

from sunpack.contracts.detection import FactBag
from sunpack.contracts.rules import RuleEffect
from sunpack.detection.pipeline.rules.base import RuleBase
from sunpack.detection.pipeline.rules.fact_requirements import FactRequirement
from sunpack.detection.pipeline.rules.registry import register_rule
from sunpack.analysis import embedded_result_from_dict
from sunpack.coordinator.nested_extraction_policy import EMBEDDED_SCAN_ALLOWED_FACT


DEFAULT_DEEP_SCAN_SINGLE_CANDIDATE_RATIO = 0.3


@dataclass(frozen=True)
class _EmbeddedModuleEnabled:
    required_facts: set[str] = field(default_factory=set)

    def matches(self, facts: FactBag, config: dict[str, Any]) -> bool:
        del config
        return bool(facts.get(EMBEDDED_SCAN_ALLOWED_FACT))


@register_rule(name="embedded_payload_identity", layer="precheck")
class EmbeddedPayloadIdentityPrecheckRule(RuleBase):
    # The recursive scan policy authorizes this module for the whole candidate;
    # executable carriers are not a separate extension-based exception.
    fact_requirements = [
        FactRequirement("executable.carrier", _EmbeddedModuleEnabled()),
    ]
    produced_facts = {
        "file.detected_ext",
        "file.container_type",
        "file.probe_detected_archive",
        "file.probe_offset",
        "file.embedded_archive_found",
        "analysis.signature_prepass",
    }
    config_schema = {
        "deep_scan_single_candidate_ratio": {
            "type": "float",
            "required": False,
            "default": DEFAULT_DEEP_SCAN_SINGLE_CANDIDATE_RATIO,
            "description": "Minimum share of unresolved recursive candidate bytes held by one logical candidate before reliable embedded scanning.",
        },
    }

    def prepare_config(self, config: dict[str, Any]) -> dict[str, Any]:
        prepared = dict(config)
        ratio = float(
            prepared.get(
                "deep_scan_single_candidate_ratio",
                DEFAULT_DEEP_SCAN_SINGLE_CANDIDATE_RATIO,
            )
        )
        if not 0.0 <= ratio <= 1.0:
            raise ValueError("deep_scan_single_candidate_ratio must be between 0.0 and 1.0")
        prepared["deep_scan_single_candidate_ratio"] = ratio
        return prepared

    def evaluate(self, facts: FactBag, config: dict[str, Any]) -> RuleEffect:
        del config
        carrier = facts.get("executable.carrier") or {}
        if carrier.get("is_executable"):
            facts.set("file.container_type", "pe")
        if carrier.get("kind") == "runtime_bundle":
            profile = str(carrier.get("runtime_profile") or "unknown")
            return RuleEffect.reject(
                f"Executable application/installer bundle ({profile}) is not treated as a user archive"
            )

        if carrier.get("kind") == "self_extracting_archive":
            detected_ext = str(carrier.get("payload_detected_ext") or "")
            offset = int(carrier.get("payload_header_offset") or 0)
            if detected_ext:
                facts.set("file.detected_ext", detected_ext)
            facts.set("file.probe_detected_archive", True)
            facts.set("file.probe_offset", offset)
            facts.set("file.embedded_archive_found", True)
            return RuleEffect.accept(f"Validated PE overlay archive payload at offset {offset}")

        if not facts.has("embedded_archive.analysis"):
            if facts.is_missing("embedded_archive.analysis"):
                return RuleEffect.pass_()
            return RuleEffect.require_facts({"embedded_archive.analysis"})

        analysis = facts.get("embedded_archive.analysis") or {}
        candidates = [
            item
            for item in (analysis.get("candidates") or [])
            if item.get("candidate_kind", "logical_archive") == "logical_archive"
        ]
        if not analysis.get("complete") or not candidates:
            return RuleEffect.pass_()

        candidates.sort(
            key=lambda item: (
                -float(item.get("confidence") or 0.0),
                int(item.get("offset") or 0),
                str(item.get("format") or ""),
            )
        )
        primary = candidates[0]
        detected_ext = str(primary.get("detected_ext") or "")
        offset = int(primary.get("offset") or 0)
        if detected_ext:
            facts.set("file.detected_ext", detected_ext)
        facts.set("file.probe_detected_archive", True)
        facts.set("file.probe_offset", offset)
        facts.set("file.embedded_archive_found", True)
        facts.set("analysis.signature_prepass", embedded_result_from_dict(analysis).to_prepass())
        return RuleEffect.accept(
            f"Validated embedded {primary.get('format') or 'archive'} payload at offset {offset}"
        )
