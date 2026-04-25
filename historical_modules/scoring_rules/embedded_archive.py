from typing import Any, Dict

from smart_unpacker.contracts.detection import FactBag
from smart_unpacker.contracts.rules import RuleEffect
from smart_unpacker.detection.pipeline.rules.base import RuleBase
from smart_unpacker.detection.pipeline.rules.fact_requirements import FactRequirement, PathExtensionInConfig
from smart_unpacker.detection.pipeline.rules.registry import register_rule


DEFAULT_SCORE = 5
DEFAULT_LOOSE_SCAN_SCORE = 4
DEFAULT_REQUIRE_ZIP_PLAUSIBILITY_FOR_LOOSE_SCAN = True
DEFAULT_REQUIRE_ZIP_PLAUSIBILITY_FOR_CARRIER_TAIL = False


@register_rule(name="embedded_archive", layer="scoring")
class EmbeddedArchiveScoreRule(RuleBase):
    required_facts = {"embedded_archive.analysis"}
    fact_requirements = [
        FactRequirement(
            "embedded_archive.analysis",
            condition=PathExtensionInConfig(
                fields=("carrier_exts", "ambiguous_resource_exts"),
            ),
        )
    ]
    produced_facts = {
        "file.detected_ext",
        "file.probe_detected_archive",
        "file.probe_offset",
        "file.embedded_archive_found",
        "zip.local_header_plausible",
        "zip.local_header_offset",
        "zip.local_header_error",
    }
    config_schema = {
        "score": {
            "type": "int",
            "required": False,
            "default": DEFAULT_SCORE,
            "description": "Score when a structured carrier tail contains an archive payload.",
        },
        "loose_scan_score": {
            "type": "int",
            "required": False,
            "default": DEFAULT_LOOSE_SCAN_SCORE,
            "description": "Score when loose scanning finds an embedded archive payload.",
        },
        "zip_plausibility_required_for_loose_scan": {
            "type": "bool",
            "required": False,
            "default": DEFAULT_REQUIRE_ZIP_PLAUSIBILITY_FOR_LOOSE_SCAN,
            "description": "Require a structurally plausible ZIP local header before accepting loose-scan ZIP hits.",
        },
        "zip_plausibility_required_for_carrier_tail": {
            "type": "bool",
            "required": False,
            "default": DEFAULT_REQUIRE_ZIP_PLAUSIBILITY_FOR_CARRIER_TAIL,
            "description": "Require a structurally plausible ZIP local header before accepting carrier-tail ZIP hits.",
        },
        "carrier_exts": {
            "type": "list[str]",
            "required": False,
            "description": "Extensions whose native EOF marker is used before tail-archive scanning.",
        },
        "ambiguous_resource_exts": {
            "type": "list[str]",
            "required": False,
            "description": "Extensions eligible for loose embedded-archive scanning.",
        },
        "loose_scan_min_prefix": {
            "type": "int",
            "required": False,
            "description": "Minimum prefix bytes before loose scan hits are accepted.",
        },
        "loose_scan_min_tail_bytes": {
            "type": "int",
            "required": False,
            "description": "Minimum payload bytes after a loose scan hit.",
        },
        "loose_scan_max_hits": {
            "type": "int",
            "required": False,
            "description": "Maximum loose scan hits to inspect per file.",
        },
        "loose_scan_tail_window_bytes": {
            "type": "int",
            "required": False,
            "description": "Tail window scanned before considering a full loose scan.",
        },
        "loose_scan_full_scan_max_bytes": {
            "type": "int",
            "required": False,
            "description": "Maximum file size eligible for automatic full loose scan after tail scan misses.",
        },
        "loose_scan_deep_scan": {
            "type": "bool",
            "required": False,
            "description": "Allow full loose scan for files larger than loose_scan_full_scan_max_bytes.",
        },
        "carrier_scan_tail_window_bytes": {
            "type": "int",
            "required": False,
            "description": "Tail window searched for native carrier EOF markers before full carrier scanning.",
        },
        "carrier_scan_full_scan_max_bytes": {
            "type": "int",
            "required": False,
            "description": "Maximum file size eligible for automatic full carrier marker scan after tail scan misses.",
        },
        "carrier_scan_deep_scan": {
            "type": "bool",
            "required": False,
            "description": "Allow full carrier marker scan for files larger than carrier_scan_full_scan_max_bytes.",
        },
    }

    def _zip_plausibility_required(self, analysis: Dict[str, Any], config: Dict[str, Any]) -> bool:
        if analysis.get("detected_ext") != ".zip":
            return False
        if analysis.get("mode") == "loose_scan":
            return bool(config.get(
                "zip_plausibility_required_for_loose_scan",
                DEFAULT_REQUIRE_ZIP_PLAUSIBILITY_FOR_LOOSE_SCAN,
            ))
        return bool(config.get(
            "zip_plausibility_required_for_carrier_tail",
            DEFAULT_REQUIRE_ZIP_PLAUSIBILITY_FOR_CARRIER_TAIL,
        ))

    def _record_zip_plausibility(self, facts: FactBag, analysis: Dict[str, Any]):
        zip_header = analysis.get("zip_local_header") or {}
        if not zip_header:
            return
        facts.set("zip.local_header_plausible", bool(zip_header.get("plausible")))
        facts.set("zip.local_header_offset", int(zip_header.get("offset") or analysis.get("offset") or 0))
        facts.set("zip.local_header_error", str(zip_header.get("error") or ""))

    def _passes_zip_plausibility(self, facts: FactBag, analysis: Dict[str, Any], config: Dict[str, Any]) -> bool:
        if not self._zip_plausibility_required(analysis, config):
            return True
        self._record_zip_plausibility(facts, analysis)
        return bool((analysis.get("zip_local_header") or {}).get("plausible"))

    def evaluate(self, facts: FactBag, config: Dict[str, Any]) -> RuleEffect:
        analysis = facts.get("embedded_archive.analysis") or {}
        if not analysis.get("found"):
            return RuleEffect.pass_()

        if not self._passes_zip_plausibility(facts, analysis, config):
            return RuleEffect.pass_()

        detected_ext = analysis.get("detected_ext") or ""
        if detected_ext:
            facts.set("file.detected_ext", detected_ext)
        facts.set("file.probe_detected_archive", True)
        facts.set("file.probe_offset", int(analysis.get("offset") or 0))
        facts.set("file.embedded_archive_found", True)
        self._record_zip_plausibility(facts, analysis)

        if analysis.get("mode") == "loose_scan":
            score = config.get("loose_scan_score", DEFAULT_LOOSE_SCAN_SCORE)
            return RuleEffect.add_score(score, reason=f"Loose scan found embedded {detected_ext} archive")

        score = config.get("score", DEFAULT_SCORE)
        return RuleEffect.add_score(score, reason=f"Carrier tail contains embedded {detected_ext} archive")
