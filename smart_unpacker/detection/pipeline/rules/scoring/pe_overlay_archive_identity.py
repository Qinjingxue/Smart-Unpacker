from typing import Any, Dict

from smart_unpacker.contracts.detection import FactBag
from smart_unpacker.contracts.rules import RuleEffect
from smart_unpacker.detection.pipeline.rules.base import RuleBase
from smart_unpacker.detection.pipeline.rules.registry import register_rule


DEFAULT_OVERLAY_START_SCORE = 5
DEFAULT_OVERLAY_NEAR_START_SCORE = 4


@register_rule(name="pe_overlay_archive_identity", layer="scoring")
class PeOverlayArchiveIdentityScoreRule(RuleBase):
    required_facts = {"pe.overlay_structure"}
    fact_requirements = []
    produced_facts = {
        "file.detected_ext",
        "file.container_type",
        "file.probe_detected_archive",
        "file.probe_offset",
        "file.embedded_archive_found",
        "zip.local_header_plausible",
        "zip.local_header_offset",
        "zip.local_header_error",
    }
    config_schema = {
        "overlay_start_score": {
            "type": "int",
            "required": False,
            "default": DEFAULT_OVERLAY_START_SCORE,
            "description": "Score for archive evidence exactly at the PE overlay start.",
        },
        "overlay_near_start_score": {
            "type": "int",
            "required": False,
            "default": DEFAULT_OVERLAY_NEAR_START_SCORE,
            "description": "Score for archive evidence near the PE overlay start.",
        },
    }

    def _record_zip_plausibility(self, facts: FactBag, overlay: dict[str, Any]):
        zip_header = overlay.get("zip_local_header") or {}
        if not zip_header:
            return
        facts.set("zip.local_header_plausible", bool(zip_header.get("plausible")))
        facts.set("zip.local_header_offset", int(zip_header.get("offset") or overlay.get("archive_offset") or 0))
        facts.set("zip.local_header_error", str(zip_header.get("error") or ""))

    def evaluate(self, facts: FactBag, config: Dict[str, Any]) -> RuleEffect:
        overlay = facts.get("pe.overlay_structure") or {}
        if not overlay.get("archive_like"):
            return RuleEffect.pass_()

        detected_ext = overlay.get("detected_ext") or ""
        if detected_ext:
            facts.set("file.detected_ext", detected_ext)
        facts.set("file.container_type", "pe")
        facts.set("file.probe_detected_archive", True)
        facts.set("file.probe_offset", int(overlay.get("archive_offset") or 0))
        facts.set("file.embedded_archive_found", True)
        self._record_zip_plausibility(facts, overlay)

        delta = int(overlay.get("offset_delta_from_overlay") or 0)
        if delta == 0:
            score = config.get("overlay_start_score", DEFAULT_OVERLAY_START_SCORE)
            reason = "PE overlay archive at overlay start"
        else:
            score = config.get("overlay_near_start_score", DEFAULT_OVERLAY_NEAR_START_SCORE)
            reason = "PE overlay archive near overlay start"
        if not score:
            return RuleEffect.pass_()

        archive_format = overlay.get("format") or detected_ext or "archive"
        confidence = overlay.get("confidence") or "unknown"
        return RuleEffect.add_score(score, reason=f"{reason}: {archive_format} ({confidence})")
