from typing import Any, Dict

from smart_unpacker.contracts.detection import FactBag
from smart_unpacker.contracts.rules import RuleEffect
from smart_unpacker.detection.pipeline.rules.base import RuleBase
from smart_unpacker.detection.pipeline.rules.fact_requirements import FactRequirement
from smart_unpacker.detection.pipeline.rules.registry import register_rule


DEFAULT_MAGIC_START_SCORE = 5
DEFAULT_CARRIER_TAIL_SCORE = 5
DEFAULT_LOOSE_SCAN_SCORE = 4
DEFAULT_SFX_HINT_SCORE = 3
DEFAULT_REQUIRE_ZIP_PLAUSIBILITY_FOR_LOOSE_SCAN = True
DEFAULT_REQUIRE_ZIP_PLAUSIBILITY_FOR_CARRIER_TAIL = False


@register_rule(name="archive_identity", layer="scoring")
class ArchiveIdentityScoreRule(RuleBase):
    required_facts = {"archive.identity"}
    fact_requirements = [FactRequirement("archive.identity")]
    produced_facts = {
        "file.detected_ext",
        "file.magic_matched",
        "file.probe_detected_archive",
        "file.probe_offset",
        "file.embedded_archive_found",
        "zip.local_header_plausible",
        "zip.local_header_offset",
        "zip.local_header_error",
    }
    config_schema = {
        "magic_start_score": {
            "type": "int",
            "required": False,
            "default": DEFAULT_MAGIC_START_SCORE,
            "description": "Score for strong archive magic at offset zero.",
        },
        "carrier_tail_score": {
            "type": "int",
            "required": False,
            "default": DEFAULT_CARRIER_TAIL_SCORE,
            "description": "Score for archive payload detected after a carrier EOF marker.",
        },
        "loose_scan_score": {
            "type": "int",
            "required": False,
            "default": DEFAULT_LOOSE_SCAN_SCORE,
            "description": "Score for loose embedded archive identity evidence.",
        },
        "sfx_hint_score": {
            "type": "int",
            "required": False,
            "default": DEFAULT_SFX_HINT_SCORE,
            "description": "Score for archive identity evidence inside an executable-like carrier.",
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
        "identity_scan_exts": {
            "type": "list[str]",
            "required": True,
            "description": "Extensions eligible for cheap magic-start archive identity checks.",
        },
        "carrier_exts": {
            "type": "list[str]",
            "required": False,
            "description": "Extensions whose native EOF marker is used before tail-archive scanning.",
        },
        "ambiguous_resource_exts": {
            "type": "list[str]",
            "required": False,
            "description": "Extensions eligible for loose embedded-archive identity scanning.",
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
        "carrier_scan_prefix_window_bytes": {
            "type": "int",
            "required": False,
            "description": "Prefix window searched for carrier EOF markers before full carrier scanning.",
        },
        "carrier_scan_full_scan_max_bytes": {
            "type": "int",
            "required": False,
            "description": "Maximum file size eligible for automatic full carrier marker scan after tail scan misses. Set 0 to disable full carrier scans unless carrier_scan_deep_scan is enabled.",
        },
        "carrier_scan_deep_scan": {
            "type": "bool",
            "required": False,
            "description": "Allow full carrier marker scans regardless of carrier_scan_full_scan_max_bytes.",
        },
    }

    def _record_zip_plausibility(self, facts: FactBag, identity: Dict[str, Any]):
        zip_header = identity.get("zip_local_header") or {}
        if not zip_header:
            return
        facts.set("zip.local_header_plausible", bool(zip_header.get("plausible")))
        facts.set("zip.local_header_offset", int(zip_header.get("offset") or identity.get("offset") or 0))
        facts.set("zip.local_header_error", str(zip_header.get("error") or ""))

    def _zip_plausibility_required(self, identity: Dict[str, Any], config: Dict[str, Any]) -> bool:
        if identity.get("detected_ext") != ".zip":
            return False
        if identity.get("mode") == "loose_scan":
            return bool(config.get(
                "zip_plausibility_required_for_loose_scan",
                DEFAULT_REQUIRE_ZIP_PLAUSIBILITY_FOR_LOOSE_SCAN,
            ))
        return bool(config.get(
            "zip_plausibility_required_for_carrier_tail",
            DEFAULT_REQUIRE_ZIP_PLAUSIBILITY_FOR_CARRIER_TAIL,
        ))

    def _passes_zip_plausibility(self, facts: FactBag, identity: Dict[str, Any], config: Dict[str, Any]) -> bool:
        if not self._zip_plausibility_required(identity, config):
            return True
        self._record_zip_plausibility(facts, identity)
        return bool((identity.get("zip_local_header") or {}).get("plausible"))

    def _score_for_mode(self, mode: str, config: Dict[str, Any]) -> int:
        if mode == "magic_start":
            return config.get("magic_start_score", DEFAULT_MAGIC_START_SCORE)
        if mode == "carrier_tail":
            return config.get("carrier_tail_score", DEFAULT_CARRIER_TAIL_SCORE)
        if mode == "sfx_hint":
            return config.get("sfx_hint_score", DEFAULT_SFX_HINT_SCORE)
        if mode == "loose_scan":
            return config.get("loose_scan_score", DEFAULT_LOOSE_SCAN_SCORE)
        return 0

    def evaluate(self, facts: FactBag, config: Dict[str, Any]) -> RuleEffect:
        identity = facts.get("archive.identity") or {}
        if not identity.get("is_archive_like"):
            return RuleEffect.pass_()

        if not self._passes_zip_plausibility(facts, identity, config):
            return RuleEffect.pass_()

        detected_ext = identity.get("detected_ext") or ""
        if detected_ext:
            facts.set("file.detected_ext", detected_ext)
        if identity.get("mode") == "magic_start":
            facts.set("file.magic_matched", True)
        facts.set("file.probe_detected_archive", True)
        facts.set("file.probe_offset", int(identity.get("offset") or 0))
        if identity.get("mode") in {"carrier_tail", "loose_scan", "sfx_hint"}:
            facts.set("file.embedded_archive_found", True)
        self._record_zip_plausibility(facts, identity)

        mode = identity.get("mode") or ""
        score = self._score_for_mode(mode, config)
        if not score:
            return RuleEffect.pass_()

        confidence = identity.get("confidence") or "unknown"
        archive_format = identity.get("format") or detected_ext or "archive"
        return RuleEffect.add_score(
            score,
            reason=f"Archive identity {archive_format} via {mode} ({confidence})",
        )
