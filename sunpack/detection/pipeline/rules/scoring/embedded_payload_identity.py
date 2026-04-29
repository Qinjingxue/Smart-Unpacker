import os
from typing import Any, Dict

from sunpack.contracts.detection import FactBag
from sunpack.contracts.rules import RuleEffect
from sunpack.detection.pipeline.rules.base import RuleBase
from sunpack.detection.pipeline.rules.registry import register_rule


DEFAULT_CARRIER_TAIL_SCORE = 5
DEFAULT_LOOSE_SCAN_SCORE = 4
DEFAULT_OVERLAY_START_SCORE = 6
DEFAULT_OVERLAY_NEAR_START_SCORE = 4
DEFAULT_REQUIRE_ZIP_PLAUSIBILITY_FOR_LOOSE_SCAN = True
DEFAULT_REQUIRE_ZIP_PLAUSIBILITY_FOR_CARRIER_TAIL = False


def _format_from_ext(ext: str) -> str:
    return ext[1:].lower() if ext.startswith(".") else ext.lower()


@register_rule(name="embedded_payload_identity", layer="scoring")
class EmbeddedPayloadIdentityScoreRule(RuleBase):
    required_facts = {"embedded_archive.analysis", "pe.overlay_structure"}
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

    def _record_zip_plausibility(self, facts: FactBag, payload: Dict[str, Any]):
        zip_header = payload.get("zip_local_header") or {}
        if not zip_header:
            return
        facts.set("zip.local_header_plausible", bool(zip_header.get("plausible")))
        facts.set("zip.local_header_offset", int(zip_header.get("offset") or payload.get("offset") or payload.get("archive_offset") or 0))
        facts.set("zip.local_header_error", str(zip_header.get("error") or ""))

    def _zip_plausibility_required(self, payload: Dict[str, Any], config: Dict[str, Any]) -> bool:
        if payload.get("detected_ext") != ".zip":
            return False
        mode = payload.get("mode") or ""
        if mode == "loose_scan":
            return bool(config.get(
                "zip_plausibility_required_for_loose_scan",
                DEFAULT_REQUIRE_ZIP_PLAUSIBILITY_FOR_LOOSE_SCAN,
            ))
        if mode == "carrier_tail":
            return bool(config.get(
                "zip_plausibility_required_for_carrier_tail",
                DEFAULT_REQUIRE_ZIP_PLAUSIBILITY_FOR_CARRIER_TAIL,
            ))
        return False

    def _passes_zip_plausibility(self, facts: FactBag, payload: Dict[str, Any], config: Dict[str, Any]) -> bool:
        if not self._zip_plausibility_required(payload, config):
            return True
        self._record_zip_plausibility(facts, payload)
        return bool((payload.get("zip_local_header") or {}).get("plausible"))

    def _embedded_candidate(self, facts: FactBag) -> dict[str, Any] | None:
        analysis = facts.get("embedded_archive.analysis") or {}
        if not analysis.get("found"):
            return None
        path_ext = os.path.splitext(facts.get("file.path") or "")[1].lower()
        mode = analysis.get("mode") or ""
        if path_ext == ".exe" and mode == "loose_scan":
            return None

        detected_ext = analysis.get("detected_ext") or ""
        archive_format = _format_from_ext(detected_ext)
        confidence = "strong" if mode == "carrier_tail" else "medium"
        return {
            "source": "embedded_archive",
            "mode": mode,
            "format": archive_format,
            "detected_ext": detected_ext,
            "offset": int(analysis.get("offset") or 0),
            "confidence": confidence,
            "zip_local_header": analysis.get("zip_local_header") or {},
        }

    def _overlay_candidate(self, facts: FactBag) -> dict[str, Any] | None:
        overlay = facts.get("pe.overlay_structure") or {}
        if not overlay.get("archive_like"):
            return None
        delta = int(overlay.get("offset_delta_from_overlay") or 0)
        return {
            "source": "pe_overlay",
            "mode": "pe_overlay_start" if delta == 0 else "pe_overlay_near_start",
            "format": overlay.get("format") or "",
            "detected_ext": overlay.get("detected_ext") or "",
            "offset": int(overlay.get("archive_offset") or 0),
            "confidence": overlay.get("confidence") or "unknown",
            "zip_local_header": overlay.get("zip_local_header") or {},
            "offset_delta_from_overlay": delta,
        }

    def _candidate_score(self, candidate: dict[str, Any], config: Dict[str, Any]) -> tuple[int, str]:
        mode = candidate.get("mode") or ""
        if mode == "carrier_tail":
            return config.get("carrier_tail_score", DEFAULT_CARRIER_TAIL_SCORE), "carrier tail"
        if mode == "loose_scan":
            return config.get("loose_scan_score", DEFAULT_LOOSE_SCAN_SCORE), "loose scan"
        if mode == "pe_overlay_start":
            return config.get("overlay_start_score", DEFAULT_OVERLAY_START_SCORE), "PE overlay start"
        if mode == "pe_overlay_near_start":
            return config.get("overlay_near_start_score", DEFAULT_OVERLAY_NEAR_START_SCORE), "PE overlay near start"
        return 0, mode or "embedded payload"

    def evaluate(self, facts: FactBag, config: Dict[str, Any]) -> RuleEffect:
        candidates = [
            candidate
            for candidate in (self._overlay_candidate(facts), self._embedded_candidate(facts))
            if candidate is not None
        ]
        if not candidates:
            return RuleEffect.pass_()

        candidate = candidates[0]
        if not self._passes_zip_plausibility(facts, candidate, config):
            return RuleEffect.pass_()

        detected_ext = candidate.get("detected_ext") or ""
        if detected_ext:
            facts.set("file.detected_ext", detected_ext)
        if candidate.get("source") == "pe_overlay":
            facts.set("file.container_type", "pe")
        facts.set("file.probe_detected_archive", True)
        facts.set("file.probe_offset", int(candidate.get("offset") or 0))
        facts.set("file.embedded_archive_found", True)
        self._record_zip_plausibility(facts, candidate)

        score, label = self._candidate_score(candidate, config)
        if not score:
            return RuleEffect.pass_()

        archive_format = candidate.get("format") or detected_ext or "archive"
        confidence = candidate.get("confidence") or "unknown"
        return RuleEffect.add_score(score, reason=f"Embedded payload {archive_format} via {label} ({confidence})")
