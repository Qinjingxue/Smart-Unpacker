from typing import Any

from sunpack.contracts.detection import FactBag
from sunpack.contracts.rules import RuleEffect
from sunpack.detection.pipeline.rules.base import RuleBase
from sunpack.detection.pipeline.rules.registry import register_rule


DEFAULT_DEEP_SCAN_SIZE_COVERAGE_RATIO = 0.5
DEFAULT_EMBEDDED_PAYLOAD_SCORE = 6


@register_rule(name="embedded_payload_identity", layer="scoring")
class EmbeddedPayloadIdentityScoreRule(RuleBase):
    required_facts = {"embedded_archive.analysis", "pe.overlay_structure"}
    produced_facts = {
        "file.detected_ext",
        "file.container_type",
        "file.probe_detected_archive",
        "file.probe_offset",
        "file.embedded_archive_found",
        "analysis.signature_prepass",
    }
    config_schema = {
        "deep_scan_size_coverage_ratio": {
            "type": "float",
            "required": False,
            "default": DEFAULT_DEEP_SCAN_SIZE_COVERAGE_RATIO,
            "description": "Cumulative byte share of unresolved candidates selected for reliable embedded scanning.",
        },
        "embedded_payload_score": {
            "type": "int",
            "required": False,
            "default": DEFAULT_EMBEDDED_PAYLOAD_SCORE,
            "description": "Score for at least one structurally validated embedded archive.",
        },
    }

    def prepare_config(self, config: dict[str, Any]) -> dict[str, Any]:
        prepared = dict(config)
        ratio = float(prepared.get("deep_scan_size_coverage_ratio", DEFAULT_DEEP_SCAN_SIZE_COVERAGE_RATIO))
        if not 0.0 <= ratio <= 1.0:
            raise ValueError("deep_scan_size_coverage_ratio must be between 0.0 and 1.0")
        prepared["deep_scan_size_coverage_ratio"] = ratio
        return prepared

    def evaluate(self, facts: FactBag, config: dict[str, Any]) -> RuleEffect:
        overlay = facts.get("pe.overlay_structure") or {}
        if overlay.get("archive_like"):
            detected_ext = str(overlay.get("detected_ext") or "")
            offset = int(overlay.get("archive_offset") or 0)
            if detected_ext:
                facts.set("file.detected_ext", detected_ext)
            facts.set("file.container_type", "pe")
            facts.set("file.probe_detected_archive", True)
            facts.set("file.probe_offset", offset)
            facts.set("file.embedded_archive_found", True)
            return RuleEffect.add_score(
                int(config.get("embedded_payload_score", DEFAULT_EMBEDDED_PAYLOAD_SCORE)),
                reason=f"Validated PE overlay archive payload at offset {offset}",
            )

        analysis = facts.get("embedded_archive.analysis") or {}
        candidates = list(analysis.get("candidates") or [])
        if not analysis.get("complete") or not candidates:
            return RuleEffect.pass_()

        candidates.sort(key=lambda item: (-float(item.get("confidence") or 0.0), int(item.get("offset") or 0), str(item.get("format") or "")))
        primary = candidates[0]
        detected_ext = str(primary.get("detected_ext") or "")
        offset = int(primary.get("offset") or 0)
        facts.set("file.detected_ext", detected_ext)
        facts.set("file.probe_detected_archive", True)
        facts.set("file.probe_offset", offset)
        facts.set("file.embedded_archive_found", True)
        facts.set("analysis.signature_prepass", _prepass_from_scan(analysis))

        score = int(config.get("embedded_payload_score", DEFAULT_EMBEDDED_PAYLOAD_SCORE))
        return RuleEffect.add_score(
            score,
            reason=f"Validated embedded {primary.get('format') or 'archive'} payload at offset {offset}",
        )


def _prepass_from_scan(analysis: dict[str, Any]) -> dict[str, Any]:
    candidates = list(analysis.get("candidates") or [])
    validated_formats = {str(item.get("format") or "") for item in candidates}
    hit_format = {
        "zip_local": "zip", "zip_eocd": "zip", "rar4": "rar", "rar5": "rar",
        "7z": "7z", "gzip": "gzip", "bzip2": "bzip2", "xz": "xz",
        "zstd": "zstd", "tar_ustar": "tar",
    }
    hits = [
        hit for hit in list(analysis.get("hits") or [])
        if hit_format.get(str(hit.get("name") or "")) in validated_formats
    ]
    return {
        "hits": hits,
        "formats": sorted({str(item.get("format") or "") for item in candidates if item.get("format")}),
        "full_scan_bytes": int(analysis.get("read_bytes") or 0),
        "full_scan_complete": bool(analysis.get("complete")),
        "source": "detection_embedded_scan",
        "embedded_candidates": candidates,
    }
