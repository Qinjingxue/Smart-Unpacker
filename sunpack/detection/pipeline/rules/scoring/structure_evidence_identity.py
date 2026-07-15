from __future__ import annotations

from typing import Any

from sunpack.contracts.detection import FactBag
from sunpack.contracts.rules import RuleEffect
from sunpack.detection.pipeline.rules.base import RuleBase
from sunpack.detection.pipeline.rules.fact_requirements import ArchiveStructureCandidate, FactRequirement
from sunpack.detection.pipeline.rules.registry import register_rule


DEFAULT_STRUCTURE_SCORE = 6
DEFAULT_PASSWORD_SCORE = 6
DEFAULT_MIN_CONFIDENCE = 0.70


@register_rule(name="structure_evidence_identity", layer="scoring")
class StructureEvidenceIdentityScoreRule(RuleBase):
    required_facts = {"analysis.structure_evidence"}
    fact_requirements = [
        FactRequirement("analysis.structure_evidence", ArchiveStructureCandidate()),
    ]
    produced_facts = {
        "file.detected_ext",
        "file.probe_detected_archive",
        "file.probe_offset",
        "file.embedded_archive_found",
    }
    config_schema = {
        "structure_score": {
            "type": "int",
            "required": False,
            "default": DEFAULT_STRUCTURE_SCORE,
            "description": "Score for extractable forensic structure evidence.",
        },
        "password_required_score": {
            "type": "int",
            "required": False,
            "default": DEFAULT_PASSWORD_SCORE,
            "description": "Score for structurally valid encrypted archives requiring a password.",
        },
        "minimum_confidence": {
            "type": "float",
            "required": False,
            "default": DEFAULT_MIN_CONFIDENCE,
            "description": "Minimum forensic confidence accepted as archive identity evidence.",
        },
        "candidate_extensions": {
            "type": "list[str]",
            "required": False,
            "description": "Extensions eligible for on-demand forensic structure analysis.",
        },
        "head_bytes": {"type": "int", "required": False, "description": "Prepass head bytes."},
        "tail_bytes": {"type": "int", "required": False, "description": "Prepass tail bytes."},
        "full_scan_max_bytes": {
            "type": "int",
            "required": False,
            "description": "Maximum candidate size eligible for an automatic full signature scan.",
        },
        "deep_scan": {"type": "bool", "required": False, "description": "Allow unbounded full scanning."},
        "fuzzy_enabled": {"type": "bool", "required": False, "description": "Enable fuzzy structure routing."},
        "max_read_mb_per_archive": {
            "type": "int",
            "required": False,
            "description": "Read budget for forensic structure analysis.",
        },
    }

    def evaluate(self, facts: FactBag, config: dict[str, Any]) -> RuleEffect:
        payload = facts.get("analysis.structure_evidence") or {}
        selected = payload.get("selected") if isinstance(payload.get("selected"), dict) else {}
        if not selected:
            return RuleEffect.pass_()
        confidence = float(selected.get("confidence") or 0.0)
        if confidence < float(config.get("minimum_confidence", DEFAULT_MIN_CONFIDENCE) or 0.0):
            return RuleEffect.pass_()
        password_required = bool(payload.get("password_required"))
        if not payload.get("has_extractable") and not password_required:
            return RuleEffect.pass_()

        format_name = str(selected.get("format") or "")
        offset = int(selected.get("start_offset") or 0)
        facts.set("analysis.status", str(selected.get("status") or "extractable"))
        facts.set("analysis.selected_format", format_name)
        facts.set("analysis.confidence", confidence)
        facts.set("analysis.prepass", dict(payload.get("prepass") or {}))
        facts.set("analysis.read_bytes", int(payload.get("read_bytes") or 0))
        facts.set("file.detected_ext", _format_extension(format_name))
        facts.set("file.probe_detected_archive", True)
        facts.set("file.probe_offset", offset)
        facts.set("file.embedded_archive_found", offset > 0)

        score = int(
            config.get("password_required_score", DEFAULT_PASSWORD_SCORE)
            if password_required
            else config.get("structure_score", DEFAULT_STRUCTURE_SCORE)
        )
        if not score:
            return RuleEffect.pass_()
        qualifier = "password-required" if password_required else "extractable"
        return RuleEffect.add_score(
            score,
            reason=f"Forensic structure: {format_name} {qualifier} ({confidence:.2f})",
        )


def _format_extension(format_name: str) -> str:
    normalized = str(format_name or "").strip().lower().lstrip(".")
    return {
        "gzip": ".gz",
        "bzip2": ".bz2",
        "zstd": ".zst",
        "tar.gz": ".tar.gz",
        "tar.bz2": ".tar.bz2",
        "tar.xz": ".tar.xz",
        "tar.zst": ".tar.zst",
    }.get(normalized, f".{normalized}" if normalized else "")
