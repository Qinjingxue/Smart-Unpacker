from __future__ import annotations

from typing import Any

from sunpack.contracts.detection import FactBag
from sunpack.contracts.rules import ConfirmationEffect
from sunpack.detection.pipeline.rules.base import RuleBase
from sunpack.detection.pipeline.rules.registry import register_rule


@register_rule("archive_identity_consensus", "confirmation")
class ArchiveIdentityConsensusRule(RuleBase):
    """Confirm archive identity from already-collected, bounded structural facts."""

    required_facts = {"file.path"}
    produced_facts = {"confirmation.identity_required", "confirmation.identity"}
    config_schema = {
        "always_run": {"type": "bool", "required": False, "default": True},
        "minimum_analysis_confidence": {"type": "float", "required": False, "default": 0.90},
    }

    def evaluate(self, facts: FactBag, config: dict[str, Any]) -> ConfirmationEffect:
        facts.set("confirmation.identity_required", True)
        identity = _strong_identity(facts, float(config.get("minimum_analysis_confidence", 0.90)))
        if not identity:
            facts.set("confirmation.identity", {"verdict": "abstain", "strength": "none"})
            return ConfirmationEffect.pass_()
        facts.set("confirmation.identity", identity)
        detected_ext = str(identity.get("detected_ext") or "")
        if detected_ext:
            facts.set("file.detected_ext", detected_ext)
        facts.set("file.probe_detected_archive", True)
        facts.set("file.probe_offset", int(identity.get("offset") or 0))
        return ConfirmationEffect.confirm(
            f"Fast structural consensus confirmed {identity['format']} archive identity"
        )


def _strong_identity(facts: FactBag, minimum_analysis_confidence: float) -> dict[str, Any] | None:
    overlay = facts.get("pe.overlay_structure") or {}
    if overlay.get("archive_like") and str(overlay.get("confidence") or "") == "strong":
        return _identity(str(overlay.get("format") or "archive"), str(overlay.get("detected_ext") or ""), int(overlay.get("archive_offset") or 0), "pe_overlay")

    embedded = facts.get("embedded_archive.analysis") or {}
    candidates = list(embedded.get("candidates") or []) if embedded.get("complete") else []
    if candidates:
        best = max(candidates, key=lambda item: float(item.get("confidence") or 0.0))
        if float(best.get("confidence") or 0.0) >= 0.95:
            return _identity(str(best.get("format") or "archive"), str(best.get("detected_ext") or ""), int(best.get("offset") or 0), "embedded_structure")

    zip_structure = facts.get("zip.eocd_structure") or {}
    zip_empty = int(zip_structure.get("total_entries") or 0) == 0 and int(zip_structure.get("central_directory_size") or 0) == 0
    if zip_structure.get("plausible") and (
        zip_empty or (
            zip_structure.get("central_directory_present")
            and zip_structure.get("central_directory_walk_ok")
            and zip_structure.get("local_header_links_ok")
        )
    ):
        return _identity("zip", ".zip", int(zip_structure.get("archive_offset") or 0), "zip_directory_links")

    seven = facts.get("7z.structure") or {}
    seven_crc = seven.get("next_header_crc_ok") if seven.get("next_header_crc_checked") else True
    if seven.get("plausible") and seven.get("start_header_crc_ok") and seven_crc:
        return _identity("7z", ".7z", 0, "7z_header_crc")

    rar = facts.get("rar.structure") or {}
    if rar.get("plausible") and rar.get("magic_matched") and (
        rar.get("header_crc_ok") or rar.get("block_walk_ok") or rar.get("header_encrypted")
    ):
        return _identity("rar", ".rar", 0, "rar_header_crc")

    tar = facts.get("tar.header_structure") or {}
    if tar.get("plausible") and int(tar.get("stored_checksum") or -1) == int(tar.get("computed_checksum") or -2):
        return _identity("tar", ".tar", 0, "tar_header_checksum")

    stream = facts.get("compression.stream_structure") or {}
    if stream.get("plausible") and stream.get("magic_matched") and str(stream.get("confidence") or "") in {"medium", "strong"}:
        return _identity(str(stream.get("format") or "stream"), str(stream.get("detected_ext") or ""), 0, "stream_header")

    container = facts.get("archive.container_structure") or {}
    if container.get("plausible") and str(container.get("confidence") or "") == "strong":
        return _identity(str(container.get("format") or "archive"), str(container.get("detected_ext") or ""), 0, "container_header")

    analysis = facts.get("analysis.structure_evidence") or {}
    selected = analysis.get("selected") if isinstance(analysis.get("selected"), dict) else {}
    if selected and float(selected.get("confidence") or 0.0) >= minimum_analysis_confidence and (
        analysis.get("has_extractable") or analysis.get("password_required")
    ):
        fmt = str(selected.get("format") or "archive")
        return _identity(fmt, _format_extension(fmt), int(selected.get("start_offset") or 0), "analysis_structure")
    return None


def _identity(fmt: str, ext: str, offset: int, evidence: str) -> dict[str, Any]:
    return {
        "verdict": "confirm",
        "strength": "strong",
        "format": fmt,
        "detected_ext": ext,
        "offset": offset,
        "evidence": [evidence],
    }


def _format_extension(fmt: str) -> str:
    value = str(fmt or "").lower().lstrip(".")
    return {"gzip": ".gz", "bzip2": ".bz2", "zstd": ".zst"}.get(value, f".{value}" if value else "")
