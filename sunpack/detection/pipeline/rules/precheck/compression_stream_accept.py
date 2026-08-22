from typing import Any

from sunpack.contracts.detection import FactBag
from sunpack.contracts.rules import RuleEffect
from sunpack.detection.pipeline.rules.base import RuleBase
from sunpack.detection.pipeline.rules.registry import register_rule


@register_rule(name="compression_stream_accept", layer="precheck")
class CompressionStreamAcceptRule(RuleBase):
    """Accept an exact, complete structural walk without claiming payload integrity."""

    required_facts = {"compression.stream_structure"}
    produced_facts = {"file.detected_ext", "file.probe_detected_archive", "file.probe_offset"}
    routing_formats = {"gzip", "bzip2", "xz", "zstd"}
    routing_extensions = {
        ".gz", ".tgz", ".tar.gz",
        ".bz2", ".tbz", ".tbz2", ".tar.bz2",
        ".xz", ".txz", ".tar.xz",
        ".zst", ".tzst", ".tar.zst",
    }
    can_be_promoted = True

    def evaluate(self, facts: FactBag, config: dict[str, Any]) -> RuleEffect:
        del config
        structure = facts.get("compression.stream_structure") or {}
        damage = list(structure.get("damage_flags") or [])
        if not (
            structure.get("plausible")
            and structure.get("structure_validation_complete")
            and structure.get("boundary_exact")
            and str(structure.get("structure_status") or "") == "complete"
            and str(structure.get("confidence") or "") == "strong"
            and not damage
            and int(structure.get("archive.trailing_data") or 0) == 0
        ):
            return RuleEffect.pass_()

        detected_ext = str(structure.get("detected_ext") or "")
        if detected_ext:
            facts.set("file.detected_ext", detected_ext)
        facts.set("file.probe_detected_archive", True)
        facts.set("file.probe_offset", 0)
        return RuleEffect.accept(
            f"{structure.get('format') or 'compression'} stream passed complete structural validation"
        )
