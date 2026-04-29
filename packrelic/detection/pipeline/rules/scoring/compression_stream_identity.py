from typing import Any, Dict

from packrelic.contracts.detection import FactBag
from packrelic.contracts.rules import RuleEffect
from packrelic.detection.pipeline.rules.base import RuleBase
from packrelic.detection.pipeline.rules.registry import register_rule


DEFAULT_COMPRESSION_STREAM_SCORE = 5
DEFAULT_COMPRESSION_MAGIC_SCORE = 2


@register_rule(name="compression_stream_identity", layer="scoring")
class CompressionStreamIdentityScoreRule(RuleBase):
    required_facts = {"compression.stream_structure"}
    fact_requirements = []
    produced_facts = {"file.detected_ext", "file.probe_detected_archive", "file.probe_offset"}
    config_schema = {
        "stream_score": {
            "type": "int",
            "required": False,
            "default": DEFAULT_COMPRESSION_STREAM_SCORE,
            "description": "Score for a plausible gzip, bzip2, xz, or zstd stream structure.",
        },
        "magic_score": {
            "type": "int",
            "required": False,
            "default": DEFAULT_COMPRESSION_MAGIC_SCORE,
            "description": "Score for a compression stream magic signature without stronger stream structure.",
        },
    }

    def evaluate(self, facts: FactBag, config: Dict[str, Any]) -> RuleEffect:
        structure = facts.get("compression.stream_structure") or {}
        if not structure.get("plausible") and not structure.get("magic_matched"):
            return RuleEffect.pass_()

        detected_ext = structure.get("detected_ext") or ""
        if detected_ext:
            facts.set("file.detected_ext", detected_ext)
        facts.set("file.probe_detected_archive", True)
        facts.set("file.probe_offset", 0)

        score = (
            config.get("stream_score", DEFAULT_COMPRESSION_STREAM_SCORE)
            if structure.get("plausible")
            else config.get("magic_score", DEFAULT_COMPRESSION_MAGIC_SCORE)
        )
        if not score:
            return RuleEffect.pass_()
        archive_format = structure.get("format") or detected_ext or "compression_stream"
        confidence = structure.get("confidence") or "unknown"
        label = "structure" if structure.get("plausible") else "magic"
        return RuleEffect.add_score(
            score,
            reason=f"Compression stream {label} {archive_format} ({confidence})",
        )
