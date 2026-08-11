from typing import Any

from sunpack.contracts.detection import FactBag
from sunpack.contracts.rules import RuleEffect
from sunpack.detection.pipeline.rules.base import RuleBase
from sunpack.detection.pipeline.rules.registry import register_rule
from sunpack.detection.pipeline.rules.scoring._fuzzy import (
    add_component,
    available,
    fuzzy_effect_reason,
    naming_prior,
    text_contains,
)


_FORMAT_META = {
    "gzip": ({"gzip"}, {".gz", ".tgz", ".tar.gz"}, ".gz"),
    "bzip2": ({"bzip2"}, {".bz2", ".tbz", ".tbz2", ".tar.bz2"}, ".bz2"),
    "xz": ({"xz"}, {".xz", ".txz", ".tar.xz"}, ".xz"),
    "zstd": ({"zstd"}, {".zst", ".zstd", ".tzst", ".tar.zst"}, ".zst"),
}


@register_rule(name="compression_stream_identity", layer="scoring")
class CompressionStreamIdentityScoreRule(RuleBase):
    required_facts = {"compression.stream_structure"}
    produced_facts = {"file.detected_ext", "file.probe_detected_archive", "file.probe_offset"}
    score_group = "archive_format"
    config_schema: dict[str, dict[str, Any]] = {}

    def evaluate(self, facts: FactBag, config: dict[str, Any]) -> RuleEffect:
        del config
        structure = facts.get("compression.stream_structure") or {}
        format_name = str(structure.get("format") or "").lower()
        if not structure.get("magic_matched") or format_name not in _FORMAT_META:
            return RuleEffect.pass_()

        components: list[str] = []
        score = add_component(components, "signature", 2, True)
        header_ok, secondary_ok, integrity_ok, contradiction = _format_evidence(format_name, structure)
        score += add_component(components, "header-fields", 2, header_ok)
        score += add_component(components, "secondary-anchor", 2, secondary_ok)
        score += add_component(components, "integrity-fragment", 1, integrity_ok)
        formats, extensions, default_ext = _FORMAT_META[format_name]
        naming, label = naming_prior(facts, formats=formats, extensions=extensions)
        score += add_component(components, label, naming, naming > 0)
        score += add_component(components, "format-contradiction", -2, contradiction)

        detected_ext = str(structure.get("detected_ext") or default_ext)
        facts.set("file.detected_ext", detected_ext)
        facts.set("file.probe_detected_archive", True)
        facts.set("file.probe_offset", 0)
        return RuleEffect.add_score(score, reason=fuzzy_effect_reason(format_name, components))


def _format_evidence(format_name: str, structure: dict[str, Any]) -> tuple[bool, bool, bool, bool]:
    error = str(structure.get("error") or "")
    damage = {str(item) for item in structure.get("damage_flags") or []}
    if format_name == "gzip":
        method = structure.get("member.header.compression_method")
        header_ok = method == 8 and available(structure.get("member.header.flags"))
        secondary = available(structure.get("member.deflate.blocks")) or _positive_int(structure.get("decoded_bytes"))
        integrity = bool(structure.get("validation_complete")) or text_contains(
            structure.get("member.trailer.crc32"), "ok=true"
        )
        contradiction = "reserved_flags" in error or (available(method) and method != 8)
        return header_ok, secondary, integrity, contradiction
    if format_name == "bzip2":
        block_size = structure.get("stream.block_size_100k")
        header_ok = isinstance(block_size, int) and 1 <= block_size <= 9
        marker = structure.get("block.marker")
        secondary = available(marker) and marker != 2**64 - 1
        integrity = bool(structure.get("stream.end_marker")) or bool(structure.get("validation_complete"))
        return header_ok, secondary, integrity, False
    if format_name == "xz":
        flags = structure.get("stream.header.flags")
        header_ok = available(flags) and not text_contains(error, "reserved")
        secondary = available(structure.get("stream.footer.magic")) or available(structure.get("block.header.size"))
        integrity = text_contains(structure.get("stream.header.crc32"), "ok=true") or bool(
            structure.get("validation_complete")
        )
        contradiction = text_contains(error, "reserved")
        return header_ok, secondary, integrity, contradiction

    descriptor = structure.get("frame.header.descriptor")
    header_ok = available(descriptor) and not text_contains(error, "reserved_bit")
    secondary = available(structure.get("block.header.type")) or _positive_int(structure.get("frame.sequence"))
    integrity = bool(structure.get("validation_complete")) or available(structure.get("frame.content_checksum"))
    contradiction = "zstd_reserved_bit_set" in damage or text_contains(error, "reserved_bit")
    return header_ok, secondary, integrity, contradiction


def _positive_int(value: Any) -> bool:
    if not available(value):
        return False
    try:
        return int(value) > 0
    except (TypeError, ValueError):
        return False
