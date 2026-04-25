import binascii
from typing import Any, Dict, Tuple, Optional
from smart_unpacker.contracts.rules import RuleEffect
from smart_unpacker.contracts.detection import FactBag
from smart_unpacker.detection.pipeline.rules.registry import register_rule
from smart_unpacker.detection.pipeline.rules.base import RuleBase

DEFAULT_STRONG_SIGNATURES_HEX = {
    "377abcaf271c": ".7z",
    "52617221": ".rar",
    "504b0304": ".zip",
    "504b0506": ".zip",
    "504b0708": ".zip",
    "1f8b": ".gz",
    "425a68": ".bz2",
    "fd377a585a00": ".xz",
}
DEFAULT_WEAK_SIGNATURES_HEX = {
    "4d5a": ".exe",
}
DEFAULT_STRONG_SCORE = 5
DEFAULT_WEAK_SCORE = -1

@register_rule(name="magic_bytes", layer="scoring")
class MagicBytesScoreRule(RuleBase):
    required_facts = {"file.magic_bytes"}
    fact_requirements = []
    produced_facts = {"file.detected_ext", "file.magic_matched"}
    config_schema = {
        "strong_signatures_hex": {
            "type": "dict[str,str]",
            "required": False,
            "default": DEFAULT_STRONG_SIGNATURES_HEX,
            "description": "Hex magic signatures that strongly identify archive formats.",
        },
        "weak_signatures_hex": {
            "type": "dict[str,str]",
            "required": False,
            "default": DEFAULT_WEAK_SIGNATURES_HEX,
            "description": "Hex signatures that identify weak/non-archive container hints.",
        },
        "strong_score": {
            "type": "int",
            "required": False,
            "default": DEFAULT_STRONG_SCORE,
            "description": "Score for strong signature matches.",
        },
        "weak_score": {
            "type": "int",
            "required": False,
            "default": DEFAULT_WEAK_SCORE,
            "description": "Score for weak signature matches.",
        },
    }

    def _match_signatures(self, magic_bytes: bytes, sigs_hex: Dict[str, str]) -> Tuple[Optional[str], bool]:
        for hex_sig, ext in sigs_hex.items():
            try:
                sig_bytes = binascii.unhexlify(hex_sig)
                if magic_bytes.startswith(sig_bytes):
                    return ext, True
            except binascii.Error:
                continue
        return None, False

    def evaluate(self, facts: FactBag, config: Dict[str, Any]) -> RuleEffect:
        magic = facts.get("file.magic_bytes")
        if not magic:
            return RuleEffect.pass_()

        strong_sigs = config.get("strong_signatures_hex", DEFAULT_STRONG_SIGNATURES_HEX)
        ext, matched = self._match_signatures(magic, strong_sigs)
        if matched:
            facts.set("file.detected_ext", ext)
            facts.set("file.magic_matched", True)
            return RuleEffect.add_score(config.get("strong_score", DEFAULT_STRONG_SCORE), reason=f"Matched strong magic signature for {ext}")

        weak_sigs = config.get("weak_signatures_hex", DEFAULT_WEAK_SIGNATURES_HEX)
        ext, matched = self._match_signatures(magic, weak_sigs)
        if matched:
            facts.set("file.detected_ext", ext)
            return RuleEffect.add_score(config.get("weak_score", DEFAULT_WEAK_SCORE), reason=f"Matched weak magic signature for {ext}")

        return RuleEffect.pass_()
