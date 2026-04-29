from typing import Any, Dict

from packrelic.contracts.detection import FactBag
from packrelic.contracts.rules import RuleEffect
from packrelic.detection.pipeline.rules.base import RuleBase
from packrelic.detection.pipeline.rules.fact_requirements import FactRequirement, MagicBytesStartsWith
from packrelic.detection.pipeline.rules.registry import register_rule


DEFAULT_ZIP_EOCD_SCORE = 6
DEFAULT_ZIP_EMBEDDED_EOCD_SCORE = 4
DEFAULT_ZIP_EMPTY_EOCD_SCORE = 4
DEFAULT_ZIP_MAGIC_SCORE = 2
DEFAULT_ZIP_LOCAL_HEADER_SCORE = 4
DEFAULT_ZIP_CD_WALK_SCORE = 7
ZIP_START_MAGICS = (b"PK\x03\x04", b"PK\x05\x06", b"PK\x07\x08")


@register_rule(name="zip_structure_identity", layer="scoring")
class ZipStructureIdentityScoreRule(RuleBase):
    required_facts = {"zip.local_header", "zip.eocd_structure"}
    fact_requirements = [
        FactRequirement("zip.local_header"),
        FactRequirement("zip.eocd_structure", MagicBytesStartsWith(ZIP_START_MAGICS)),
    ]
    produced_facts = {"file.detected_ext", "file.probe_detected_archive", "file.probe_offset"}
    config_schema = {
        "eocd_score": {
            "type": "int",
            "required": False,
            "default": DEFAULT_ZIP_EOCD_SCORE,
            "description": "Score for a plausible ZIP EOCD and central directory structure.",
        },
        "empty_eocd_score": {
            "type": "int",
            "required": False,
            "default": DEFAULT_ZIP_EMPTY_EOCD_SCORE,
            "description": "Score for a plausible empty ZIP EOCD without central directory entries.",
        },
        "embedded_eocd_score": {
            "type": "int",
            "required": False,
            "default": DEFAULT_ZIP_EMBEDDED_EOCD_SCORE,
            "description": "Score for a plausible ZIP EOCD whose archive payload starts after a leading stub.",
        },
        "magic_score": {
            "type": "int",
            "required": False,
            "default": DEFAULT_ZIP_MAGIC_SCORE,
            "description": "Score for a ZIP-like magic signature at offset zero without stronger ZIP structure.",
        },
        "local_header_score": {
            "type": "int",
            "required": False,
            "default": DEFAULT_ZIP_LOCAL_HEADER_SCORE,
            "description": "Score for a plausible ZIP local file header without EOCD evidence.",
        },
        "cd_walk_score": {
            "type": "int",
            "required": False,
            "default": DEFAULT_ZIP_CD_WALK_SCORE,
            "description": "Score for ZIP EOCD, central directory entry walk, and local-header back references.",
        },
        "max_cd_entries_to_walk": {
            "type": "int",
            "required": False,
            "description": "Maximum central directory entries checked by the ZIP structure processor.",
        },
    }

    def evaluate(self, facts: FactBag, config: Dict[str, Any]) -> RuleEffect:
        structure = facts.get("zip.eocd_structure") or {}
        local_header = facts.get("zip.local_header") or {}
        if not structure.get("plausible") and not local_header.get("magic_matched"):
            return RuleEffect.pass_()

        facts.set("file.detected_ext", ".zip")
        facts.set("file.probe_detected_archive", True)
        facts.set("file.probe_offset", int(structure.get("archive_offset") or 0))

        archive_offset = int(structure.get("archive_offset") or 0)
        if (
            structure.get("plausible")
            and structure.get("central_directory_walk_ok")
            and structure.get("local_header_links_ok")
            and archive_offset == 0
        ):
            score = config.get("cd_walk_score", DEFAULT_ZIP_CD_WALK_SCORE)
            reason = "ZIP structure: central directory entries and local header links"
        elif structure.get("plausible") and archive_offset > 0:
            score = config.get("embedded_eocd_score", DEFAULT_ZIP_EMBEDDED_EOCD_SCORE)
            reason = "ZIP structure: embedded EOCD and central directory"
        elif structure.get("plausible") and structure.get("central_directory_present"):
            score = config.get("eocd_score", DEFAULT_ZIP_EOCD_SCORE)
            reason = "ZIP structure: EOCD and central directory"
        elif structure.get("plausible"):
            score = config.get("empty_eocd_score", DEFAULT_ZIP_EMPTY_EOCD_SCORE)
            reason = "ZIP structure: empty EOCD"
        elif local_header.get("plausible"):
            score = config.get("local_header_score", DEFAULT_ZIP_LOCAL_HEADER_SCORE)
            reason = "ZIP structure: local file header"
        else:
            score = config.get("magic_score", DEFAULT_ZIP_MAGIC_SCORE)
            reason = "ZIP structure: magic signature"
        if not score:
            return RuleEffect.pass_()
        return RuleEffect.add_score(score, reason=reason)
