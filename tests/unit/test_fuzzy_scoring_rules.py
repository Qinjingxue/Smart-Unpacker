from sunpack.contracts.detection import FactBag
from sunpack.detection.pipeline.rules.scoring.compression_stream_identity import (
    CompressionStreamIdentityScoreRule,
)
from sunpack.detection.pipeline.rules.scoring.rar_structure_identity import (
    RarStructureIdentityScoreRule,
)
from sunpack.detection.pipeline.rules.scoring.seven_zip_structure_identity import (
    SevenZipStructureIdentityScoreRule,
)
from sunpack.detection.pipeline.rules.scoring.tar_structure_identity import (
    TarStructureIdentityScoreRule,
)
from sunpack.detection.pipeline.rules.scoring.zip_structure_identity import (
    ZipStructureIdentityScoreRule,
)


def _bag(path: str) -> FactBag:
    bag = FactBag()
    bag.set("file.path", path)
    bag.set("candidate.entry_path", path)
    bag.set("candidate.logical_name", path)
    return bag


def test_zip_local_header_survives_missing_eocd_with_matching_logical_name():
    bag = _bag("damaged.zip")
    bag.set("zip.local_header", {"magic_matched": True, "plausible": True})
    bag.set("zip.eocd_structure", {})

    effect = ZipStructureIdentityScoreRule().evaluate(bag, {})

    assert effect.decision == "score"
    assert effect.score == 6


def test_seven_zip_crc_damage_keeps_independent_header_evidence():
    bag = _bag("damaged.7z")
    bag.set("7z.structure", {
        "magic_matched": True,
        "version_major": 0,
        "next_header_offset": 32,
        "next_header_size": 64,
        "start_header_crc_ok": False,
        "next_header_crc_ok": False,
        "next_header_nid_valid": False,
        "error": "start_header_crc_mismatch",
    })

    effect = SevenZipStructureIdentityScoreRule().evaluate(bag, {})

    assert effect.score >= 6


def test_rar_header_crc_damage_keeps_type_size_and_version_evidence():
    bag = _bag("damaged.rar")
    bag.set("rar.structure", {
        "magic_matched": True,
        "version": 5,
        "first_header_type": 1,
        "first_header_size": 24,
        "header_crc_ok": False,
        "error": "rar5_header_crc_mismatch",
    })

    effect = RarStructureIdentityScoreRule().evaluate(bag, {})

    assert effect.score >= 6


def test_tar_checksum_damage_keeps_ustar_and_field_layout_evidence():
    bag = _bag("damaged.tar")
    bag.set("tar.header_structure", {
        "ustar_magic": True,
        "fuzzy_name_nonempty": True,
        "fuzzy_numeric_fields_valid": True,
        "fuzzy_typeflag_valid": True,
        "fuzzy_payload_in_range": True,
        "stored_checksum": 1,
        "computed_checksum": 2,
        "error": "checksum_mismatch",
    })

    effect = TarStructureIdentityScoreRule().evaluate(bag, {})

    assert effect.score >= 6


def test_tar_nonempty_prefix_without_fixed_layout_anchor_does_not_score():
    bag = _bag("ordinary.bin")
    bag.set("tar.header_structure", {
        "ustar_magic": False,
        "fuzzy_name_nonempty": True,
        "fuzzy_numeric_fields_valid": False,
        "fuzzy_typeflag_valid": True,
        "fuzzy_payload_in_range": True,
        "stored_checksum": 0,
        "computed_checksum": 15970,
        "error": "invalid_checksum_field",
    })

    effect = TarStructureIdentityScoreRule().evaluate(bag, {})

    assert effect.decision == "pass"
    assert bag.get("file.detected_ext") is None


def test_embedded_zip_with_verified_directory_and_local_links_reaches_threshold():
    bag = _bag("carrier.bin")
    bag.set("zip.local_header", {})
    bag.set("zip.eocd_structure", {
        "eocd_candidate_found": True,
        "eocd_candidate_declared_entry_count_present": True,
        "eocd_candidate_declared_cd_offset_present": True,
        "central_directory_present": True,
        "central_directory_walk_ok": True,
        "local_header_links_ok": True,
        "archive_offset": 4096,
    })

    effect = ZipStructureIdentityScoreRule().evaluate(bag, {})

    assert effect.score == 6
    assert bag.get("file.detected_ext") == ".zip"
    assert bag.get("file.probe_offset") == 4096


def test_truncated_gzip_header_can_score_without_complete_structure():
    bag = _bag("damaged.gz")
    bag.set("compression.stream_structure", {
        "format": "gzip",
        "detected_ext": ".gz",
        "magic_matched": True,
        "member.header.compression_method": 8,
        "member.header.flags": 0,
        "member.deflate.blocks": "unavailable",
        "structure_validation_complete": False,
        "integrity_status": "deferred",
        "damage_flags": ["truncated_stream"],
    })

    effect = CompressionStreamIdentityScoreRule().evaluate(bag, {})

    assert effect.score == 6


def test_filename_without_binary_evidence_never_scores():
    zip_bag = _bag("ordinary.zip")
    zip_bag.set("zip.local_header", {})
    zip_bag.set("zip.eocd_structure", {})
    gzip_bag = _bag("ordinary.gz")
    gzip_bag.set("compression.stream_structure", {"format": "gzip", "magic_matched": False})

    assert ZipStructureIdentityScoreRule().evaluate(zip_bag, {}).decision == "pass"
    assert CompressionStreamIdentityScoreRule().evaluate(gzip_bag, {}).decision == "pass"


def test_magic_only_stays_below_archive_threshold():
    bag = _bag("opaque.bin")
    bag.set("7z.structure", {"magic_matched": True, "version_major": 9})

    effect = SevenZipStructureIdentityScoreRule().evaluate(bag, {})

    assert effect.score < 6
