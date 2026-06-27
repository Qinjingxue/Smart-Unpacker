from sunpack.contracts.detection import FactBag
from sunpack.contracts.rules import RuleDecision
from sunpack.detection.pipeline.processors.modules.embedded_payload.executable_carrier import (
    classify_executable_carrier,
)
from sunpack.detection.scheduler import DetectionScheduler
from tests.helpers.detection_config import with_detection_pipeline


def _overlay(*, archive_like: bool = False) -> dict:
    return {
        "is_pe": True,
        "archive_like": archive_like,
        "overlay_offset": 4096,
        "archive_offset": 4096 if archive_like else 0,
        "format": "7z" if archive_like else "",
        "confidence": "strong" if archive_like else "none",
        "evidence": ["pe:valid_headers", "pe:overlay_present"],
    }


def _rescue() -> dict:
    return {
        "has_extractable": True,
        "selected": {"format": "zip", "confidence": 0.99, "start_offset": 0},
    }


def _policy_config() -> dict:
    return with_detection_pipeline(
        {"thresholds": {"archive_score_threshold": 6, "maybe_archive_threshold": 3}},
        confirmation=[
            {
                "name": "executable_carrier_policy",
                "enabled": True,
                "always_run": True,
                "reject_runtime_bundles": True,
            }
        ],
    )


def _initial_decision() -> RuleDecision:
    return RuleDecision(
        should_extract=False,
        total_score=0,
        matched_rules=[],
        decision="not_archive",
        decision_stage="scoring",
    )


def test_par_runtime_bundle_is_classified_separately_from_sfx(tmp_path):
    executable = tmp_path / "packed.exe"
    executable.write_bytes(b"MZ" + b"x" * 32 + b"PAR::Packer" + b"y" * 32 + b"PAR_TEMP")

    carrier = classify_executable_carrier(str(executable), _overlay(), _rescue())

    assert carrier["kind"] == "runtime_bundle"
    assert carrier["runtime_profile"] == "par_packer"
    assert carrier["confidence"] == "high"


def test_known_sfx_overlay_is_not_rejected(tmp_path):
    executable = tmp_path / "archive.exe"
    executable.write_bytes(b"MZ" + b"stub" + b"7z\xbc\xaf\x27\x1c")

    carrier = classify_executable_carrier(str(executable), _overlay(archive_like=True))

    assert carrier["kind"] == "self_extracting_archive"
    assert carrier["confidence"] == "strong"


def test_runtime_marker_inside_sfx_payload_does_not_reclassify_stub(tmp_path):
    executable = tmp_path / "archive-with-packed-member.exe"
    executable.write_bytes(b"MZ" + b"stub" + b"7z\xbc\xaf\x27\x1c" + b"PAR::Packer" + b"PAR_TEMP")
    overlay = _overlay(archive_like=True)
    overlay["overlay_offset"] = 6

    carrier = classify_executable_carrier(str(executable), overlay)

    assert carrier["kind"] == "self_extracting_archive"


def test_unknown_structural_executable_archive_remains_eligible(tmp_path):
    executable = tmp_path / "unusual-sfx.exe"
    executable.write_bytes(b"MZ" + b"custom stub without a known runtime packer")

    carrier = classify_executable_carrier(str(executable), _overlay(), _rescue())

    assert carrier["kind"] == "executable_archive"
    assert carrier["confidence"] == "medium"


def test_structure_rescue_rejects_runtime_bundle_through_confirmation_pipeline():
    bag = FactBag()
    bag.set("file.path", "packed.exe")
    bag.set("executable.carrier", {
        "is_executable": True,
        "kind": "runtime_bundle",
        "runtime_profile": "par_packer",
    })

    decision = DetectionScheduler(_policy_config()).refine_with_structure(
        bag,
        _initial_decision(),
        _rescue(),
    )

    assert not decision.should_extract
    assert decision.decision == "not_archive"
    assert decision.deciding_rule == "executable_carrier_policy"


def test_structure_rescue_keeps_sfx_including_damaged_or_encrypted_routes():
    bag = FactBag()
    bag.set("file.path", "archive.exe")
    bag.set("executable.carrier", {
        "is_executable": True,
        "kind": "self_extracting_archive",
        "runtime_profile": "",
    })
    structure = _rescue()
    structure["selected"]["details"] = {
        "password_required": True,
        "damage_flags": ["truncated_tail"],
    }

    decision = DetectionScheduler(_policy_config()).refine_with_structure(
        bag,
        _initial_decision(),
        structure,
    )

    assert decision.should_extract
    assert decision.decision == "archive"
    assert decision.total_score == 6
