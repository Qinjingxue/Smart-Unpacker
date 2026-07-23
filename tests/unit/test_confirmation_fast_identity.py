from sunpack.contracts.detection import FactBag
from sunpack.detection.pipeline.processors.context import FactProcessorContext
from sunpack.detection.pipeline.processors.modules.confirmation import archive_metadata_open
from sunpack.detection.pipeline.processors.modules.embedded_payload.executable_carrier import classify_executable_carrier
from sunpack.detection.pipeline.rules.confirmation.archive_identity_consensus import ArchiveIdentityConsensusRule
from sunpack.detection.pipeline.rules.confirmation.executable_carrier_veto import ExecutableCarrierVetoRule
from sunpack.detection.scheduler import DetectionScheduler
from sunpack.support.sevenzip_bridge_worker import SevenZipMetadataOpenResult
from tests.helpers.detection_config import with_detection_pipeline


def test_structural_consensus_confirms_zip_without_backend_probe():
    facts = FactBag()
    facts.set("file.path", "archive.zip")
    facts.set("zip.eocd_structure", {
        "plausible": True,
        "central_directory_present": True,
        "central_directory_walk_ok": True,
        "local_header_links_ok": True,
        "archive_offset": 0,
        "total_entries": 2,
        "central_directory_size": 100,
    })
    effect = ArchiveIdentityConsensusRule().evaluate(facts, {})
    assert effect.decision == "confirm"
    assert facts.get("confirmation.identity")["format"] == "zip"


def test_extension_score_cannot_bypass_missing_identity_confirmation():
    config = with_detection_pipeline(
        {"thresholds": {"archive_score_threshold": 6, "maybe_archive_threshold": 3}},
        scoring=[{
            "name": "extension", "enabled": True,
            "extension_score_groups": [{"score": 7, "extensions": [".zip"]}],
        }],
        confirmation=[{"name": "archive_identity_consensus", "enabled": True, "always_run": True}],
    )
    facts = FactBag()
    facts.set("file.path", "not-really.zip")
    decision = DetectionScheduler(config).evaluate_bag(facts)
    assert decision.should_extract is False
    assert decision.decision == "maybe_archive"
    assert decision.discarded_at == "confirmation_inconclusive"


def test_runtime_bundle_veto_rejects_before_identity_confirmation():
    facts = FactBag()
    facts.set("executable.carrier", {
        "is_executable": True,
        "kind": "runtime_bundle",
        "runtime_profile": "par_packer",
    })
    effect = ExecutableCarrierVetoRule().evaluate(facts, {"reject_runtime_bundles": True})
    assert effect.decision == "reject"
    assert effect.reason == "Executable application/installer bundle (par_packer) is not treated as a user archive"


def test_inno_setup_stub_is_rejected_as_an_installer_bundle(tmp_path):
    path = tmp_path / "setup.exe"
    path.write_bytes(b"MZ generic Inno Setup text")
    generic = classify_executable_carrier(
        str(path),
        {"is_pe": True, "overlay_offset": path.stat().st_size, "archive_like": False},
    )
    assert generic["kind"] == "plain_executable"

    stub = b"MZ" + b"Inno Setup Setup Data (5.5.7) (u)" + b"JR.Inno.Setup"
    path.write_bytes(stub)

    carrier = classify_executable_carrier(
        str(path),
        {"is_pe": True, "overlay_offset": len(stub), "archive_like": False},
    )
    assert carrier["kind"] == "runtime_bundle"
    assert carrier["runtime_profile"] == "inno_setup"

    facts = FactBag()
    facts.set("executable.carrier", carrier)
    effect = ExecutableCarrierVetoRule().evaluate(facts, {"reject_runtime_bundles": True})
    assert effect.decision == "reject"
    assert effect.reason == "Executable application/installer bundle (inno_setup) is not treated as a user archive"


def test_squirrel_setup_stub_is_rejected_as_an_installer_bundle(tmp_path):
    path = tmp_path / "Setup.exe"
    stub = (
        b"MZ"
        + "SquirrelAwareVersion".encode("utf-16le")
        + "SquirrelSetup.log".encode("utf-16le")
    )
    path.write_bytes(stub)

    carrier = classify_executable_carrier(
        str(path),
        {"is_pe": True, "overlay_offset": len(stub), "archive_like": False},
    )
    assert carrier["kind"] == "runtime_bundle"
    assert carrier["runtime_profile"] == "squirrel_windows"

    facts = FactBag()
    facts.set("executable.carrier", carrier)
    effect = ExecutableCarrierVetoRule().evaluate(facts, {"reject_runtime_bundles": True})
    assert effect.decision == "reject"
    assert effect.reason == (
        "Executable application/installer bundle (squirrel_windows) is not treated as a user archive"
    )


def test_qt_ifw_tail_layout_is_rejected_as_an_installer_bundle(tmp_path):
    path = tmp_path / "qt-installer.exe"
    cookie = (0xC2630A1C99D668F8).to_bytes(8, "little")
    installer_marker = (0x12023233).to_bytes(8, "little")
    binary_content_size = (64).to_bytes(8, "little")
    stub = b"MZ" + (b"\0" * 64) + binary_content_size + installer_marker + cookie + b"signed-tail"
    path.write_bytes(stub)

    carrier = classify_executable_carrier(
        str(path),
        {"is_pe": True, "overlay_offset": 66, "archive_like": False},
    )
    assert carrier["kind"] == "runtime_bundle"
    assert carrier["runtime_profile"] == "qt_installer_framework"

    facts = FactBag()
    facts.set("executable.carrier", carrier)
    effect = ExecutableCarrierVetoRule().evaluate(facts, {"reject_runtime_bundles": True})
    assert effect.decision == "reject"
    assert effect.reason == (
        "Executable application/installer bundle (qt_installer_framework) is not treated as a user archive"
    )


def test_qt_ifw_cookie_without_valid_marker_is_not_a_runtime_bundle(tmp_path):
    path = tmp_path / "not-qt-installer.exe"
    cookie = (0xC2630A1C99D668F8).to_bytes(8, "little")
    stub = b"MZ" + (b"\0" * 64) + (64).to_bytes(8, "little") + (0).to_bytes(8, "little") + cookie
    path.write_bytes(stub)

    carrier = classify_executable_carrier(
        str(path),
        {"is_pe": True, "overlay_offset": len(stub), "archive_like": False},
    )
    assert carrier["kind"] == "plain_executable"


def test_metadata_open_timeout_is_inconclusive_not_rejection(tmp_path, monkeypatch):
    path = tmp_path / "ambiguous.zip"
    path.write_bytes(b"not enough structure")
    facts = FactBag()
    facts.set("file.path", str(path))
    facts.set("candidate.member_paths", [str(path)])
    facts.set("confirmation.identity_required", True)
    monkeypatch.setattr(
        archive_metadata_open,
        "open_archive_metadata",
        lambda *args, **kwargs: SevenZipMetadataOpenResult(
            False, False, "timeout", timed_out=True, message="metadata open timed out"
        ),
    )
    result = archive_metadata_open.process_archive_metadata_open(
        FactProcessorContext(facts, "archive.metadata_open", {}, {"timeout_seconds": 0.1}, None)
    )
    assert result["confirmed"] is False
    assert result["timed_out"] is True
