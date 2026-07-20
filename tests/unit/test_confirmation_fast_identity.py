from sunpack.contracts.detection import FactBag
from sunpack.detection.pipeline.processors.context import FactProcessorContext
from sunpack.detection.pipeline.processors.modules.confirmation import archive_metadata_open
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
