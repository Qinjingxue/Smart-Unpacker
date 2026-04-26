import io
import tarfile
import zipfile

from smart_unpacker.contracts.detection import FactBag
from smart_unpacker.detection import DetectionScheduler
from smart_unpacker.detection.pipeline.facts.provider import FactProvider
from smart_unpacker.detection.pipeline.processors.modules.format_structure.tar_header import inspect_tar_header_structure
from smart_unpacker.detection.pipeline.processors.modules.format_structure.zip_eocd import inspect_zip_eocd_structure
from tests.helpers.detection_config import with_detection_pipeline


def _config(scoring):
    return with_detection_pipeline({
        "thresholds": {"archive_score_threshold": 6, "maybe_archive_threshold": 3},
    }, scoring=scoring)


def test_zip_eocd_structure_rule_identifies_zip_without_magic_rule(tmp_path):
    target = tmp_path / "payload.bin"
    with zipfile.ZipFile(target, "w") as archive:
        archive.writestr("hello.txt", "hello")

    structure = inspect_zip_eocd_structure(str(target))
    assert structure["plausible"] is True
    assert structure["central_directory_present"] is True
    assert structure["central_directory_walk_ok"] is True
    assert structure["local_header_links_ok"] is True
    assert structure["central_directory_entries_checked"] == 1
    assert structure["archive_offset"] == 0

    bag = FactBag()
    decision = DetectionScheduler(_config([
        {"name": "zip_structure_identity", "enabled": True},
    ])).evaluate(bag, FactProvider(str(target)))

    assert decision.should_extract is True
    assert decision.total_score == 7
    assert bag.get("file.detected_ext") == ".zip"
    assert "zip_structure_identity" in decision.matched_rules


def test_zip_structure_accept_precheck_short_circuits_scoring(tmp_path):
    target = tmp_path / "payload.bin"
    with zipfile.ZipFile(target, "w") as archive:
        archive.writestr("hello.txt", "hello")

    bag = FactBag()
    decision = DetectionScheduler(with_detection_pipeline({
        "thresholds": {"archive_score_threshold": 6, "maybe_archive_threshold": 3},
    }, precheck=[
        {"name": "zip_structure_accept", "enabled": True},
    ], scoring=[
        {"name": "zip_structure_identity", "enabled": True},
    ])).evaluate(bag, FactProvider(str(target)))

    assert decision.should_extract is True
    assert decision.decision_stage == "precheck"
    assert decision.total_score == 0
    assert decision.matched_rules == ["zip_structure_accept"]
    assert bag.get("file.detected_ext") == ".zip"


def test_zip_eocd_structure_rule_sends_leading_stub_zip_to_confirmation_band(tmp_path):
    plain_zip = tmp_path / "plain.zip"
    target = tmp_path / "stubbed.exe"
    with zipfile.ZipFile(plain_zip, "w") as archive:
        archive.writestr("hello.txt", "hello")
    target.write_bytes(b"MZ" + b"x" * 64 + plain_zip.read_bytes())

    structure = inspect_zip_eocd_structure(str(target))
    assert structure["plausible"] is True
    assert structure["archive_offset"] > 0

    decision = DetectionScheduler(_config([
        {"name": "zip_structure_identity", "enabled": True},
    ])).evaluate(FactBag(), FactProvider(str(target)))

    assert decision.should_extract is False
    assert decision.decision == "maybe_archive"
    assert decision.total_score == 4


def test_zip_structure_accept_does_not_accept_leading_stub_zip(tmp_path):
    plain_zip = tmp_path / "plain.zip"
    target = tmp_path / "stubbed.exe"
    with zipfile.ZipFile(plain_zip, "w") as archive:
        archive.writestr("hello.txt", "hello")
    target.write_bytes(b"MZ" + b"x" * 64 + plain_zip.read_bytes())

    decision = DetectionScheduler(with_detection_pipeline({
        "thresholds": {"archive_score_threshold": 6, "maybe_archive_threshold": 3},
    }, precheck=[
        {"name": "zip_structure_accept", "enabled": True},
    ], scoring=[
        {"name": "zip_structure_identity", "enabled": True},
    ])).evaluate(FactBag(), FactProvider(str(target)))

    assert decision.should_extract is False
    assert decision.decision_stage == "scoring"
    assert decision.total_score == 4


def test_zip_eocd_structure_rejects_bad_central_directory_local_header_link(tmp_path):
    target = tmp_path / "payload.zip"
    with zipfile.ZipFile(target, "w") as archive:
        archive.writestr("hello.txt", "hello")
    data = bytearray(target.read_bytes())
    structure = inspect_zip_eocd_structure(str(target))
    cd_offset = structure["central_directory_offset"]
    # Corrupt the central directory entry's relative local-header offset.
    data[cd_offset + 42:cd_offset + 46] = (999999).to_bytes(4, "little")
    target.write_bytes(bytes(data))

    structure = inspect_zip_eocd_structure(str(target))

    assert structure["plausible"] is False
    assert structure["error"] == "local_header_offset_out_of_range"


def test_tar_structure_rule_identifies_ustar_checksum(tmp_path):
    target = tmp_path / "payload.data"
    with tarfile.open(target, "w") as archive:
        payload = b"hello"
        info = tarfile.TarInfo("hello.txt")
        info.size = len(payload)
        archive.addfile(info, io.BytesIO(payload))

    structure = inspect_tar_header_structure(str(target))
    assert structure["plausible"] is True
    assert structure["ustar_magic"] is True
    assert structure["entry_walk_ok"] is True
    assert structure["entries_checked"] == 1

    bag = FactBag()
    decision = DetectionScheduler(_config([
        {"name": "tar_structure_identity", "enabled": True},
    ])).evaluate(bag, FactProvider(str(target)))

    assert decision.should_extract is True
    assert decision.total_score == 7
    assert bag.get("file.detected_ext") == ".tar"
    assert "tar_structure_identity" in decision.matched_rules


def test_tar_structure_accept_precheck_short_circuits_scoring(tmp_path):
    target = tmp_path / "payload.data"
    with tarfile.open(target, "w") as archive:
        payload = b"hello"
        info = tarfile.TarInfo("hello.txt")
        info.size = len(payload)
        archive.addfile(info, io.BytesIO(payload))

    bag = FactBag()
    decision = DetectionScheduler(with_detection_pipeline({
        "thresholds": {"archive_score_threshold": 6, "maybe_archive_threshold": 3},
    }, precheck=[
        {"name": "tar_structure_accept", "enabled": True},
    ], scoring=[
        {"name": "tar_structure_identity", "enabled": True},
    ])).evaluate(bag, FactProvider(str(target)))

    assert decision.should_extract is True
    assert decision.decision_stage == "precheck"
    assert decision.total_score == 0
    assert decision.matched_rules == ["tar_structure_accept"]
    assert bag.get("file.detected_ext") == ".tar"


def test_tar_structure_walks_multiple_entries(tmp_path):
    target = tmp_path / "payload.data"
    with tarfile.open(target, "w") as archive:
        for name, payload in {"a.txt": b"alpha", "b.txt": b"beta"}.items():
            info = tarfile.TarInfo(name)
            info.size = len(payload)
            archive.addfile(info, io.BytesIO(payload))

    structure = inspect_tar_header_structure(str(target))

    assert structure["plausible"] is True
    assert structure["entry_walk_ok"] is True
    assert structure["entries_checked"] == 2
    assert structure["end_zero_blocks"] is True


def test_tar_structure_rejects_bad_checksum(tmp_path):
    target = tmp_path / "not.tar"
    target.write_bytes(b"name".ljust(148, b"\x00") + b"0000000\x00" + b"x" * (512 - 156))

    structure = inspect_tar_header_structure(str(target))
    assert structure["plausible"] is False
    assert structure["error"] == "checksum_mismatch"

    decision = DetectionScheduler(_config([
        {"name": "tar_structure_identity", "enabled": True},
    ])).evaluate(FactBag(), FactProvider(str(target)))

    assert decision.should_extract is False
    assert decision.total_score == 0
