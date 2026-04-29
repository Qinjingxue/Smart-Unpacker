from packrelic.contracts.detection import FactBag
from packrelic.contracts.tasks import ArchiveTask
from packrelic.extraction.result import ExtractionResult
from packrelic.verification import VerificationScheduler


def test_expected_name_matching_is_case_and_path_normalized(tmp_path):
    archive = tmp_path / "sample.zip"
    archive.write_bytes(b"zip")
    out_dir = tmp_path / "out"
    out_dir.mkdir()
    (out_dir / "Docs").mkdir()
    (out_dir / "Docs" / "Readme.TXT").write_text("hello", encoding="utf-8")
    bag = FactBag()
    bag.set("resource.analysis", {"expected_names": ["docs/readme.txt"]})
    task = ArchiveTask(fact_bag=bag, score=10, key="sample", main_path=str(archive), all_parts=[str(archive)])
    result = ExtractionResult(success=True, archive=str(archive), out_dir=str(out_dir), all_parts=[str(archive)])

    verification = VerificationScheduler({
        "verification": {
            "enabled": True,
            "methods": [{"name": "expected_name_presence"}],
        }
    }).verify(task, result)

    assert verification.decision_hint == "accept"
    assert verification.assessment_status == "complete"
    assert verification.completeness == 1.0
