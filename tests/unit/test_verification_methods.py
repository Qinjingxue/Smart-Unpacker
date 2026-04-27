from smart_unpacker.contracts.detection import FactBag
from smart_unpacker.contracts.tasks import ArchiveTask
from smart_unpacker.extraction.result import ExtractionResult
from smart_unpacker.verification import VerificationScheduler


def _task(tmp_path, analysis=None):
    archive = tmp_path / "sample.zip"
    archive.write_bytes(b"zip")
    bag = FactBag()
    bag.set("resource.analysis", analysis or {})
    return ArchiveTask(fact_bag=bag, score=10, key="sample", main_path=str(archive), all_parts=[str(archive)])


def _scheduler(methods):
    return VerificationScheduler({
        "verification": {
            "enabled": True,
            "initial_score": 100,
            "pass_threshold": 70,
            "fail_fast_threshold": 40,
            "methods": methods,
        }
    })


def test_extraction_exit_signal_hard_fails_failed_extraction(tmp_path):
    task = _task(tmp_path)
    result = ExtractionResult(
        success=False,
        archive=task.main_path,
        out_dir=str(tmp_path / "out"),
        all_parts=task.all_parts,
        error="boom",
    )

    verification = _scheduler([{"name": "extraction_exit_signal"}]).verify(task, result)

    assert verification.ok is False
    assert verification.status == "failed"
    assert verification.score == 0
    assert verification.issues[0].code == "fail.extraction_failed"


def test_output_presence_fails_missing_or_empty_output(tmp_path):
    task = _task(tmp_path)
    result = ExtractionResult(success=True, archive=task.main_path, out_dir=str(tmp_path / "missing"), all_parts=task.all_parts)

    missing = _scheduler([{"name": "output_presence"}]).verify(task, result)

    assert missing.ok is False
    assert missing.issues[0].code == "fail.output_missing"

    out_dir = tmp_path / "empty"
    out_dir.mkdir()
    result.out_dir = str(out_dir)
    empty = _scheduler([{"name": "output_presence"}]).verify(task, result)

    assert empty.ok is False
    assert empty.issues[0].code == "fail.output_empty"


def test_manifest_size_match_passes_with_small_tolerance(tmp_path):
    out_dir = tmp_path / "out"
    out_dir.mkdir()
    (out_dir / "a.txt").write_text("hello", encoding="utf-8")
    task = _task(tmp_path, {"file_count": 1, "total_unpacked_size": 5})
    result = ExtractionResult(success=True, archive=task.main_path, out_dir=str(out_dir), all_parts=task.all_parts)

    verification = _scheduler([{"name": "manifest_size_match"}]).verify(task, result)

    assert verification.ok is True
    assert verification.status == "passed"
    assert verification.score == 100


def test_manifest_size_match_deducts_for_large_manifest_gap(tmp_path):
    out_dir = tmp_path / "out"
    out_dir.mkdir()
    (out_dir / "a.txt").write_text("hello", encoding="utf-8")
    task = _task(tmp_path, {"file_count": 10, "total_unpacked_size": 10 * 1024 * 1024})
    result = ExtractionResult(success=True, archive=task.main_path, out_dir=str(out_dir), all_parts=task.all_parts)

    verification = _scheduler([{"name": "manifest_size_match"}]).verify(task, result)

    assert verification.ok is False
    assert verification.score < verification.pass_threshold
    assert {issue.code for issue in verification.issues} == {
        "fail.manifest_file_count_under",
        "fail.manifest_size_under",
    }


def test_expected_name_presence_passes_when_manifest_name_exists(tmp_path):
    out_dir = tmp_path / "out"
    out_dir.mkdir()
    (out_dir / "docs").mkdir()
    (out_dir / "docs" / "Readme.TXT").write_text("hello", encoding="utf-8")
    task = _task(tmp_path, {"expected_names": ["docs/readme.txt"]})
    result = ExtractionResult(success=True, archive=task.main_path, out_dir=str(out_dir), all_parts=task.all_parts)

    verification = _scheduler([{"name": "expected_name_presence"}]).verify(task, result)

    assert verification.ok is True
    assert verification.status == "passed"


def test_expected_name_presence_deducts_when_names_are_missing(tmp_path):
    out_dir = tmp_path / "out"
    out_dir.mkdir()
    (out_dir / "actual.txt").write_text("hello", encoding="utf-8")
    task = _task(tmp_path, {"expected_names": ["expected.txt", "missing.bin"]})
    result = ExtractionResult(success=True, archive=task.main_path, out_dir=str(out_dir), all_parts=task.all_parts)

    verification = _scheduler([{"name": "expected_name_presence"}]).verify(task, result)

    assert verification.ok is False
    assert verification.issues[0].code == "fail.expected_names_all_missing"


def test_expected_name_presence_skips_without_manifest_names(tmp_path):
    out_dir = tmp_path / "out"
    out_dir.mkdir()
    (out_dir / "actual.txt").write_text("hello", encoding="utf-8")
    task = _task(tmp_path)
    result = ExtractionResult(success=True, archive=task.main_path, out_dir=str(out_dir), all_parts=task.all_parts)

    verification = _scheduler([{"name": "expected_name_presence"}]).verify(task, result)

    assert verification.ok is True
    assert verification.status == "passed"
    assert verification.steps[0].status == "skipped"


