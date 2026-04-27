from smart_unpacker.contracts.detection import FactBag
from smart_unpacker.contracts.tasks import ArchiveTask
from smart_unpacker.extraction.result import ExtractionResult
from smart_unpacker.verification import VerificationScheduler


def _task_and_result(tmp_path, analysis=None):
    archive = tmp_path / "sample.zip"
    archive.write_bytes(b"zip")
    out_dir = tmp_path / "out"
    out_dir.mkdir()
    bag = FactBag()
    bag.set("resource.analysis", analysis or {})
    task = ArchiveTask(fact_bag=bag, score=10, key="sample", main_path=str(archive), all_parts=[str(archive)])
    result = ExtractionResult(success=True, archive=str(archive), out_dir=str(out_dir), all_parts=[str(archive)])
    return task, result, out_dir


def _verify(methods, task, result, pass_threshold=70, fail_fast_threshold=40):
    return VerificationScheduler({
        "verification": {
            "enabled": True,
            "initial_score": 100,
            "pass_threshold": pass_threshold,
            "fail_fast_threshold": fail_fast_threshold,
            "methods": methods,
        }
    }).verify(task, result)


def test_name_presence_sanitizes_nested_dicts_bytes_and_parent_paths(tmp_path):
    task, result, out_dir = _task_and_result(tmp_path)
    (out_dir / "safe").mkdir()
    (out_dir / "safe" / "Name.TXT").write_text("ok", encoding="utf-8")
    task.fact_bag.set("verification.expected_names", [
        {"path": b"../safe/name.txt"},
        {"filename": "./safe//name.txt"},
    ])

    verification = _verify([{"name": "expected_name_presence"}], task, result)

    assert verification.ok is True
    assert verification.steps[0].status == "passed"


