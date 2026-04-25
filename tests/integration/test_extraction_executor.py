import subprocess

from smart_unpacker.extraction.scheduler import ExtractionScheduler
from smart_unpacker.contracts.detection import FactBag
from smart_unpacker.contracts.tasks import ArchiveTask


def test_extractor_failure_path_runs_through_concurrent_executor(tmp_path, monkeypatch):
    archive = tmp_path / "not_archive.txt"
    archive.write_text("not an archive", encoding="utf-8")
    out_dir = tmp_path / "extracted_fake"

    bag = FactBag()
    bag.set("file.path", str(archive))
    bag.set("file.detected_ext", ".txt")
    task = ArchiveTask(fact_bag=bag, score=10)

    extractor = ExtractionScheduler(max_retries=1, max_workers=2)
    monkeypatch.setattr(extractor.metadata_scanner, "scan", lambda *_args, **_kwargs: None)

    def fake_run(*_args, **_kwargs):
        return subprocess.CompletedProcess(args=[], returncode=2, stdout="", stderr="can not open file as archive")

    monkeypatch.setattr("smart_unpacker.extraction.scheduler.subprocess.run", fake_run)

    results = extractor.extract_all([task, task], lambda _item: str(out_dir))

    assert len(results) == 2
    assert all(result.success is False for _, result in results)
    assert all(result.error for _, result in results)
    assert not out_dir.exists()
