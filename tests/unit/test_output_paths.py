from sunpack.contracts.detection import FactBag
from sunpack.contracts.tasks import ArchiveTask
from sunpack.extraction.internal.workflow.output_paths import default_output_dir_for_task


def _task(path):
    return ArchiveTask(
        fact_bag=FactBag(),
        score=10,
        main_path=str(path),
        all_parts=[str(path)],
        logical_name=path.stem,
    )


def test_default_output_dir_uses_archive_stem_when_available(tmp_path):
    archive = tmp_path / "sample.zip"
    archive.write_bytes(b"zip")

    assert default_output_dir_for_task(_task(archive)) == str(tmp_path / "sample")


def test_default_output_dir_avoids_existing_same_name_directory(tmp_path):
    archive = tmp_path / "sample.zip"
    archive.write_bytes(b"zip")
    (tmp_path / "sample").mkdir()

    assert default_output_dir_for_task(_task(archive)) == str(tmp_path / "sample_extracted")


def test_default_output_dir_increments_when_extracted_directory_exists(tmp_path):
    archive = tmp_path / "sample.zip"
    archive.write_bytes(b"zip")
    (tmp_path / "sample").mkdir()
    (tmp_path / "sample_extracted").mkdir()

    assert default_output_dir_for_task(_task(archive)) == str(tmp_path / "sample_extracted_2")


def test_default_output_dir_avoids_existing_same_name_file(tmp_path):
    archive = tmp_path / "sample.zip"
    archive.write_bytes(b"zip")
    (tmp_path / "sample").write_text("existing", encoding="utf-8")

    assert default_output_dir_for_task(_task(archive)) == str(tmp_path / "sample_extracted")
