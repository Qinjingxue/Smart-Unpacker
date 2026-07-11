from types import SimpleNamespace

from sunpack.contracts.detection import FactBag
from sunpack.contracts.tasks import ArchiveTask
from sunpack.extraction.internal.workflow.single_archive_extractor import SingleArchiveExtractor


def test_successful_first_attempt_checks_free_space_once(tmp_path):
    archive = tmp_path / "input.7z"
    archive.write_bytes(b"dummy")
    output = tmp_path / "out"
    calls = []
    task = ArchiveTask(FactBag(), 1, main_path=str(archive), all_parts=[str(archive)], detected_ext=".7z")
    task.fact_bag.set("archive.encrypted", False)
    runner = SimpleNamespace(run_extract=lambda **_kwargs: SimpleNamespace(
        returncode=0, stdout="", stderr="", worker_diagnostics={"result": {"status": "ok"}}
    ))
    rename = SimpleNamespace(
        normalize_archive_paths=lambda archive, parts, **_kwargs: SimpleNamespace(archive=archive, run_parts=parts, cleanup_parts=parts),
        cleanup_normalized_split_group=lambda _staged: None,
    )
    extractor = SingleArchiveExtractor(
        seven_z_path="", password_store=SimpleNamespace(has_candidates=lambda: False),
        password_resolver=SimpleNamespace(password_tester=SimpleNamespace(passwords=[])),
        metadata_scanner=SimpleNamespace(scan_for_task=lambda *_args, **_kwargs: SimpleNamespace(selected_codepage=None, decoded_names=[], error=None)),
        rename_scheduler=rename, ensure_space=lambda amount: calls.append(amount) or True,
        retry_policy=SimpleNamespace(max_retries=1),
        split_entry_resolver=SimpleNamespace(resolve=lambda archive, parts, split: (archive, parts, split)),
        sevenzip_runner=runner,
    )
    output.mkdir()

    result = extractor.extract(task, str(output))

    assert result.success
    assert calls == [5]
