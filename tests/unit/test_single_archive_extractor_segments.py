from types import SimpleNamespace

from sunpack.analysis.knowledge import write_extractable_segments
from sunpack.contracts.detection import FactBag
from sunpack.contracts.tasks import ArchiveTask, SplitArchiveInfo
from sunpack.extraction.internal.workflow.single_archive_extractor import SingleArchiveExtractor
from sunpack.extraction.internal.sevenzip.metadata import ArchiveMetadataScanner


class _FakePasswordStore:
    def has_candidates(self):
        return False


class _FakePasswordResolver:
    password_tester = SimpleNamespace(passwords=[])


class _FakeRenameScheduler:
    def normalize_archive_paths(self, archive, all_parts, **_kwargs):
        return SimpleNamespace(archive=archive, run_parts=list(all_parts), cleanup_parts=list(all_parts))

    def cleanup_normalized_split_group(self, _staged):
        return None


class _FakeRetryPolicy:
    max_retries = 1

    def can_retry(self, *_args, **_kwargs):
        return False

    def append_retry_count(self, error, _retry_count):
        return error


class _FakeSplitEntryResolver:
    def resolve(self, archive, all_parts, split_info):
        return archive, list(all_parts), split_info


class _FakeSevenZipRunner:
    def __init__(self, *, include_output_counts: bool = True):
        self.sources = []
        self.include_output_counts = bool(include_output_counts)

    def run_extract(self, *, out_dir, task, **_kwargs):
        state = task.archive_state()
        source = state.to_archive_input_descriptor().to_dict()
        self.sources.append(source)
        name = str(source.get("format_hint") or "archive")
        import os

        os.makedirs(out_dir, exist_ok=True)
        with open(os.path.join(out_dir, f"{name}.txt"), "wb") as handle:
            handle.write(b"ok")
        result = {
            "status": "ok",
            "item_count": 1 if self.include_output_counts else 0,
        }
        if self.include_output_counts:
            result.update({
                "files_written": 1,
                "bytes_written": 2,
            })
        return SimpleNamespace(
            returncode=0,
            worker_diagnostics={"result": result},
        )


def _task(path):
    bag = FactBag()
    bag.set("candidate.entry_path", str(path))
    bag.set("candidate.member_paths", [str(path)])
    return ArchiveTask(
        fact_bag=bag,
        score=10,
        main_path=str(path),
        all_parts=[str(path)],
        logical_name="case",
        split_info=SplitArchiveInfo(parts=[str(path)]),
    )


def test_extractor_runs_analysis_segments_inside_same_task_and_restores_source(tmp_path):
    carrier = tmp_path / "carrier.bin"
    carrier.write_bytes(b"prefix-zip-rar-tail")
    task = _task(carrier)
    write_extractable_segments(task, [
        {
            "segment_id": "embedded_01_zip",
            "format": "zip",
            "logical_name": "case_01_zip",
            "archive_input": {
                "kind": "archive_input",
                "entry_path": str(carrier),
                "open_mode": "file_range",
                "format_hint": "zip",
                "logical_name": "case_01_zip",
                "parts": [{"path": str(carrier), "role": "main", "start": 7, "end": 10}],
            },
        },
        {
            "segment_id": "embedded_02_rar",
            "format": "rar",
            "logical_name": "case_02_rar",
            "archive_input": {
                "kind": "archive_input",
                "entry_path": str(carrier),
                "open_mode": "file_range",
                "format_hint": "rar",
                "logical_name": "case_02_rar",
                "parts": [{"path": str(carrier), "role": "main", "start": 11, "end": 14}],
            },
        },
    ])
    runner = _FakeSevenZipRunner()
    extractor = SingleArchiveExtractor(
        seven_z_path="7z",
        password_store=_FakePasswordStore(),
        password_resolver=_FakePasswordResolver(),
        metadata_scanner=ArchiveMetadataScanner(),
        rename_scheduler=_FakeRenameScheduler(),
        ensure_space=lambda _gb: True,
        retry_policy=_FakeRetryPolicy(),
        split_entry_resolver=_FakeSplitEntryResolver(),
        sevenzip_runner=runner,
        best_effort=True,
    )

    result = extractor.extract(task, str(tmp_path / "out"))

    assert result.success is True
    assert [source["format_hint"] for source in runner.sources] == ["zip", "rar"]
    assert runner.sources[0]["open_mode"] == "file_range"
    assert (tmp_path / "out" / "embedded_01_zip" / "zip.txt").exists()
    assert (tmp_path / "out" / "embedded_02_rar" / "rar.txt").exists()
    assert len(result.diagnostics["embedded_segments"]) == 2
    assert task.archive_state().to_archive_input_descriptor().open_mode == "file"


def test_extractor_fills_success_output_counts_when_worker_omits_them(tmp_path):
    archive = tmp_path / "case.zip"
    archive.write_bytes(b"PK\x05\x06" + b"\0" * 18)
    task = _task(archive)
    runner = _FakeSevenZipRunner(include_output_counts=False)
    extractor = SingleArchiveExtractor(
        seven_z_path="7z",
        password_store=_FakePasswordStore(),
        password_resolver=_FakePasswordResolver(),
        metadata_scanner=ArchiveMetadataScanner(),
        rename_scheduler=_FakeRenameScheduler(),
        ensure_space=lambda _gb: True,
        retry_policy=_FakeRetryPolicy(),
        split_entry_resolver=_FakeSplitEntryResolver(),
        sevenzip_runner=runner,
        best_effort=True,
        write_progress_manifest=True,
    )

    result = extractor.extract(task, str(tmp_path / "out"), allow_embedded_segments=False)

    assert result.success is True
    assert result.files_written == 1
    assert result.bytes_written == 2
    assert result.diagnostics["result"]["files_written"] == 1
    assert result.diagnostics["result"]["bytes_written"] == 2
    assert result.progress_manifest_payload["files_written"] == 1
    assert result.progress_manifest_payload["bytes_written"] == 2
