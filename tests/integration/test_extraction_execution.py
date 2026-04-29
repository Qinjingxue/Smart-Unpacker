import json
import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace

from sunpack.detection.nested_scan_policy import NestedOutputScanPolicy as OutputScanPolicy
from sunpack.config.schema import normalize_config
from sunpack.extraction.scheduler import ExtractionScheduler
from sunpack.contracts.detection import FactBag
from sunpack.contracts.tasks import ArchiveTask
from tests.helpers.detection_config import with_detection_pipeline


def runner_config():
    return normalize_config(with_detection_pipeline({
        "thresholds": {"archive_score_threshold": 5, "maybe_archive_threshold": 3},
        "recursive_extract": "1",
        "post_extract": {
            "archive_cleanup_mode": "k",
            "flatten_single_directory": False,
        },
    }))


class FakePasswordResolver:
    password_tester = SimpleNamespace(passwords=[])

    def resolve(self, archive_path, fact_bag, part_paths=None):
        return SimpleNamespace(password="", test_result=None, error_text="")


class FakeMetadataScanner:
    def scan(self, archive, password=None, part_paths=None):
        return None


class FakeStager:
    def normalize_archive_paths(self, archive, all_parts, startupinfo=None, volume_entries=None):
        parts = list(all_parts)
        return SimpleNamespace(archive=archive, run_parts=parts, cleanup_parts=parts)

    def cleanup_normalized_split_group(self, staged):
        return None


class ExtractionExecutionTests(unittest.TestCase):
    def test_extractor_success_reports_cleanup_parts_not_candidate_run_parts(self):
        with tempfile.TemporaryDirectory() as tmp:
            archive_path = Path(tmp) / "sample.7z.001"
            candidate_path = Path(tmp) / "sample"
            archive_path.write_bytes(b"7z")
            candidate_path.write_bytes(b"candidate")
            out_dir = Path(tmp) / "sample_out"

            class CandidateStager:
                def normalize_archive_paths(self, archive, all_parts, startupinfo=None, volume_entries=None):
                    return SimpleNamespace(
                        archive=archive,
                        run_parts=[str(archive_path), str(candidate_path)],
                        cleanup_parts=[str(archive_path)],
                    )

                def cleanup_normalized_split_group(self, staged):
                    return None

            extractor = ExtractionScheduler(max_retries=1)
            extractor.password_resolver = FakePasswordResolver()
            extractor.metadata_scanner = FakeMetadataScanner()
            extractor.rename_scheduler = CandidateStager()

            bag = FactBag()
            task = ArchiveTask(fact_bag=bag, score=10, main_path=str(archive_path), all_parts=[str(archive_path)])

            succeeded = SimpleNamespace(returncode=0, stdout="", stderr="")
            extractor.sevenzip_runner.run_extract = lambda **_kwargs: succeeded
            result = extractor.extract(task, str(out_dir))

            self.assertTrue(result.success)
            self.assertEqual(result.all_parts, [str(archive_path)])

    def test_extractor_retries_after_disk_space_error(self):
        with tempfile.TemporaryDirectory() as tmp:
            archive_path = Path(tmp) / "sample.zip"
            archive_path.write_bytes(b"zip")
            out_dir = Path(tmp) / "sample"

            calls = []

            def ensure_space(required_gb):
                calls.append(required_gb)
                return True

            extractor = ExtractionScheduler(ensure_space=ensure_space, max_retries=2)
            extractor.password_resolver = FakePasswordResolver()
            extractor.metadata_scanner = FakeMetadataScanner()
            extractor.rename_scheduler = FakeStager()

            failed = SimpleNamespace(returncode=8, stdout="", stderr="write error")
            succeeded = SimpleNamespace(returncode=0, stdout="", stderr="")

            bag = FactBag()
            task = ArchiveTask(fact_bag=bag, score=10, main_path=str(archive_path), all_parts=[str(archive_path)])

            attempts = iter([failed, succeeded])
            extractor.sevenzip_runner.run_extract = lambda **_kwargs: next(attempts)
            extractor.retry_policy.backoff = lambda _retry_count: None
            result = extractor.extract(task, str(out_dir))

            self.assertTrue(result.success)
            self.assertIn(10, calls)

    def test_extractor_retries_transient_failure_and_cleans_partial_output(self):
        with tempfile.TemporaryDirectory() as tmp:
            archive_path = Path(tmp) / "sample.zip"
            archive_path.write_bytes(b"zip")
            out_dir = Path(tmp) / "sample"
            partial_path = out_dir / "partial.bin"

            extractor = ExtractionScheduler(max_retries=2)
            extractor.password_resolver = FakePasswordResolver()
            extractor.metadata_scanner = FakeMetadataScanner()
            extractor.rename_scheduler = FakeStager()

            failed = SimpleNamespace(returncode=-102, stdout="", stderr="7z process made no observable progress")
            succeeded = SimpleNamespace(returncode=0, stdout="", stderr="")
            calls = 0

            def fake_run(*_args, **_kwargs):
                nonlocal calls
                calls += 1
                if calls == 1:
                    partial_path.parent.mkdir(parents=True, exist_ok=True)
                    partial_path.write_text("partial", encoding="utf-8")
                    return failed
                return succeeded

            bag = FactBag()
            task = ArchiveTask(fact_bag=bag, score=10, main_path=str(archive_path), all_parts=[str(archive_path)])

            extractor.sevenzip_runner.run_extract = lambda **_kwargs: fake_run()
            extractor.retry_policy.backoff = lambda _retry_count: None
            result = extractor.extract(task, str(out_dir))

            self.assertTrue(result.success)
            self.assertFalse(partial_path.exists())

    def test_extractor_does_not_retry_damaged_archive(self):
        with tempfile.TemporaryDirectory() as tmp:
            archive_path = Path(tmp) / "broken.zip"
            archive_path.write_bytes(b"zip")
            out_dir = Path(tmp) / "broken"

            extractor = ExtractionScheduler(max_retries=3)
            extractor.password_resolver = FakePasswordResolver()
            extractor.metadata_scanner = FakeMetadataScanner()
            extractor.rename_scheduler = FakeStager()

            failed = SimpleNamespace(returncode=2, stdout="", stderr="Headers Error")
            bag = FactBag()
            task = ArchiveTask(fact_bag=bag, score=10, main_path=str(archive_path), all_parts=[str(archive_path)])

            calls = 0

            def fake_extract(**_kwargs):
                nonlocal calls
                calls += 1
                return failed

            extractor.sevenzip_runner.run_extract = fake_extract
            result = extractor.extract(task, str(out_dir))

            self.assertFalse(result.success)
            self.assertEqual(result.error, "压缩包损坏")
            self.assertEqual(calls, 1)

    def test_extractor_preserves_best_effort_outputs_for_item_payload_failure(self):
        with tempfile.TemporaryDirectory() as tmp:
            archive_path = Path(tmp) / "broken_payload.zip"
            archive_path.write_bytes(b"zip")
            out_dir = Path(tmp) / "broken_payload"
            good_path = out_dir / "good.txt"
            partial_path = out_dir / "bad.bin"

            extractor = ExtractionScheduler(max_retries=1)
            extractor.password_resolver = FakePasswordResolver()
            extractor.metadata_scanner = FakeMetadataScanner()
            extractor.rename_scheduler = FakeStager()

            def fake_extract(**_kwargs):
                good_path.parent.mkdir(parents=True, exist_ok=True)
                good_path.write_text("good", encoding="utf-8")
                partial_path.write_bytes(b"bad-")
                diagnostics = {
                    "source": "sevenzip_worker",
                    "returncode": 2,
                    "failure_stage": "item_extract",
                    "failure_kind": "checksum_error",
                    "result": {
                        "type": "result",
                        "status": "failed",
                        "native_status": "damaged",
                        "failure_stage": "item_extract",
                        "failure_kind": "checksum_error",
                        "checksum_error": True,
                        "files_written": 2,
                        "bytes_written": 8,
                        "diagnostics": {
                            "output_trace": {
                                "items": [
                                    {
                                        "path": str(good_path),
                                        "archive_path": "good.txt",
                                        "failed": False,
                                        "bytes_written": 4,
                                        "expected_size": 4,
                                        "crc_ok": True,
                                    },
                                    {
                                        "path": str(partial_path),
                                        "archive_path": "bad.bin",
                                        "failed": True,
                                        "bytes_written": 4,
                                        "expected_size": 8,
                                        "crc_ok": False,
                                        "failure_stage": "item_extract",
                                        "failure_kind": "checksum_error",
                                    },
                                ],
                                "total_bytes_written": 8,
                            }
                        },
                    },
                }
                return SimpleNamespace(returncode=2, stdout="", stderr="CRC Failed", worker_diagnostics=diagnostics)

            bag = FactBag()
            task = ArchiveTask(fact_bag=bag, score=10, main_path=str(archive_path), all_parts=[str(archive_path)])
            extractor.sevenzip_runner.run_extract = fake_extract

            result = extractor.extract(task, str(out_dir))

            self.assertFalse(result.success)
            self.assertTrue(result.partial_outputs)
            self.assertTrue(good_path.exists())
            self.assertTrue(partial_path.exists())
            self.assertEqual(result.progress_manifest, "")
            self.assertFalse((out_dir / ".sunpack" / "extraction_manifest.json").exists())
            manifest = result.progress_manifest_payload
            self.assertIsInstance(manifest, dict)
            by_archive_path = {item["archive_path"]: item for item in manifest["files"]}
            self.assertEqual(by_archive_path["good.txt"]["status"], "complete")
            self.assertEqual(by_archive_path["bad.bin"]["status"], "partial")
            self.assertEqual(manifest["summary"]["partial"], 1)

    def test_extractor_can_write_progress_manifest_when_enabled(self):
        with tempfile.TemporaryDirectory() as tmp:
            archive_path = Path(tmp) / "partial.zip"
            archive_path.write_bytes(b"zip")
            out_dir = Path(tmp) / "out"
            good_path = out_dir / "good.txt"

            extractor = ExtractionScheduler(max_retries=1, extraction_config={"write_progress_manifest": True})
            extractor.password_resolver = FakePasswordResolver()
            extractor.metadata_scanner = FakeMetadataScanner()
            extractor.rename_scheduler = FakeStager()

            def fake_extract(**_kwargs):
                good_path.parent.mkdir(parents=True, exist_ok=True)
                good_path.write_text("ok", encoding="utf-8")
                diagnostics = {
                    "result": {
                        "status": "error",
                        "failure_stage": "item_extract",
                        "failure_kind": "checksum_error",
                        "diagnostics": {
                            "output_trace": {
                                "items": [
                                    {
                                        "path": str(good_path),
                                        "archive_path": "good.txt",
                                        "bytes_written": 2,
                                    },
                                ],
                            }
                        },
                    }
                }
                return SimpleNamespace(returncode=2, stdout="", stderr="CRC Failed", worker_diagnostics=diagnostics)

            bag = FactBag()
            task = ArchiveTask(fact_bag=bag, score=10, main_path=str(archive_path), all_parts=[str(archive_path)])
            extractor.sevenzip_runner.run_extract = fake_extract

            result = extractor.extract(task, str(out_dir))

            self.assertTrue(Path(result.progress_manifest).is_file())
            manifest = json.loads(Path(result.progress_manifest).read_text(encoding="utf-8"))
            self.assertEqual(manifest["summary"]["total"], 1)

    def test_extractor_reports_retry_count_after_transient_failures_are_exhausted(self):
        with tempfile.TemporaryDirectory() as tmp:
            archive_path = Path(tmp) / "busy.zip"
            archive_path.write_bytes(b"zip")
            out_dir = Path(tmp) / "busy"

            extractor = ExtractionScheduler(max_retries=2)
            extractor.password_resolver = FakePasswordResolver()
            extractor.metadata_scanner = FakeMetadataScanner()
            extractor.rename_scheduler = FakeStager()

            failed = SimpleNamespace(returncode=-100, stdout="", stderr="7z process failed to start")
            bag = FactBag()
            task = ArchiveTask(fact_bag=bag, score=10, main_path=str(archive_path), all_parts=[str(archive_path)])

            extractor.sevenzip_runner.run_extract = lambda **_kwargs: failed
            extractor.retry_policy.backoff = lambda _retry_count: None
            result = extractor.extract(task, str(out_dir))

            self.assertFalse(result.success)
            self.assertIn("已重试 1 次", result.error)

    def test_runner_skips_strong_scene_output_directory_for_recursion(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root / "www" / "audio").mkdir(parents=True)
            (root / "www" / "data").mkdir(parents=True)
            (root / "www" / "js").mkdir(parents=True)
            (root / "game.exe").write_bytes(b"MZ")
            (root / "www" / "data" / "Map001.json").write_text("{}", encoding="utf-8")
            (root / "www" / "audio" / "bgm.7z").write_bytes(b"7z\xbc\xaf\x27\x1c")

            policy = OutputScanPolicy(runner_config())

            self.assertFalse(policy.should_scan_output_dir(str(root)))


if __name__ == "__main__":
    unittest.main()
