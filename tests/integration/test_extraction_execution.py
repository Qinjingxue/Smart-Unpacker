import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch

from smart_unpacker.coordinator.output_scan import OutputScanPolicy
from smart_unpacker.config.schema import normalize_config
from smart_unpacker.extraction.scheduler import ExtractionScheduler
from smart_unpacker.contracts.detection import FactBag
from smart_unpacker.contracts.tasks import ArchiveTask
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
    def resolve(self, archive_path, fact_bag, part_paths=None):
        return SimpleNamespace(password="", test_result=None, error_text="")


class FakeMetadataScanner:
    def scan(self, archive, password=None, part_paths=None):
        return None


class FakeStager:
    def normalize(self, archive, all_parts, startupinfo=None):
        parts = list(all_parts)
        return SimpleNamespace(archive=archive, run_parts=parts, cleanup_parts=parts)

    def cleanup(self, staged):
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
                def normalize(self, archive, all_parts, startupinfo=None):
                    return SimpleNamespace(
                        archive=archive,
                        run_parts=[str(archive_path), str(candidate_path)],
                        cleanup_parts=[str(archive_path)],
                    )

                def cleanup(self, staged):
                    return None

            extractor = ExtractionScheduler(max_retries=1)
            extractor.password_resolver = FakePasswordResolver()
            extractor.metadata_scanner = FakeMetadataScanner()
            extractor.volume_normalizer = CandidateStager()

            bag = FactBag()
            task = ArchiveTask(fact_bag=bag, score=10, main_path=str(archive_path), all_parts=[str(archive_path)])

            succeeded = SimpleNamespace(returncode=0, stdout="", stderr="")
            with patch("smart_unpacker.extraction.scheduler.subprocess.run", return_value=succeeded):
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
            extractor.volume_normalizer = FakeStager()

            failed = SimpleNamespace(returncode=8, stdout="", stderr="write error")
            succeeded = SimpleNamespace(returncode=0, stdout="", stderr="")

            bag = FactBag()
            task = ArchiveTask(fact_bag=bag, score=10, main_path=str(archive_path), all_parts=[str(archive_path)])

            with patch("smart_unpacker.extraction.scheduler.subprocess.run", side_effect=[failed, succeeded]):
                result = extractor.extract(task, str(out_dir))

            self.assertTrue(result.success)
            self.assertIn(10, calls)

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
