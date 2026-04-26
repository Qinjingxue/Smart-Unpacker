import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch

from smart_unpacker.coordinator.output_scan import OutputScanPolicy
from smart_unpacker.extraction.scheduler import ExtractionScheduler
from smart_unpacker.contracts.detection import FactBag
from smart_unpacker.contracts.tasks import ArchiveTask
from tests.helpers.detection_config import with_detection_pipeline


def runner_config():
    return with_detection_pipeline({
        "thresholds": {"archive_score_threshold": 5, "maybe_archive_threshold": 3},
        "recursive_extract": {"mode": "fixed", "max_rounds": 1},
        "post_extract": {
            "archive_cleanup_mode": "keep",
            "flatten_single_directory": False,
        },
    })


class FakePasswordResolver:
    def resolve(self, archive_path, fact_bag):
        return SimpleNamespace(password="", test_result=None, error_text="")


class FakeMetadataScanner:
    def scan(self, archive, password=None):
        return None


class FakeStager:
    def stage(self, archive, all_parts, startupinfo=None):
        return SimpleNamespace(archive=archive, all_parts=list(all_parts))

    def cleanup(self, staged):
        return None


class ExtractionExecutionTests(unittest.TestCase):
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
            extractor.split_stager = FakeStager()

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
