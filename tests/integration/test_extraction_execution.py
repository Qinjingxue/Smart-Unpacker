import os
import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch

from smart_unpacker.coordinator.output_scan import OutputScanPolicy
from smart_unpacker.coordinator.runner import PipelineRunner
from smart_unpacker.extraction.internal.password_manager import PasswordManager
from smart_unpacker.extraction.internal.split_stager import SplitVolumeStager, StagedSplit
from smart_unpacker.extraction.scheduler import ExtractionScheduler
from smart_unpacker.contracts.detection import FactBag
from smart_unpacker.contracts.tasks import ArchiveTask, SplitArchiveInfo
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


class FakePasswordManager(PasswordManager):
    def __init__(self):
        pass

    def find_working_password(self, archive_path):
        return "", None, ""


class FakeMetadataScanner:
    def scan(self, archive, password=None):
        return None


class FakeStager:
    def stage(self, archive, all_parts, startupinfo=None):
        return StagedSplit(archive=archive, all_parts=list(all_parts))

    def cleanup(self, staged):
        return None


class ExtractionExecutionTests(unittest.TestCase):
    def test_extractor_uses_split_data_entry_for_sfx_7z_parts(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            exe = root / "payload.exe"
            first = root / "payload.7z.001"
            second = root / "payload.7z.002"
            exe.write_bytes(b"MZ")
            first.write_bytes(b"first")
            second.write_bytes(b"second")

            extractor = ExtractionScheduler()
            entry, parts, split_info = extractor._resolve_split_entry(
                str(exe),
                [str(exe), str(first), str(second)],
                SplitArchiveInfo(is_split=True, is_sfx_stub=True, parts=[str(exe), str(first), str(second)]),
            )

            self.assertEqual(entry, str(first))
            self.assertIn(str(second), parts)
            self.assertTrue(split_info.is_split)
            self.assertTrue(split_info.is_sfx_stub)

    def test_extractor_finds_sfx_split_entry_from_directory_when_detection_is_off(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            exe = root / "payload.exe"
            first = root / "payload.001"
            second = root / "payload.002"
            exe.write_bytes(b"MZ")
            first.write_bytes(b"first")
            second.write_bytes(b"second")

            extractor = ExtractionScheduler()
            entry, parts, split_info = extractor._resolve_split_entry(str(exe), [str(exe)], SplitArchiveInfo())

            self.assertEqual(entry, str(first))
            self.assertEqual(parts, [str(exe), str(first), str(second)])
            self.assertTrue(split_info.is_split)
            self.assertTrue(split_info.is_sfx_stub)

    def test_extractor_supports_rar_sfx_part_names(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            exe = root / "payload.exe"
            first = root / "payload.part1.rar"
            second = root / "payload.part2.rar"
            exe.write_bytes(b"MZ")
            first.write_bytes(b"first")
            second.write_bytes(b"second")

            extractor = ExtractionScheduler()
            entry, parts, _ = extractor._resolve_split_entry(str(exe), [str(exe)], SplitArchiveInfo())

            self.assertEqual(entry, str(first))
            self.assertIn(str(second), parts)

    def test_extractor_supports_legacy_rar_sfx_volume_names(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            exe = root / "payload.exe"
            first = root / "payload.rar"
            second = root / "payload.r00"
            exe.write_bytes(b"MZ")
            first.write_bytes(b"first")
            second.write_bytes(b"second")

            extractor = ExtractionScheduler()
            entry, parts, _ = extractor._resolve_split_entry(str(exe), [str(exe)], SplitArchiveInfo())

            self.assertEqual(entry, str(first))
            self.assertIn(str(second), parts)

    def test_split_stager_repairs_misnamed_numeric_volume_in_temp_dir(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            first = root / "payload.7z.001"
            second = root / "payload.7z.2"
            first.write_bytes(b"first")
            second.write_bytes(b"second")

            stager = SplitVolumeStager("7z")
            with patch("smart_unpacker.extraction.internal.split_stager.subprocess.run", return_value=SimpleNamespace(returncode=0)):
                staged = stager.stage(str(first), [str(first)])

            try:
                self.assertNotEqual(os.path.dirname(staged.archive), str(root))
                self.assertTrue(staged.archive.endswith("payload.7z.001"))
                self.assertIn(str(second), staged.all_parts)
                self.assertTrue(os.path.isdir(staged.temp_dir))
            finally:
                stager.cleanup(staged)

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
            extractor.password_manager = FakePasswordManager()
            extractor.password_resolver.password_manager = extractor.password_manager
            extractor.metadata_scanner = FakeMetadataScanner()
            extractor.split_stager = FakeStager()

            failed = SimpleNamespace(returncode=8, stdout="", stderr="write error")
            succeeded = SimpleNamespace(returncode=0, stdout="", stderr="")

            bag = FactBag()
            bag.set("file.path", str(archive_path))
            task = ArchiveTask.from_fact_bag(bag, score=10)

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

    def test_round_postprocess_clears_success_archive_queue(self):
        with tempfile.TemporaryDirectory() as tmp:
            archive_path = Path(tmp) / "sample.zip"
            archive_path.write_bytes(b"zip")

            runner = PipelineRunner(runner_config())
            runner.context.unpacked_archives.append([str(archive_path)])

            runner._apply_postprocess_actions()

            self.assertEqual(runner.context.unpacked_archives, [])
            self.assertTrue(archive_path.exists())


if __name__ == "__main__":
    unittest.main()
