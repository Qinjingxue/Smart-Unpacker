import tempfile
import os
import subprocess
import sys
import unittest
from unittest.mock import patch
from types import SimpleNamespace
import json


REPO_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if REPO_ROOT not in sys.path:
    sys.path.insert(0, REPO_ROOT)
from pathlib import Path

from smart_unpacker.core.engine import Engine
from smart_unpacker.support.resources import ResourceLocator


class ModuleUnitTest(unittest.TestCase):
    def make_engine(self, root: Path) -> Engine:
        engine = Engine(str(root), [], lambda _msg: None, lambda: None)
        engine.max_workers_limit = 1
        engine.current_concurrency_limit = 1
        return engine

    def test_logical_name_normalization(self):
        with tempfile.TemporaryDirectory() as td:
            engine = self.make_engine(Path(td))
            self.assertEqual(engine.get_logical_name("game.7z.001"), "game")
            self.assertEqual(engine.get_logical_name("bundle.part01.rar"), "bundle")
            self.assertEqual(engine.get_logical_name("archive.001"), "archive")
            self.assertEqual(engine.get_logical_name("solo.7z"), "solo")

    def test_scene_context_detects_rpg_maker(self):
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            (root / "www" / "js").mkdir(parents=True)
            (root / "www" / "data").mkdir(parents=True)
            (root / "Game.exe").write_bytes(b"MZ")
            (root / "www" / "js" / "rpg_core.js").write_text("// core", encoding="utf-8")
            engine = self.make_engine(root)
            context = engine._detect_scene_context(str(root))
            self.assertEqual(context.scene_type, "rpg_maker_game")
            self.assertEqual(context.match_strength, "strong")
            self.assertIn("www_dir", context.markers)

    def test_scene_context_detects_renpy(self):
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            (root / "game").mkdir(parents=True)
            (root / "renpy").mkdir(parents=True)
            (root / "game" / "script.rpy").write_text("label start:\n    return\n", encoding="utf-8")
            engine = self.make_engine(root)
            context = engine._detect_scene_context(str(root))
            self.assertEqual(context.scene_type, "renpy_game")
            self.assertEqual(context.match_strength, "strong")
            self.assertIn("game_dir", context.markers)

    def test_scene_context_detects_godot(self):
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            (root / "godot_game.exe").write_bytes(b"MZ")
            (root / "data.pck").write_bytes(b"x")
            engine = self.make_engine(root)
            context = engine._detect_scene_context(str(root))
            self.assertEqual(context.scene_type, "godot_game")
            self.assertEqual(context.match_strength, "strong")
            self.assertIn("data_pck", context.markers)

    def test_scene_context_detects_nwjs(self):
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            (root / "nw.exe").write_bytes(b"MZ")
            (root / "package.nw").write_bytes(b"x")
            engine = self.make_engine(root)
            context = engine._detect_scene_context(str(root))
            self.assertEqual(context.scene_type, "nwjs_game")
            self.assertEqual(context.match_strength, "strong")
            self.assertIn("package_nw", context.markers)

    def test_scene_context_detects_electron(self):
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            (root / "resources").mkdir(parents=True)
            (root / "app.exe").write_bytes(b"MZ")
            (root / "resources" / "app.asar").write_bytes(b"x")
            engine = self.make_engine(root)
            context = engine._detect_scene_context(str(root))
            self.assertEqual(context.scene_type, "electron_app_game")
            self.assertEqual(context.match_strength, "strong")
            self.assertIn("app_asar", context.markers)

    def test_scene_context_detects_supported_variant_as_weak_match(self):
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            (root / "www" / "js").mkdir(parents=True)
            (root / "www" / "img").mkdir(parents=True)
            (root / "Playtest.exe").write_bytes(b"MZ")
            engine = self.make_engine(root)
            context = engine._detect_scene_context(str(root))
            self.assertEqual(context.scene_type, "rpg_maker_game")
            self.assertEqual(context.match_strength, "weak")

    def test_weak_scene_directory_does_not_short_circuit_scan(self):
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            (root / "resources").mkdir(parents=True)
            (root / "launcher.exe").write_bytes(b"MZ")
            (root / "payload.zip").write_bytes(b"PK\x03\x04" + b"x" * (2 * 1024 * 1024))
            engine = self.make_engine(root)
            context = engine._detect_scene_context(str(root))
            self.assertEqual(context.scene_type, "electron_app_game")
            self.assertEqual(context.match_strength, "weak")

            with patch.object(engine, "_collect_archive_groups", return_value={}) as collect_groups:
                tasks = engine.scan_archives_readonly()

            self.assertEqual(tasks, [])
            collect_groups.assert_called_once()

    def test_scene_context_reuses_generic_cache(self):
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            (root / "nested").mkdir(parents=True)
            (root / "readme.txt").write_text("hello", encoding="utf-8")
            engine = self.make_engine(root)

            first = engine._detect_scene_context(str(root))
            self.assertEqual(first.scene_type, "generic")

            with patch.object(engine.scene_analyzer, "_collect_scene_markers") as collect_markers:
                second = engine._detect_scene_context(str(root))

            self.assertEqual(second.scene_type, "generic")
            collect_markers.assert_not_called()

    def test_strong_scene_directory_scan_short_circuits_before_file_inspection(self):
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            (root / "www" / "js").mkdir(parents=True)
            (root / "www" / "data").mkdir(parents=True)
            (root / "Game.exe").write_bytes(b"MZ")
            (root / "www" / "js" / "rpg_core.js").write_text("// core", encoding="utf-8")
            (root / "www" / "fonts").mkdir(parents=True)
            (root / "www" / "fonts" / "payload.7z").write_bytes(b"7z\xbc\xaf'\x1c" + b"x" * 1024)
            engine = self.make_engine(root)

            with patch.object(engine, "_collect_archive_groups") as collect_groups:
                tasks = engine.scan_archives_readonly()

            self.assertEqual(tasks, [])
            collect_groups.assert_not_called()

    def test_should_scan_output_dir_skips_strong_scene_directory_before_candidate_walk(self):
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            (root / "resources").mkdir(parents=True)
            (root / "app.exe").write_bytes(b"MZ")
            (root / "resources" / "app.asar").write_bytes(b"x")
            engine = self.make_engine(root)

            with patch.object(engine, "_iter_scan_candidate_files") as iter_candidates:
                should_scan = engine.should_scan_output_dir(str(root))

            self.assertFalse(should_scan)
            iter_candidates.assert_not_called()

    def test_classify_extract_error(self):
        with tempfile.TemporaryDirectory() as td:
            engine = self.make_engine(Path(td))
            self.assertEqual(
                engine._classify_extract_error(None, "Unexpected end of archive", archive="demo.7z.001", all_parts=["a", "b"]),
                "分卷缺失或不完整",
            )
            self.assertEqual(engine._classify_extract_error(None, "wrong password", archive="demo.zip"), "密码错误")
            self.assertEqual(engine._classify_extract_error(None, "headers error", archive="demo.rar"), "压缩包损坏")

    def test_build_directory_relationships_marks_split_exe_companion(self):
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            engine = self.make_engine(root)
            files = ["bundle.exe", "bundle.7z.001", "bundle.7z.002"]
            relations = engine._build_directory_relationships(str(root), files, scan_root=str(root))
            self.assertTrue(relations["bundle.exe"].is_split_exe_companion)
            self.assertTrue(relations["bundle.7z.001"].is_split_member)

    def test_fake_split_candidate_stays_maybe_archive(self):
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            noise = root / "trap.part1.rar"
            noise.write_bytes(b"x" * (2 * 1024 * 1024 + 2048))
            engine = self.make_engine(root)
            with patch.object(
                engine,
                "_probe_archive_with_7z",
                return_value={"is_archive": False, "type": None, "offset": 0, "is_encrypted": False, "is_broken": False},
            ), patch.object(
                engine,
                "_validate_with_7z",
                return_value={"ok": False, "encrypted": False, "error_text": ""},
            ):
                info = engine.inspect_archive_candidate(str(noise))
            self.assertEqual(info.decision, "maybe_archive")
            self.assertFalse(info.should_extract)
            self.assertTrue(info.is_split_candidate)

    def test_standard_archive_with_magic_skips_validation(self):
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            archive = root / "demo.7z"
            archive.write_bytes(b"7z\xbc\xaf'\x1c" + b"x" * (2 * 1024 * 1024))
            engine = self.make_engine(root)
            with patch.object(engine, "_validate_with_7z") as validate:
                info = engine.inspect_archive_candidate(str(archive))
            validate.assert_not_called()
            self.assertEqual(info.decision, "archive")
            self.assertTrue(info.validation_skipped)
            self.assertFalse(info.validation_ok)

    def test_unitypackage_is_semantically_protected_from_generic_extraction(self):
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            archive = root / "asset.unitypackage"
            archive.write_bytes(b"\x1f\x8b" + b"x" * (2 * 1024 * 1024))
            engine = self.make_engine(root)

            with patch.object(engine, "_validate_with_7z") as validate, patch.object(
                engine, "_probe_archive_with_7z"
            ) as probe:
                info = engine.inspect_archive_candidate(str(archive))

            self.assertEqual(info.decision, "not_archive")
            self.assertFalse(info.should_extract)
            self.assertTrue(any("强语义保护命中" in reason for reason in info.reasons))
            validate.assert_not_called()
            probe.assert_not_called()

    def test_output_dir_scan_ignores_unitypackage_only_payloads(self):
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            archive = root / "asset.unitypackage"
            archive.write_bytes(b"\x1f\x8b" + b"x" * (2 * 1024 * 1024))
            engine = self.make_engine(root)

            self.assertFalse(engine.should_scan_output_dir(str(root)))

    def test_probe_detected_archive_still_validates(self):
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            disguised = root / "demo.jpg"
            disguised.write_bytes(b"\xff\xd8\xff\xe0" + b"x" * (2 * 1024 * 1024))
            engine = self.make_engine(root)
            with patch.object(
                engine,
                "_validate_with_7z",
                return_value={"ok": False, "encrypted": False, "error_text": ""},
            ) as validate, patch.object(
                engine.inspector,
                "_find_embedded_archive_after_carrier",
                return_value={"detected_ext": ".rar", "offset": 512},
            ):
                info = engine.inspect_archive_candidate(str(disguised))
            validate.assert_called_once()
            self.assertTrue(info.probe_detected_archive)
            self.assertFalse(info.validation_skipped)

    def test_loose_embedded_scan_detects_non_tail_disguised_archive(self):
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            disguised = root / "payload.bin"
            disguised.write_bytes(b"x" * 4096 + b"PK\x03\x04" + b"y" * (2 * 1024 * 1024))
            engine = self.make_engine(root)
            with patch.object(
                engine,
                "_validate_with_7z",
                return_value={"ok": False, "encrypted": False, "error_text": ""},
            ) as validate:
                info = engine.inspect_archive_candidate(str(disguised))
            validate.assert_called_once()
            self.assertTrue(info.probe_detected_archive)
            self.assertEqual(info.detected_ext, ".zip")
            self.assertTrue(any("宽松扫描" in reason for reason in info.reasons))

    @patch("smart_unpacker.detection.inspector.subprocess.run")
    def test_validate_with_7z_disconnects_stdin(self, mock_run):
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            archive = root / "demo.7z"
            archive.write_bytes(b"7z\xbc\xaf'\x1c" + b"x" * 1024)
            engine = self.make_engine(root)
            mock_run.return_value = SimpleNamespace(returncode=0, stdout="", stderr="")
            engine.inspector._validate_with_7z(str(archive))
        self.assertIs(mock_run.call_args.kwargs.get("stdin"), subprocess.DEVNULL)

    @patch("smart_unpacker.detection.inspector.subprocess.run")
    def test_probe_with_7z_disconnects_stdin(self, mock_run):
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            archive = root / "demo.bin"
            archive.write_bytes(b"x" * (2 * 1024 * 1024))
            engine = self.make_engine(root)
            mock_run.return_value = SimpleNamespace(returncode=1, stdout="", stderr="")
            engine.inspector._probe_archive_with_7z(str(archive))
        self.assertIs(mock_run.call_args.kwargs.get("stdin"), subprocess.DEVNULL)

    def test_small_file_skips_all_followup_checks(self):
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            archive = root / "tiny.jpg"
            archive.write_bytes(b"\xff\xd8\xff\xe0" + b"x" * 128)
            engine = self.make_engine(root)
            engine.MIN_SIZE = 1024
            with patch.object(engine.inspector, "_apply_embedded_tail_analysis") as tail_check, patch.object(
                engine, "_probe_archive_with_7z"
            ) as probe, patch.object(engine, "_validate_with_7z") as validate:
                info = engine.inspect_archive_candidate(str(archive))
            self.assertTrue(info.skipped_by_size_limit)
            self.assertEqual(info.decision, "not_archive")
            self.assertFalse(info.should_extract)
            tail_check.assert_not_called()
            probe.assert_not_called()
            validate.assert_not_called()

    def test_resource_locator_reads_min_inspection_size_config(self):
        with tempfile.TemporaryDirectory() as td:
            config_path = Path(td) / "smart_unpacker_config.json"
            config_path.write_text(json.dumps({"min_inspection_size_bytes": 2048}), encoding="utf-8")
            locator = ResourceLocator()
            with patch.object(locator, "get_resource_base_path", return_value=td):
                config = locator.get_app_config()
            self.assertEqual(config.min_inspection_size_bytes, 2048)


if __name__ == "__main__":
    unittest.main()
