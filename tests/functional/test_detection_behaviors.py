import os
import io
import tempfile
import unittest
import zipfile
from pathlib import Path

from smart_unpacker.contracts.detection import FactBag
from smart_unpacker.coordinator.inspector import InspectOrchestrator
from smart_unpacker.detection import DetectionScheduler
from smart_unpacker.detection.scene.definitions import RECOMMENDED_SCENE_RULES_PAYLOAD
from tests.helpers.detection_config import with_detection_pipeline


def config_with_rules(scoring):
    return with_detection_pipeline({
        "thresholds": {
            "archive_score_threshold": 5,
            "maybe_archive_threshold": 3,
        },
    }, precheck=[
        {"name": "size_minimum", "enabled": True, "min_inspection_size_bytes": 0},
    ], scoring=scoring)


class DetectionBehaviorTests(unittest.TestCase):
    def test_group_builder_sets_split_relation_facts(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            first = root / "game.part1.rar"
            second = root / "game.part2.rar"
            first.write_bytes(b"one")
            second.write_bytes(b"two")
            (root / "orphan.002").write_bytes(b"alone")

            groups = DetectionScheduler(config_with_rules([])).build_candidate_fact_bags([str(root)])

            split_group = next(group for group in groups if group.get("file.logical_name") == "game")
            orphan = next(group for group in groups if group.get("file.path", "").endswith("orphan.002"))

            self.assertTrue(split_group.get("relation.is_split_related"))
            self.assertEqual(split_group.get("file.split_role"), "first")
            self.assertEqual(len(split_group.get("file.split_members")), 1)
            self.assertEqual(split_group.get("candidate.kind"), "split_archive")
            self.assertEqual(split_group.get("candidate.entry_path"), str(first))
            self.assertEqual(split_group.get("candidate.member_paths"), [str(first), str(second)])
            self.assertEqual(split_group.get("relation.split_family"), "rar_part")
            self.assertTrue(split_group.get("relation.split_is_first"))
            self.assertFalse(orphan.get("relation.is_split_related"))

    def test_inspect_uses_target_grouping_for_directory_split_sets(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            first = root / "game.part1.rar"
            second = root / "game.part2.rar"
            first.write_bytes(b"one")
            second.write_bytes(b"two")

            results = InspectOrchestrator(config_with_rules([])).inspect([str(root)])

            split_result = next(result for result in results if result.fact_bag.get("file.logical_name") == "game")
            self.assertEqual(split_result.path, str(first))
            self.assertEqual(split_result.split_role, "first")
            self.assertEqual(split_result.fact_bag.get("file.split_members"), [str(second)])
            self.assertTrue(split_result.fact_bag.get("relation.is_split_related"))

    def test_embedded_archive_rule_detects_carrier_tail_archive(self):
        with tempfile.TemporaryDirectory() as tmp:
            carrier = Path(tmp) / "cover.jpg"
            carrier.write_bytes(b"\xff\xd8image-bytes\xff\xd9" + b"PK\x03\x04" + b"zip-ish")

            bag = FactBag()
            bag.set("file.path", str(carrier))
            decision = DetectionScheduler(config_with_rules([
                {"name": "embedded_payload_identity", "enabled": True},
            ])).evaluate_bag(bag)

            self.assertTrue(decision.should_extract)
            self.assertEqual(bag.get("file.detected_ext"), ".zip")
            self.assertTrue(bag.get("file.embedded_archive_found"))

    def test_embedded_archive_rule_detects_default_prefix_rar5_carrier(self):
        with tempfile.TemporaryDirectory() as tmp:
            carrier = Path(tmp) / "cover.jpg"
            carrier.write_bytes(
                b"\xff\xd8image-padding"
                + (b"x" * 1024)
                + b"\xff\xd9"
                + b"Rar!\x1a\x07\x01\x00"
                + b"encrypted-looking-payload"
                + b"\xff\xd9"
                + (b"tail" * 1024)
            )

            bag = FactBag()
            bag.set("file.path", str(carrier))
            decision = DetectionScheduler(config_with_rules([
                {
                    "name": "embedded_payload_identity",
                    "enabled": True,
                    "carrier_scan_tail_window_bytes": 128,
                },
            ])).evaluate_bag(bag)

            self.assertTrue(decision.should_extract)
            self.assertEqual(bag.get("file.detected_ext"), ".rar")
            self.assertTrue(bag.get("file.embedded_archive_found"))
            self.assertEqual((bag.get("embedded_archive.analysis") or {}).get("scan_scope"), "prefix")

    def test_carrier_scan_can_disable_prefix_and_full_scan_for_large_middle_marker(self):
        with tempfile.TemporaryDirectory() as tmp:
            carrier = Path(tmp) / "cover.jpg"
            carrier.write_bytes(b"\xff\xd8image\xff\xd9" + b"7z\xbc\xaf\x27\x1c" + b"x" * 4096)

            bag = FactBag()
            bag.set("file.path", str(carrier))
            decision = DetectionScheduler(config_with_rules([
                {
                    "name": "embedded_payload_identity",
                    "enabled": True,
                    "carrier_exts": [".jpg"],
                    "ambiguous_resource_exts": [],
                    "carrier_scan_tail_window_bytes": 128,
                    "carrier_scan_prefix_window_bytes": 0,
                    "carrier_scan_full_scan_max_bytes": 1024,
                },
            ])).evaluate_bag(bag)

            self.assertFalse(decision.should_extract)
            self.assertFalse(bag.get("file.embedded_archive_found"))

    def test_loose_scan_rejects_implausible_zip_local_header(self):
        with tempfile.TemporaryDirectory() as tmp:
            carrier = Path(tmp) / "payload.bin"
            carrier.write_bytes(b"x" * 64 + b"PK\x03\x04" + b"not-a-real-zip-header" + b"x" * 4096)

            bag = FactBag()
            bag.set("file.path", str(carrier))
            decision = DetectionScheduler(config_with_rules([
                {
                    "name": "embedded_payload_identity",
                    "enabled": True,
                    "ambiguous_resource_exts": [".bin"],
                    "loose_scan_score": 5,
                    "loose_scan_min_tail_bytes": 1,
                },
            ])).evaluate_bag(bag)

            self.assertFalse(decision.should_extract)
            self.assertFalse(bag.get("zip.local_header_plausible"))
            self.assertEqual(bag.get("zip.local_header_offset"), 64)
            self.assertTrue(bag.get("zip.local_header_error"))
            self.assertFalse(bag.get("file.embedded_archive_found"))

    def test_loose_scan_accepts_plausible_embedded_zip_local_header(self):
        with tempfile.TemporaryDirectory() as tmp:
            zip_buffer = io.BytesIO()
            with zipfile.ZipFile(zip_buffer, "w", zipfile.ZIP_STORED) as archive:
                archive.writestr("inside.txt", "hello")

            carrier = Path(tmp) / "payload.bin"
            carrier.write_bytes(b"x" * 64 + zip_buffer.getvalue())

            bag = FactBag()
            bag.set("file.path", str(carrier))
            decision = DetectionScheduler(config_with_rules([
                {
                    "name": "embedded_payload_identity",
                    "enabled": True,
                    "ambiguous_resource_exts": [".bin"],
                    "loose_scan_score": 5,
                    "loose_scan_min_tail_bytes": 1,
                },
            ])).evaluate_bag(bag)

            self.assertTrue(decision.should_extract)
            self.assertTrue(bag.get("zip.local_header_plausible"))
            self.assertEqual(bag.get("zip.local_header_offset"), 64)
            self.assertEqual(bag.get("file.detected_ext"), ".zip")
            self.assertTrue(bag.get("file.embedded_archive_found"))

    def test_loose_scan_checks_tail_window_before_full_scan(self):
        with tempfile.TemporaryDirectory() as tmp:
            carrier = Path(tmp) / "payload.bin"
            carrier.write_bytes(b"x" * 4096 + b"7z\xbc\xaf\x27\x1c" + b"payload-tail")

            bag = FactBag()
            bag.set("file.path", str(carrier))
            decision = DetectionScheduler(config_with_rules([
                {
                    "name": "embedded_payload_identity",
                    "enabled": True,
                    "ambiguous_resource_exts": [".bin"],
                    "loose_scan_score": 5,
                    "loose_scan_min_tail_bytes": 1,
                    "loose_scan_tail_window_bytes": 128,
                    "loose_scan_full_scan_max_bytes": 128,
                },
            ])).evaluate_bag(bag)

            self.assertTrue(decision.should_extract)
            self.assertEqual(bag.get("file.detected_ext"), ".7z")
            self.assertEqual(bag.get("embedded_archive.analysis").get("scan_scope"), "tail")

    def test_loose_scan_skips_large_middle_hits_without_deep_scan(self):
        with tempfile.TemporaryDirectory() as tmp:
            carrier = Path(tmp) / "payload.bin"
            carrier.write_bytes(b"x" * 256 + b"7z\xbc\xaf\x27\x1c" + b"x" * 4096)

            bag = FactBag()
            bag.set("file.path", str(carrier))
            decision = DetectionScheduler(config_with_rules([
                {
                    "name": "embedded_payload_identity",
                    "enabled": True,
                    "ambiguous_resource_exts": [".bin"],
                    "loose_scan_score": 5,
                    "loose_scan_min_tail_bytes": 1,
                    "loose_scan_tail_window_bytes": 128,
                    "loose_scan_full_scan_max_bytes": 1024,
                },
            ])).evaluate_bag(bag)

            self.assertFalse(decision.should_extract)
            self.assertFalse(bag.get("file.embedded_archive_found"))

    def test_loose_scan_deep_scan_finds_large_middle_hits(self):
        with tempfile.TemporaryDirectory() as tmp:
            carrier = Path(tmp) / "payload.bin"
            carrier.write_bytes(b"x" * 256 + b"7z\xbc\xaf\x27\x1c" + b"x" * 4096)

            bag = FactBag()
            bag.set("file.path", str(carrier))
            decision = DetectionScheduler(config_with_rules([
                {
                    "name": "embedded_payload_identity",
                    "enabled": True,
                    "ambiguous_resource_exts": [".bin"],
                    "loose_scan_score": 5,
                    "loose_scan_min_tail_bytes": 1,
                    "loose_scan_tail_window_bytes": 128,
                    "loose_scan_full_scan_max_bytes": 1024,
                    "loose_scan_deep_scan": True,
                },
            ])).evaluate_bag(bag)

            self.assertTrue(decision.should_extract)
            self.assertEqual(bag.get("file.detected_ext"), ".7z")
            self.assertEqual(bag.get("embedded_archive.analysis").get("scan_scope"), "full")

    def test_scene_penalty_suppresses_embedded_runtime_resource(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root / "www" / "audio").mkdir(parents=True)
            (root / "www" / "data").mkdir(parents=True)
            (root / "game.exe").write_bytes(b"MZ")
            (root / "www" / "data" / "Map001.json").write_text("{}", encoding="utf-8")
            resource = root / "www" / "audio" / "bgm.jpg"
            resource.write_bytes(b"\xff\xd8audio-cover\xff\xd9" + b"PK\x03\x04" + b"hidden")

            bag = FactBag()
            bag.set("file.path", str(resource))
            config = with_detection_pipeline({
                "thresholds": {"archive_score_threshold": 5, "maybe_archive_threshold": 3},
            }, precheck=[
                {"name": "scene_protect", "enabled": True, "scene_rules": RECOMMENDED_SCENE_RULES_PAYLOAD},
            ], scoring=[
                {"name": "embedded_payload_identity", "enabled": True},
                {"name": "scene_penalty", "enabled": True, "scene_rules": RECOMMENDED_SCENE_RULES_PAYLOAD},
            ])
            decision = DetectionScheduler(config).evaluate_bag(bag)

            self.assertFalse(decision.should_extract)
            self.assertTrue(bag.get("file.embedded_archive_found"))
            self.assertIn("scene_penalty", decision.matched_rules)

    def test_scene_protect_stops_protected_archive_but_not_runtime_exact_path(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root / "www" / "audio").mkdir(parents=True)
            (root / "www" / "data").mkdir(parents=True)
            runtime = root / "game.exe"
            archive = root / "www" / "audio" / "bgm.7z"
            runtime.write_bytes(b"MZ")
            archive.write_bytes(b"7z\xbc\xaf\x27\x1c")

            config = with_detection_pipeline(precheck=[
                {"name": "scene_protect", "enabled": True, "scene_rules": RECOMMENDED_SCENE_RULES_PAYLOAD},
            ])

            archive_bag = FactBag()
            archive_bag.set("file.path", str(archive))
            archive_decision = DetectionScheduler(config).evaluate_bag(archive_bag)

            runtime_bag = FactBag()
            runtime_bag.set("file.path", str(runtime))
            runtime_decision = DetectionScheduler(config).evaluate_bag(runtime_bag)

            self.assertFalse(archive_decision.should_extract)
            self.assertEqual(archive_decision.stop_reason.split(":", 1)[0], "Scene Protect")
            self.assertTrue(archive_bag.get("scene.is_runtime_resource_archive"))
            self.assertFalse(runtime_bag.get("scene.is_runtime_resource_archive"))
            self.assertFalse(runtime_decision.should_extract)
            self.assertIsNone(runtime_decision.stop_reason)

    def test_scene_penalty_applies_large_penalty_when_scene_protect_is_disabled(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root / "www" / "audio").mkdir(parents=True)
            (root / "www" / "data").mkdir(parents=True)
            (root / "game.exe").write_bytes(b"MZ")
            archive = root / "www" / "audio" / "bgm.7z"
            archive.write_bytes(b"7z\xbc\xaf\x27\x1c")

            bag = FactBag()
            bag.set("file.path", str(archive))
            config = with_detection_pipeline({
                "thresholds": {"archive_score_threshold": 5, "maybe_archive_threshold": 3},
            }, scoring=[
                {"name": "extension", "enabled": True, "extension_score_groups": [{"score": 5, "extensions": [".zip", ".7z", ".rar", ".gz", ".bz2", ".xz", ".001"]}]},
                {
                    "name": "scene_penalty",
                    "enabled": True,
                    "scene_rules": RECOMMENDED_SCENE_RULES_PAYLOAD,
                    "runtime_resource_archive_penalty": -99,
                },
            ])

            decision = DetectionScheduler(config).evaluate_bag(bag)

            self.assertFalse(decision.should_extract)
            self.assertEqual(decision.total_score, -94)
            self.assertIn("extension", decision.matched_rules)
            self.assertIn("scene_penalty", decision.matched_rules)
            self.assertTrue(bag.get("scene.is_runtime_resource_archive"))

    def test_weak_scene_protected_archive_is_penalized_when_precheck_allows_weak_matches(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root / "www" / "audio").mkdir(parents=True)
            (root / "www" / "js").mkdir(parents=True)
            archive = root / "www" / "audio" / "bgm.7z"
            archive.write_bytes(b"7z\xbc\xaf\x27\x1c")

            bag = FactBag()
            bag.set("file.path", str(archive))
            config = with_detection_pipeline({
                "thresholds": {"archive_score_threshold": 5, "maybe_archive_threshold": 3},
            }, precheck=[
                {
                    "name": "scene_protect",
                    "enabled": True,
                    "scene_rules": RECOMMENDED_SCENE_RULES_PAYLOAD,
                    "protect_weak_matches": False,
                },
            ], scoring=[
                {"name": "extension", "enabled": True, "extension_score_groups": [{"score": 5, "extensions": [".zip", ".7z", ".rar", ".gz", ".bz2", ".xz", ".001"]}]},
                {
                    "name": "scene_penalty",
                    "enabled": True,
                    "scene_rules": RECOMMENDED_SCENE_RULES_PAYLOAD,
                    "runtime_resource_archive_penalty": -99,
                },
            ])

            decision = DetectionScheduler(config).evaluate_bag(bag)

            self.assertIsNone(decision.stop_reason)
            self.assertFalse(decision.should_extract)
            self.assertEqual(bag.get("scene.match_strength"), "weak")
            self.assertTrue(bag.get("scene.is_runtime_resource_archive"))
            self.assertIn("scene_penalty", decision.matched_rules)

    def test_maybe_split_with_strong_signal_stays_uncertain_after_scoring(self):
        with tempfile.TemporaryDirectory() as tmp:
            first = Path(tmp) / "payload.001"
            second = Path(tmp) / "payload.002"
            first.write_bytes(b"head")
            second.write_bytes(b"tail")

            bag = FactBag()
            bag.set("file.path", str(first))
            bag.set("file.split_members", [str(second)])
            bag.set("file.is_split_candidate", True)
            bag.set("relation.is_split_related", True)
            bag.set("file.magic_matched", True)

            config = config_with_rules([
                {"name": "extension", "enabled": True, "extension_score_groups": [{"score": 5, "extensions": [".zip", ".7z", ".rar", ".gz", ".bz2", ".xz", ".001"]}]},
            ])
            config["thresholds"]["archive_score_threshold"] = 6
            decision = DetectionScheduler(config).evaluate_bag(bag)

            self.assertFalse(decision.should_extract)
            self.assertEqual(decision.decision, "maybe_archive")
            self.assertNotIn("group_decision", decision.matched_rules)


if __name__ == "__main__":
    unittest.main()
