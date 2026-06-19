import os
import io
import tempfile
import unittest
import zipfile
from pathlib import Path

from sunpack.contracts.detection import FactBag
from sunpack.coordinator.inspector import InspectOrchestrator
from sunpack.detection import DetectionScheduler
from sunpack.coordinator.target_scan import build_fact_bags_for_targets
from tests.helpers.detection_config import with_detection_pipeline


def config_with_rules(scoring):
    return with_detection_pipeline({
        "thresholds": {
            "archive_score_threshold": 5,
            "maybe_archive_threshold": 3,
        },
    }, precheck=[
        {"name": "size_range", "enabled": True, "gte": 0},
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

            groups = build_fact_bags_for_targets([str(root)], config=config_with_rules([]))

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

    def test_embedded_archive_analysis_is_only_required_for_configured_extensions(self):
        with tempfile.TemporaryDirectory() as tmp:
            plain = Path(tmp) / "movie.mp4"
            plain.write_bytes(b"\x00" * 64 + b"PK\x03\x04" + b"not-scanned")

            bag = FactBag()
            bag.set("file.path", str(plain))
            decision = DetectionScheduler(config_with_rules([
                {
                    "name": "embedded_payload_identity",
                    "enabled": True,
                    "carrier_exts": [".jpg"],
                    "ambiguous_resource_exts": [".bin"],
                },
            ])).evaluate_bag(bag)

            self.assertFalse(decision.should_extract)
            self.assertFalse(bag.has("embedded_archive.analysis"))

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
                    "embedded_payload_scan_level": "manual",
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
                    "embedded_payload_scan_level": "manual",
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
                    "embedded_payload_scan_level": "manual",
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
                    "embedded_payload_scan_level": "manual",
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
                    "embedded_payload_scan_level": "manual",
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
                    "embedded_payload_scan_level": "manual",
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
                    "embedded_payload_scan_level": "manual",
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

    def test_pe_overlay_start_strong_hit_reaches_default_archive_threshold(self):
        bag = FactBag()
        bag.set("file.path", "installer.exe")
        bag.set("embedded_archive.analysis", {"found": False})
        bag.set("pe.overlay_structure", {
            "archive_like": True,
            "offset_delta_from_overlay": 0,
            "format": "7z",
            "detected_ext": ".7z",
            "archive_offset": 434176,
            "confidence": "strong",
        })

        decision = DetectionScheduler(with_detection_pipeline({
            "thresholds": {
                "archive_score_threshold": 6,
                "maybe_archive_threshold": 3,
            },
        }, scoring=[
            {"name": "embedded_payload_identity", "enabled": True},
        ])).evaluate_bag(bag)

        self.assertTrue(decision.should_extract)
        self.assertEqual(decision.total_score, 6)
        self.assertEqual(bag.get("file.detected_ext"), ".7z")
        self.assertEqual(bag.get("file.probe_offset"), 434176)

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

