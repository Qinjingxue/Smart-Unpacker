import io
import tempfile
import unittest
import zipfile
from pathlib import Path

from sunpack.contracts.detection import FactBag
from sunpack.coordinator.inspector import InspectOrchestrator
from sunpack.coordinator.task_provider import ArchiveTaskProvider, _select_single_candidate_ratio
from sunpack.coordinator.target_scan import build_fact_bags_for_targets
from sunpack.detection import DetectionScheduler
from tests.helpers.detection_config import with_detection_pipeline


def config_with_rules(scoring):
    return with_detection_pipeline({
        "thresholds": {"archive_score_threshold": 5, "maybe_archive_threshold": 3},
    }, precheck=[{"name": "size_range", "enabled": True, "gte": 0}], scoring=scoring)


def embedded_config(*, ratio=1.0):
    return config_with_rules([{
        "name": "embedded_payload_identity",
        "enabled": True,
        "deep_scan_single_candidate_ratio": ratio,
        "embedded_payload_score": 5,
    }])


def zip_bytes():
    output = io.BytesIO()
    with zipfile.ZipFile(output, "w", zipfile.ZIP_STORED) as archive:
        archive.writestr("inside.txt", "hello")
    return output.getvalue()


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
            self.assertEqual(split_group.get("candidate.entry_path"), str(first))
            self.assertEqual(split_group.get("candidate.member_paths"), [str(first), str(second)])
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
            self.assertEqual(split_result.fact_bag.get("file.split_members"), [str(second)])

    def test_unresolved_extensionless_file_gets_reliable_full_embedded_scan(self):
        with tempfile.TemporaryDirectory() as tmp:
            carrier = Path(tmp) / "movie.mp4"
            carrier.write_bytes(b"video-prefix" + zip_bytes())
            results = ArchiveTaskProvider(embedded_config()).detect_targets([str(carrier)])
            self.assertEqual(len(results), 1)
            result = results[0]
            self.assertTrue(result.decision.should_extract)
            self.assertEqual(result.fact_bag.get("file.detected_ext"), ".zip")
            self.assertTrue(result.fact_bag.get("file.embedded_archive_found"))
            self.assertTrue(result.fact_bag.get("analysis.signature_prepass", {}).get("full_scan_complete"))

    def test_single_candidate_ratio_selects_every_candidate_at_or_above_threshold(self):
        bags = []
        for name, size in (("large", 40), ("medium", 30), ("small", 30)):
            bag = FactBag()
            bag.set("file.path", name)
            bag.set("file.size", size)
            bags.append(bag)
        self.assertEqual(
            [bag.get("file.path") for bag in _select_single_candidate_ratio(bags, 0.3)],
            ["large", "medium", "small"],
        )
        self.assertEqual(
            [bag.get("file.path") for bag in _select_single_candidate_ratio(bags, 0.31)],
            ["large"],
        )

    def test_single_candidate_ratio_counts_split_group_once_at_logical_size(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            first = root / "game.001"
            second = root / "game.002"
            other = root / "other.bin"
            first.write_bytes(b"a" * 40)
            second.write_bytes(b"b" * 30)
            other.write_bytes(b"c" * 30)

            split = FactBag()
            split.set("file.path", str(first))
            split.set("file.size", 40)
            split.set("candidate.member_paths", [str(first), str(second), str(first)])
            ordinary = FactBag()
            ordinary.set("file.path", str(other))
            ordinary.set("file.size", 30)

            selected = _select_single_candidate_ratio([split, ordinary], 0.7)
            self.assertEqual(selected, [split])

    def test_single_candidate_ratio_skips_empty_or_disabled_selection(self):
        empty = FactBag()
        empty.set("file.path", "empty")
        empty.set("file.size", 0)
        self.assertEqual(_select_single_candidate_ratio([empty], 0.3), [])
        self.assertEqual(_select_single_candidate_ratio([empty], 0.0), [])

    def test_structurally_invalid_magic_is_not_accepted(self):
        with tempfile.TemporaryDirectory() as tmp:
            carrier = Path(tmp) / "payload.data"
            carrier.write_bytes(b"prefix" + b"PK\x03\x04not-a-local-header")
            results = ArchiveTaskProvider(embedded_config()).detect_targets([str(carrier)])
            self.assertFalse(results[0].decision.should_extract)

    def test_pe_overlay_remains_an_ordinary_detection_result(self):
        bag = FactBag()
        bag.set("file.path", "installer.exe")
        bag.set("embedded_archive.analysis", {"found": False})
        bag.set("pe.overlay_structure", {
            "archive_like": True,
            "format": "7z",
            "detected_ext": ".7z",
            "archive_offset": 434176,
        })
        decision = DetectionScheduler(embedded_config()).evaluate_bag(bag)
        self.assertTrue(decision.should_extract)
        self.assertEqual(bag.get("file.container_type"), "pe")
        self.assertEqual(bag.get("file.probe_offset"), 434176)


if __name__ == "__main__":
    unittest.main()
