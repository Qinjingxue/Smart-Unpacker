import json
from pathlib import Path

import pytest

from repair_training.build_features import main as build_features_main
from repair_training.core.features import load_feature_schema
from repair_training.core.datasets import read_jsonl, split_rows
from repair_training.core.normal_structure_inference import NormalStructureModel
from repair_training.core.plugin import load_training_format_plugin
from repair_training.formats.zip.plugin import postprocess_damage_prediction, zip_module_family
from repair_training.train import main as train_main
from sunpack.repair.policy.adapters.normal_structure import ZipNormalQueryBuilder, ZipNormalStructureAdapter


def test_split_rows_keeps_sample_groups_together():
    rows = [
        {"episode_id": "a", "source_identity": {"source_archive_id": "same"}, "value": 1},
        {"episode_id": "b", "source_identity": {"source_archive_id": "same"}, "value": 2},
        {"episode_id": "c", "source_identity": {"source_archive_id": "other"}, "value": 3},
    ]

    splits = split_rows(rows)
    locations = {
        row["value"]: split
        for split, split_rows_ in splits.items()
        for row in split_rows_
    }

    assert locations[1] == locations[2]


def test_format_plugins_expose_dual_model_contract():
    for fmt in ("zip", "seven_zip"):
        plugin = load_training_format_plugin(fmt)
        assert plugin.damage_label_schema is not None
        assert plugin.damage_feature_spec is not None
        assert plugin.action_feature_spec is not None
        assert plugin.lightgbm_params is not None
        assert plugin.action_label is not None
        assert plugin.damage_label_schema().labels


def test_zip_plugin_declares_rich_labels_and_module_families():
    plugin = load_training_format_plugin("zip")
    labels = set(plugin.damage_label_schema().labels)
    metadata = plugin.damage_label_schema().metadata

    assert {"zone:eocd", "zone:central_directory", "field:eocd.cd_offset"}.issubset(labels)
    assert all(label.startswith(("zone:", "field:")) for label in labels)
    assert {"zone", "field"}.issubset(metadata["label_groups"])
    assert "family" not in metadata["label_groups"]
    assert "route" not in metadata["label_groups"]
    assert zip_module_family("zip_trim_trailing_junk") == "boundary"
    assert zip_module_family("zip_fix_cd_offset") == "pointer"
    assert zip_module_family("zip_fix_zip64_eocd") == "zip64"
    assert zip_module_family("zip_rebuild_cd_from_data_descriptors") == "descriptor"
    assert zip_module_family("zip_rebuild_cd_from_local_headers") == "rebuild"
    assert zip_module_family("zip_local_header_partial_scan") == "salvage"
    assert zip_module_family("zip_resolve_duplicate_entries") == "conflict"
    assert zip_module_family("zip_rebuild_cd_preserve_raw_names") == "naming"
    assert zip_module_family("undo_patch") == "control_undo"
    assert zip_module_family("unknown_zip_module") == "zip_other"


def test_zip_postprocess_damage_prediction_routes_and_fallback():
    selected = postprocess_damage_prediction({
        "scores": {
            "field:eocd.cd_offset": 0.9,
            "zone:eocd": 0.7,
        },
        "threshold": 0.5,
    })
    fallback = postprocess_damage_prediction({
        "scores": {
            "zone:tail": 0.2,
            "field:central_directory.local_header_offset": 0.3,
        },
        "threshold": 0.9,
    })

    assert "field:eocd.cd_offset" in selected["damage_labels"]
    assert selected["route_hints"] == []
    assert {"kind": "eocd", "path": "eocd"} in selected["damage_zones"]
    assert fallback["damage_labels"] == ["field:central_directory.local_header_offset", "zone:central_directory"]
    assert fallback["route_hints"] == []


def test_zip_action_label_control_heuristics():
    assert _zip_label({"action_type": "apply_patch", "long_term_value": 1.0, "is_best_action": True}) >= 24
    assert _zip_label({"action_type": "stop", "long_term_value": 0.1, "current_recovery": {"score": 0.97}}) >= 28
    assert _zip_label({"action_type": "undo_patch", "long_term_value": 0.0, "current_recovery": {"score": 0.1}, "next_recovery": {"score": 0.8}}) >= 22
    assert _zip_label({"action_type": "give_up", "long_term_value": 1.0, "current_recovery": {"score": 0.4}}) <= 3


def test_build_features_writes_npz_and_schema(tmp_path):
    run_dir = _write_fake_run(tmp_path)

    assert build_features_main(["--format", "zip", "--model", "damage_analysis", "--run-dir", str(run_dir)]) == 0
    assert build_features_main(["--format", "zip", "--model", "repair_action", "--run-dir", str(run_dir)]) == 0

    assert (run_dir / "features" / "damage_analysis" / "train.npz").is_file()
    assert (run_dir / "features" / "damage_analysis" / "feature_schema.json").is_file()
    assert (run_dir / "features" / "repair_action" / "train.npz").is_file()
    assert (run_dir / "features" / "repair_action" / "group_train.txt").is_file()
    schema = load_feature_schema(run_dir / "features" / "repair_action" / "feature_schema.json")
    assert "candidate_snapshot.module_family" in schema["categorical_features"]


def test_lightgbm_training_writes_model_artifacts(tmp_path):
    pytest.importorskip("lightgbm")
    run_dir = _write_fake_run(tmp_path)
    build_features_main(["--format", "zip", "--model", "damage_analysis", "--run-dir", str(run_dir)])
    build_features_main(["--format", "zip", "--model", "repair_action", "--run-dir", str(run_dir)])

    assert train_main(["--format", "zip", "--model", "damage_analysis", "--run-dir", str(run_dir)]) == 0
    assert train_main(["--format", "zip", "--model", "repair_action", "--run-dir", str(run_dir)]) == 0

    assert (run_dir / "models" / "damage_analysis" / "models.json").is_file()
    assert (run_dir / "models" / "damage_analysis" / "model_card.json").is_file()
    assert (run_dir / "models" / "repair_action" / "model.txt").is_file()
    assert (run_dir / "models" / "repair_action" / "model_card.json").is_file()


def test_zip_normal_query_builder_outputs_query_rows_without_raw_paths():
    graph = _normal_query_graph()
    rows = ZipNormalQueryBuilder().build_training_queries(
        graph,
        sample_id="clean:0",
        source_identity={"source_archive_id": "clean"},
    )

    assert rows
    assert {row["row_type"] for row in rows} == {"normal_structure_query"}
    assert {"field_value", "field_match", "span_relation", "explanation"}.issubset({row["query_type"] for row in rows})
    assert any(row["target_field"] == "central_directory.local_header_offset" and row["candidate_kind"] == "counterfactual" for row in rows)
    assert any(row["target_field"] == "central_directory.compressed_size" and "payload_end_equals_next_local" in row["features"] for row in rows)
    assert "path" not in json.dumps(rows).lower()
    assert "clean_sha256" not in json.dumps(rows).lower()


def test_zip_normal_adapter_aggregates_query_scores():
    adapter = ZipNormalStructureAdapter()
    rows = adapter.rows_from_graph(_normal_query_graph())
    scores = [0.1 if row["target_field"] == "eocd.cd_offset" else 0.95 for row in rows]

    anomaly = adapter.build_anomaly_payload(rows, scores)

    assert anomaly["queries"]
    assert anomaly["summary"]["max_anomaly_by_field"]["eocd.cd_offset"] > 0.8
    assert "eocd" in anomaly["summary"]["mean_anomaly_by_zone"]
    assert "trusted_explanations" in anomaly["summary"]


def test_normal_structure_features_use_query_schema(tmp_path):
    run_dir = tmp_path / "run"
    datasets = run_dir / "datasets"
    datasets.mkdir(parents=True)
    rows = ZipNormalQueryBuilder().build_training_queries(_normal_query_graph(), sample_id="clean:0")
    with (datasets / "normal_structure_queries.jsonl").open("w", encoding="utf-8") as handle:
        for row in rows:
            handle.write(json.dumps(row, ensure_ascii=False, sort_keys=True) + "\n")

    assert build_features_main(["--format", "zip", "--model", "normal_structure", "--run-dir", str(run_dir)]) == 0
    schema = load_feature_schema(run_dir / "features" / "normal_structure" / "feature_schema.json")

    assert "target_field" in schema["categorical_features"]
    assert any(name.startswith("features.") for name in schema["feature_names"])
    assert not any(name.startswith("object_type") for name in schema["feature_names"])
    assert not any(name.startswith("candidate_kind") or name.startswith("candidate_source") for name in schema["feature_names"])
    assert not any("raw" in name or "path" in name for name in schema["feature_names"])
    assert (run_dir / "features" / "normal_structure" / "meta_train.jsonl").is_file()


def test_normal_structure_model_flags_unseen_structural_anomaly(tmp_path):
    pytest.importorskip("lightgbm")
    plugin = load_training_format_plugin("zip")
    run_dir = tmp_path / "run"
    datasets = run_dir / "datasets"
    datasets.mkdir(parents=True)
    clean = _normal_query_graph()
    train_rows = []
    for index in range(12):
        train_rows.extend(ZipNormalQueryBuilder().build_training_queries(clean, sample_id=f"clean:{index}"))
    with (datasets / "normal_structure_queries.jsonl").open("w", encoding="utf-8") as handle:
        for row in train_rows:
            handle.write(json.dumps(row, ensure_ascii=False, sort_keys=True) + "\n")
    build_features_main(["--format", "zip", "--model", "normal_structure", "--run-dir", str(run_dir)])
    train_main(["--format", "zip", "--model", "normal_structure", "--run-dir", str(run_dir)])

    damaged = _normal_query_graph()
    damaged["summary"]["declared_central_directory_offset"] = 64
    damaged["summary"]["central_directory_offset_delta"] = 56
    damaged["edges"][0]["valid"] = False
    damaged["violations"] = [
        {
            "kind": "bad_reference",
            "source_node": "eocd:0",
            "target_node": "central_directory:0",
            "field": "eocd.cd_offset",
            "expected": 8,
            "observed": 64,
            "delta": 56,
            "severity": "high",
        }
    ]
    adapter = ZipNormalStructureAdapter()
    clean_rows = adapter.rows_from_graph(clean)
    clean_scores = NormalStructureModel(model_dir=run_dir / "models" / "normal_structure", plugin=plugin).predict_rows(clean_rows)
    clean_anomaly = adapter.build_anomaly_payload(clean_rows, clean_scores)
    runtime_rows = adapter.rows_from_graph(damaged)
    scores = NormalStructureModel(model_dir=run_dir / "models" / "normal_structure", plugin=plugin).predict_rows(runtime_rows)
    anomaly = adapter.build_anomaly_payload(runtime_rows, scores)

    assert anomaly["summary"]["max_anomaly_by_field"]["eocd.cd_offset"] > clean_anomaly["summary"]["max_anomaly_by_field"]["eocd.cd_offset"]
    assert anomaly["summary"]["max_anomaly_by_field"]["eocd.cd_offset"] > 0.05


def _write_fake_run(tmp_path: Path) -> Path:
    run_dir = tmp_path / "run"
    datasets = run_dir / "datasets"
    datasets.mkdir(parents=True)
    damage_rows = []
    action_rows = []
    for index in range(8):
        family = "central_directory" if index % 2 == 0 else "boundary"
        episode = f"ep{index}"
        damage_rows.append({
            "episode_id": episode,
            "format": "zip",
            "source_identity": {"source_archive_id": f"src{index // 2}"},
            "state_digest": f"state{index}",
            "round_index": 0,
            "damage_analysis_input": {
                "format": "zip",
                "runtime_context": {
                    "analysis_summary": {"format": "zip", "confidence": 1.0},
                    "extraction_summary": {"failure_stage": "extract", "failure_kind": family},
                    "verification_summary": {"decision_hint": "repair", "completeness": 0.0},
                    "job_summary": {"damage_flag_count": index % 3},
                },
            },
            "damage_analysis_target": {
                "labels": [
                    {
                        "zone": {
                            "kind": "zip",
                            "path": "zip.eocd.cd_offset" if family == "central_directory" else "archive.tail",
                        }
                    }
                ],
            },
        })
        for action_type, candidate_id, value in (
            ("apply_patch", f"cand{index}", 1.0 if index % 2 == 0 else 0.2),
            ("stop", "", 0.1),
            ("give_up", "", 0.0),
        ):
            action_rows.append({
                "episode_id": episode,
                "format": "zip",
                "source_identity": {"source_archive_id": f"src{index // 2}"},
                "state_digest": f"state{index}",
                "round_index": 0,
                "action_type": action_type,
                "candidate_id": candidate_id,
                "candidate_snapshot": {
                    "candidate_id": candidate_id,
                    "module_name": "zip_fix_cd_offset" if candidate_id else "",
                    "module_family": zip_module_family("zip_fix_cd_offset") if candidate_id else zip_module_family(action_type),
                    "action_type": action_type,
                    "patch_depth": 1 if candidate_id else 0,
                    "patch_operation_count": 1 if candidate_id else 0,
                    "confidence": 0.8 if candidate_id else 0.0,
                    "validation_summary": {"accepted": True, "score": 0.8},
                },
                "damage_analysis_target": {"damage_families": [family], "route_hints": []},
                "current_recovery": {"score": 0.0, "status": "empty", "decision_hint": "repair"},
                "next_recovery": {"score": value, "status": "partial", "decision_hint": "repair"},
                "recovery_delta": value,
                "long_term_value": value,
                "is_best_action": action_type == "apply_patch",
                "regret": 0.0 if action_type == "apply_patch" else 1.0,
            })
    _write_jsonl(datasets / "damage_rows.jsonl", damage_rows)
    _write_jsonl(datasets / "action_values.jsonl", action_rows)
    assert read_jsonl(datasets / "damage_rows.jsonl")
    return run_dir


def _normal_query_graph() -> dict:
    return {
        "schema_version": 1,
        "format": "zip",
        "nodes": [
            {"id": "archive:0", "kind": "archive", "start": 0, "end": 200, "size": 200},
            {"id": "eocd:0", "kind": "eocd", "start": 178, "end": 200, "size": 22},
            {"id": "central_directory:0", "kind": "central_directory", "start": 120, "end": 178, "size": 58},
            {"id": "cd_entry:0", "kind": "cd_entry", "start": 120, "end": 178, "size": 58},
            {"id": "local_header:0", "kind": "local_header_candidate", "start": 0, "end": 40, "size": 40},
            {"id": "payload_span:0", "kind": "payload_span", "start": 40, "end": 100, "size": 60},
            {"id": "descriptor_candidate:0", "kind": "descriptor_candidate", "start": 100, "end": 116, "size": 16},
        ],
        "edges": [
            {"source_node": "eocd:0", "target_node": "central_directory:0", "kind": "points_to", "field": "central_directory", "valid": True},
            {"source_node": "cd_entry:0", "target_node": "local_header:0", "kind": "points_to", "field": "local_header_offset", "valid": True},
            {"source_node": "local_header:0", "target_node": "payload_span:0", "kind": "owns_span", "field": "payload", "valid": True},
        ],
        "violations": [],
        "explanations": [
            {"kind": "sfx_prefix_adjustment", "applies": False, "delta": 0},
            {"kind": "descriptor_span_adjustment", "applies": True, "delta": 0},
        ],
        "summary": {
            "file_size": 200,
            "eocd_present": True,
            "declared_central_directory_offset": 120,
            "physical_central_directory_offset": 120,
            "central_directory_offset_delta": 0,
            "central_directory_size_delta": 0,
            "cd_entry_count": 1,
            "cd_entries_checked": 1,
            "entry_count_delta": 0,
            "local_header_candidate_count": 1,
            "sfx_prefix_len": 0,
            "trailing_bytes_after_eocd": 0,
            "central_local_crc_mismatch_count": 0,
            "central_local_flags_mismatch_count": 0,
            "central_local_method_mismatch_count": 0,
            "central_local_name_mismatch_count": 0,
            "central_local_compressed_size_mismatch_count": 0,
            "span_conflict_count": 0,
            "descriptor_conflict_count": 0,
        },
    }


def _write_jsonl(path: Path, rows: list[dict]) -> None:
    with path.open("w", encoding="utf-8") as handle:
        for row in rows:
            handle.write(json.dumps(row, sort_keys=True) + "\n")


def _zip_label(row: dict) -> int:
    plugin = load_training_format_plugin("zip")
    return int(plugin.action_label(row))
