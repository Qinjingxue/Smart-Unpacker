import json
from pathlib import Path

import pytest

from repair_training.build_features import main as build_features_main
from repair_training.core.features import load_feature_schema
from repair_training.core.datasets import read_jsonl, split_rows
from repair_training.core.normal_structure_inference import NormalStructureModel
from repair_training.core.plugin import load_training_format_plugin
from repair_training.evaluate_normal_structure_model import main as evaluate_normal_structure_main
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
    assert zip_module_family("checkout_node") == "zip_other"
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
    assert _zip_label({"action_type": "expand_edge", "long_term_value": 1.0, "is_best_action": True}) >= 24
    assert _zip_label({"action_type": "stop_signal", "long_term_value": 0.1, "current_recovery": {"score": 0.97}}) >= 28
    assert _zip_label({"action_type": "checkout_node", "long_term_value": 0.0, "current_recovery": {"score": 0.1}}) >= 14
    assert _zip_label({
        "action_type": "stop_signal",
        "current_recovery": {"score": 0.77},
        "state_value": {"reachable_recovery_value": 0.79},
        "long_term_value": 0.0,
    }) <= 8
    assert _zip_label({
        "action_type": "stop_signal",
        "current_recovery": {"score": 0.2},
        "state_value": {"reachable_recovery_value": 0.8},
        "long_term_value": 1.0,
    }) <= 8
    assert _zip_label({
        "action_type": "expand_edge",
        "current_recovery": {"score": 0.2},
        "candidate_snapshot": {"validation_summary": {"accepted": True}},
        "state_value": {"reachable_recovery_value": 0.8},
        "long_term_value": 0.0,
    }) >= 18
    assert _zip_label({
        "action_type": "checkout_node",
        "current_recovery": {"score": 0.2},
        "state_value": {"reachable_recovery_value": 0.25},
        "parent_state_value": {"reachable_recovery_value": 0.75},
        "long_term_value": 0.0,
    }) >= 14
    assert _zip_label({
        "action_type": "stop_signal",
        "current_recovery": {"score": 0.0},
        "state_value": {"reachable_recovery_value": 0.3},
        "long_term_value": 1.0,
    }) <= 8
    assert _zip_label({
        "action_type": "expand_edge",
        "candidate_snapshot": {"module_name": "zip_partial_salvage_missing_volume"},
        "current_recovery": {"score": 0.0},
        "state_value": {"reachable_recovery_value": 0.3},
        "long_term_value": -0.2,
    }) >= 18
    assert _zip_label({
        "action_type": "expand_edge",
        "candidate_snapshot": {"module_name": "zip_fix_cd_offset", "validation_summary": {"accepted": True}},
        "current_recovery": {"score": 0.0},
        "state_value": {"reachable_recovery_value": 0.3},
        "long_term_value": -0.2,
    }) >= 14


def test_build_features_writes_npz_and_schema(tmp_path):
    run_dir = _write_fake_run(tmp_path)

    assert build_features_main(["--format", "zip", "--model", "damage_analysis", "--run-dir", str(run_dir)]) == 0
    assert build_features_main(["--format", "zip", "--model", "graph_action", "--run-dir", str(run_dir)]) == 0

    assert (run_dir / "features" / "damage_analysis" / "train.npz").is_file()
    assert (run_dir / "features" / "damage_analysis" / "feature_schema.json").is_file()
    assert (run_dir / "features" / "graph_action" / "train.npz").is_file()
    assert (run_dir / "features" / "graph_action" / "group_train.txt").is_file()
    schema = load_feature_schema(run_dir / "features" / "graph_action" / "feature_schema.json")
    assert "candidate_snapshot.module_family" in schema["categorical_features"]
    assert not any(
        name.startswith(("next_recovery", "recovery_delta"))
        or "candidate_snapshot.recovery" in name
        or "candidate_snapshot.patch_digest" in name
        or "candidate_snapshot.patch_depth" in name
        or "candidate_snapshot.patch_count" in name
        or "candidate_snapshot.last_patch_module" in name
        or "candidate_snapshot.has_archive_state_plan" in name
        or "candidate_snapshot.branchable" in name
        or "candidate_snapshot.metadata.score_source" in name
        or "candidate_snapshot.verification_summary" in name
        for name in schema["feature_names"]
    )


def test_lightgbm_training_writes_model_artifacts(tmp_path):
    pytest.importorskip("lightgbm")
    run_dir = _write_fake_run(tmp_path)
    build_features_main(["--format", "zip", "--model", "damage_analysis", "--run-dir", str(run_dir)])
    build_features_main(["--format", "zip", "--model", "graph_action", "--run-dir", str(run_dir)])

    assert train_main(["--format", "zip", "--model", "damage_analysis", "--run-dir", str(run_dir)]) == 0
    assert train_main(["--format", "zip", "--model", "graph_action", "--run-dir", str(run_dir)]) == 0

    assert (run_dir / "models" / "damage_analysis" / "models.json").is_file()
    assert (run_dir / "models" / "damage_analysis" / "model_card.json").is_file()
    assert (run_dir / "models" / "graph_action" / "model.txt").is_file()
    assert (run_dir / "models" / "graph_action" / "model_card.json").is_file()


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
    for row in rows:
        features = row.get("features") or {}
        assert "candidate_source_delta_bucket" not in features
        assert "violation_kind" not in features
        assert "violation_severity" not in features


def test_zip_normal_adapter_aggregates_query_scores():
    adapter = ZipNormalStructureAdapter()
    rows = adapter.rows_from_graph(_normal_query_graph())
    scores = [0.1 if row["target_field"] == "eocd.cd_offset" else 0.95 for row in rows]

    anomaly = adapter.build_anomaly_payload(rows, scores)

    assert anomaly["queries"]
    assert anomaly["compact_attribution"]["top_queries"]
    assert "eocd.cd_offset" in anomaly["compact_attribution"]["by_field"]
    assert "field_value" in anomaly["compact_attribution"]["by_relation"]
    assert "eocd|field_value" in anomaly["compact_attribution"]["by_zone_relation"]
    assert "sfx_cd_offset" in anomaly["compact_attribution"]["conflict_pairs"]
    assert anomaly["summary"]["max_anomaly_by_field"]["eocd.cd_offset"] > 0.8
    assert "eocd" in anomaly["summary"]["mean_anomaly_by_zone"]
    assert "trusted_explanations" in anomaly["summary"]
    assert "path" not in json.dumps(anomaly["compact_attribution"]["top_queries"]).lower()
    assert "hash" not in json.dumps(anomaly["compact_attribution"]["top_queries"]).lower()


def test_zip_normal_adapter_reads_structure_runtime_payload_facts():
    adapter = ZipNormalStructureAdapter()
    payload = {
        "runtime_context": {
            "analysis_native_probe": {
                "structure": {
                    "graph": _normal_query_graph(),
                    "runtime": {
                        "payload_content_failure_observed": True,
                        "payload_direct_crc_or_hash_failure_observed": True,
                        "payload_size_or_content_mismatch_observed": True,
                        "extraction_item_failure_observed": True,
                        "payload_verification_observed": True,
                        "payload_verified_intact": False,
                        "payload_unverified_but_no_failure": False,
                        "no_payload_hash_crc_failure": False,
                        "extraction_entry_outcomes": {
                            "entry_failed_count": 2,
                            "data_error_count": 1,
                            "unexpected_end_count": 1,
                        },
                        "verification_coverage_breakdown": {
                            "crc_mismatch_count": 3,
                            "payload_hash_mismatch_count": 1,
                        },
                    },
                },
            },
        },
    }

    rows = adapter.rows_from_request_payload(payload)
    by_field = {row["target_field"]: row for row in rows}
    payload_features = by_field["payload.compressed_data"]["features"]
    crc_features = by_field["local_header.crc"]["features"]

    assert payload_features["payload_content_failure_observed"] is True
    assert payload_features["payload_direct_crc_or_hash_failure_observed"] is True
    assert payload_features["payload_size_or_content_mismatch_observed"] is True
    assert payload_features["extraction_item_failure_observed"] is True
    assert payload_features["payload_verification_observed"] is True
    assert payload_features["payload_verified_intact"] is False
    assert payload_features["payload_unverified_but_no_failure"] is False
    assert payload_features["no_payload_hash_crc_failure"] is False
    assert payload_features["crc_mismatch_count"] == 3
    assert payload_features["payload_hash_mismatch_count"] == 1
    assert payload_features["entry_failed_count"] == 2
    assert payload_features["data_error_count"] == 1
    assert payload_features["unexpected_end_count"] == 1
    assert payload_features["direct_field_violation_present"] is True
    assert crc_features["crc_mismatch_count"] == 3
    assert crc_features["verification_crc_failure"] is True


def test_zip_damage_feature_spec_uses_structure_not_raw_structure():
    plugin = load_training_format_plugin("zip")
    spec = plugin.damage_feature_spec()

    assert spec is not None
    assert any(prefix.startswith("runtime_context.analysis_native_probe.structure.") for prefix in spec.include_prefixes)
    assert not any("structure.anomaly" in prefix for prefix in spec.include_prefixes)
    assert "runtime_context.analysis_native_probe.structure.anomaly" in spec.ignore_prefixes
    assert not any("raw_structure" in prefix for prefix in spec.include_prefixes)
    assert not any("raw_structure" in path for path in spec.categorical_paths)
    assert not any("raw_structure" in prefix for prefix in spec.ignore_prefixes)
    assert "runtime_context.analysis_native_probe.structure.runtime.payload_extraction_content_failure_observed" in spec.ignore_paths


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
    assert "features.candidate_source_delta_bucket" not in schema["feature_names"]
    assert "features.violation_kind" not in schema["feature_names"]
    assert "features.violation_severity" not in schema["feature_names"]
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


def test_evaluate_normal_structure_model_reports_attribution_metrics(tmp_path):
    pytest.importorskip("lightgbm")
    run_dir = tmp_path / "run"
    datasets = run_dir / "datasets"
    datasets.mkdir(parents=True)
    clean = _normal_query_graph()
    train_rows = []
    for index in range(12):
        train_rows.extend(ZipNormalQueryBuilder().build_training_queries(clean, sample_id=f"clean:{index}"))
    _write_jsonl(datasets / "normal_structure_queries.jsonl", train_rows)
    build_features_main(["--format", "zip", "--model", "normal_structure", "--run-dir", str(run_dir)])
    train_main(["--format", "zip", "--model", "normal_structure", "--run-dir", str(run_dir)])

    damaged = _normal_query_graph()
    damaged["summary"]["declared_central_directory_offset"] = 64
    damaged["violations"] = [{
        "kind": "bad_reference",
        "source_node": "eocd:0",
        "field": "eocd.cd_offset",
        "expected": 8,
        "observed": 64,
        "delta": 56,
        "severity": "high",
    }]
    damage_rows = [{
        "sample_id": "damaged:0",
        "damage_analysis_input": {
            "runtime_context": {
                "analysis_native_probe": {
                    "structure": {"graph": damaged},
                },
            },
        },
        "damage_analysis_target": {
            "damage_labels": ["field:eocd.cd_offset", "zone:eocd"],
        },
    }]
    _write_jsonl(datasets / "damage_rows_raw.jsonl", damage_rows)
    output = run_dir / "reports" / "normal_eval"

    assert evaluate_normal_structure_main([
        "--format", "zip",
        "--input", str(datasets / "damage_rows_raw.jsonl"),
        "--normal-model-dir", str(run_dir / "models" / "normal_structure"),
        "--output", str(output),
        "--top-k", "3",
    ]) == 0
    metrics = json.loads((output / "normal_structure_attribution_metrics.json").read_text(encoding="utf-8"))

    assert metrics["rows"] == 1
    assert "field_top1_accuracy" in metrics
    assert "field_top5_recall" in metrics
    assert "zone_top1_accuracy" in metrics
    assert "relation_kind_top3_recall" in metrics
    assert "conflict_pair_top3_hit_rate" in metrics
    assert (output / "normal_structure_attribution_predictions.jsonl").is_file()


def _write_fake_run(tmp_path: Path) -> Path:
    run_dir = tmp_path / "run"
    datasets = run_dir / "datasets"
    datasets.mkdir(parents=True)
    damage_rows = []
    action_rows = []
    value_rows = []
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
            ("expand_edge", f"cand{index}", 1.0 if index % 2 == 0 else 0.2),
            ("stop_signal", "", 0.1),
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
                "node_id": f"node:{index}",
                "parent_node_id": "",
                "frontier_edge_id": f"edge:{index}" if candidate_id else "",
                "graph_action": {"action_type": action_type, "edge_id": f"edge:{index}" if candidate_id else ""},
                "graph_best_node_id": f"node:{index}",
                "branch_status": "active",
                "policy_prior_label": 28 if action_type == "expand_edge" else 4,
                "is_best_action": action_type == "expand_edge",
            })
        value_rows.append({
            "episode_id": episode,
            "format": "zip",
            "state_digest": f"state{index}",
            "round_index": 0,
            "patch_depth": 0,
            "damage_analysis": {"damage_labels": [f"family:{family}"]},
            "current_recovery": {"score": 0.0, "status": "empty", "decision_hint": "repair"},
            "best_seen_recovery": {"score": 0.0},
            "parent_recovery": {"score": 0.0},
            "repair_history": {},
            "graph_summary": {"node_count": 1, "edge_count": 1, "frontier_count": 1, "best_recovery": 0.0},
            "frontier_summary": {"frontier_count": 1, "module_count": 1, "top_prior": 1.0 if index % 2 == 0 else 0.2},
            "branch_status": "active",
            "reachable_recovery_value": 1.0 if index % 2 == 0 else 0.5,
        })
    _write_jsonl(datasets / "damage_rows.jsonl", damage_rows)
    _write_jsonl(datasets / "action_policy_rows.jsonl", action_rows)
    _write_jsonl(datasets / "state_value_rows.jsonl", value_rows)
    assert read_jsonl(datasets / "damage_rows.jsonl")
    return run_dir


def test_state_value_rows_are_written_by_run_fixture(tmp_path):
    run_dir = _write_fake_run(tmp_path)
    value_rows = read_jsonl(run_dir / "datasets" / "state_value_rows.jsonl")

    assert len(value_rows) == 8
    assert all(0.0 <= row["reachable_recovery_value"] <= 1.0 for row in value_rows)
    assert all("frontier_summary" in row for row in value_rows)
    assert any(row["frontier_summary"]["frontier_count"] == 1 for row in value_rows)


def test_build_features_and_train_state_value(tmp_path):
    pytest.importorskip("lightgbm")
    run_dir = _write_fake_run(tmp_path)

    assert build_features_main(["--format", "zip", "--model", "graph_state_value", "--run-dir", str(run_dir)]) == 0
    schema = load_feature_schema(run_dir / "features" / "graph_state_value" / "feature_schema.json")
    assert "current_recovery.score" in schema["feature_names"]
    assert "frontier_summary.frontier_count" in schema["feature_names"]
    assert not any(
        "path" in name
        or "patch_digest" in name
        or "candidate_summary.max_candidate_recovery" in name
        or "candidate_summary.mean_candidate_recovery" in name
        or "candidate_summary.recovery_delta" in name
        for name in schema["feature_names"]
    )

    assert train_main(["--format", "zip", "--model", "graph_state_value", "--run-dir", str(run_dir)]) == 0
    metrics = json.loads((run_dir / "models" / "graph_state_value" / "metrics.json").read_text(encoding="utf-8"))
    assert "mae" in metrics
    assert (run_dir / "models" / "graph_state_value" / "model.txt").is_file()


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
