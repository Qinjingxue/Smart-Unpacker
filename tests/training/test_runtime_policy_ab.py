from __future__ import annotations

import importlib.util
import json
import sys
from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]
SCRIPT = ROOT / "repair_training" / "evaluation" / "runtime_policy_ab.py"
COMPARE_SCRIPT = ROOT / "repair_training" / "evaluation" / "compare_training_runtime.py"


def _load_module():
    spec = importlib.util.spec_from_file_location("evaluate_runtime_policy_ab", SCRIPT)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


def _load_compare_module():
    spec = importlib.util.spec_from_file_location("compare_training_runtime_policy_env", COMPARE_SCRIPT)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


def test_compare_pairs_reports_runtime_and_recovery_deltas():
    mod = _load_module()
    rows = [
        {"sample_id": "a", "mode": "selector_baseline", "complete": False, "recovery_ratio": 0.5, "wall_seconds": 2.0, "damage_profile": "p", "repair_module_path": ["baseline"]},
        {"sample_id": "a", "mode": "zip_model_policy", "complete": True, "recovery_ratio": 1.0, "wall_seconds": 1.0, "damage_profile": "p", "repair_module_path": ["model"], "policy_selected_count": 1},
        {"sample_id": "b", "mode": "selector_baseline", "complete": True, "recovery_ratio": 1.0, "wall_seconds": 3.0, "damage_profile": "q", "repair_module_path": ["baseline"]},
        {"sample_id": "b", "mode": "zip_model_policy", "complete": False, "recovery_ratio": 0.25, "wall_seconds": 2.0, "damage_profile": "q", "repair_module_path": ["model"], "policy_fallback_count": 1},
    ]

    summary = mod.compare_pairs(rows)

    assert summary["paired_sample_count"] == 2
    assert summary["model_complete_delta"] == 0
    assert summary["model_improvement_count"] == 1
    assert summary["model_regression_count"] == 1
    assert summary["model_regression_samples"][0]["sample_id"] == "b"


def test_sample_records_loads_damage_json_and_resolves_paths(tmp_path):
    mod = _load_module()
    material = tmp_path / "repair_training" / "material" / "zip" / "s" / "damaged" / "case"
    material.mkdir(parents=True)
    damaged = material / "bad.zip"
    damaged.write_bytes(b"PK\x05\x06" + b"\x00" * 18)
    damage_json = material / "case.damage.json"
    damage_json.write_text(json.dumps({
        "sample_id": "s_zip_duplicate_entry_crc_conflict_0",
        "damage_profile": "zip_duplicate_entry_crc_conflict",
        "material_format": "zip",
        "damaged_path": str(damaged),
        "damaged_input": {"kind": "file", "path": str(damaged), "format_hint": "zip"},
        "oracle": {"expected_files": {}},
    }), encoding="utf-8")
    dataset = tmp_path / "rows.jsonl"
    dataset.write_text(json.dumps({
        "sample_id": "s_zip_duplicate_entry_crc_conflict_0",
        "damage_json_path": str(damage_json),
        "damaged_path": str(damaged),
        "material_format": "zip",
    }) + "\n", encoding="utf-8")

    records = mod.sample_records(dataset, sample_count=1, seed=1, profile_filters=["duplicate_entry"])

    assert len(records) == 1
    assert records[0]["oracle"] == {"expected_files": {}}
    assert Path(records[0]["damaged_path"]).is_absolute()


def test_summarize_mode_counts_policy_and_terminal_fields():
    mod = _load_module()
    summary = mod.summarize_mode([
        {"complete": True, "recovery_ratio": 1.0, "wall_seconds": 2.0, "terminal_status": "complete", "policy_selected_count": 1, "candidate_count": 4, "damage_profile": "p"},
        {"complete": False, "recovery_ratio": 0.0, "wall_seconds": 4.0, "terminal_status": "timeout", "policy_fallback_count": 1, "beam_used_count": 1, "candidate_count": 2, "damage_profile": "p"},
    ])

    assert summary["complete_count"] == 1
    assert summary["zero_recovery_count"] == 1
    assert summary["timeout_count"] == 1
    assert summary["policy_selected_count"] == 1
    assert summary["policy_fallback_count"] == 1
    assert summary["beam_used_count"] == 1


def test_task_from_record_attaches_split_sidecars(tmp_path):
    mod = _load_module()
    main = tmp_path / "case.zip"
    part = tmp_path / "case.z01"
    main.write_bytes(b"PK\x05\x06" + b"\x00" * 18)
    part.write_bytes(b"part")
    record = {
        "sample_id": "case_zip_split_missing_middle_volume_0",
        "damage_profile": "zip_split_missing_middle_volume",
        "material_format": "zip",
        "damaged_path": str(main),
        "damaged_input": {"kind": "file", "path": str(main), "format_hint": "zip", "parts": [{"path": str(part), "role": "volume"}]},
        "zip_container_tags": ["split_archive"],
        "damage_flags": ["damaged"],
    }

    task = mod.task_from_record(mod.prepare_record(record))

    assert str(main) in task.all_parts
    assert str(part) in task.all_parts
    assert task.split_info.is_split is True
    assert task.fact_bag.get("relation.is_split_related") is True
    assert str(part) in task.fact_bag.get("candidate.member_paths")


def test_runtime_config_modes_lock_policy_and_beam(tmp_path):
    mod = _load_module()
    baseline = mod.runtime_config(
        mod.RUN_MODES[0],
        workspace=tmp_path / "repair-a",
        output_root=tmp_path / "out-a",
        max_rounds=4,
        disable_repair_cache=False,
    )
    model = mod.runtime_config(
        mod.RUN_MODES[1],
        workspace=tmp_path / "repair-b",
        output_root=tmp_path / "out-b",
        max_rounds=4,
        disable_repair_cache=True,
    )

    assert baseline["repair"]["policy"]["enabled"] is False
    assert baseline["repair"]["beam"]["enabled"] is True
    assert model["repair"]["policy"]["enabled"] is True
    assert model["repair"]["policy"]["disable_beam_when_model_active"] is True
    assert model["repair"]["runtime_cache"]["enabled"] is False


def test_summarize_trace_counts_policy_and_beam_events():
    mod = _load_module()
    events = [
        {"event": "repair_candidates_generated", "candidate_count": 2, "candidates": [{"module_name": "a"}, {"module_name": "b"}]},
        {"event": "repair_selected_result", "result": {"module_name": "b", "actions": ["act"]}, "selection": {"policy": {"decision_status": "selected"}, "candidates": [{"module_name": "a"}, {"module_name": "b"}]}},
        {"event": "repair_selected_result", "result": {"module_name": "c", "actions": []}, "selection": {"policy": {"decision_status": "fallback"}, "policy_fallback": True}},
    ]
    candidate_log = [{"phase": "beam_run", "candidate": {"module_name": "beam_mod"}}, {"phase": "beam_selected", "candidate": {"module_name": "beam_selected"}}]

    summary = mod.summarize_trace(events, candidate_log, policy_enabled=True)

    assert summary["candidate_count"] == 2
    assert summary["policy_selected_count"] == 1
    assert summary["policy_fallback_count"] == 1
    assert summary["beam_used_count"] == 2
    assert "b" in summary["repair_module_path"]


def test_compare_training_runtime_detects_candidate_and_feature_mismatch():
    mod = _load_compare_module()
    training_rows = [
        {
            "sample_id": "sample_a",
            "round": 0,
            "query_id": "sample_a:0",
            "candidate_id": "t1",
            "module_name": "zip_fix_cd_offset",
            "repair_name": "zip_fix_cd_offset",
            "native_target": "cd_offset",
            "patch_facts": ["fixed_field=cd_offset"],
            "stable_features": {
                "runtime_context": {"job_summary": {"route_evidence_flags": ["central_directory_offset_bad"]}},
                "candidate_proposal": {"patch_facts": ["fixed_field=cd_offset"]},
            },
            "rl": {"single_path_robust_return": 1.0},
        }
    ]
    probe_events = [
        {
            "event": "policy_probe_request",
            "run_id": "sample_a:zip_model_policy",
            "query_id": "runtime-q0",
            "round": 0,
            "candidate_payloads": [
                {
                    "candidate_id": "r1",
                    "module_name": "zip_quarantine_failed_entries",
                    "repair_name": "zip_quarantine_failed_entries",
                    "native_target": "entry_quarantine",
                    "runtime_context": {"job_summary": {}},
                    "candidate_proposal": {"patch_facts": ["quarantined_failed_entries"]},
                }
            ],
        },
        {
            "event": "policy_probe_decision",
            "query_id": "runtime-q0",
            "policy": {"decision_status": "selected"},
            "selected_candidate": {
                "module_name": "zip_quarantine_failed_entries",
                "repair_name": "zip_quarantine_failed_entries",
                "native_target": "entry_quarantine",
                "candidate_proposal": {"patch_facts": ["quarantined_failed_entries"]},
            },
        },
    ]

    rows = mod.compare_training_runtime(training_rows, probe_events)

    assert len(rows) == 1
    assert rows[0]["candidate_overlap_count"] == 0
    assert rows[0]["candidate_missing_in_runtime"]
    assert rows[0]["selection_matches_training_best"] is False
    assert "runtime_context_missing_in_runtime" in rows[0]["feature_key_diff"]
