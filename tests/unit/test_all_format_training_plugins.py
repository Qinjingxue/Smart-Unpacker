from __future__ import annotations

from pathlib import Path

import pytest

from repair_training import __main__ as training_main
from repair_training.data import collection
from repair_training.formats.atomic_common import FORMAT_PROFILES
from repair_training.formats.base import load_training_format_plugin
from sunpack.repair.model.diagnosis.graph_dispatcher import build_diagnosis_graph_sample_for_format
from sunpack.repair.pipeline.registry import discover_repair_modules, get_repair_module_registry


FORMATS = ("rar", "tar", "gzip", "bzip2", "xz", "zstd")


@pytest.mark.parametrize("format_name", FORMATS)
def test_atomic_format_plugin_generates_every_profile_and_graph(format_name: str, tmp_path: Path) -> None:
    plugin = load_training_format_plugin(format_name)
    profiles = FORMAT_PROFILES[format_name]
    rows = plugin.generate_collection_records(tmp_path / "material", tmp_path / "workspace", 17, 1, len(profiles))

    assert {row["damage_profile"] for row in rows} == {profile.name for profile in profiles}
    assert all(Path(row["damaged_input"]["path"]).is_file() for row in rows)
    assert all(row["clean_sha256"] != row["corrupted_sha256"] for row in rows)
    for row in rows:
        graph = build_diagnosis_graph_sample_for_format(format_name, row)
        assert graph.labels.root_case_labels
        assert graph.graph.nodes


def test_all_generated_expected_actions_are_registered_atomic_modules() -> None:
    discover_repair_modules()
    registry = get_repair_module_registry()
    for profiles in FORMAT_PROFILES.values():
        for profile in profiles:
            module = registry.get(profile.expected_module)
            assert module is not None, profile.expected_module
            assert module.spec.atomic is True


def test_pipeline_collect_stage_precedes_graph_and_training(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    commands: list[list[str]] = []
    monkeypatch.setattr(training_main, "_run_pipeline_command", lambda command: commands.append(command))
    monkeypatch.setattr(training_main, "write_latest_run", lambda *_args: None)

    assert training_main.pipeline_main([
        "--format", "rar",
        "--run-dir", str(tmp_path / "run"),
        "--stage", "collect,graphs:diagnosis_gnn,train:diagnosis_gnn",
        "--limit", "7",
        "--seed", "23",
    ]) == 0

    assert "repair_training.data.collection" in commands[0]
    assert commands[0][commands[0].index("--limit") + 1] == "7"
    assert "repair_training.diagnosis.graph_rows" in commands[1]
    assert commands[2][-5:] == ["--format", "rar", "--model", "diagnosis_gnn", "--run-dir", str(tmp_path / "run")][-5:]


def test_collection_cli_accepts_non_zip_plugin(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    record = {"sample_id": "rar-1", "format": "rar", "metadata": {"damage_profile": "main_header_crc"}}
    monkeypatch.setattr(collection, "_records_for_args", lambda _args, workspace: [record])
    monkeypatch.setattr(collection, "collect_damage_rows", lambda records, workspace, workers: (records, []))

    output = tmp_path / "run" / "datasets" / "damage_rows.jsonl"
    assert collection.main(["--format", "rar", "--output", str(output), "--keep-workspace"]) == 0
    assert output.is_file()
