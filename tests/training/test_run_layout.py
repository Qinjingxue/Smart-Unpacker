from __future__ import annotations

import os
from pathlib import Path

from repair_training.core import run_layout


def test_latest_training_dataset_only_checks_canonical_run_datasets(tmp_path, monkeypatch):
    training_root = tmp_path / "repair_training"
    runs_root = training_root / "runs"
    older = runs_root / "zip" / "older" / "datasets" / "runtime_graph_success.jsonl"
    newer = runs_root / "zip" / "newer" / "datasets" / "runtime_graph_success.jsonl"
    nested_tmp = (
        runs_root
        / "zip"
        / "older"
        / "tmp"
        / ("runtime_output_" + "x" * 180)
        / "datasets"
        / "runtime_graph_success.jsonl"
    )
    for path in (older, newer, nested_tmp):
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text("{}\n", encoding="utf-8")
    os.utime(older, ns=(1_000_000_000, 1_000_000_000))
    os.utime(newer, ns=(2_000_000_000, 2_000_000_000))
    os.utime(nested_tmp, ns=(3_000_000_000, 3_000_000_000))

    monkeypatch.setattr(run_layout, "TRAINING_ROOT", training_root)
    monkeypatch.setattr(run_layout, "RUNS_ROOT", runs_root)
    monkeypatch.setattr(run_layout, "LATEST_RUNS", training_root / "latest_runs.json")
    monkeypatch.setattr(run_layout, "LEGACY_LATEST_RUN", training_root / "latest_run.txt")

    assert run_layout.latest_training_dataset() == newer


def test_latest_training_dataset_prefers_explicit_latest_run(tmp_path, monkeypatch):
    training_root = tmp_path / "repair_training"
    runs_root = training_root / "runs"
    latest_run = runs_root / "zip" / "selected"
    selected = latest_run / "datasets" / "runtime_graph_success.jsonl"
    newer = runs_root / "zip" / "newer" / "datasets" / "runtime_graph_success.jsonl"
    selected.parent.mkdir(parents=True)
    newer.parent.mkdir(parents=True)
    selected.write_text("{}\n", encoding="utf-8")
    newer.write_text("{}\n", encoding="utf-8")
    os.utime(selected, ns=(1_000_000_000, 1_000_000_000))
    os.utime(newer, ns=(2_000_000_000, 2_000_000_000))

    monkeypatch.setattr(run_layout, "TRAINING_ROOT", training_root)
    monkeypatch.setattr(run_layout, "RUNS_ROOT", runs_root)
    monkeypatch.setattr(run_layout, "LATEST_RUNS", training_root / "latest_runs.json")
    monkeypatch.setattr(run_layout, "LEGACY_LATEST_RUN", training_root / "latest_run.txt")
    run_layout.write_latest_run("zip", latest_run)

    assert run_layout.latest_training_dataset() == selected


def test_latest_training_dataset_returns_stable_fallback_when_runs_are_missing(tmp_path, monkeypatch):
    training_root = tmp_path / "repair_training"
    monkeypatch.setattr(run_layout, "TRAINING_ROOT", training_root)
    monkeypatch.setattr(run_layout, "RUNS_ROOT", training_root / "runs")
    monkeypatch.setattr(run_layout, "LATEST_RUNS", training_root / "latest_runs.json")
    monkeypatch.setattr(run_layout, "LEGACY_LATEST_RUN", training_root / "latest_run.txt")

    assert run_layout.latest_training_dataset() == training_root / "datasets" / "runtime_graph_success.jsonl"
