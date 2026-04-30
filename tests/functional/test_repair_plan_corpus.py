from __future__ import annotations

import gzip
import json
import subprocess
import sys
import tarfile
import zipfile
from pathlib import Path

from repair_training.training_corruption import (
    BinaryCorruptor,
    apply_mutations,
    verify_repaired_output_against_oracle,
)


def test_training_corruption_manifest_round_trips_and_replays(tmp_path):
    case = BinaryCorruptor(31337).zip_combo_directory_payload_raw_noise(tmp_path / "case")
    record = case.corpus_manifest_record(
        source_archive_id="source-zip",
        source_path="clean.zip",
        damage_profile="boundary+directory+payload",
        variant_index=0,
    )

    assert apply_mutations(case.clean_data, case.mutations) == case.corrupted_data
    parsed = json.loads(json.dumps(record))
    assert parsed["corruption_plan"]
    for mutation in parsed["corruption_plan"]:
        assert mutation["kind"]
        assert mutation["zone"]
        assert "offset" in mutation
        assert "size" in mutation
    assert parsed["oracle"]["expected_files"]


def test_training_corruption_oracle_marks_wrong_content_hard_negative(tmp_path):
    case = BinaryCorruptor(2026).zip_missing_cd_payload_bad_tail(tmp_path / "case")
    wrong = tmp_path / "wrong.zip"
    with zipfile.ZipFile(wrong, "w") as archive:
        archive.writestr("good.txt", b"wrong payload")

    result = verify_repaired_output_against_oracle(case, wrong)

    assert result["label"] == -1
    assert result["status"] == "hard_negative"


def test_repair_plan_corpus_scripts_generate_and_collect_state_action_rows(tmp_path):
    material_root = tmp_path / "material"
    build = subprocess.run(
        [
            sys.executable,
            "repair_training/build_repair_plan_corpus.py",
            "--init-material",
            "--material-root",
            str(material_root),
        ],
        cwd=Path.cwd(),
        text=True,
        capture_output=True,
        check=True,
    )
    init_summary = json.loads(build.stdout.strip())
    assert {"zip", "7z", "rar", "tar", "gzip", "bzip2", "xz", "zstd", "tar_gz", "tar_bz2", "tar_xz", "tar_zst"} <= set(init_summary["format_dirs"])
    sample_dir = material_root / "zip" / "sample_a"
    sample_dir.mkdir()
    source = sample_dir / "sample.zip"
    _write_clean_zip(source)
    old_damaged = sample_dir / "damaged"
    old_damaged.mkdir()
    (old_damaged / "stale.txt").write_text("stale", encoding="utf-8")

    build = subprocess.run(
        [
            sys.executable,
            "repair_training/build_repair_plan_corpus.py",
            "--material-root",
            str(material_root),
            "--per-sample",
            "3",
            "--seed",
            "101",
            "--no-pretty",
        ],
        cwd=Path.cwd(),
        text=True,
        capture_output=True,
        check=True,
    )
    build_summary = json.loads(build.stdout.strip())
    assert build_summary["generated"] == 3
    assert source.exists()
    assert not (old_damaged / "stale.txt").exists()
    manifest = sample_dir / "damage_manifest.jsonl"
    manifest_rows = [json.loads(line) for line in manifest.read_text(encoding="utf-8").splitlines()]
    assert len(manifest_rows) == 3
    assert all(len(row["corruption_plan"]) >= 2 for row in manifest_rows)
    assert all(row["material_format"] == "zip" for row in manifest_rows)
    assert all(row["material_sample_id"] == "sample_a" for row in manifest_rows)
    damage_jsons = sorted((sample_dir / "damaged").rglob("*.damage.json"))
    assert len(damage_jsons) == 3

    success_output = tmp_path / "repair_plan_ltr_success.jsonl"
    failure_output = tmp_path / "repair_plan_ltr_failure.jsonl"
    collect = subprocess.run(
        [
            sys.executable,
            "repair_training/collect_repair_plan_data.py",
            "--material-root",
            str(material_root),
            "--success-output",
            str(success_output),
            "--failure-output",
            str(failure_output),
            "--max-rounds",
            "2",
            "--max-candidates-per-round",
            "4",
            "--case-timeout-seconds",
            "20",
            "--no-pretty",
        ],
        cwd=Path.cwd(),
        text=True,
        capture_output=True,
        check=True,
    )
    collect_summary = json.loads(collect.stdout.strip())
    assert collect_summary["samples"] == 3
    rows = _jsonl(success_output) + _jsonl(failure_output)
    assert rows
    assert all("stable_features" in row for row in rows)
    assert all("teacher_features" in row for row in rows)
    assert all(row["material_format"] == "zip" for row in rows)
    assert all(row["material_sample_id"] == "sample_a" for row in rows)
    assert all(row["source_archive_name"] == "sample.zip" for row in rows)
    assert {row["source"] for row in rows} == {"repair_plan_corpus"}


def test_material_build_seed_controls_reproducibility(tmp_path):
    material_root = tmp_path / "material"
    sample_dir = material_root / "zip" / "sample_seed"
    sample_dir.mkdir(parents=True)
    _write_clean_zip(sample_dir / "sample.zip")

    _run_material_build(material_root, seed="777")
    first = (sample_dir / "damage_manifest.jsonl").read_text(encoding="utf-8")
    _run_material_build(material_root, seed="777")
    second = (sample_dir / "damage_manifest.jsonl").read_text(encoding="utf-8")
    assert first == second

    _run_material_build(material_root, seed="random")
    random_first = (sample_dir / "damage_manifest.jsonl").read_text(encoding="utf-8")
    _run_material_build(material_root, seed="random")
    random_second = (sample_dir / "damage_manifest.jsonl").read_text(encoding="utf-8")
    assert random_first != random_second


def test_material_build_organizes_direct_format_root_archives(tmp_path):
    material_root = tmp_path / "material"
    zip_root = material_root / "zip"
    zip_root.mkdir(parents=True)
    direct_source = zip_root / "direct.zip"
    _write_clean_zip(direct_source)

    subprocess.run(
        [
            sys.executable,
            "repair_training/build_repair_plan_corpus.py",
            "--material-root",
            str(material_root),
            "--per-sample",
            "2",
            "--seed",
            "2024",
            "--no-pretty",
        ],
        cwd=Path.cwd(),
        text=True,
        capture_output=True,
        check=True,
    )

    sample_dir = zip_root / "direct"
    moved_source = sample_dir / "direct.zip"
    assert not direct_source.exists()
    assert moved_source.exists()
    assert (sample_dir / "damaged").is_dir()
    rows = _jsonl(sample_dir / "damage_manifest.jsonl")
    assert len(rows) == 2
    assert {row["material_sample_id"] for row in rows} == {"direct"}
    assert {row["source_archive_name"] for row in rows} == {"direct.zip"}


def _write_clean_zip(path: Path) -> None:
    with zipfile.ZipFile(path, "w") as archive:
        archive.writestr("alpha.txt", b"alpha payload")
        archive.writestr("bravo.bin", b"bravo payload" * 8)


def _write_clean_tar(path: Path) -> None:
    source = path.parent / "tar-src"
    source.mkdir()
    (source / "alpha.txt").write_bytes(b"alpha tar payload")
    (source / "bravo.bin").write_bytes(b"bravo tar payload" * 8)
    with tarfile.open(path, "w") as archive:
        archive.add(source / "alpha.txt", arcname="alpha.txt")
        archive.add(source / "bravo.bin", arcname="bravo.bin")


def _jsonl(path: Path) -> list[dict]:
    if not path.exists():
        return []
    return [json.loads(line) for line in path.read_text(encoding="utf-8").splitlines() if line.strip()]


def _run_material_build(material_root: Path, *, seed: str) -> None:
    subprocess.run(
        [
            sys.executable,
            "repair_training/build_repair_plan_corpus.py",
            "--material-root",
            str(material_root),
            "--per-sample",
            "2",
            "--seed",
            seed,
            "--no-pretty",
        ],
        cwd=Path.cwd(),
        text=True,
        capture_output=True,
        check=True,
    )
