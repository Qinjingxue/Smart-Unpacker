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
    assert all(row["damage_layer"] for row in manifest_rows)
    assert all(row["damage_layer_weight"] > 0 for row in manifest_rows)
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


def test_derive_archives_generates_material_from_source_folders(tmp_path):
    source_root = tmp_path / "source_material"
    material_root = tmp_path / "material"
    sample = source_root / "sample_plain"
    sample.mkdir(parents=True)
    (sample / "alpha.txt").write_text("alpha payload", encoding="utf-8")
    nested = sample / "nested"
    nested.mkdir()
    (nested / "bravo.bin").write_bytes(b"bravo payload" * 8)
    config = tmp_path / "archive_derivation_config.json"
    config.write_text(
        json.dumps(
            {
                "parallel": {"workers": 2, "task_timeout_seconds": 30},
                "formats": {
                    "zip": {"enabled": False},
                    "7z": {"enabled": False},
                    "rar": {"enabled": False},
                    "zstd": {"enabled": False},
                    "tar": {"enabled": True},
                    "gzip": {"enabled": True, "levels": [1]},
                    "bzip2": {"enabled": True, "levels": [1]},
                    "xz": {"enabled": True, "levels": [0]},
                    "tar_gz": {"enabled": False},
                    "tar_bz2": {"enabled": False},
                    "tar_xz": {"enabled": False},
                    "tar_zst": {"enabled": False},
                },
            }
        ),
        encoding="utf-8",
    )

    derive = subprocess.run(
        [
            sys.executable,
            "repair_training/derive_archives.py",
            "--source-root",
            str(source_root),
            "--material-root",
            str(material_root),
            "--config",
            str(config),
            "--no-pretty",
        ],
        cwd=Path.cwd(),
        text=True,
        capture_output=True,
        check=True,
    )
    derive_summary = json.loads(derive.stdout.strip())
    assert derive_summary["generated"] == 4
    assert derive_summary["failed"] == 0
    assert not (material_root / "zip" / "sample_plain").exists()
    derived_rows = _jsonl(sample / "derived_manifest.jsonl")
    assert len(derived_rows) == 4
    assert {row["material_format"] for row in derived_rows} == {"tar", "gzip", "bzip2", "xz"}
    assert all(row["sha256"] for row in derived_rows if row["status"] == "generated")
    assert all(Path(str(row["output_path"]) + ".derived.json").is_file() for row in derived_rows)

    subprocess.run(
        [
            sys.executable,
            "repair_training/build_repair_plan_corpus.py",
            "--material-root",
            str(material_root),
            "--formats",
            "tar",
            "--per-sample",
            "1",
            "--seed",
            "404",
            "--no-pretty",
        ],
        cwd=Path.cwd(),
        text=True,
        capture_output=True,
        check=True,
    )
    damage_rows = _jsonl(material_root / "tar" / "sample_plain" / "damage_manifest.jsonl")
    assert len(damage_rows) == 1
    assert damage_rows[0]["source_derivation"]["source_material_dir"] == str(sample)
    assert damage_rows[0]["source_derivation"]["material_format"] == "tar"

    success_output = tmp_path / "derived_success.jsonl"
    failure_output = tmp_path / "derived_failure.jsonl"
    subprocess.run(
        [
            sys.executable,
            "repair_training/collect_repair_plan_data.py",
            "--material-root",
            str(material_root),
            "--formats",
            "tar",
            "--success-output",
            str(success_output),
            "--failure-output",
            str(failure_output),
            "--max-rounds",
            "1",
            "--max-candidates-per-round",
            "2",
            "--case-timeout-seconds",
            "20",
            "--no-pretty",
        ],
        cwd=Path.cwd(),
        text=True,
        capture_output=True,
        check=True,
    )
    collected_rows = _jsonl(success_output) + _jsonl(failure_output)
    assert collected_rows
    assert all(row["source_derivation"]["source_material_dir"] == str(sample) for row in collected_rows)
    assert all(row["stable_features"]["state"]["source_derivation"]["material_format"] == "tar" for row in collected_rows)


def test_derive_archives_random_mode_limits_and_seed_controls_selection(tmp_path):
    source_root = tmp_path / "source_material"
    material_root = tmp_path / "material"
    sample = source_root / "sample_random"
    sample.mkdir(parents=True)
    (sample / "alpha.txt").write_text("alpha payload", encoding="utf-8")
    config = tmp_path / "archive_derivation_config.json"
    config.write_text(
        json.dumps(
            {
                "derivation": {"random_mode": {"enabled": True, "archives_per_sample": 2, "seed": "1234"}},
                "formats": {
                    "zip": {"enabled": False},
                    "7z": {"enabled": False},
                    "rar": {"enabled": False},
                    "zstd": {"enabled": False},
                    "tar": {"enabled": True},
                    "gzip": {"enabled": True, "levels": [1, 6]},
                    "bzip2": {"enabled": True, "levels": [1]},
                    "xz": {"enabled": True, "levels": [0]},
                    "tar_gz": {"enabled": False},
                    "tar_bz2": {"enabled": False},
                    "tar_xz": {"enabled": False},
                    "tar_zst": {"enabled": False},
                },
            }
        ),
        encoding="utf-8",
    )

    def run(extra: list[str]) -> tuple[dict, list[dict]]:
        completed = subprocess.run(
            [
                sys.executable,
                "repair_training/derive_archives.py",
                "--source-root",
                str(source_root),
                "--material-root",
                str(material_root),
                "--config",
                str(config),
                "--no-pretty",
                *extra,
            ],
            cwd=Path.cwd(),
            text=True,
            capture_output=True,
            check=True,
        )
        return json.loads(completed.stdout.strip()), _jsonl(sample / "derived_manifest.jsonl")

    summary, rows = run([])
    assert summary["available_tasks"] == 5
    assert summary["generated"] == 2
    first_selection = [row["output_name"] for row in rows]

    _, rows = run([])
    assert [row["output_name"] for row in rows] == first_selection

    summary, rows = run(["--no-random-mode"])
    assert summary["generated"] == 5
    assert len(rows) == 5


def test_derive_archives_organizes_direct_source_material_files(tmp_path):
    source_root = tmp_path / "source_material"
    material_root = tmp_path / "material"
    source_root.mkdir()
    direct = source_root / "loose.txt"
    direct.write_text("loose source material", encoding="utf-8")
    config = tmp_path / "archive_derivation_config.json"
    config.write_text(
        json.dumps(
            {
                "formats": {
                    "zip": {"enabled": False},
                    "7z": {"enabled": False},
                    "rar": {"enabled": False},
                    "zstd": {"enabled": False},
                    "tar": {"enabled": True},
                    "gzip": {"enabled": False},
                    "bzip2": {"enabled": False},
                    "xz": {"enabled": False},
                    "tar_gz": {"enabled": False},
                    "tar_bz2": {"enabled": False},
                    "tar_xz": {"enabled": False},
                    "tar_zst": {"enabled": False},
                },
            }
        ),
        encoding="utf-8",
    )

    derive = subprocess.run(
        [
            sys.executable,
            "repair_training/derive_archives.py",
            "--source-root",
            str(source_root),
            "--material-root",
            str(material_root),
            "--config",
            str(config),
            "--no-pretty",
        ],
        cwd=Path.cwd(),
        text=True,
        capture_output=True,
        check=True,
    )

    summary = json.loads(derive.stdout.strip())
    assert summary["organized_root_files"] == 1
    assert not direct.exists()
    assert (source_root / "loose" / "loose.txt").is_file()
    rows = _jsonl(source_root / "loose" / "derived_manifest.jsonl")
    assert len(rows) == 1
    assert rows[0]["material_format"] == "tar"
    assert (material_root / "tar" / "loose" / rows[0]["output_name"]).is_file()


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
