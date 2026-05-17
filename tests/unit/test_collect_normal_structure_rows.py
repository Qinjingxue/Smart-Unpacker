import json

from repair_training.collect_normal_structure_rows import _collect_one, _job_for_path, _password_for_clean_zip


def test_normal_zip_collector_reads_zipcrypto_password_from_material_manifest(tmp_path):
    sample_dir = tmp_path / "material" / "zip" / "22"
    sample_dir.mkdir(parents=True)
    archive = sample_dir / "22__zip__encrypted_zipcrypto__deflate__l0.zip"
    archive.write_bytes(b"not a real zip")
    manifest = sample_dir / "damage_manifest.jsonl"
    manifest.write_text(
        json.dumps({
            "source_derivation": {
                "output_name": archive.name,
                "zip_password": "sunpack",
            }
        }) + "\n",
        encoding="utf-8",
    )

    job = _job_for_path(archive, index=0)

    assert _password_for_clean_zip(archive) == "sunpack"
    assert job.password == "sunpack"
    assert job.source_input["password"] == "sunpack"
    assert job.archive_state.to_archive_input_descriptor().password == "sunpack"
    assert job.knowledge["archive"]["password"] == "sunpack"


def test_normal_zip_collector_falls_back_to_generated_zipcrypto_name(tmp_path):
    archive = tmp_path / "22__zip__encrypted_zipcrypto__deflate__l0.zip"
    archive.write_bytes(b"not a real zip")

    job = _job_for_path(archive, index=0)

    assert job.password == "sunpack"
    assert job.knowledge["archive"]["password"] == "sunpack"


def test_normal_zip_collector_keeps_directory_clean_sample_when_runtime_fails(tmp_path, monkeypatch):
    archive = tmp_path / "22__zip__normal__deflate__l0.zip"
    archive.write_bytes(b"not a real zip")

    def fail_runtime(*_args, **_kwargs):
        raise RuntimeError("simulated runtime failure")

    monkeypatch.setattr("repair_training.collect_normal_structure_rows.observe_damage_runtime", fail_runtime)
    row, failure = _collect_one(0, archive, max_entries=8, workspace=tmp_path / "work", runtime_validation=True)

    assert failure is None
    assert row is not None
    assert row["runtime_observation"]["directory_semantics_kept"] is True
    assert row["runtime_observation"]["runtime_error"] == "RuntimeError"
