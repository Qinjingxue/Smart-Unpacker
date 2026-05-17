import json
import zipfile
from pathlib import Path

from repair_training.build_single_field_damage_rows import build_single_field_records
from repair_training.formats.zip.corruption_impl import build_corpus_corruption_case, single_field_profile_for_field
from repair_training.core.features import damage_location_labels_from_target
from repair_training.taxonomy import normalize_damage_record


def _write_zip(path: Path) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with zipfile.ZipFile(path, "w", compression=zipfile.ZIP_DEFLATED) as archive:
        archive.writestr("alpha.txt", b"alpha" * 32)
        archive.writestr("beta.txt", b"beta" * 32)


def _labels_for_field(tmp_path: Path, field: str) -> tuple[list[str], list[str]]:
    source = tmp_path / "source.zip"
    _write_zip(source)
    profile = single_field_profile_for_field(field)
    case = build_corpus_corruption_case(
        tmp_path / field.replace(".", "_"),
        source_path=source,
        fmt="zip",
        seed=123,
        variant_index=0,
        damage_profile=profile,
    )
    record = case.corpus_manifest_record(
        source_archive_id="source",
        source_path=str(source),
        damage_profile=profile,
        variant_index=0,
    )
    labels = damage_location_labels_from_target(normalize_damage_record(record).to_dict())
    return [mutation.zone for mutation in case.mutations], labels


def test_single_field_profiles_emit_exact_root_labels(tmp_path: Path):
    expectations = {
        "eocd.cd_offset": "zip.eocd.cd_offset",
        "eocd.cd_size": "zip.eocd.cd_size",
        "central_directory.local_header_offset": "zip.central_directory.local_header_offset",
        "central_directory.flags": "zip.central_directory.flags",
        "local_header.crc": "zip.local_header.crc",
        "tail.trailing_bytes": "archive.tail",
        "sfx_prefix.bytes": "zip.sfx.prefix",
    }
    for field, zone in expectations.items():
        zones, labels = _labels_for_field(tmp_path / field.replace(".", "_"), field)
        assert zones == [zone]
        assert f"field:{field}" in labels


def test_single_field_special_source_skips_when_unsupported(tmp_path: Path):
    material_root = tmp_path / "material"
    sample = material_root / "zip" / "sample"
    sample.mkdir(parents=True)
    source = sample / "plain.zip"
    _write_zip(source)

    records, report = build_single_field_records(
        material_root=material_root,
        workspace=tmp_path / "workspace",
        samples_per_field=1,
        seed=123,
        fields=["zip64.locator"],
    )

    assert records == []
    assert report["skipped"]["zip64.locator"]["reason"] in {"no_compatible_source", "insufficient_supported_sources"}


def test_single_field_records_mark_root_field(tmp_path: Path):
    material_root = tmp_path / "material"
    sample = material_root / "zip" / "sample"
    sample.mkdir(parents=True)
    source = sample / "plain.zip"
    _write_zip(source)

    records, report = build_single_field_records(
        material_root=material_root,
        workspace=tmp_path / "workspace",
        samples_per_field=1,
        seed=123,
        fields=["eocd.cd_offset"],
    )

    assert len(records) == 1
    assert records[0]["single_field_root"] == "eocd.cd_offset"
    assert report["generated_by_field"] == {"eocd.cd_offset": 1}
    assert json.dumps(records[0])
