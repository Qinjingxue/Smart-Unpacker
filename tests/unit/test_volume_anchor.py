from __future__ import annotations

import bz2
import zipfile

from sunpack.analysis.volume_anchor import probe_volume_anchor_paths


def test_large_ordinary_candidate_uses_bounded_head_and_tail_reads(tmp_path):
    candidate = tmp_path / "opaque.large.part"
    with candidate.open("wb") as stream:
        stream.truncate(32 * 1024 * 1024)

    evidence = probe_volume_anchor_paths([str(candidate)]).get(str(candidate))

    assert evidence is not None
    assert evidence.error == ""
    assert evidence.format == ""
    assert evidence.bytes_read <= 512 + 65_557


def test_leading_stream_structure_is_standalone_not_a_foreign_volume(tmp_path):
    candidate = tmp_path / "shared.zip.002.disguise.bin"
    candidate.write_bytes(bz2.compress(b"payload" * 1024))

    evidence = probe_volume_anchor_paths([str(candidate)]).get(str(candidate))

    assert evidence is not None
    assert evidence.structurally_confirmed
    assert evidence.format == "bzip2"
    assert evidence.standalone is True
    assert evidence.multivolume is False


def test_non_sfx_embedded_archive_signature_is_not_promoted(tmp_path):
    candidate = tmp_path / "raw.middle.part"
    candidate.write_bytes(b"not-an-sfx" + b"7z\xbc\xaf\x27\x1c" + b"\0" * 1024)

    evidence = probe_volume_anchor_paths([str(candidate)]).get(str(candidate))

    assert evidence is not None
    assert evidence.format == ""
    assert evidence.confidence == "none"


def test_small_zip_tail_is_read_past_the_initial_prefix(tmp_path):
    candidate = tmp_path / "small.zip"
    with zipfile.ZipFile(candidate, "w", compression=zipfile.ZIP_STORED) as archive:
        archive.writestr("payload.bin", b"x" * 2048)

    evidence = probe_volume_anchor_paths([str(candidate)]).get(str(candidate))

    assert evidence is not None
    assert evidence.structurally_confirmed
    assert evidence.format == "zip"
    assert evidence.standalone is True
    assert {"first", "terminal", "standalone"} <= set(evidence.anchor_roles)
