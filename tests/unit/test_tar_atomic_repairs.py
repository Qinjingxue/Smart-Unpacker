import io
import tarfile

from sunpack.repair.pipeline.modules.tar.atomic import (
    TarGnuLongNameQuarantine,
    TarPaxHeaderQuarantine,
    TarSparseEntryQuarantine,
    _tar_entries,
)


def _pax_archive() -> bytes:
    output = io.BytesIO()
    path = "nested/" + "p" * 180 + "/payload.bin"
    with tarfile.open(fileobj=output, mode="w", format=tarfile.PAX_FORMAT) as archive:
        info = tarfile.TarInfo(path)
        info.size = 1
        archive.addfile(info, io.BytesIO(b"x"))
    return output.getvalue()


def test_lossy_tar_metadata_quarantines_are_not_safe():
    assert TarPaxHeaderQuarantine.spec.safe is False
    assert TarGnuLongNameQuarantine.spec.safe is False
    assert TarSparseEntryQuarantine.spec.safe is False


def test_invalid_per_file_pax_quarantine_removes_dependent_member_atomically():
    data = bytearray(_pax_archive())
    assert data[156] == ord("x")
    data[512] = ord("9") if data[512] != ord("9") else ord("8")
    entries = list(_tar_entries(bytes(data), 20))
    assert len(entries) >= 2

    mutations = list(TarPaxHeaderQuarantine().mutations(bytes(data), {"max_entries": 20}))

    assert len(mutations) == 1
    assert mutations[0].partial is True
    assert mutations[0].details["dependent_member_end"] == entries[1].end
    assert mutations[0].data == bytes(data[entries[1].end:])
