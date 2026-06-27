import struct

from sunpack.analysis.view import _probe_zip_view


class _BytesView:
    def __init__(self, data: bytes):
        self.data = data

    def read_at(self, offset: int, size: int) -> bytes:
        return self.data[offset:offset + size]


def test_zip_probe_preserves_multidisk_eocd_metadata():
    eocd = struct.pack(
        "<4sHHHHIIH",
        b"PK\x05\x06",
        2,
        2,
        1,
        3,
        128,
        4096,
        0,
    )

    result = _probe_zip_view(_BytesView(eocd), 0, 32)

    assert result["error"] == "zip_multi_disk"
    assert result["is_multi_disk"] is True
    assert result["disk_number"] == 2
    assert result["central_directory_disk"] == 2
    assert result["disk_entries"] == 1
    assert result["declared_total_disks"] == 3
    assert result["evidence"] == ["zip:eocd_multi_disk"]
