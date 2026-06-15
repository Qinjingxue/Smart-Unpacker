from pathlib import Path

import pytest

from sunpack.support.sevenzip_bridge import NativePasswordTester
from tests.helpers.fs_builder import make_zip


def test_native_probe_finds_embedded_zip_carrier(tmp_path: Path):
    tester = NativePasswordTester()
    if not tester.available():
        pytest.skip("native 7z wrapper is not available")

    prefix = b"\xff\xd8synthetic image\xff\xd9"
    carrier = tmp_path / "cover.jpg"
    carrier.write_bytes(prefix + make_zip({"payload.txt": "hello"}))

    probe = tester.probe_archive(str(carrier))

    assert probe.is_archive is True
    assert probe.archive_type == "zip"
    assert probe.offset == len(prefix)
