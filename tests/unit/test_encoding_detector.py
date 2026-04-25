import builtins
import struct
import zlib
from types import SimpleNamespace

from smart_unpacker.extraction.internal.metadata import ArchiveMetadataScanResult, ArchiveMetadataScanner
from smart_unpacker.extraction.scheduler import ExtractionScheduler
from smart_unpacker.contracts.detection import FactBag
from smart_unpacker.contracts.tasks import ArchiveTask


def write_stored_zip_with_raw_names(zip_path, raw_names: list[bytes], utf8_flags: list[bool] | None = None):
    utf8_flags = utf8_flags or [False] * len(raw_names)
    local_records = []
    central_records = []
    offset = 0
    payload = b"payload"

    for index, raw_name in enumerate(raw_names):
        flag = 0x800 if utf8_flags[index] else 0
        crc = zlib.crc32(payload) & 0xFFFFFFFF
        local = (
            struct.pack(
                "<4s5H3I2H",
                b"PK\x03\x04",
                20,
                flag,
                0,
                0,
                0,
                crc,
                len(payload),
                len(payload),
                len(raw_name),
                0,
            )
            + raw_name
            + payload
        )
        local_records.append(local)
        central_records.append(
            struct.pack(
                "<4s6H3I5H2I",
                b"PK\x01\x02",
                20,
                20,
                flag,
                0,
                0,
                0,
                crc,
                len(payload),
                len(payload),
                len(raw_name),
                0,
                0,
                0,
                0,
                0,
                offset,
            )
            + raw_name
        )
        offset += len(local)

    central_offset = offset
    central = b"".join(central_records)
    eocd = struct.pack(
        "<4s4H2IH",
        b"PK\x05\x06",
        0,
        0,
        len(raw_names),
        len(raw_names),
        len(central),
        central_offset,
        0,
    )
    zip_path.write_bytes(b"".join(local_records) + central + eocd)


def scan_zip_metadata(root, raw_names: list[bytes], utf8_flags: list[bool] | None = None):
    archive = root / "encoded.zip"
    write_stored_zip_with_raw_names(archive, raw_names, utf8_flags=utf8_flags)
    return ArchiveMetadataScanner().scan(str(archive))


def test_metadata_scanner_detects_gbk_zip_filenames(tmp_path):
    scan = scan_zip_metadata(
        tmp_path,
        [
            "中文/说明.txt".encode("cp936"),
            "资料/第一章.txt".encode("cp936"),
        ],
    )

    assert scan.archive_type == "zip"
    assert scan.selected_codepage == "936"
    assert scan.confidence >= 0.3
    assert scan.sample_count == 2


def test_metadata_scanner_detects_cp932_zip_filenames(tmp_path):
    scan = scan_zip_metadata(
        tmp_path,
        [
            "かな/テスト.txt".encode("cp932"),
            "日本語/メモ.txt".encode("cp932"),
        ],
    )

    assert scan.selected_codepage == "932"
    assert scan.sample_count == 2


def test_metadata_scanner_keeps_utf8_flagged_zip_default(tmp_path):
    scan = scan_zip_metadata(
        tmp_path,
        ["中文/かな.txt".encode("utf-8")],
        utf8_flags=[True],
    )

    assert scan.selected_codepage is None
    assert any("UTF-8 标记" in reason for reason in scan.reasons)


def test_metadata_scanner_keeps_ascii_zip_default(tmp_path):
    scan = scan_zip_metadata(tmp_path, [b"docs/readme.txt", b"english/name.txt"])

    assert scan.selected_codepage is None
    assert any("ASCII" in reason for reason in scan.reasons)


def test_metadata_scanner_keeps_low_confidence_zip_default(tmp_path):
    scan = scan_zip_metadata(tmp_path, [bytes([0x81, 0x40]) + b".txt"])

    assert scan.selected_codepage is None


def test_metadata_scanner_does_not_read_zip_payload(tmp_path, monkeypatch):
    archive = tmp_path / "large_payload.zip"
    raw_name = "中文说明资料第一章.txt".encode("cp936")
    payload = b"x" * (3 * 1024 * 1024)
    crc = zlib.crc32(payload) & 0xFFFFFFFF
    local = (
        struct.pack(
            "<4s5H3I2H",
            b"PK\x03\x04",
            20,
            0,
            0,
            0,
            0,
            crc,
            len(payload),
            len(payload),
            len(raw_name),
            0,
        )
        + raw_name
        + payload
    )
    central_offset = len(local)
    central = (
        struct.pack(
            "<4s6H3I5H2I",
            b"PK\x01\x02",
            20,
            20,
            0,
            0,
            0,
            0,
            crc,
            len(payload),
            len(payload),
            len(raw_name),
            0,
            0,
            0,
            0,
            0,
            0,
        )
        + raw_name
    )
    eocd = struct.pack("<4s4H2IH", b"PK\x05\x06", 0, 0, 1, 1, len(central), central_offset, 0)
    archive.write_bytes(local + central + eocd)
    read_sizes = []
    real_open = builtins.open

    class TrackingFile:
        def __init__(self, handle):
            self.handle = handle

        def __enter__(self):
            self.handle.__enter__()
            return self

        def __exit__(self, exc_type, exc, tb):
            return self.handle.__exit__(exc_type, exc, tb)

        def read(self, size=-1):
            read_sizes.append(size)
            return self.handle.read(size)

        def seek(self, *args):
            return self.handle.seek(*args)

    def tracking_open(*args, **kwargs):
        return TrackingFile(real_open(*args, **kwargs))

    monkeypatch.setenv("SMART_UNPACKER_DISABLE_NATIVE", "1")
    monkeypatch.setattr(builtins, "open", tracking_open)

    scan = ArchiveMetadataScanner().scan(str(archive))

    assert scan.selected_codepage == "936"
    assert read_sizes
    assert max(read_sizes) < len(payload)


def test_metadata_scanner_uses_native_zip_name_samples(tmp_path, monkeypatch):
    archive = tmp_path / "encoded.zip"
    archive.write_bytes(b"not a real zip when native is faked")
    calls = []

    def fake_native(path, max_samples, max_filename_bytes):
        calls.append((path, max_samples, max_filename_bytes))
        return {
            "status": "ok",
            "raw_names": ["中文/说明.txt".encode("cp936")],
            "utf8_marked": 0,
            "truncated": False,
        }

    monkeypatch.delenv("SMART_UNPACKER_DISABLE_NATIVE", raising=False)
    monkeypatch.setattr("smart_unpacker.extraction.internal.metadata._NATIVE_SCAN_ZIP_NAMES", fake_native)

    scan = ArchiveMetadataScanner().scan(str(archive))

    assert scan.selected_codepage == "936"
    assert scan.sample_count == 1
    assert calls == [(str(archive), ArchiveMetadataScanner.MAX_ZIP_SAMPLES, ArchiveMetadataScanner.MAX_FILENAME_BYTES)]


def test_metadata_scanner_native_zip_warning_status(tmp_path, monkeypatch):
    archive = tmp_path / "encoded.zip"
    archive.write_bytes(b"short")

    def fake_native(*_args):
        return {
            "status": "eocd_not_found",
            "raw_names": [],
            "utf8_marked": 0,
            "truncated": False,
        }

    monkeypatch.delenv("SMART_UNPACKER_DISABLE_NATIVE", raising=False)
    monkeypatch.setattr("smart_unpacker.extraction.internal.metadata._NATIVE_SCAN_ZIP_NAMES", fake_native)

    scan = ArchiveMetadataScanner().scan(str(archive))

    assert any("未找到 ZIP EOCD" in warning for warning in scan.warnings)


def test_metadata_scanner_native_zip_failure_falls_back_to_python(tmp_path, monkeypatch):
    archive = tmp_path / "encoded.zip"
    write_stored_zip_with_raw_names(archive, ["中文/说明.txt".encode("cp936")])

    def failing_native(*_args):
        raise RuntimeError("native unavailable")

    monkeypatch.delenv("SMART_UNPACKER_DISABLE_NATIVE", raising=False)
    monkeypatch.setattr("smart_unpacker.extraction.internal.metadata._NATIVE_SCAN_ZIP_NAMES", failing_native)

    scan = ArchiveMetadataScanner().scan(str(archive))

    assert scan.selected_codepage == "936"
    assert scan.sample_count == 1


def test_extract_command_uses_metadata_codepage(tmp_path, monkeypatch):
    archive = tmp_path / "demo.zip"
    archive.write_bytes(b"demo")
    out_dir = tmp_path / "out"
    bag = FactBag()
    bag.set("file.path", str(archive))
    extractor = ExtractionScheduler(cli_passwords=[], builtin_passwords=[])

    scan = ArchiveMetadataScanResult(str(archive), "zip")
    scan.selected_codepage = "936"
    extractor.metadata_scanner.scan = lambda *_args, **_kwargs: scan

    calls = []

    def fake_run(cmd, **_kwargs):
        calls.append(cmd)
        return SimpleNamespace(returncode=0, stdout="", stderr="")

    monkeypatch.setattr("smart_unpacker.extraction.scheduler.subprocess.run", fake_run)

    result = extractor.extract(ArchiveTask(fact_bag=bag, score=5), str(out_dir))

    assert result.success is True
    assert any("-mcp=936" in arg for arg in calls[-1])


def test_extract_command_omits_low_confidence_metadata_codepage(tmp_path, monkeypatch):
    archive = tmp_path / "demo.zip"
    archive.write_bytes(b"demo")
    out_dir = tmp_path / "out"
    bag = FactBag()
    bag.set("file.path", str(archive))
    extractor = ExtractionScheduler(cli_passwords=[], builtin_passwords=[])
    extractor.metadata_scanner.scan = lambda *_args, **_kwargs: ArchiveMetadataScanResult(str(archive), "zip")

    calls = []

    def fake_run(cmd, **_kwargs):
        calls.append(cmd)
        return SimpleNamespace(returncode=0, stdout="", stderr="")

    monkeypatch.setattr("smart_unpacker.extraction.scheduler.subprocess.run", fake_run)

    result = extractor.extract(ArchiveTask(fact_bag=bag, score=5), str(out_dir))

    assert result.success is True
    assert not any(str(arg).startswith("-mcp=") for arg in calls[-1])
