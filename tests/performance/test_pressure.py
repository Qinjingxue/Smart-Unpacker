import time
import zipfile
from pathlib import Path

from packrelic.coordinator.scanner import ScanOrchestrator
from tests.helpers.detection_config import with_detection_pipeline
from tests.helpers.fs_builder import make_zip


def pressure_scan_config() -> dict:
    return with_detection_pipeline({
        "thresholds": {
            "archive_score_threshold": 5,
            "maybe_archive_threshold": 3,
        },
    }, precheck=[
        {"name": "size_minimum", "enabled": True, "min_inspection_size_bytes": 0},
        {
            "name": "blacklist",
            "enabled": True,
            "blocked_extensions": [".jar", ".docx", ".apk", ".xlsx"],
        },
    ], scoring=[
        {"name": "extension", "enabled": True, "extension_score_groups": [{"score": 5, "extensions": [".zip", ".7z", ".rar", ".gz", ".bz2", ".xz", ".001"]}]},
        {"name": "embedded_payload_identity", "enabled": True, "carrier_tail_score": 5},
    ], confirmation=[
        {"name": "seven_zip_probe", "enabled": True},
        {"name": "seven_zip_validation", "enabled": True},
    ])


def write_large_resource(path: Path, label: str, size: int = 128 * 1024):
    chunk = (f"PRESSURE::{label}::".encode("ascii") * 4096)[:8192]
    with path.open("wb") as handle:
        remaining = size
        while remaining > 0:
            piece = chunk[: min(len(chunk), remaining)]
            handle.write(piece)
            remaining -= len(piece)


def create_container(path: Path, kind: str):
    with zipfile.ZipFile(path, "w", compression=zipfile.ZIP_STORED) as archive:
        if kind == "jar":
            archive.writestr("META-INF/MANIFEST.MF", "Manifest-Version: 1.0\n")
            archive.writestr("com/example/App.class", b"\xca\xfe\xba\xbe")
        elif kind == "docx":
            archive.writestr("[Content_Types].xml", "<Types></Types>")
            archive.writestr("word/document.xml", "<w:document />")
        elif kind == "apk":
            archive.writestr("AndroidManifest.xml", b"\x03\x00\x08\x00")
            archive.writestr("classes.dex", b"dex\n035\x00")
        elif kind == "xlsx":
            archive.writestr("[Content_Types].xml", "<Types></Types>")
            archive.writestr("xl/workbook.xml", "<workbook />")
        else:
            raise ValueError(kind)


def build_pressure_corpus(root: Path):
    normal_exts = [".jpg", ".png", ".mp4", ".dll", ".pak", ".bin", ".dat", ".log"]
    for index in range(32):
        write_large_resource(root / f"bulk_asset_{index:03d}{normal_exts[index % len(normal_exts)]}", f"normal-{index}")

    expected = []
    for index in range(3):
        archive = root / f"real_archive_{index:02d}.zip"
        archive.write_bytes(make_zip({f"marker_{index}.txt": f"real::{index}"}))
        expected.append(archive.name)

    for index in range(2):
        disguised = root / f"masked_archive_{index:02d}.jpg"
        disguised.write_bytes(b"\xff\xd8synthetic-image\xff\xd9" + b"7z\xbc\xaf\x27\x1c")
        expected.append(disguised.name)

    for index, kind in enumerate(["jar", "docx", "apk", "xlsx"]):
        create_container(root / f"container_{index:02d}.{kind}", kind)

    write_large_resource(root / "ordinary_tool.exe", "ordinary-tool", size=32 * 1024)
    write_large_resource(root / "ordinary_tool.part1.rar", "ordinary-part", size=32 * 1024)
    return sorted(expected)


def test_pressure_scan_finds_expected_archives_in_mixed_corpus(tmp_path):
    expected = build_pressure_corpus(tmp_path)

    start = time.perf_counter()
    results = ScanOrchestrator(pressure_scan_config()).scan(str(tmp_path))
    elapsed = time.perf_counter() - start
    actual = sorted(Path(result.main_path).name for result in results)

    assert actual == expected
    assert elapsed < 2.0
