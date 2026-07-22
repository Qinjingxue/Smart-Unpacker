from __future__ import annotations

import shutil
import unicodedata
import zipfile
from dataclasses import dataclass
from pathlib import Path
from typing import Callable

import pytest

from sunpack.coordinator.task_scan import direct_file_task
from sunpack.extraction.scheduler import ExtractionScheduler
from tests.helpers.real_archives import ArchiveCase, ArchiveFixtureFactory, corrupt_file
from tests.integration.test_extension_independent_detection import _detected
from tests.integration.test_real_archive_edge_cases import assert_success, marker_was_extracted, run_pipeline


FACTORY = ArchiveFixtureFactory()
PASSWORD = "sunpack-acceptance-123"


@dataclass(frozen=True)
class SplitNamingCase:
    case_id: str
    archive_format: str
    name_for_part: Callable[[str, int, int], str]


SPLIT_NAMING_CASES = [
    SplitNamingCase("7z-numbered", "7z", lambda _base, index, _count: f"payload.7z.{index:03d}"),
    SplitNamingCase(
        "7z-numbered-cjk",
        "7z",
        lambda _base, index, _count: f"中文 分卷【素材】.7z.{index:03d}",
    ),
    SplitNamingCase(
        "7z-numbered-long-name",
        "7z",
        lambda _base, index, _count: f"a very long archive name with spaces and brackets [release].7z.{index:03d}",
    ),
    SplitNamingCase("7z-plain-numbered", "7z", lambda _base, index, _count: f"payload.{index:03d}"),
    SplitNamingCase(
        "7z-plain-numbered-cjk",
        "7z",
        lambda _base, index, _count: f"かな 素材.{index:03d}",
    ),
    SplitNamingCase("zip-numbered", "zip", lambda _base, index, _count: f"payload.zip.{index:03d}"),
    SplitNamingCase(
        "zip-numbered-cjk",
        "zip",
        lambda _base, index, _count: f"中文 ZIP 分卷.zip.{index:03d}",
    ),
    SplitNamingCase("zip-zero-numbered", "zip", lambda _base, index, _count: f"payload.zip.{index - 1:04d}"),
]


@pytest.mark.parametrize("naming", SPLIT_NAMING_CASES, ids=lambda item: item.case_id)
def test_acceptance_real_split_volume_naming(tmp_path: Path, naming: SplitNamingCase):
    case = FACTORY.create(
        tmp_path,
        naming.case_id,
        naming.archive_format,
        split=True,
        payload_size=420 * 1024,
    )
    _rename_split_parts(case, naming)

    summary = run_pipeline(case.archive_dir)

    assert summary.success_count == 1
    assert summary.failed_tasks == []
    assert marker_was_extracted(case.archive_dir, case.marker_name, case.marker_text)


@pytest.mark.parametrize(
    ("case_id", "archive_format", "password", "split"),
    [
        ("zip-zipcrypto-ascii", "zip", PASSWORD, False),
        ("zip-zipcrypto-special", "zip", "space & symbols !@#", False),
        ("zip-zipcrypto-split", "zip", PASSWORD, True),
        ("7z-header-encrypted-ascii", "7z", PASSWORD, False),
        ("7z-header-encrypted-unicode", "7z", "密码-かな-🔐", False),
        ("7z-header-encrypted-split", "7z", PASSWORD, True),
    ],
)
def test_acceptance_real_encrypted_archives(
    tmp_path: Path,
    case_id: str,
    archive_format: str,
    password: str,
    split: bool,
):
    case = FACTORY.create(
        tmp_path,
        case_id,
        archive_format,
        password=password,
        split=split,
        payload_size=220 * 1024,
    )

    without_password = run_pipeline(case.archive_dir)
    assert without_password.success_count == 0
    assert without_password.failed_tasks

    assert_success(case, passwords=["definitely-wrong", password])


@pytest.mark.parametrize(
    ("case_id", "members", "expect_success"),
    [
        ("multilingual", {"日本語/说明/marker.txt": "multilingual"}, True),
        (
            "unicode-normalization",
            {
                f"{unicodedata.normalize('NFD', 'café')}/😀/marker.txt": "unicode-normalization",
            },
            True,
        ),
        ("long-path", {("deep-directory/" * 22) + "marker.txt": "long-path"}, True),
        ("case-collision", {"Case/marker.txt": "upper", "case/MARKER.txt": "lower"}, True),
        ("path-traversal", {"../escape.txt": "must-not-escape", "safe/marker.txt": "safe"}, False),
    ],
)
def test_acceptance_real_windows_name_and_path_boundaries(
    tmp_path: Path,
    case_id: str,
    members: dict[str, str],
    expect_success: bool,
):
    archive = tmp_path / f"{case_id}.zip"
    _write_zip_members(archive, members)
    output_dir = tmp_path / f"{case_id}-out"

    result = _extract_direct(archive, output_dir, detected_ext="zip")

    assert (tmp_path / "escape.txt").exists() is False
    if expect_success:
        assert result.success is True
        if case_id == "case-collision":
            collision = output_dir / "Case" / "marker.txt"
            assert collision.read_text(encoding="utf-8") in {"upper", "lower"}
            return
        for member_name, expected in members.items():
            extracted = output_dir / Path(member_name)
            assert extracted.read_text(encoding="utf-8") == expected
    else:
        worker = result.diagnostics.get("result", {})
        assert result.success is False or result.partial_outputs or worker.get("item_failures")


@pytest.mark.parametrize(
    ("case_id", "damage", "expected_success"),
    [
        ("zip-download-truncated", "truncate", False),
        ("zip-payload-bitrot", "byte_flip", False),
        ("zip-appended-download-junk", "trailing_junk", True),
        ("7z-missing-middle-volume", "missing_middle", False),
    ],
)
def test_acceptance_real_damage_patterns(
    tmp_path: Path,
    case_id: str,
    damage: str,
    expected_success: bool,
):
    if damage == "missing_middle":
        case = FACTORY.create(tmp_path, case_id, "7z", split=True, payload_size=420 * 1024)
        parts = sorted(path for path in case.archive_dir.iterdir() if path.is_file())
        assert len(parts) >= 3
        parts[1].unlink()
        remaining = [path for path in parts if path.exists()]
        result = _extract_direct(
            case.entry_path,
            tmp_path / f"{case_id}-out",
            detected_ext="7z",
            parts=remaining,
        )
        worker = result.diagnostics.get("result", {})
        assert result.success is False
        assert worker.get("missing_volume") is True or worker.get("category") == "invalid_request"
        return

    case = FACTORY.create(tmp_path, case_id, "zip", payload_size=260 * 1024)
    corrupt_file(case.entry_path, mode=damage)

    result = _extract_direct(case.entry_path, tmp_path / f"{case_id}-out", detected_ext="zip")

    assert result.success is expected_success


@pytest.mark.parametrize(
    ("case_id", "password"),
    [
        ("7z-sfx-plain", None),
        ("7z-sfx-encrypted", PASSWORD),
    ],
)
def test_acceptance_real_sfx_archives(tmp_path: Path, case_id: str, password: str | None):
    case = FACTORY.create(tmp_path, case_id, "7z", password=password, sfx=True)

    assert_success(case, passwords=[password] if password else None)


@pytest.mark.parametrize("tool_name", ["7z.exe", "sunpack_sevenzip_worker.exe"])
def test_acceptance_real_executables_are_not_archive_candidates(tmp_path: Path, tool_name: str):
    source = Path(__file__).resolve().parents[2] / "tools" / tool_name
    assert source.is_file(), f"Acceptance runtime tool is missing: {source}"
    executable = tmp_path / tool_name
    shutil.copyfile(source, executable)

    assert _detected(executable) == []


def _rename_split_parts(case: ArchiveCase, naming: SplitNamingCase) -> None:
    original = sorted(path for path in case.archive_dir.iterdir() if path.is_file())
    assert len(original) >= 3
    temporary = []
    for index, path in enumerate(original, start=1):
        staged = path.with_name(f".__sunpack_stage_{index:04d}")
        path.rename(staged)
        temporary.append(staged)
    renamed = []
    for index, path in enumerate(temporary, start=1):
        target = case.archive_dir / naming.name_for_part("payload", index, len(temporary))
        path.rename(target)
        renamed.append(target)
    case.entry_path = renamed[0]


def _write_zip_members(path: Path, members: dict[str, str]) -> None:
    with zipfile.ZipFile(path, "w", compression=zipfile.ZIP_STORED, allowZip64=True) as archive:
        for name, payload in members.items():
            archive.writestr(name, payload.encode("utf-8"))


def _extract_direct(
    archive: Path,
    output_dir: Path,
    *,
    detected_ext: str,
    parts: list[Path] | None = None,
):
    task = direct_file_task(str(archive), all_parts=[str(path) for path in (parts or [archive])])
    task.detected_ext = detected_ext
    task.fact_bag.set("file.detected_ext", detected_ext)
    scheduler = ExtractionScheduler(max_retries=1)
    try:
        return scheduler.extract(task.ensure_archive_state(), str(output_dir))
    finally:
        scheduler.close()
