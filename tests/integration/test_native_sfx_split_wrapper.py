import pytest

from smart_unpacker.support.sevenzip_native import get_native_password_tester
from tests.helpers.real_archives import ArchiveFixtureFactory
from tests.helpers.tool_config import get_optional_rar, require_7z


PASSWORD = "sfx-split-secret"
WRONG_PASSWORD = "wrong-sfx-password"


def _parts(case):
    return sorted(str(path) for path in case.archive_dir.iterdir() if path.is_file())


def _remove_last_data_part(case):
    parts = sorted(
        path for path in case.archive_dir.iterdir()
        if path.is_file() and not path.name.lower().endswith(".exe")
    )
    if not parts:
        pytest.skip("generated SFX archive has no separate data volumes")
    parts[-1].unlink()


@pytest.mark.parametrize("password", [None, PASSWORD])
def test_native_wrapper_handles_7z_sfx_split_health_password_and_resources(tmp_path, password):
    require_7z()
    case = ArchiveFixtureFactory().create(
        tmp_path,
        f"native_7z_sfx_split_pwd_{bool(password)}",
        "7z",
        split=True,
        sfx=True,
        password=password,
    )
    tester = get_native_password_tester()
    parts = _parts(case)

    health = tester.check_archive_health(str(case.entry_path), part_paths=parts)
    if password:
        assert health.is_encrypted
        assert tester.test_archive(str(case.entry_path), password=password, part_paths=parts).ok
        attempt = tester.try_passwords(str(case.entry_path), [WRONG_PASSWORD, password], part_paths=parts)
        assert attempt.ok
        assert attempt.matched_index == 1
    else:
        assert health.ok
        assert tester.test_archive(str(case.entry_path), part_paths=parts).ok

    analysis = tester.analyze_archive_resources(str(case.entry_path), password or "", part_paths=parts)
    assert analysis.ok
    assert analysis.file_count >= 1


def test_native_wrapper_detects_missing_7z_sfx_split_tail(tmp_path):
    require_7z()
    case = ArchiveFixtureFactory().create(tmp_path, "native_7z_sfx_missing_tail", "7z", split=True, sfx=True)
    _remove_last_data_part(case)

    health = get_native_password_tester().check_archive_health(str(case.entry_path), part_paths=_parts(case))

    assert health.is_missing_volume


@pytest.mark.parametrize("password", [None, PASSWORD])
def test_native_wrapper_handles_zip_sfx_split_health_password_and_resources(tmp_path, password):
    require_7z()
    case = ArchiveFixtureFactory().create(
        tmp_path,
        f"native_zip_sfx_split_pwd_{bool(password)}",
        "zip",
        split=True,
        sfx=True,
        password=password,
    )
    tester = get_native_password_tester()
    parts = _parts(case)

    health = tester.check_archive_health(str(case.entry_path), part_paths=parts)
    if password:
        assert health.is_encrypted
        assert tester.test_archive(str(case.entry_path), password=password, part_paths=parts).ok
        attempt = tester.try_passwords(str(case.entry_path), [WRONG_PASSWORD, password], part_paths=parts)
        assert attempt.ok
        assert attempt.matched_index == 1
    else:
        assert health.ok
        assert tester.test_archive(str(case.entry_path), part_paths=parts).ok

    analysis = tester.analyze_archive_resources(str(case.entry_path), password or "", part_paths=parts)
    assert analysis.ok
    assert analysis.file_count >= 1


def test_native_wrapper_detects_missing_zip_sfx_split_tail(tmp_path):
    require_7z()
    case = ArchiveFixtureFactory().create(tmp_path, "native_zip_sfx_missing_tail", "zip", split=True, sfx=True)
    _remove_last_data_part(case)

    health = get_native_password_tester().check_archive_health(str(case.entry_path), part_paths=_parts(case))

    assert health.is_missing_volume


def test_native_wrapper_detects_damaged_zip_sfx_split_tail(tmp_path):
    require_7z()
    case = ArchiveFixtureFactory().create(
        tmp_path,
        "native_zip_sfx_damaged_tail",
        "zip",
        split=True,
        sfx=True,
        payload_size=350_000,
    )
    parts = sorted(
        path for path in case.archive_dir.iterdir()
        if path.is_file() and not path.name.lower().endswith(".exe")
    )
    if len(parts) < 2:
        pytest.skip("generated ZIP SFX archive has no tail data volume")
    parts[-1].write_bytes(b"\0" * parts[-1].stat().st_size)

    tester = get_native_password_tester()
    health = tester.check_archive_health(str(case.entry_path), part_paths=_parts(case))

    assert health.ok
    full_test = tester.test_archive(str(case.entry_path), part_paths=_parts(case))
    assert full_test.checksum_error or not full_test.ok


@pytest.mark.parametrize("password", [None, PASSWORD])
def test_native_wrapper_handles_rar_sfx_split_health_password_and_resources(tmp_path, password):
    require_7z()
    if not get_optional_rar():
        pytest.skip("RAR generator is not configured")
    case = ArchiveFixtureFactory().create(
        tmp_path,
        f"native_rar_sfx_split_pwd_{bool(password)}",
        "rar",
        split=True,
        sfx=True,
        password=password,
    )
    tester = get_native_password_tester()
    parts = _parts(case)

    health = tester.check_archive_health(str(case.entry_path), part_paths=parts)
    if password:
        assert health.is_encrypted
        assert tester.test_archive(str(case.entry_path), password=password, part_paths=parts).ok
        attempt = tester.try_passwords(str(case.entry_path), [WRONG_PASSWORD, password], part_paths=parts)
        assert attempt.ok
        assert attempt.matched_index == 1
    else:
        assert health.ok
        assert tester.test_archive(str(case.entry_path), part_paths=parts).ok

    analysis = tester.analyze_archive_resources(str(case.entry_path), password or "", part_paths=parts)
    assert analysis.ok
    assert analysis.file_count >= 1


def test_native_wrapper_detects_missing_rar_sfx_split_tail(tmp_path):
    require_7z()
    if not get_optional_rar():
        pytest.skip("RAR generator is not configured")
    case = ArchiveFixtureFactory().create(tmp_path, "native_rar_sfx_missing_tail", "rar", split=True, sfx=True)
    parts = sorted(path for path in case.archive_dir.iterdir() if path.is_file())
    parts[-1].unlink()

    health = get_native_password_tester().check_archive_health(str(case.entry_path), part_paths=_parts(case))

    assert health.is_missing_volume


@pytest.mark.parametrize(
    ("archive_format", "case_kwargs"),
    [
        ("7z", {"sfx": True}),
        ("7z", {"carrier": "jpg"}),
        ("rar", {}),
        ("rar", {"split": True}),
    ],
)
def test_native_password_retry_reaches_correct_password_after_wrong_passwords(tmp_path, archive_format, case_kwargs):
    require_7z()
    if archive_format == "rar" and not get_optional_rar():
        pytest.skip("RAR generator is not configured")
    case = ArchiveFixtureFactory().create(
        tmp_path,
        f"native_retry_after_wrong_{archive_format}_{'_'.join(case_kwargs) or 'plain'}",
        archive_format,
        password=PASSWORD,
        **case_kwargs,
    )

    attempt = get_native_password_tester().try_passwords(
        str(case.entry_path),
        [WRONG_PASSWORD, "still-wrong", PASSWORD],
        part_paths=_parts(case),
    )

    assert attempt.ok
    assert attempt.matched_index == 2
