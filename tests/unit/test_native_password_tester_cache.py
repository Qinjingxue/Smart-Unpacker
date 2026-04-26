from smart_unpacker.extraction.internal import native_password_tester as native
from smart_unpacker.support.external_command_cache import clear_cache_namespace


def _clear_native_7z_caches():
    clear_cache_namespace("native_7z_probe")
    clear_cache_namespace("native_7z_test")


class FakeTester:
    wrapper_path = "wrapper.dll"
    seven_zip_dll_path = "7z.dll"

    def __init__(self):
        self.probe_calls = 0
        self.test_calls = 0

    def probe_archive(self, archive_path: str):
        self.probe_calls += 1
        return native.NativeArchiveProbe(
            status=native.STATUS_OK,
            is_archive=True,
            is_encrypted=False,
            is_broken=False,
            checksum_error=False,
            offset=0,
            item_count=1,
            archive_type="zip",
            message="ok",
        )

    def test_archive(self, archive_path: str, password: str = ""):
        self.test_calls += 1
        return native.NativeArchiveTest(
            status=native.STATUS_OK,
            command_ok=True,
            encrypted=False,
            checksum_error=False,
            archive_type="zip",
            message="ok",
        )


class UnsupportedProbeTester(FakeTester):
    def probe_archive(self, archive_path: str):
        self.probe_calls += 1
        return native.NativeArchiveProbe(
            status=native.STATUS_UNSUPPORTED,
            is_archive=True,
            is_encrypted=True,
            is_broken=False,
            checksum_error=False,
            offset=0,
            item_count=0,
            archive_type="7z",
            message="unsupported",
        )


def _install_fake_tester(monkeypatch):
    fake = FakeTester()
    monkeypatch.setattr(native, "_DEFAULT_TESTER", fake)
    _clear_native_7z_caches()
    return fake


def _install_tester(monkeypatch, tester):
    monkeypatch.setattr(native, "_DEFAULT_TESTER", tester)
    _clear_native_7z_caches()
    return tester


def test_cached_probe_reuses_result_for_unchanged_file(tmp_path, monkeypatch):
    fake = _install_fake_tester(monkeypatch)
    archive = tmp_path / "sample.zip"
    archive.write_bytes(b"PK")

    first = native.cached_probe_archive(str(archive))
    second = native.cached_probe_archive(str(archive))

    assert first.archive_type == "zip"
    assert second.archive_type == "zip"
    assert fake.probe_calls == 1
    _clear_native_7z_caches()


def test_empty_password_test_reuses_probe_without_second_native_call(tmp_path, monkeypatch):
    fake = _install_fake_tester(monkeypatch)
    archive = tmp_path / "sample.zip"
    archive.write_bytes(b"PK")

    probe = native.cached_probe_archive(str(archive))
    test = native.cached_test_archive(str(archive))

    assert probe.status == native.STATUS_OK
    assert test.ok
    assert test.archive_type == "zip"
    assert fake.probe_calls == 1
    assert fake.test_calls == 0
    _clear_native_7z_caches()


def test_password_test_keeps_password_specific_native_call(tmp_path, monkeypatch):
    fake = _install_fake_tester(monkeypatch)
    archive = tmp_path / "sample.zip"
    archive.write_bytes(b"PK")

    first = native.cached_test_archive(str(archive), password="secret")
    second = native.cached_test_archive(str(archive), password="secret")

    assert first.ok
    assert second.ok
    assert fake.probe_calls == 0
    assert fake.test_calls == 1
    _clear_native_7z_caches()


def test_empty_password_test_derives_validation_fields_from_status(tmp_path, monkeypatch):
    fake = _install_tester(monkeypatch, UnsupportedProbeTester())
    archive = tmp_path / "sample.7z"
    archive.write_bytes(b"7z")

    test = native.cached_test_archive(str(archive))

    assert not test.ok
    assert not test.encrypted
    assert test.status == native.STATUS_UNSUPPORTED
    assert fake.probe_calls == 1
    assert fake.test_calls == 0
    _clear_native_7z_caches()
