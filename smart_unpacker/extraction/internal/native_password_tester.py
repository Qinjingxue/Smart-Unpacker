import ctypes
import subprocess
import sys
import threading
from dataclasses import dataclass
from pathlib import Path

from smart_unpacker.support.resources import candidate_resource_roots, get_7z_dll_path
from smart_unpacker.support.external_command_cache import cached_value, file_identity


STATUS_OK = 0
STATUS_WRONG_PASSWORD = 1
STATUS_DAMAGED = 2
STATUS_UNSUPPORTED = 3
STATUS_BACKEND_UNAVAILABLE = 4
STATUS_ERROR = 5


@dataclass(frozen=True)
class NativePasswordAttempt:
    status: int
    matched_index: int
    attempts: int
    message: str

    @property
    def ok(self) -> bool:
        return self.status == STATUS_OK and self.matched_index >= 0

    def as_completed_process(self, archive_path: str) -> subprocess.CompletedProcess:
        return subprocess.CompletedProcess(
            args=["7z.dll", "test-passwords", archive_path],
            returncode=0 if self.ok else 2,
            stdout="" if self.ok else self.message,
            stderr="" if self.ok else self.message,
        )


@dataclass(frozen=True)
class NativeArchiveTest:
    status: int
    command_ok: bool
    encrypted: bool
    checksum_error: bool
    archive_type: str
    message: str

    @property
    def ok(self) -> bool:
        return self.status == STATUS_OK and self.command_ok

    def as_completed_process(self, archive_path: str) -> subprocess.CompletedProcess:
        return subprocess.CompletedProcess(
            args=["7z.dll", "test-archive", archive_path],
            returncode=0 if self.ok else 2,
            stdout="" if self.ok else self.message,
            stderr="" if self.ok else self.message,
        )


@dataclass(frozen=True)
class NativeArchiveProbe:
    status: int
    is_archive: bool
    is_encrypted: bool
    is_broken: bool
    checksum_error: bool
    offset: int
    item_count: int
    archive_type: str
    message: str


@dataclass(frozen=True)
class NativeArchiveHealth:
    status: int
    is_archive: bool
    is_encrypted: bool
    is_broken: bool
    is_missing_volume: bool
    is_wrong_password: bool
    operation_result: int
    archive_type: str
    message: str

    @property
    def ok(self) -> bool:
        return self.status == STATUS_OK and self.is_archive and not self.is_broken and not self.is_missing_volume


@dataclass(frozen=True)
class NativeArchiveResourceAnalysis:
    status: int
    is_archive: bool
    is_encrypted: bool
    is_broken: bool
    solid: bool
    item_count: int
    file_count: int
    dir_count: int
    archive_size: int
    total_unpacked_size: int
    total_packed_size: int
    largest_item_size: int
    largest_dictionary_size: int
    archive_type: str
    dominant_method: str
    message: str

    @property
    def ok(self) -> bool:
        return self.status == STATUS_OK and self.is_archive and not self.is_broken


class _Sup7zArchiveHealth(ctypes.Structure):
    _fields_ = [
        ("status", ctypes.c_int),
        ("is_archive", ctypes.c_int),
        ("is_encrypted", ctypes.c_int),
        ("is_broken", ctypes.c_int),
        ("is_missing_volume", ctypes.c_int),
        ("is_wrong_password", ctypes.c_int),
        ("operation_result", ctypes.c_int),
        ("archive_type", ctypes.c_wchar * 32),
    ]


class _Sup7zArchiveResourceAnalysis(ctypes.Structure):
    _fields_ = [
        ("status", ctypes.c_int),
        ("is_archive", ctypes.c_int),
        ("is_encrypted", ctypes.c_int),
        ("is_broken", ctypes.c_int),
        ("solid", ctypes.c_int),
        ("item_count", ctypes.c_int),
        ("file_count", ctypes.c_int),
        ("dir_count", ctypes.c_int),
        ("archive_size", ctypes.c_ulonglong),
        ("total_unpacked_size", ctypes.c_ulonglong),
        ("total_packed_size", ctypes.c_ulonglong),
        ("largest_item_size", ctypes.c_ulonglong),
        ("largest_dictionary_size", ctypes.c_ulonglong),
        ("archive_type", ctypes.c_wchar * 32),
        ("dominant_method", ctypes.c_wchar * 128),
    ]


class NativePasswordTester:
    def __init__(self, wrapper_path: str | None = None, seven_zip_dll_path: str | None = None):
        self.wrapper_path = wrapper_path or self._default_wrapper_path()
        self.seven_zip_dll_path = seven_zip_dll_path or get_7z_dll_path()
        self._library = None
        self._load_lock = threading.Lock()

    def available(self) -> bool:
        return bool(self.wrapper_path and self.seven_zip_dll_path and Path(self.wrapper_path).exists())

    def try_passwords(self, archive_path: str, passwords: list[str]) -> NativePasswordAttempt:
        library = self._load()

        normalized_passwords = list(passwords or [""])
        password_array_type = ctypes.c_wchar_p * len(normalized_passwords)
        password_array = password_array_type(*normalized_passwords)
        matched_index = ctypes.c_int(-1)
        attempts = ctypes.c_int(0)
        message = ctypes.create_unicode_buffer(512)

        status = library.sup7z_try_passwords(
            ctypes.c_wchar_p(str(self.seven_zip_dll_path)),
            ctypes.c_wchar_p(str(archive_path)),
            password_array,
            ctypes.c_int(len(normalized_passwords)),
            ctypes.byref(matched_index),
            ctypes.byref(attempts),
            message,
            ctypes.c_int(len(message)),
        )
        return NativePasswordAttempt(
            status=int(status),
            matched_index=int(matched_index.value),
            attempts=int(attempts.value),
            message=message.value,
        )

    def test_archive(self, archive_path: str, password: str = "") -> NativeArchiveTest:
        library = self._load()

        command_ok = ctypes.c_int(0)
        encrypted = ctypes.c_int(0)
        checksum_error = ctypes.c_int(0)
        archive_type = ctypes.create_unicode_buffer(64)
        message = ctypes.create_unicode_buffer(512)

        status = library.sup7z_test_archive(
            ctypes.c_wchar_p(str(self.seven_zip_dll_path)),
            ctypes.c_wchar_p(str(archive_path)),
            ctypes.c_wchar_p(str(password or "")),
            ctypes.byref(command_ok),
            ctypes.byref(encrypted),
            ctypes.byref(checksum_error),
            archive_type,
            ctypes.c_int(len(archive_type)),
            message,
            ctypes.c_int(len(message)),
        )
        return NativeArchiveTest(
            status=int(status),
            command_ok=bool(command_ok.value),
            encrypted=bool(encrypted.value),
            checksum_error=bool(checksum_error.value),
            archive_type=archive_type.value,
            message=message.value,
        )

    def probe_archive(self, archive_path: str) -> NativeArchiveProbe:
        library = self._load()

        is_archive = ctypes.c_int(0)
        is_encrypted = ctypes.c_int(0)
        is_broken = ctypes.c_int(0)
        checksum_error = ctypes.c_int(0)
        offset = ctypes.c_ulonglong(0)
        item_count = ctypes.c_int(0)
        archive_type = ctypes.create_unicode_buffer(64)
        message = ctypes.create_unicode_buffer(512)

        status = library.sup7z_probe_archive(
            ctypes.c_wchar_p(str(self.seven_zip_dll_path)),
            ctypes.c_wchar_p(str(archive_path)),
            ctypes.byref(is_archive),
            ctypes.byref(is_encrypted),
            ctypes.byref(is_broken),
            ctypes.byref(checksum_error),
            ctypes.byref(offset),
            ctypes.byref(item_count),
            archive_type,
            ctypes.c_int(len(archive_type)),
            message,
            ctypes.c_int(len(message)),
        )
        return NativeArchiveProbe(
            status=int(status),
            is_archive=bool(is_archive.value),
            is_encrypted=bool(is_encrypted.value),
            is_broken=bool(is_broken.value),
            checksum_error=bool(checksum_error.value),
            offset=int(offset.value),
            item_count=int(item_count.value),
            archive_type=archive_type.value,
            message=message.value,
        )

    def check_archive_health(self, archive_path: str, password: str = "") -> NativeArchiveHealth:
        library = self._load()

        health = _Sup7zArchiveHealth()
        message = ctypes.create_unicode_buffer(512)

        status = library.sup7z_check_archive_health(
            ctypes.c_wchar_p(str(self.seven_zip_dll_path)),
            ctypes.c_wchar_p(str(archive_path)),
            ctypes.c_wchar_p(str(password or "")),
            ctypes.byref(health),
            message,
            ctypes.c_int(len(message)),
        )
        return NativeArchiveHealth(
            status=int(status),
            is_archive=bool(health.is_archive),
            is_encrypted=bool(health.is_encrypted),
            is_broken=bool(health.is_broken),
            is_missing_volume=bool(health.is_missing_volume),
            is_wrong_password=bool(health.is_wrong_password),
            operation_result=int(health.operation_result),
            archive_type=str(health.archive_type),
            message=message.value,
        )

    def analyze_archive_resources(self, archive_path: str, password: str = "") -> NativeArchiveResourceAnalysis:
        library = self._load()

        analysis = _Sup7zArchiveResourceAnalysis()
        message = ctypes.create_unicode_buffer(512)

        status = library.sup7z_analyze_archive_resources(
            ctypes.c_wchar_p(str(self.seven_zip_dll_path)),
            ctypes.c_wchar_p(str(archive_path)),
            ctypes.c_wchar_p(str(password or "")),
            ctypes.byref(analysis),
            message,
            ctypes.c_int(len(message)),
        )
        return NativeArchiveResourceAnalysis(
            status=int(status),
            is_archive=bool(analysis.is_archive),
            is_encrypted=bool(analysis.is_encrypted),
            is_broken=bool(analysis.is_broken),
            solid=bool(analysis.solid),
            item_count=int(analysis.item_count),
            file_count=int(analysis.file_count),
            dir_count=int(analysis.dir_count),
            archive_size=int(analysis.archive_size),
            total_unpacked_size=int(analysis.total_unpacked_size),
            total_packed_size=int(analysis.total_packed_size),
            largest_item_size=int(analysis.largest_item_size),
            largest_dictionary_size=int(analysis.largest_dictionary_size),
            archive_type=str(analysis.archive_type),
            dominant_method=str(analysis.dominant_method),
            message=message.value,
        )

    def _load(self):
        if self._library is not None:
            return self._library
        with self._load_lock:
            if self._library is not None:
                return self._library
            if sys.platform != "win32":
                raise RuntimeError("7z.dll wrapper is only supported on Windows in this test build.")
            if not self.wrapper_path or not Path(self.wrapper_path).exists():
                raise FileNotFoundError("Required sevenzip_password_tester_capi.dll was not found.")
            if not self.seven_zip_dll_path or not Path(self.seven_zip_dll_path).exists():
                raise FileNotFoundError("Required 7z.dll was not found.")

            library = ctypes.WinDLL(str(self.wrapper_path))
            library.sup7z_try_passwords.argtypes = [
                ctypes.c_wchar_p,
                ctypes.c_wchar_p,
                ctypes.POINTER(ctypes.c_wchar_p),
                ctypes.c_int,
                ctypes.POINTER(ctypes.c_int),
                ctypes.POINTER(ctypes.c_int),
                ctypes.c_wchar_p,
                ctypes.c_int,
            ]
            library.sup7z_try_passwords.restype = ctypes.c_int
            library.sup7z_test_archive.argtypes = [
                ctypes.c_wchar_p,
                ctypes.c_wchar_p,
                ctypes.c_wchar_p,
                ctypes.POINTER(ctypes.c_int),
                ctypes.POINTER(ctypes.c_int),
                ctypes.POINTER(ctypes.c_int),
                ctypes.c_wchar_p,
                ctypes.c_int,
                ctypes.c_wchar_p,
                ctypes.c_int,
            ]
            library.sup7z_test_archive.restype = ctypes.c_int
            library.sup7z_probe_archive.argtypes = [
                ctypes.c_wchar_p,
                ctypes.c_wchar_p,
                ctypes.POINTER(ctypes.c_int),
                ctypes.POINTER(ctypes.c_int),
                ctypes.POINTER(ctypes.c_int),
                ctypes.POINTER(ctypes.c_int),
                ctypes.POINTER(ctypes.c_ulonglong),
                ctypes.POINTER(ctypes.c_int),
                ctypes.c_wchar_p,
                ctypes.c_int,
                ctypes.c_wchar_p,
                ctypes.c_int,
            ]
            library.sup7z_probe_archive.restype = ctypes.c_int
            library.sup7z_check_archive_health.argtypes = [
                ctypes.c_wchar_p,
                ctypes.c_wchar_p,
                ctypes.c_wchar_p,
                ctypes.POINTER(_Sup7zArchiveHealth),
                ctypes.c_wchar_p,
                ctypes.c_int,
            ]
            library.sup7z_check_archive_health.restype = ctypes.c_int
            library.sup7z_analyze_archive_resources.argtypes = [
                ctypes.c_wchar_p,
                ctypes.c_wchar_p,
                ctypes.c_wchar_p,
                ctypes.POINTER(_Sup7zArchiveResourceAnalysis),
                ctypes.c_wchar_p,
                ctypes.c_int,
            ]
            library.sup7z_analyze_archive_resources.restype = ctypes.c_int
            self._library = library
            return library

    def _default_wrapper_path(self) -> str:
        candidates: list[Path] = []
        for root in candidate_resource_roots():
            candidates.extend([
                root / "tools" / "sevenzip_password_tester_capi.dll",
                root / "sevenzip_password_tester_capi.dll",
            ])
        for candidate in candidates:
            if candidate.exists():
                return str(candidate)
        raise FileNotFoundError("Required sevenzip_password_tester_capi.dll was not found under tools\\ or the application root.")


_DEFAULT_TESTER: NativePasswordTester | None = None
_DEFAULT_TESTER_LOCK = threading.Lock()


def get_native_password_tester() -> NativePasswordTester:
    global _DEFAULT_TESTER
    if _DEFAULT_TESTER is not None:
        return _DEFAULT_TESTER
    with _DEFAULT_TESTER_LOCK:
        if _DEFAULT_TESTER is None:
            _DEFAULT_TESTER = NativePasswordTester()
        return _DEFAULT_TESTER


def _cache_key(tester: NativePasswordTester, archive_path: str) -> tuple:
    return (
        str(tester.wrapper_path),
        str(tester.seven_zip_dll_path),
        file_identity(archive_path),
    )


def cached_probe_archive(archive_path: str) -> NativeArchiveProbe:
    tester = get_native_password_tester()
    return cached_value(
        "native_7z_probe",
        _cache_key(tester, archive_path),
        lambda: tester.probe_archive(archive_path),
    )


def _test_from_probe(probe: NativeArchiveProbe) -> NativeArchiveTest:
    return NativeArchiveTest(
        status=probe.status,
        command_ok=probe.status == STATUS_OK,
        encrypted=probe.status == STATUS_WRONG_PASSWORD,
        checksum_error=probe.status == STATUS_DAMAGED,
        archive_type=probe.archive_type,
        message=probe.message,
    )


def cached_test_archive(archive_path: str, password: str = "") -> NativeArchiveTest:
    tester = get_native_password_tester()
    password = password or ""
    key = _cache_key(tester, archive_path) + (password,)
    if not password:
        return cached_value(
            "native_7z_test",
            key,
            lambda: _test_from_probe(cached_probe_archive(archive_path)),
        )
    return cached_value(
        "native_7z_test",
        key,
        lambda: tester.test_archive(archive_path, password=password),
    )


def cached_check_archive_health(archive_path: str, password: str = "") -> NativeArchiveHealth:
    tester = get_native_password_tester()
    password = password or ""
    return cached_value(
        "native_7z_health",
        _cache_key(tester, archive_path) + (password,),
        lambda: tester.check_archive_health(archive_path, password=password),
    )


def cached_analyze_archive_resources(archive_path: str, password: str = "") -> NativeArchiveResourceAnalysis:
    tester = get_native_password_tester()
    password = password or ""
    return cached_value(
        "native_7z_resources",
        _cache_key(tester, archive_path) + (password,),
        lambda: tester.analyze_archive_resources(archive_path, password=password),
    )
