import ctypes
import atexit
import json
import subprocess
import sys
import threading
import uuid
from dataclasses import dataclass
from pathlib import Path

from smart_unpacker.support.resources import candidate_resource_roots, get_7z_dll_path, get_sevenzip_worker_path
from smart_unpacker.support.global_cache_manager import cached_value, file_identity


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


@dataclass(frozen=True)
class NativeArchiveCrcManifest:
    status: int
    is_archive: bool
    encrypted: bool
    damaged: bool
    checksum_error: bool
    item_count: int
    file_count: int
    files: list[dict]
    message: str

    @property
    def ok(self) -> bool:
        return self.status == STATUS_OK and self.is_archive and not self.damaged and not self.checksum_error


class _PasswordWorker:
    def __init__(self, worker_path: str):
        startupinfo = None
        if sys.platform == "win32":
            startupinfo = subprocess.STARTUPINFO()
            startupinfo.dwFlags |= subprocess.STARTF_USESHOWWINDOW
        self.worker_path = worker_path
        self.process = subprocess.Popen(
            [worker_path, "--persistent"],
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            encoding="utf-8",
            errors="replace",
            startupinfo=startupinfo,
        )
        self.lock = threading.Lock()

    def request(self, payload: dict) -> dict:
        with self.lock:
            if self.process.poll() is not None or self.process.stdin is None or self.process.stdout is None:
                raise RuntimeError("sevenzip password worker is not running")
            self.process.stdin.write(json.dumps(payload, ensure_ascii=False) + "\n")
            self.process.stdin.flush()
            while True:
                line = self.process.stdout.readline()
                if not line:
                    raise RuntimeError("sevenzip password worker closed stdout")
                event = json.loads(line)
                if event.get("type") == "result" and event.get("job_id") == payload.get("job_id"):
                    return event

    def close(self) -> None:
        with self.lock:
            if self.process.poll() is not None:
                return
            try:
                if self.process.stdin is not None:
                    self.process.stdin.write('{"worker_command":"shutdown","job_id":"shutdown"}\n')
                    self.process.stdin.flush()
            except OSError:
                pass
            try:
                self.process.wait(timeout=2)
            except subprocess.TimeoutExpired:
                self.process.kill()
                self.process.wait(timeout=2)
            for stream in (self.process.stdin, self.process.stdout, self.process.stderr):
                try:
                    if stream is not None:
                        stream.close()
                except OSError:
                    pass


class _PasswordWorkerPool:
    def __init__(self, worker_path: str, size: int | None = None):
        self.worker_path = worker_path
        self.size = max(1, int(size or 2))
        self._workers: list[_PasswordWorker] = []
        self._lock = threading.Lock()
        self._next = 0

    def try_passwords(
        self,
        *,
        seven_zip_dll_path: str,
        archive_path: str,
        passwords: list[str],
        part_paths: list[str] | None = None,
        archive_input: dict | None = None,
    ) -> NativePasswordAttempt:
        worker = self._borrow()
        payload = {
            "worker_command": "try_passwords",
            "job_id": f"pw-{uuid.uuid4().hex}",
            "seven_zip_dll_path": seven_zip_dll_path,
            "archive_path": archive_path,
            "part_paths": list(part_paths or []),
            "passwords": list(passwords or [""]),
        }
        if archive_input:
            payload["archive_input"] = archive_input
        result = worker.request(payload)
        native_status = str(result.get("native_status") or "")
        return NativePasswordAttempt(
            status=_password_status_from_worker(native_status),
            matched_index=_json_int(result, "matched_index", -1),
            attempts=_json_int(result, "attempts", 0),
            message=str(result.get("message") or native_status or "password worker failed"),
        )

    def _borrow(self) -> _PasswordWorker:
        with self._lock:
            while len(self._workers) < self.size:
                self._workers.append(_PasswordWorker(self.worker_path))
            worker = self._workers[self._next % len(self._workers)]
            self._next += 1
            return worker

    def close(self) -> None:
        with self._lock:
            workers = list(self._workers)
            self._workers.clear()
        for worker in workers:
            worker.close()


def _password_status_from_worker(native_status: str) -> int:
    normalized = native_status.lower()
    if normalized == "ok":
        return STATUS_OK
    if normalized == "wrong_password":
        return STATUS_WRONG_PASSWORD
    if normalized == "damaged":
        return STATUS_DAMAGED
    if normalized == "unsupported":
        return STATUS_UNSUPPORTED
    if normalized == "backend_unavailable":
        return STATUS_BACKEND_UNAVAILABLE
    return STATUS_ERROR


def _json_int(payload: dict, key: str, default: int) -> int:
    value = payload.get(key, default)
    if value is None:
        return default
    try:
        return int(value)
    except (TypeError, ValueError):
        return default


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
        self._password_worker_pool: _PasswordWorkerPool | None = None
        self._password_worker_lock = threading.Lock()

    def available(self) -> bool:
        return bool(self.wrapper_path and self.seven_zip_dll_path and Path(self.wrapper_path).exists())

    def _part_array(self, archive_path: str, part_paths: list[str] | None):
        normalized_parts = list(dict.fromkeys(part_paths or [archive_path]))
        array_type = ctypes.c_wchar_p * len(normalized_parts)
        return normalized_parts, array_type(*normalized_parts)

    def try_passwords(
        self,
        archive_path: str,
        passwords: list[str],
        part_paths: list[str] | None = None,
        archive_input: dict | None = None,
    ) -> NativePasswordAttempt:
        normalized_passwords = list(passwords or [""])
        if len(normalized_passwords) == 1:
            return self._try_passwords_ctypes(archive_path, normalized_passwords, part_paths)
        worker_attempt = self._try_passwords_with_worker(
            archive_path,
            passwords,
            part_paths=part_paths,
            archive_input=archive_input,
        )
        if worker_attempt is not None:
            return worker_attempt

        return self._try_passwords_ctypes(archive_path, normalized_passwords, part_paths)

    def _try_passwords_ctypes(
        self,
        archive_path: str,
        passwords: list[str],
        part_paths: list[str] | None = None,
    ) -> NativePasswordAttempt:
        library = self._load()
        password_array_type = ctypes.c_wchar_p * len(passwords)
        password_array = password_array_type(*passwords)
        normalized_parts, part_array = self._part_array(archive_path, part_paths)
        matched_index = ctypes.c_int(-1)
        attempts = ctypes.c_int(0)
        message = ctypes.create_unicode_buffer(512)

        status = library.sup7z_try_passwords_with_parts(
            ctypes.c_wchar_p(str(self.seven_zip_dll_path)),
            ctypes.c_wchar_p(str(archive_path)),
            part_array,
            ctypes.c_int(len(normalized_parts)),
            password_array,
            ctypes.c_int(len(passwords)),
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

    def _try_passwords_with_worker(
        self,
        archive_path: str,
        passwords: list[str],
        *,
        part_paths: list[str] | None = None,
        archive_input: dict | None = None,
    ) -> NativePasswordAttempt | None:
        try:
            pool = self._get_password_worker_pool()
            return pool.try_passwords(
                seven_zip_dll_path=str(self.seven_zip_dll_path),
                archive_path=str(archive_path),
                passwords=list(passwords or [""]),
                part_paths=part_paths,
                archive_input=archive_input,
            )
        except Exception:
            return None

    def _get_password_worker_pool(self) -> "_PasswordWorkerPool":
        if self._password_worker_pool is not None:
            return self._password_worker_pool
        with self._password_worker_lock:
            if self._password_worker_pool is None:
                self._password_worker_pool = _PasswordWorkerPool(get_sevenzip_worker_path())
                atexit.register(self._password_worker_pool.close)
            return self._password_worker_pool

    def test_archive(self, archive_path: str, password: str = "", part_paths: list[str] | None = None) -> NativeArchiveTest:
        library = self._load()

        normalized_parts, part_array = self._part_array(archive_path, part_paths)
        command_ok = ctypes.c_int(0)
        encrypted = ctypes.c_int(0)
        checksum_error = ctypes.c_int(0)
        archive_type = ctypes.create_unicode_buffer(64)
        message = ctypes.create_unicode_buffer(512)

        status = library.sup7z_test_archive_with_parts(
            ctypes.c_wchar_p(str(self.seven_zip_dll_path)),
            ctypes.c_wchar_p(str(archive_path)),
            part_array,
            ctypes.c_int(len(normalized_parts)),
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

    def probe_archive(self, archive_path: str, part_paths: list[str] | None = None) -> NativeArchiveProbe:
        if part_paths and len(part_paths) > 1:
            health = self.check_archive_health(archive_path, part_paths=part_paths)
            return NativeArchiveProbe(
                status=health.status,
                is_archive=health.is_archive,
                is_encrypted=health.is_encrypted,
                is_broken=health.is_broken or health.is_missing_volume,
                checksum_error=health.is_broken,
                offset=0,
                item_count=1 if health.ok else 0,
                archive_type=health.archive_type,
                message=health.message,
            )

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

    def check_archive_health(self, archive_path: str, password: str = "", part_paths: list[str] | None = None) -> NativeArchiveHealth:
        library = self._load()

        normalized_parts, part_array = self._part_array(archive_path, part_paths)
        health = _Sup7zArchiveHealth()
        message = ctypes.create_unicode_buffer(512)

        status = library.sup7z_check_archive_health_with_parts(
            ctypes.c_wchar_p(str(self.seven_zip_dll_path)),
            ctypes.c_wchar_p(str(archive_path)),
            part_array,
            ctypes.c_int(len(normalized_parts)),
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

    def analyze_archive_resources(self, archive_path: str, password: str = "", part_paths: list[str] | None = None) -> NativeArchiveResourceAnalysis:
        library = self._load()

        normalized_parts, part_array = self._part_array(archive_path, part_paths)
        analysis = _Sup7zArchiveResourceAnalysis()
        message = ctypes.create_unicode_buffer(512)

        status = library.sup7z_analyze_archive_resources_with_parts(
            ctypes.c_wchar_p(str(self.seven_zip_dll_path)),
            ctypes.c_wchar_p(str(archive_path)),
            part_array,
            ctypes.c_int(len(normalized_parts)),
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

    def read_archive_crc_manifest(
        self,
        archive_path: str,
        password: str = "",
        part_paths: list[str] | None = None,
        max_items: int = 200000,
    ) -> NativeArchiveCrcManifest:
        library = self._load()

        normalized_parts, part_array = self._part_array(archive_path, part_paths)
        manifest_json = ctypes.create_unicode_buffer(_manifest_buffer_chars(max_items))
        message = ctypes.create_unicode_buffer(512)

        status = library.sup7z_read_archive_crc_manifest_with_parts(
            ctypes.c_wchar_p(str(self.seven_zip_dll_path)),
            ctypes.c_wchar_p(str(archive_path)),
            part_array,
            ctypes.c_int(len(normalized_parts)),
            ctypes.c_wchar_p(str(password or "")),
            ctypes.c_int(max(0, int(max_items or 0))),
            manifest_json,
            ctypes.c_int(len(manifest_json)),
            message,
            ctypes.c_int(len(message)),
        )
        payload = _parse_manifest_json(manifest_json.value)
        return NativeArchiveCrcManifest(
            status=int(status),
            is_archive=bool(payload.get("is_archive", False)),
            encrypted=bool(payload.get("encrypted", False)),
            damaged=bool(payload.get("damaged", False)),
            checksum_error=bool(payload.get("checksum_error", False)),
            item_count=int(payload.get("item_count", 0) or 0),
            file_count=int(payload.get("file_count", 0) or 0),
            files=list(payload.get("files") or []),
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
            library.sup7z_try_passwords_with_parts.argtypes = [
                ctypes.c_wchar_p,
                ctypes.c_wchar_p,
                ctypes.POINTER(ctypes.c_wchar_p),
                ctypes.c_int,
                ctypes.POINTER(ctypes.c_wchar_p),
                ctypes.c_int,
                ctypes.POINTER(ctypes.c_int),
                ctypes.POINTER(ctypes.c_int),
                ctypes.c_wchar_p,
                ctypes.c_int,
            ]
            library.sup7z_try_passwords_with_parts.restype = ctypes.c_int
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
            library.sup7z_test_archive_with_parts.argtypes = [
                ctypes.c_wchar_p,
                ctypes.c_wchar_p,
                ctypes.POINTER(ctypes.c_wchar_p),
                ctypes.c_int,
                ctypes.c_wchar_p,
                ctypes.POINTER(ctypes.c_int),
                ctypes.POINTER(ctypes.c_int),
                ctypes.POINTER(ctypes.c_int),
                ctypes.c_wchar_p,
                ctypes.c_int,
                ctypes.c_wchar_p,
                ctypes.c_int,
            ]
            library.sup7z_test_archive_with_parts.restype = ctypes.c_int
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
            library.sup7z_check_archive_health_with_parts.argtypes = [
                ctypes.c_wchar_p,
                ctypes.c_wchar_p,
                ctypes.POINTER(ctypes.c_wchar_p),
                ctypes.c_int,
                ctypes.c_wchar_p,
                ctypes.POINTER(_Sup7zArchiveHealth),
                ctypes.c_wchar_p,
                ctypes.c_int,
            ]
            library.sup7z_check_archive_health_with_parts.restype = ctypes.c_int
            library.sup7z_analyze_archive_resources.argtypes = [
                ctypes.c_wchar_p,
                ctypes.c_wchar_p,
                ctypes.c_wchar_p,
                ctypes.POINTER(_Sup7zArchiveResourceAnalysis),
                ctypes.c_wchar_p,
                ctypes.c_int,
            ]
            library.sup7z_analyze_archive_resources.restype = ctypes.c_int
            library.sup7z_analyze_archive_resources_with_parts.argtypes = [
                ctypes.c_wchar_p,
                ctypes.c_wchar_p,
                ctypes.POINTER(ctypes.c_wchar_p),
                ctypes.c_int,
                ctypes.c_wchar_p,
                ctypes.POINTER(_Sup7zArchiveResourceAnalysis),
                ctypes.c_wchar_p,
                ctypes.c_int,
            ]
            library.sup7z_analyze_archive_resources_with_parts.restype = ctypes.c_int
            self._bind_optional_crc_manifest_api(library)
            self._library = library
            return library

    def _bind_optional_crc_manifest_api(self, library) -> None:
        library.sup7z_read_archive_crc_manifest.argtypes = [
            ctypes.c_wchar_p,
            ctypes.c_wchar_p,
            ctypes.c_wchar_p,
            ctypes.c_int,
            ctypes.c_wchar_p,
            ctypes.c_int,
            ctypes.c_wchar_p,
            ctypes.c_int,
        ]
        library.sup7z_read_archive_crc_manifest.restype = ctypes.c_int
        library.sup7z_read_archive_crc_manifest_with_parts.argtypes = [
            ctypes.c_wchar_p,
            ctypes.c_wchar_p,
            ctypes.POINTER(ctypes.c_wchar_p),
            ctypes.c_int,
            ctypes.c_wchar_p,
            ctypes.c_int,
            ctypes.c_wchar_p,
            ctypes.c_int,
            ctypes.c_wchar_p,
            ctypes.c_int,
        ]
        library.sup7z_read_archive_crc_manifest_with_parts.restype = ctypes.c_int

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


def _cache_key(tester: NativePasswordTester, archive_path: str, part_paths: list[str] | None = None) -> tuple:
    parts = tuple(file_identity(path) for path in list(dict.fromkeys(part_paths or [archive_path])))
    return (
        str(tester.wrapper_path),
        str(tester.seven_zip_dll_path),
        file_identity(archive_path),
        parts,
    )


def cached_probe_archive(archive_path: str, part_paths: list[str] | None = None) -> NativeArchiveProbe:
    tester = get_native_password_tester()
    return cached_value(
        "native_7z_probe",
        _cache_key(tester, archive_path, part_paths),
        lambda: tester.probe_archive(archive_path, part_paths=part_paths),
    )


def _parse_manifest_json(value: str) -> dict:
    try:
        parsed = json.loads(value or "{}")
    except json.JSONDecodeError:
        return {}
    return parsed if isinstance(parsed, dict) else {}


def _manifest_buffer_chars(max_items: int) -> int:
    try:
        item_count = max(1, int(max_items or 0))
    except (TypeError, ValueError):
        item_count = 1
    return min(max(1024 * 1024, item_count * 256), 16 * 1024 * 1024)


def cached_test_archive(archive_path: str, password: str = "", part_paths: list[str] | None = None) -> NativeArchiveTest:
    tester = get_native_password_tester()
    password = password or ""
    key = _cache_key(tester, archive_path, part_paths) + (password,)
    return cached_value(
        "native_7z_test",
        key,
        lambda: tester.test_archive(archive_path, password=password, part_paths=part_paths),
    )


def cached_check_archive_health(archive_path: str, password: str = "", part_paths: list[str] | None = None) -> NativeArchiveHealth:
    tester = get_native_password_tester()
    password = password or ""
    return cached_value(
        "native_7z_health",
        _cache_key(tester, archive_path, part_paths) + (password,),
        lambda: tester.check_archive_health(archive_path, password=password, part_paths=part_paths),
    )


def cached_analyze_archive_resources(archive_path: str, password: str = "", part_paths: list[str] | None = None) -> NativeArchiveResourceAnalysis:
    tester = get_native_password_tester()
    password = password or ""
    return cached_value(
        "native_7z_resources",
        _cache_key(tester, archive_path, part_paths) + (password,),
        lambda: tester.analyze_archive_resources(archive_path, password=password, part_paths=part_paths),
    )


def cached_read_archive_crc_manifest(
    archive_path: str,
    password: str = "",
    part_paths: list[str] | None = None,
    max_items: int = 200000,
) -> NativeArchiveCrcManifest:
    tester = get_native_password_tester()
    password = password or ""
    max_items = max(0, int(max_items or 0))
    return cached_value(
        "native_7z_crc_manifest",
        _cache_key(tester, archive_path, part_paths) + (password, max_items),
        lambda: tester.read_archive_crc_manifest(
            archive_path,
            password=password,
            part_paths=part_paths,
            max_items=max_items,
        ),
    )
