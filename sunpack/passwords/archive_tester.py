from typing import List

from sunpack.support.sevenzip_bridge import cached_test_archive, get_native_password_tester
from sunpack.support.sevenzip_bridge import (
    STATUS_BACKEND_UNAVAILABLE,
    STATUS_DAMAGED,
    STATUS_UNSUPPORTED,
    STATUS_WRONG_PASSWORD,
)
from sunpack.passwords.internal.store import PasswordStore
from sunpack.passwords.result import PasswordProbeResult
from sunpack.passwords.scheduler import PasswordScheduler


class ArchivePasswordTester:
    def __init__(
        self,
        cli_passwords: List[str] = None,
        builtin_passwords_file: str = None,
        builtin_passwords: List[str] = None,
        password_store: PasswordStore | None = None,
    ):
        self.password_store = password_store or PasswordStore.from_sources(
            cli_passwords=cli_passwords or [],
            builtin_passwords=builtin_passwords,
            builtin_passwords_file=builtin_passwords_file,
        )
        self.native_password_tester = get_native_password_tester()
        self.password_scheduler = PasswordScheduler.from_archive_password_tester(self)

    @property
    def recent_passwords(self) -> List[str]:
        return list(self.password_store.recent_passwords)

    @property
    def passwords(self) -> List[str]:
        return self.password_store.candidates()

    def get_passwords_to_try(self) -> List[str]:
        return self.password_store.candidates()

    def add_recent_password(self, pwd: str):
        self.password_store.remember_success(pwd)

    def test_password(
        self,
        archive_path: str,
        password: str = "",
        part_paths: list[str] | None = None,
        archive_input: dict | None = None,
    ) -> PasswordProbeResult:
        if archive_input:
            native_attempt = self.native_password_tester.try_passwords(
                archive_path,
                [password or ""],
                part_paths=part_paths,
                archive_input=archive_input,
            )
            message = native_attempt.message
            status = _native_probe_status(native_attempt.status, native_attempt.ok)
            backend_result = native_attempt
        else:
            native_test = cached_test_archive(archive_path, password=password, part_paths=part_paths)
            message = native_test.message
            if native_test.ok:
                status = "match"
            elif native_test.encrypted:
                status = "no_match"
            elif native_test.checksum_error or native_test.status == STATUS_DAMAGED:
                status = "damaged"
            else:
                status = _native_probe_status(native_test.status, False)
            backend_result = native_test
        return PasswordProbeResult(status=status, message=str(message or ""), backend_result=backend_result)

    def test_without_password(
        self,
        archive_path: str,
        part_paths: list[str] | None = None,
        archive_input: dict | None = None,
    ) -> PasswordProbeResult:
        return self.test_password(archive_path, "", part_paths=part_paths, archive_input=archive_input)


def _native_probe_status(status: int, ok: bool):
    if ok:
        return "match"
    return {
        STATUS_WRONG_PASSWORD: "no_match",
        STATUS_DAMAGED: "damaged",
        STATUS_UNSUPPORTED: "unsupported_method",
        STATUS_BACKEND_UNAVAILABLE: "backend_unavailable",
    }.get(status, "unknown_needs_final_verifier")

PasswordManager = ArchivePasswordTester
