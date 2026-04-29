import subprocess
from typing import List, Tuple

from packrelic.support.sevenzip_native import cached_test_archive, get_native_password_tester
from packrelic.support.sevenzip_native import STATUS_DAMAGED, STATUS_WRONG_PASSWORD
from packrelic.passwords.internal.store import PasswordStore
from packrelic.passwords.scheduler import PasswordScheduler


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
    ) -> Tuple[subprocess.CompletedProcess, str]:
        if archive_input:
            native_attempt = self.native_password_tester.try_passwords(
                archive_path,
                [password or ""],
                part_paths=part_paths,
                archive_input=archive_input,
            )
            ok = native_attempt.ok
            message = native_attempt.message
            encrypted = not ok and native_attempt.status == STATUS_WRONG_PASSWORD
            checksum_error = native_attempt.status == STATUS_DAMAGED
        else:
            native_test = cached_test_archive(archive_path, password=password, part_paths=part_paths)
            ok = native_test.ok
            message = native_test.message
            encrypted = native_test.encrypted
            checksum_error = native_test.checksum_error

        result = subprocess.CompletedProcess(
            args=["7z.dll", "test-archive", archive_path],
            returncode=0 if ok else 2,
            stdout="" if ok else message,
            stderr="" if ok else message,
        )
        error_text = message.lower()
        if encrypted and "wrong password" not in error_text:
            error_text = f"{error_text}\nwrong password".strip()
        if checksum_error and "checksum error" not in error_text:
            error_text = f"{error_text}\nchecksum error".strip()
        return result, error_text

    def test_without_password(
        self,
        archive_path: str,
        part_paths: list[str] | None = None,
        archive_input: dict | None = None,
    ) -> Tuple[subprocess.CompletedProcess, str]:
        return self.test_password(archive_path, "", part_paths=part_paths, archive_input=archive_input)

PasswordManager = ArchivePasswordTester
