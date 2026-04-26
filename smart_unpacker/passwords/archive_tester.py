import subprocess
from typing import List, Optional, Tuple

from smart_unpacker.support.sevenzip_native import get_native_password_tester
from smart_unpacker.passwords.internal.store import PasswordStore


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

    def test_password(self, archive_path: str, password: str = "", part_paths: list[str] | None = None) -> Tuple[subprocess.CompletedProcess, str]:
        native_test = self.native_password_tester.test_archive(archive_path, password=password, part_paths=part_paths)
        result = native_test.as_completed_process(archive_path)
        error_text = native_test.message.lower()
        if native_test.encrypted and "wrong password" not in error_text:
            error_text = f"{error_text}\nwrong password".strip()
        if native_test.checksum_error and "checksum error" not in error_text:
            error_text = f"{error_text}\nchecksum error".strip()
        return result, error_text

    def test_without_password(self, archive_path: str, part_paths: list[str] | None = None) -> Tuple[subprocess.CompletedProcess, str]:
        return self.test_password(archive_path, "", part_paths=part_paths)

    def find_working_password(self, archive_path: str, part_paths: list[str] | None = None) -> Tuple[Optional[str], subprocess.CompletedProcess, str]:
        passwords_to_try = self.get_passwords_to_try()
        if not passwords_to_try:
            passwords_to_try = [""]

        native_attempt = self.native_password_tester.try_passwords(archive_path, passwords_to_try, part_paths=part_paths)
        native_result = native_attempt.as_completed_process(archive_path)
        if native_attempt.ok:
            pwd = passwords_to_try[native_attempt.matched_index]
            self.password_store.remember_success(pwd)
            return pwd, native_result, ""
        return None, native_result, native_attempt.message.lower() or "wrong password"


PasswordManager = ArchivePasswordTester
