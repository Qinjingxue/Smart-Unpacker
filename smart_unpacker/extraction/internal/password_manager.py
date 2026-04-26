import subprocess
from typing import List, Optional, Tuple

from smart_unpacker.extraction.internal.errors import (
    has_archive_damage_signals,
    has_definite_wrong_password,
)
from smart_unpacker.passwords import dedupe_passwords, parse_password_lines, read_password_file
from smart_unpacker.extraction.internal.native_password_tester import get_native_password_tester

class PasswordManager:
    def __init__(
        self,
        cli_passwords: List[str] = None,
        builtin_passwords_file: str = None,
        builtin_passwords: List[str] = None,
    ):
        self.user_passwords = dedupe_passwords(cli_passwords or [])
        if builtin_passwords is not None:
            self.builtin_passwords = dedupe_passwords(builtin_passwords)
        elif builtin_passwords_file:
            try:
                self.builtin_passwords = dedupe_passwords(read_password_file(builtin_passwords_file))
            except Exception:
                self.builtin_passwords = []
        else:
            self.builtin_passwords = []
        self.recent_successful: List[str] = []
        self.native_password_tester = get_native_password_tester()

    @property
    def recent_passwords(self) -> List[str]:
        return list(getattr(self, "recent_successful", []))

    @property
    def passwords(self) -> List[str]:
        return self.get_passwords_to_try()

    def get_passwords_to_try(self) -> List[str]:
        return dedupe_passwords(
            list(getattr(self, "user_passwords", []))
            + list(getattr(self, "recent_successful", []))
            + list(getattr(self, "builtin_passwords", []))
        )

    def add_recent_password(self, pwd: str):
        if not pwd:
            return
        if pwd in self.recent_successful:
            self.recent_successful.remove(pwd)
        self.recent_successful.insert(0, pwd)

    def _has_archive_damage_signals(self, err_text: str) -> bool:
        return has_archive_damage_signals(err_text)

    def _has_definite_wrong_password(self, err_text: str) -> bool:
        return has_definite_wrong_password(err_text)

    def test_password(self, archive_path: str, password: str = "") -> Tuple[subprocess.CompletedProcess, str]:
        native_test = self.native_password_tester.test_archive(archive_path, password=password)
        result = native_test.as_completed_process(archive_path)
        error_text = native_test.message.lower()
        if native_test.encrypted and "wrong password" not in error_text:
            error_text = f"{error_text}\nwrong password".strip()
        if native_test.checksum_error and "checksum error" not in error_text:
            error_text = f"{error_text}\nchecksum error".strip()
        return result, error_text

    def test_without_password(self, archive_path: str) -> Tuple[subprocess.CompletedProcess, str]:
        return self.test_password(archive_path, "")

    def find_working_password(self, archive_path: str) -> Tuple[Optional[str], subprocess.CompletedProcess, str]:
        passwords_to_try = self.get_passwords_to_try()
        if not passwords_to_try:
            passwords_to_try = [""]

        native_attempt = self.native_password_tester.try_passwords(archive_path, passwords_to_try)
        native_result = native_attempt.as_completed_process(archive_path)
        if native_attempt.ok:
            pwd = passwords_to_try[native_attempt.matched_index]
            self.add_recent_password(pwd)
            return pwd, native_result, ""
        return None, native_result, native_attempt.message.lower() or "wrong password"
