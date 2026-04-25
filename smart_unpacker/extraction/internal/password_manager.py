import subprocess
from typing import List, Optional, Tuple

from smart_unpacker.extraction.internal.errors import (
    has_archive_damage_signals,
    has_definite_wrong_password,
)
from smart_unpacker.passwords import dedupe_passwords, parse_password_lines, read_password_file
from smart_unpacker.support.resources import get_7z_path
from smart_unpacker.support.external_command_cache import cached_readonly_command

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
        seven_z_path = get_7z_path()
        import sys
        si = None
        if sys.platform == "win32":
            si = subprocess.STARTUPINFO()
            si.dwFlags |= subprocess.STARTF_USESHOWWINDOW

        cmd = [seven_z_path, "t", archive_path, "-y"]
        if password:
            cmd.append(f"-p{password}")

        result = cached_readonly_command(
            cmd,
            archive_path,
            subprocess.run,
            capture_output=True,
            text=True,
            errors="replace",
            startupinfo=si,
            stdin=subprocess.DEVNULL,
        )
        return result, f"{result.stdout}\n{result.stderr}".lower()

    def test_without_password(self, archive_path: str) -> Tuple[subprocess.CompletedProcess, str]:
        return self.test_password(archive_path, "")

    def find_working_password(self, archive_path: str) -> Tuple[Optional[str], subprocess.CompletedProcess, str]:
        passwords_to_try = self.get_passwords_to_try()
        if not passwords_to_try:
            passwords_to_try = [""]

        last_error = ""
        last_result = None

        for pwd in passwords_to_try:
            result, combined = self.test_password(archive_path, pwd)
            
            if result.returncode == 0:
                self.add_recent_password(pwd)
                return pwd, result, ""
                
            last_result = result
            last_error = combined
            
            if self._has_definite_wrong_password(last_error):
                continue

            if self._has_archive_damage_signals(last_error):
                return pwd, result, last_error
                
            if "wrong password" not in last_error and "cannot open encrypted archive" not in last_error:
                return None, result, last_error
                
        return None, last_result, last_error
