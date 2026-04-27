from __future__ import annotations

import subprocess
from typing import Any

from smart_unpacker.passwords.verifier.base import PasswordBatchVerification
from smart_unpacker.support.sevenzip_native import get_native_password_tester


class SevenZipDllVerifier:
    def __init__(self, native_password_tester: object | None = None, password_tester: Any = None):
        self.native_password_tester = native_password_tester or get_native_password_tester()
        self.password_tester = password_tester

    @classmethod
    def from_archive_password_tester(cls, password_tester: Any) -> "SevenZipDllVerifier":
        return cls(
            native_password_tester=getattr(password_tester, "native_password_tester", None),
            password_tester=password_tester,
        )

    def verify_batch(
        self,
        archive_path: str,
        passwords: list[str],
        *,
        part_paths: list[str] | None = None,
    ) -> PasswordBatchVerification:
        normalized_passwords = list(passwords or [""])
        native_attempt = self.native_password_tester.try_passwords(
            archive_path,
            normalized_passwords,
            part_paths=part_paths,
        )
        native_result = subprocess.CompletedProcess(
            args=["7z.dll", "test-passwords", archive_path],
            returncode=0 if native_attempt.ok else 2,
            stdout="" if native_attempt.ok else native_attempt.message,
            stderr="" if native_attempt.ok else native_attempt.message,
        )
        error_text = (native_attempt.message or "").lower()
        if native_attempt.ok:
            password = normalized_passwords[native_attempt.matched_index]
            if self.password_tester is not None:
                self.password_tester.add_recent_password(password)
            return PasswordBatchVerification(
                ok=True,
                status="match",
                matched_index=native_attempt.matched_index,
                attempts=native_attempt.attempts,
                test_result=native_result,
                error_text="",
                terminal=True,
            )
        return PasswordBatchVerification(
            ok=False,
            status="no_match",
            matched_index=-1,
            attempts=native_attempt.attempts,
            test_result=native_result,
            error_text=error_text or "wrong password",
            terminal=False,
        )
