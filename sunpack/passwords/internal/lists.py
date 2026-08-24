from typing import List

from sunpack.support.resource_lifecycle import open_task_file


def parse_password_lines(text: str) -> List[str]:
    return [
        line.strip()
        for line in (text or "").splitlines()
        if line.strip() and not line.lstrip().startswith("#")
    ]


def read_password_file(password_file: str) -> List[str]:
    with open_task_file(password_file, "r", encoding="utf-8") as handle:
        return parse_password_lines(handle.read())


def dedupe_passwords(passwords: List[str]) -> List[str]:
    deduped_passwords = []
    seen = set()
    for password in passwords:
        if password not in seen:
            seen.add(password)
            deduped_passwords.append(password)
    return deduped_passwords
