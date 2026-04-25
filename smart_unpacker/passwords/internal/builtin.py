from smart_unpacker.passwords.internal.lists import read_password_file
from smart_unpacker.support.resources import find_resource_path, get_resource_path


DEFAULT_BUILTIN_PASSWORDS = ["123456", "123", "0000", "789"]


def get_builtin_passwords() -> list[str]:
    builtin_path = find_resource_path("builtin_passwords.txt") or get_resource_path("builtin_passwords.txt")
    if not builtin_path.exists():
        try:
            builtin_path.parent.mkdir(parents=True, exist_ok=True)
            with open(builtin_path, "w", encoding="utf-8") as handle:
                handle.write("# 此文件为内置高频密码配置表，用户可自行编辑，每行一个密码。\n")
                for password in DEFAULT_BUILTIN_PASSWORDS:
                    handle.write(password + "\n")
        except Exception:
            pass
        return list(DEFAULT_BUILTIN_PASSWORDS)

    try:
        passwords = read_password_file(str(builtin_path))
    except Exception:
        return list(DEFAULT_BUILTIN_PASSWORDS)
    return passwords or list(DEFAULT_BUILTIN_PASSWORDS)
