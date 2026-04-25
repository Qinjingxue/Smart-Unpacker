import io
import zipfile
from pathlib import Path
from typing import Any


def build_files(root: Path, arrange: dict[str, Any] | None) -> Path:
    root.mkdir(parents=True, exist_ok=True)
    if not arrange:
        return root

    for directory in arrange.get("dirs", []):
        (root / directory).mkdir(parents=True, exist_ok=True)

    for file_spec in arrange.get("files", []):
        path = root / file_spec["path"]
        path.parent.mkdir(parents=True, exist_ok=True)
        content = file_spec.get("content", "")
        path.write_bytes(render_content(content))
    return root


def render_content(content: Any) -> bytes:
    if isinstance(content, str):
        return content.encode("utf-8")
    if isinstance(content, list):
        return b"".join(render_content(part) for part in content)
    if not isinstance(content, dict):
        raise TypeError(f"Unsupported file content: {content!r}")

    content_type = content.get("type", "text")
    if content_type == "text":
        return content.get("value", "").encode(content.get("encoding", "utf-8"))
    if content_type == "hex":
        return bytes.fromhex(content["value"])
    if content_type == "repeat":
        return render_content(content["value"]) * int(content["count"])
    if content_type == "zip":
        return make_zip(content.get("entries", {}))
    if content_type == "zip_with_prefix":
        return bytes.fromhex(content.get("prefix_hex", "")) + make_zip(content.get("entries", {}))
    if content_type == "parts":
        return b"".join(render_content(part) for part in content.get("items", []))
    raise ValueError(f"Unknown content type: {content_type}")


def make_zip(entries: dict[str, str]) -> bytes:
    buffer = io.BytesIO()
    with zipfile.ZipFile(buffer, "w", zipfile.ZIP_STORED) as archive:
        for name, value in entries.items():
            archive.writestr(name, value)
    return buffer.getvalue()
