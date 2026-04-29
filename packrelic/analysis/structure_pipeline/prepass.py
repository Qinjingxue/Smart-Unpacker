from packrelic.analysis.view import SharedBinaryView


DEFAULT_HEAD_BYTES = 1024 * 1024
DEFAULT_TAIL_BYTES = 1024 * 1024
KNOWN_SIGNATURES = {
    "zip_local": b"PK\x03\x04",
    "zip_eocd": b"PK\x05\x06",
    "rar4": b"Rar!\x1a\x07\x00",
    "rar5": b"Rar!\x1a\x07\x01\x00",
    "7z": b"7z\xbc\xaf\x27\x1c",
    "gzip": b"\x1f\x8b\x08",
    "bzip2": b"BZh",
    "xz": b"\xfd7zXZ\x00",
    "zstd": b"\x28\xb5\x2f\xfd",
    "tar_ustar": b"ustar",
}


def run_signature_prepass(view: SharedBinaryView, config: dict | None = None) -> dict:
    config = config or {}
    head_size = int(config.get("head_bytes", DEFAULT_HEAD_BYTES) or DEFAULT_HEAD_BYTES)
    tail_size = int(config.get("tail_bytes", DEFAULT_TAIL_BYTES) or DEFAULT_TAIL_BYTES)
    return view.signature_prepass(head_bytes=head_size, tail_bytes=tail_size)
