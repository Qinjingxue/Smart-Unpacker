import os
from smart_unpacker.detection.pipeline.facts.registry import register_fact

@register_fact(
    "file.magic_bytes",
    type="bytes",
    description="First 16 bytes used by processors and rules for magic signature checks.",
)
def collect_magic_bytes(base_path: str) -> bytes:
    try:
        with open(base_path, "rb") as f:
            return f.read(16)
    except OSError:
        return b""
