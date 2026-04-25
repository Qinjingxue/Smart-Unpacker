import os
from smart_unpacker.detection.pipeline.facts.registry import register_fact

@register_fact(
    "file.path",
    type="str",
    description="Absolute or normalized path of the candidate file.",
)
def collect_file_path(base_path: str) -> str:
    return base_path

@register_fact(
    "file.size",
    type="int",
    description="File size in bytes, or -1 if unavailable.",
    context=True,
)
def collect_file_size(context) -> int:
    existing = context.fact_bag.get("file.size")
    if isinstance(existing, int):
        return existing
    base_path = context.fact_bag.get("file.path") or context.base_path
    try:
        return os.path.getsize(base_path)
    except OSError:
        return -1
