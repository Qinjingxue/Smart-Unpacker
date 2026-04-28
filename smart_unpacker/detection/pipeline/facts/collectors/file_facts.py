from smart_unpacker_native import batch_file_head_facts as _native_batch_file_head_facts

from smart_unpacker.detection.pipeline.facts.registry import register_batch_fact, register_fact
from smart_unpacker.support.path_keys import path_key

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
    scan_session = getattr(context, "scan_session", None)
    base_path = context.fact_bag.get("file.path") or context.base_path
    if scan_session is not None:
        facts = scan_session.file_head_facts_for_path(base_path, magic_size=0)
        size = facts.get("size")
        if isinstance(size, int):
            return size
    rows = _native_batch_file_head_facts([base_path], 0)
    if rows and isinstance(rows[0], dict) and isinstance(rows[0].get("size"), int):
        return int(rows[0]["size"])
    return -1


@register_batch_fact("file.size")
def collect_file_size_batch(context) -> None:
    paths = [
        bag.get("file.path") or ""
        for bag in context.fact_bags
        if bag.get("file.path")
    ]
    if not paths:
        return
    scan_session = getattr(context, "scan_session", None)
    facts_by_key = (
        scan_session.file_head_facts_for_paths(paths, magic_size=0)
        if scan_session is not None
        else {}
    )
    for bag in context.fact_bags:
        path = bag.get("file.path") or ""
        if not path:
            continue
        facts = facts_by_key.get(path_key(path), {})
        size = facts.get("size")
        if isinstance(size, int):
            bag.set(context.fact_name, size)
            continue
        rows = _native_batch_file_head_facts([path], 0)
        if rows and isinstance(rows[0], dict) and isinstance(rows[0].get("size"), int):
            bag.set(context.fact_name, int(rows[0]["size"]))
        else:
            bag.set(context.fact_name, -1)
