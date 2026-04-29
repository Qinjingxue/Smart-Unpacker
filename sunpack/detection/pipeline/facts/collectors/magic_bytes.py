from sunpack_native import batch_file_head_facts as _native_batch_file_head_facts

from sunpack.detection.pipeline.facts.registry import register_batch_fact, register_fact
from sunpack.support.path_keys import path_key

@register_fact(
    "file.magic_bytes",
    type="bytes",
    description="First 16 bytes used by processors and rules for magic signature checks.",
    context=True,
)
def collect_magic_bytes(context) -> bytes:
    base_path = context.fact_bag.get("file.path") or context.base_path
    scan_session = getattr(context, "scan_session", None)
    if scan_session is not None:
        facts = scan_session.file_head_facts_for_path(base_path, magic_size=16)
        magic = facts.get("magic")
        if isinstance(magic, bytes):
            return magic[:16]
    rows = _native_batch_file_head_facts([base_path], 16)
    if rows and isinstance(rows[0], dict) and isinstance(rows[0].get("magic"), bytes):
        return rows[0]["magic"][:16]
    return b""


@register_batch_fact("file.magic_bytes")
def collect_magic_bytes_batch(context) -> None:
    paths = [
        bag.get("file.path") or ""
        for bag in context.fact_bags
        if bag.get("file.path")
    ]
    if not paths:
        return
    scan_session = getattr(context, "scan_session", None)
    facts_by_key = (
        scan_session.file_head_facts_for_paths(paths, magic_size=16)
        if scan_session is not None
        else {}
    )
    for bag in context.fact_bags:
        path = bag.get("file.path") or ""
        if not path:
            continue
        magic = facts_by_key.get(path_key(path), {}).get("magic")
        if isinstance(magic, bytes):
            bag.set(context.fact_name, magic[:16])
            continue
        rows = _native_batch_file_head_facts([path], 16)
        if rows and isinstance(rows[0], dict) and isinstance(rows[0].get("magic"), bytes):
            bag.set(context.fact_name, rows[0]["magic"][:16])
        else:
            bag.set(context.fact_name, b"")
