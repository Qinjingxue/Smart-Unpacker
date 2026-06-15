from __future__ import annotations

ROOT_CASE_SEMANTICS = "repair_actionable_root_v2"

ROOT_CASES: tuple[str, ...] = (
    "eocd.cd_offset",
    "eocd.cd_size",
    "eocd.entry_count",
    "eocd.comment_length",
    "central_directory.local_header_offset",
    "central_directory.flags",
    "central_directory.crc",
    "central_directory.compressed_size",
    "local_header.signature",
    "local_header.flags",
    "local_header.crc",
    "local_header.compressed_size",
    "compression_method",
    "entry_name",
    "generic_extra_field",
    "data_descriptor.record",
    "data_descriptor.crc",
    "data_descriptor.size",
    "payload.compressed_data",
    "zip64.eocd",
    "zip64.locator",
    "zip64.extra_length",
    "zip64.uncompressed_size",
    "tail.trailing_bytes",
    "sfx_prefix.bytes",
    "split_volume.missing_range",
)

ROOT_CASE_SET = set(ROOT_CASES)
ROOT_CASE_INDEX = {label: index for index, label in enumerate(ROOT_CASES)}

FIELD_TO_ROOT_CASE: dict[str, str] = {
    label: label for label in ROOT_CASES if "." in label
}
FIELD_TO_ROOT_CASE.update({
    "central_directory.method": "compression_method",
    "local_header.method": "compression_method",
    "central_directory.filename": "entry_name",
    "local_header.filename": "entry_name",
    "central_directory.extra": "generic_extra_field",
    "local_header.extra": "generic_extra_field",
    "central_directory.extra_length": "generic_extra_field",
    "local_header.extra_length": "generic_extra_field",
    # ZIP64 extra is a typed override container. In the current repair roots,
    # its corruptible value body belongs to the concrete ZIP64 value root,
    # while generic_extra_field is reserved for ordinary local/CD extra TLV
    # structure damage.
    "zip64.extra": "zip64.uncompressed_size",
})

IGNORED_ROOT_FIELDS = {
    "central_directory.header",
    "central_directory.metadata",
    "central_directory.external_attributes",
    "local_header.header",
    "local_header.metadata",
    "payload.crc_region",
    "payload.span",
    "central_directory.span",
    "central_directory.entry_count",
    "tail.comment",
    "eocd.comment",
}


def canonical_root_case(value: str) -> str:
    text = str(value or "")
    if text.startswith("field:"):
        text = text.split(":", 1)[1]
    if text.startswith("cause:root_case:"):
        text = text.rsplit(":", 1)[-1]
    if text in ROOT_CASE_SET:
        return text
    if text in IGNORED_ROOT_FIELDS:
        return ""
    return FIELD_TO_ROOT_CASE.get(text, "")


def root_case_label(value: str) -> str:
    root = canonical_root_case(value)
    return f"root_case:{root}" if root else ""
