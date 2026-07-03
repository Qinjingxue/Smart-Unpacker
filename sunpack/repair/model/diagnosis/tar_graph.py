from __future__ import annotations

from sunpack.repair.model.diagnosis.semantic_format_graph import (
    SemanticFormatDiagnosisGraphPlugin,
    SemanticFormatGraphDefinition,
    dependency,
    field,
)


SPECIFICATION = "https://pubs.opengroup.org/onlinepubs/9699919799/utilities/pax.html"

DEFINITION = SemanticFormatGraphDefinition(
    format_name="tar",
    specification=SPECIFICATION,
    payload_keys=("tar_structure_features",),
    fields=(
        field("member.header.name", "member_header", "tar_name_field", "name", "path"),
        field("member.header.mode", "member_header", "tar_mode_field", "mode"),
        field("member.header.uid_gid", "member_header", "tar_owner_field", "uid", "gid"),
        field("member.header.size", "member_header", "tar_size_field", "member_size", "size"),
        field("member.header.mtime", "member_header", "tar_time_field", "mtime"),
        field("member.header.checksum", "member_header", "tar_checksum_field", "checksum", "checksum_ok"),
        field("member.header.typeflag", "member_header", "tar_type_field", "typeflag", "type"),
        field("member.header.linkname", "member_header", "tar_name_field", "linkname"),
        field("member.header.magic_version", "member_header", "tar_magic_field", "ustar", "magic", "version"),
        field("member.header.prefix", "member_header", "tar_name_field", "prefix"),
        field("member.payload.span", "member_payload", "tar_payload_span", "payload_span", "member_size", "segment_end"),
        field("member.payload.data", "member_payload", "tar_payload", "payload", "data"),
        field("member.padding", "member_padding", "tar_padding", "padding", "aligned_size"),
        field("member.next_header", "member_chain", "tar_member_link", "entries_checked", "entry_walk_ok"),
        field("pax.header.length", "pax_metadata", "tar_pax_length", "pax_length"),
        field("pax.header.records", "pax_metadata", "tar_pax_records", "pax", "extended_header"),
        field("pax.target_member", "pax_metadata", "tar_member_link", "pax_target"),
        field("gnu.longname", "gnu_metadata", "tar_gnu_longname", "longname", "longlink"),
        field("gnu.target_member", "gnu_metadata", "tar_member_link", "gnu_target"),
        field("sparse.map", "sparse_metadata", "tar_sparse_map", "sparse", "sparse_map"),
        field("sparse.payload", "sparse_metadata", "tar_sparse_payload", "sparse_payload"),
        field("archive.end_zero_blocks", "boundary", "tar_end_marker", "end_zero_blocks", "zero_blocks"),
        field("archive.trailing_data", "boundary", "tar_trailing_data", "trailing_junk", "boundary_confidence"),
    ),
    dependencies=(
        dependency("member.header.checksum", "member.header.name", "validates"),
        dependency("member.header.checksum", "member.header.size", "validates"),
        dependency("member.header.checksum", "member.header.typeflag", "validates"),
        dependency("member.header.checksum", "member.header.magic_version", "validates"),
        dependency("member.header.prefix", "member.header.name", "composes_path"),
        dependency("member.header.typeflag", "member.payload.data", "selects_payload_semantics"),
        dependency("member.header.typeflag", "member.header.linkname", "gates_link_target"),
        dependency("member.header.size", "member.payload.span", "bounds"),
        dependency("member.payload.span", "member.payload.data", "contains"),
        dependency("member.payload.span", "member.padding", "aligns_to_512"),
        dependency("member.padding", "member.next_header", "precedes"),
        dependency("member.next_header", "archive.end_zero_blocks", "terminates_at"),
        dependency("archive.end_zero_blocks", "archive.trailing_data", "bounds_archive"),
        dependency("pax.header.length", "pax.header.records", "bounds"),
        dependency("pax.header.records", "pax.target_member", "overrides_next_header"),
        dependency("pax.target_member", "member.header.name", "overrides"),
        dependency("pax.target_member", "member.header.size", "overrides"),
        dependency("gnu.longname", "gnu.target_member", "applies_to_next_header"),
        dependency("gnu.target_member", "member.header.name", "overrides"),
        dependency("sparse.map", "sparse.payload", "describes_extents"),
        dependency("sparse.payload", "member.payload.data", "reconstructs"),
    ),
    flag_roots={
        "tar_checksum_bad": ("member.header.checksum",),
        "pax_header_bad": ("pax.header.length", "pax.header.records"),
        "gnu_longname_bad": ("gnu.longname", "gnu.target_member"),
        "sparse_header_bad": ("sparse.map",),
        "missing_end_block": ("archive.end_zero_blocks",),
        "trailing_junk": ("archive.trailing_data",),
        "probably_truncated": ("member.payload.span", "member.next_header", "archive.end_zero_blocks"),
    },
)


def get_diagnosis_graph_plugin() -> SemanticFormatDiagnosisGraphPlugin:
    return SemanticFormatDiagnosisGraphPlugin(DEFINITION)
