from __future__ import annotations

from sunpack.repair.model.diagnosis.semantic_format_graph import (
    SemanticFormatDiagnosisGraphPlugin,
    SemanticFormatGraphDefinition,
    dependency,
    field,
)


SPECIFICATION = "https://datatracker.ietf.org/doc/html/rfc1952"

DEFINITION = SemanticFormatGraphDefinition(
    format_name="gzip",
    specification=SPECIFICATION,
    payload_keys=("gzip_structure_features", "compression_stream_structure"),
    fields=(
        field("member.header.magic", "header", "gzip_magic", "magic", "magic_matched"),
        field("member.header.compression_method", "header", "gzip_method", "method", "compression_method"),
        field("member.header.flags", "header", "gzip_flag_field", "flags", "flags_valid"),
        field("member.header.mtime_xfl_os", "header", "gzip_metadata", "mtime", "xfl", "os"),
        field("member.header.extra_length", "optional_header", "gzip_size_field", "xlen", "extra_length"),
        field("member.header.extra", "optional_header", "gzip_extra_field", "extra", "fextra"),
        field("member.header.name", "optional_header", "gzip_name_field", "fname", "name"),
        field("member.header.comment", "optional_header", "gzip_comment_field", "fcomment", "comment"),
        field("member.header.crc16", "optional_header", "gzip_crc_field", "fhcrc", "header_crc", "header_crc16"),
        field("member.deflate.blocks", "payload", "deflate_block_chain", "deflate", "blocks", "payload"),
        field("member.deflate.final_block", "payload", "deflate_final_block", "final_block", "bfinal"),
        field("member.decoded_content", "decoded_content", "gzip_decoded_payload", "decoded", "uncompressed"),
        field("member.trailer.crc32", "trailer", "gzip_crc_field", "crc32", "footer_crc", "trailer_crc"),
        field("member.trailer.isize", "trailer", "gzip_size_field", "isize", "uncompressed_size"),
        field("member.boundary", "boundary", "gzip_member_boundary", "member_end", "segment_end"),
        field("member.next_member", "member_chain", "gzip_member_link", "member_count", "multimember"),
        field("archive.trailing_data", "boundary", "gzip_trailing_data", "trailing_junk", "boundary"),
    ),
    dependencies=(
        dependency("member.header.magic", "member.header.compression_method", "precedes"),
        dependency("member.header.compression_method", "member.deflate.blocks", "selects_decoder"),
        dependency("member.header.flags", "member.header.extra", "gates_fextra"),
        dependency("member.header.flags", "member.header.name", "gates_fname"),
        dependency("member.header.flags", "member.header.comment", "gates_fcomment"),
        dependency("member.header.flags", "member.header.crc16", "gates_fhcrc"),
        dependency("member.header.extra_length", "member.header.extra", "bounds"),
        dependency("member.header.crc16", "member.header.magic", "validates_header"),
        dependency("member.header.crc16", "member.header.flags", "validates_header"),
        dependency("member.header.crc16", "member.header.extra", "validates_header"),
        dependency("member.header.crc16", "member.header.name", "validates_header"),
        dependency("member.header.crc16", "member.header.comment", "validates_header"),
        dependency("member.deflate.blocks", "member.deflate.final_block", "terminates_at"),
        dependency("member.deflate.blocks", "member.decoded_content", "decodes_to"),
        dependency("member.deflate.final_block", "member.trailer.crc32", "precedes"),
        dependency("member.trailer.crc32", "member.decoded_content", "validates"),
        dependency("member.trailer.isize", "member.decoded_content", "matches_size_mod_2_32"),
        dependency("member.trailer.isize", "member.boundary", "locates_member_end"),
        dependency("member.boundary", "member.next_member", "precedes"),
        dependency("member.boundary", "archive.trailing_data", "distinguishes_trailing_data"),
    ),
    flag_roots={
        "gzip_header_crc_bad": ("member.header.crc16",),
        "gzip_reserved_flags_set": ("member.header.flags",),
        "gzip_footer_bad": ("member.trailer.crc32", "member.trailer.isize"),
        "trailing_junk": ("archive.trailing_data", "member.boundary"),
        "probably_truncated": ("member.deflate.final_block", "member.trailer.crc32"),
        "deflate_resync": ("member.deflate.blocks",),
    },
)


def get_diagnosis_graph_plugin() -> SemanticFormatDiagnosisGraphPlugin:
    return SemanticFormatDiagnosisGraphPlugin(DEFINITION)
