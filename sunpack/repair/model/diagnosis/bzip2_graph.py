from __future__ import annotations

from sunpack.repair.model.diagnosis.semantic_format_graph import (
    SemanticFormatDiagnosisGraphPlugin,
    SemanticFormatGraphDefinition,
    dependency,
    field,
)


SPECIFICATION = "https://sourceware.org/bzip2/manual/manual.html"

DEFINITION = SemanticFormatGraphDefinition(
    format_name="bzip2",
    specification=SPECIFICATION,
    payload_keys=("bzip2_structure_features", "compression_stream_structure"),
    fields=(
        field("stream.magic", "header", "bzip2_magic", "magic", "magic_matched"),
        field("stream.block_size_100k", "header", "bzip2_block_size", "block_size", "block_size_100k"),
        field("block.marker", "block", "bzip2_block_marker", "block_marker", "marker"),
        field("block.crc32", "block", "bzip2_crc_field", "block_crc", "crc32"),
        field("block.randomized", "block", "bzip2_flag_field", "randomized"),
        field("block.orig_ptr", "block", "bzip2_bwt_pointer", "orig_ptr"),
        field("block.huffman_tables", "entropy", "bzip2_huffman_tables", "huffman", "selectors", "code_lengths"),
        field("block.encoded_data", "block_data", "bzip2_encoded_payload", "encoded_data", "payload"),
        field("block.decoded_content", "decoded_content", "bzip2_decoded_payload", "decoded", "uncompressed"),
        field("block.sequence", "block_chain", "bzip2_block_sequence", "block_count", "blocks"),
        field("stream.end_marker", "boundary", "bzip2_end_marker", "end_marker", "eos"),
        field("stream.combined_crc32", "trailer", "bzip2_crc_field", "combined_crc", "stream_crc"),
        field("archive.trailing_data", "boundary", "bzip2_trailing_data", "trailing_junk"),
    ),
    dependencies=(
        dependency("stream.magic", "stream.block_size_100k", "declares_format"),
        dependency("stream.block_size_100k", "block.encoded_data", "limits_block_capacity"),
        dependency("block.marker", "block.crc32", "precedes"),
        dependency("block.marker", "block.encoded_data", "frames"),
        dependency("block.randomized", "block.encoded_data", "selects_inverse_transform"),
        dependency("block.orig_ptr", "block.encoded_data", "anchors_inverse_bwt"),
        dependency("block.huffman_tables", "block.encoded_data", "decodes"),
        dependency("block.encoded_data", "block.decoded_content", "decodes_to"),
        dependency("block.crc32", "block.decoded_content", "validates"),
        dependency("block.sequence", "block.marker", "orders"),
        dependency("block.sequence", "stream.end_marker", "terminates_at"),
        dependency("stream.combined_crc32", "block.crc32", "folds_in_order"),
        dependency("stream.end_marker", "stream.combined_crc32", "precedes"),
        dependency("stream.end_marker", "archive.trailing_data", "bounds_archive"),
    ),
    flag_roots={
        "bzip2_block_size_bad": ("stream.block_size_100k",),
        "trailing_junk": ("archive.trailing_data", "stream.end_marker"),
        "probably_truncated": ("stream.end_marker", "stream.combined_crc32"),
        "bzip2_block_bad": ("block.marker", "block.crc32", "block.encoded_data"),
    },
)


def get_diagnosis_graph_plugin() -> SemanticFormatDiagnosisGraphPlugin:
    return SemanticFormatDiagnosisGraphPlugin(DEFINITION)
