from __future__ import annotations

from sunpack.repair.model.diagnosis.semantic_format_graph import (
    SemanticFormatDiagnosisGraphPlugin,
    SemanticFormatGraphDefinition,
    dependency,
    field,
)


SPECIFICATION = "https://github.com/facebook/zstd/blob/dev/doc/zstd_compression_format.md"

DEFINITION = SemanticFormatGraphDefinition(
    format_name="zstd",
    specification=SPECIFICATION,
    payload_keys=("zstd_structure_features", "compression_stream_structure"),
    fields=(
        field("frame.magic", "frame_header", "zstd_magic", "magic", "magic_matched"),
        field("frame.header.descriptor", "frame_header", "zstd_frame_descriptor", "frame_descriptor", "descriptor"),
        field("frame.header.content_size_flag", "frame_header", "zstd_flag_field", "content_size_flag", "fcs_flag"),
        field("frame.header.single_segment_flag", "frame_header", "zstd_flag_field", "single_segment"),
        field("frame.header.checksum_flag", "frame_header", "zstd_flag_field", "checksum_flag"),
        field("frame.header.dictionary_id_flag", "frame_header", "zstd_flag_field", "dictionary_id_flag"),
        field("frame.header.window_descriptor", "frame_header", "zstd_window_field", "window_descriptor", "window_size"),
        field("frame.header.dictionary_id", "frame_header", "zstd_dictionary_field", "dictionary_id", "dict_id"),
        field("frame.header.content_size", "frame_header", "zstd_size_field", "content_size", "frame_content_size"),
        field("block.header.last_block", "block_header", "zstd_flag_field", "last_block"),
        field("block.header.type", "block_header", "zstd_block_type", "block_type"),
        field("block.header.size", "block_header", "zstd_size_field", "block_size"),
        field("block.content", "block_data", "zstd_block_payload", "block_content", "payload"),
        field("block.literals", "compressed_block", "zstd_literals_section", "literals", "huffman"),
        field("block.sequences", "compressed_block", "zstd_sequences_section", "sequences", "fse"),
        field("block.previous_window", "compression_state", "zstd_history_window", "previous_data", "history", "window"),
        field("block.previous_entropy_tables", "compression_state", "zstd_entropy_state", "repeat_mode", "previous_tables"),
        field("frame.decoded_content", "decoded_content", "zstd_decoded_payload", "decoded", "uncompressed"),
        field("frame.content_checksum", "frame_checksum", "zstd_checksum_field", "content_checksum", "checksum"),
        field("frame.sequence", "frame_chain", "zstd_frame_sequence", "frame_count", "multiframe"),
        field("skippable.magic", "skippable_frame", "zstd_skippable_magic", "skippable_magic"),
        field("skippable.frame_size", "skippable_frame", "zstd_size_field", "skippable_size", "frame_size"),
        field("skippable.user_data", "skippable_frame", "zstd_skippable_payload", "user_data"),
        field("archive.trailing_data", "boundary", "zstd_trailing_data", "trailing_junk"),
    ),
    dependencies=(
        dependency("frame.magic", "frame.header.descriptor", "precedes"),
        dependency("frame.header.descriptor", "frame.header.content_size_flag", "encodes"),
        dependency("frame.header.descriptor", "frame.header.single_segment_flag", "encodes"),
        dependency("frame.header.descriptor", "frame.header.checksum_flag", "encodes"),
        dependency("frame.header.descriptor", "frame.header.dictionary_id_flag", "encodes"),
        dependency("frame.header.single_segment_flag", "frame.header.window_descriptor", "gates_absence"),
        dependency("frame.header.single_segment_flag", "frame.header.content_size", "requires_presence"),
        dependency("frame.header.content_size_flag", "frame.header.content_size", "determines_field_size"),
        dependency("frame.header.dictionary_id_flag", "frame.header.dictionary_id", "determines_field_size"),
        dependency("frame.header.window_descriptor", "block.header.size", "limits_block_size"),
        dependency("frame.header.dictionary_id", "block.previous_window", "seeds_history"),
        dependency("frame.header.dictionary_id", "block.previous_entropy_tables", "seeds_entropy_tables"),
        dependency("block.header.type", "block.header.size", "defines_size_semantics"),
        dependency("block.header.size", "block.content", "bounds"),
        dependency("block.header.type", "block.literals", "selects_compressed_layout"),
        dependency("block.header.type", "block.sequences", "selects_compressed_layout"),
        dependency("block.literals", "block.sequences", "feeds_sequence_execution"),
        dependency("block.previous_window", "block.sequences", "resolves_offsets"),
        dependency("block.previous_entropy_tables", "block.literals", "decodes_repeat_mode"),
        dependency("block.previous_entropy_tables", "block.sequences", "decodes_repeat_mode"),
        dependency("block.content", "frame.decoded_content", "decodes_to"),
        dependency("block.header.last_block", "frame.content_checksum", "locates_after_last_block"),
        dependency("frame.header.checksum_flag", "frame.content_checksum", "gates_presence"),
        dependency("frame.content_checksum", "frame.decoded_content", "validates_xxh64_low32"),
        dependency("frame.header.content_size", "frame.decoded_content", "matches_size"),
        dependency("frame.sequence", "frame.magic", "orders_independent_frames"),
        dependency("skippable.magic", "skippable.frame_size", "selects_skippable_layout"),
        dependency("skippable.frame_size", "skippable.user_data", "bounds"),
        dependency("frame.sequence", "archive.trailing_data", "bounds_archive"),
    ),
    flag_roots={
        "zstd_frame_bad": ("frame.header.descriptor", "block.header.type", "block.header.size"),
        "trailing_junk": ("archive.trailing_data", "frame.sequence"),
        "probably_truncated": ("block.header.last_block", "frame.content_checksum"),
        "zstd_multiframe_damage": ("frame.sequence", "frame.magic"),
        "zstd_reserved_bit_set": ("frame.header.descriptor",),
        "zstd_window_descriptor_missing": ("frame.header.single_segment_flag", "frame.header.window_descriptor"),
        "zstd_checksum_bad": ("frame.content_checksum",),
    },
)


def get_diagnosis_graph_plugin() -> SemanticFormatDiagnosisGraphPlugin:
    return SemanticFormatDiagnosisGraphPlugin(DEFINITION)
