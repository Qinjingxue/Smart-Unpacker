from __future__ import annotations

from sunpack.repair.model.diagnosis.semantic_format_graph import (
    SemanticFormatDiagnosisGraphPlugin,
    SemanticFormatGraphDefinition,
    dependency,
    field,
)


SPECIFICATION = "https://www.rarlab.com/technote.htm"

DEFINITION = SemanticFormatGraphDefinition(
    format_name="rar",
    specification=SPECIFICATION,
    payload_keys=("rar_structure_features",),
    fields=(
        field("archive.signature", "signature", "rar_signature", "magic", "signature", "version"),
        field("block.header_crc32", "block_header", "rar_crc_field", "header_crc", "crc_ok", "header_crc_ok"),
        field("block.header_size", "block_header", "rar_size_field", "header_size", "block_size"),
        field("block.header_type", "block_header", "rar_type_field", "header_type", "block_type"),
        field("block.header_flags", "block_header", "rar_flag_field", "header_flags", "block_flags"),
        field("block.extra_area", "extra_area", "rar_extra_area", "extra_area", "extra_size"),
        field("block.data_area", "data_area", "rar_data_area", "data_area", "data_size", "packed_size"),
        field("block.sequence", "block_chain", "rar_block_sequence", "blocks_checked", "segment_end"),
        field("main_header.flags", "main_header", "rar_flag_field", "main_flags", "main_header_flags"),
        field("main_header.extra_area", "main_header", "rar_extra_area", "main_extra", "main_header_extra"),
        field("main_header.locator.quick_open_offset", "locator", "rar_offset_field", "quick_open_offset"),
        field("main_header.locator.recovery_offset", "locator", "rar_offset_field", "recovery_offset"),
        field("file_header.flags", "file_header", "rar_flag_field", "file_flags", "file_header_flags"),
        field("file_header.unpacked_size", "file_header", "rar_size_field", "unpacked_size"),
        field("file_header.data_crc32", "file_header", "rar_crc_field", "data_crc", "file_crc"),
        field("file_header.compression_info", "file_header", "rar_compression_field", "compression_info", "method", "solid"),
        field("file_header.name_size", "file_header", "rar_size_field", "name_size", "name_length"),
        field("file_header.name", "file_header", "rar_name_field", "file_name", "name"),
        field("file_header.extra_area", "file_header", "rar_extra_area", "file_extra"),
        field("file_data.packed_span", "file_data", "rar_payload_span", "packed_size", "data_span", "payload_span"),
        field("file_data.decoded_content", "file_data", "rar_decoded_payload", "decoded_size", "unpacked_data"),
        field("service_header", "service_header", "rar_service_header", "service_block", "service_header"),
        field("encryption_header", "encryption", "rar_encryption_header", "encryption_header", "encrypted"),
        field("end_header.flags", "end_header", "rar_flag_field", "end_flags", "end_block_found"),
        field("volume.parts", "multipart", "rar_volume_chain", "volume", "parts", "split"),
    ),
    dependencies=(
        dependency("archive.signature", "main_header.flags", "precedes"),
        dependency("block.header_size", "block.extra_area", "bounds"),
        dependency("block.header_size", "block.data_area", "locates_after_header"),
        dependency("block.header_type", "block.header_flags", "selects_layout"),
        dependency("block.header_flags", "block.extra_area", "gates_presence"),
        dependency("block.header_flags", "block.data_area", "gates_presence"),
        dependency("block.header_crc32", "block.header_size", "validates"),
        dependency("block.header_crc32", "block.header_type", "validates"),
        dependency("block.header_crc32", "block.header_flags", "validates"),
        dependency("block.header_crc32", "block.extra_area", "validates"),
        dependency("block.sequence", "end_header.flags", "terminates_at"),
        dependency("main_header.flags", "main_header.extra_area", "gates_presence"),
        dependency("main_header.locator.quick_open_offset", "service_header", "points_to"),
        dependency("main_header.locator.recovery_offset", "service_header", "points_to"),
        dependency("file_header.flags", "file_header.data_crc32", "gates_presence"),
        dependency("file_header.flags", "file_header.extra_area", "gates_presence"),
        dependency("file_header.flags", "file_data.packed_span", "continues_across_volumes"),
        dependency("file_header.name_size", "file_header.name", "bounds"),
        dependency("file_header.compression_info", "file_data.packed_span", "decodes"),
        dependency("file_header.unpacked_size", "file_data.decoded_content", "matches_size"),
        dependency("file_header.data_crc32", "file_data.decoded_content", "validates"),
        dependency("file_data.packed_span", "file_data.decoded_content", "decodes_to"),
        dependency("volume.parts", "file_header.flags", "constrains_split_flags"),
        dependency("encryption_header", "file_data.packed_span", "decrypts_before_decode"),
    ),
    flag_roots={
        "rar_main_header_crc_bad": ("block.header_crc32", "main_header.flags"),
        "rar_file_header_crc_bad": ("block.header_crc32", "file_header.flags"),
        "rar_service_header_crc_bad": ("block.header_crc32", "service_header"),
        "rar_end_header_crc_bad": ("block.header_crc32", "end_header.flags"),
        "missing_end_block": ("end_header.flags", "block.sequence"),
        "trailing_junk": ("end_header.flags",),
        "carrier_prefix": ("archive.signature",),
        "rar_file_block_bad": ("file_data.packed_span", "file_header.data_crc32"),
        "rar_service_block_bad": ("service_header", "block.header_crc32"),
    },
)


def get_diagnosis_graph_plugin() -> SemanticFormatDiagnosisGraphPlugin:
    return SemanticFormatDiagnosisGraphPlugin(DEFINITION)
