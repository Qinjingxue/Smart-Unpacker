use pyo3::prelude::*;

mod analysis;
mod archive_deep_repair;
mod archive_state_ops;
mod binary_profile;
mod carrier;
mod compression_stream_repair;
mod directory_scan;
mod file_crc;
mod format_structure;
mod magic;
mod password_7z;
mod password_input;
mod password_rar;
mod password_zip;
mod pe_overlay;
mod postprocess_ops;
mod relations;
mod repair_io;
mod scene_semantics;
mod util;
mod zip_deep_repair;
mod zip_names;

#[cfg(test)]
mod test_support {
    use std::fs;
    use std::path::PathBuf;
    use std::time::{SystemTime, UNIX_EPOCH};

    pub(crate) fn temp_file(name: &str, contents: &[u8]) -> PathBuf {
        let nonce = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("time should be monotonic enough for tests")
            .as_nanos();
        let path = std::env::temp_dir().join(format!("sunpack_native_{name}_{nonce}.bin"));
        fs::write(&path, contents).expect("write test file");
        path
    }
}

#[pyfunction]
fn native_available() -> bool {
    true
}

#[pyfunction]
fn scanner_version() -> &'static str {
    env!("CARGO_PKG_VERSION")
}

#[pymodule]
fn sunpack_native(m: &Bound<'_, PyModule>) -> PyResult<()> {
    m.add_function(wrap_pyfunction!(native_available, m)?)?;
    m.add_function(wrap_pyfunction!(scanner_version, m)?)?;
    m.add_class::<analysis::AnalysisBinaryView>()?;
    m.add_class::<analysis::AnalysisMultiVolumeView>()?;
    m.add_function(wrap_pyfunction!(magic::scan_after_markers, m)?)?;
    m.add_function(wrap_pyfunction!(magic::scan_magics_anywhere, m)?)?;
    m.add_function(wrap_pyfunction!(
        binary_profile::fuzzy_binary_profile_for_paths,
        m
    )?)?;
    m.add_function(wrap_pyfunction!(carrier::scan_carrier_archive, m)?)?;
    m.add_function(wrap_pyfunction!(
        zip_names::scan_zip_central_directory_names,
        m
    )?)?;
    m.add_function(wrap_pyfunction!(directory_scan::scan_directory_entries, m)?)?;
    m.add_function(wrap_pyfunction!(
        scene_semantics::scene_semantics_payloads,
        m
    )?)?;
    m.add_function(wrap_pyfunction!(
        directory_scan::list_regular_files_in_directory,
        m
    )?)?;
    m.add_function(wrap_pyfunction!(directory_scan::batch_file_head_facts, m)?)?;
    m.add_function(wrap_pyfunction!(relations::relations_detect_split_role, m)?)?;
    m.add_function(wrap_pyfunction!(relations::relations_logical_name, m)?)?;
    m.add_function(wrap_pyfunction!(
        relations::relations_parse_numbered_volume,
        m
    )?)?;
    m.add_function(wrap_pyfunction!(relations::relations_split_sort_key, m)?)?;
    m.add_function(wrap_pyfunction!(
        relations::relations_build_candidate_groups,
        m
    )?)?;
    m.add_function(wrap_pyfunction!(directory_scan::scan_output_tree, m)?)?;
    m.add_function(wrap_pyfunction!(
        file_crc::compute_directory_crc_manifest,
        m
    )?)?;
    m.add_function(wrap_pyfunction!(
        file_crc::match_archive_output_crc_coverage,
        m
    )?)?;
    m.add_function(wrap_pyfunction!(file_crc::sample_directory_readability, m)?)?;
    m.add_function(wrap_pyfunction!(
        format_structure::inspect_zip_local_header,
        m
    )?)?;
    m.add_function(wrap_pyfunction!(
        format_structure::inspect_zip_eocd_structure,
        m
    )?)?;
    m.add_function(wrap_pyfunction!(
        format_structure::inspect_seven_zip_structure,
        m
    )?)?;
    m.add_function(wrap_pyfunction!(
        format_structure::inspect_rar_structure,
        m
    )?)?;
    m.add_function(wrap_pyfunction!(
        format_structure::inspect_tar_header_structure,
        m
    )?)?;
    m.add_function(wrap_pyfunction!(
        format_structure::inspect_compression_stream_structure,
        m
    )?)?;
    m.add_function(wrap_pyfunction!(
        format_structure::inspect_archive_container_structure,
        m
    )?)?;
    m.add_function(wrap_pyfunction!(
        pe_overlay::inspect_pe_overlay_structure,
        m
    )?)?;
    m.add_function(wrap_pyfunction!(postprocess_ops::scan_watch_candidates, m)?)?;
    m.add_function(wrap_pyfunction!(
        postprocess_ops::watch_candidate_for_path,
        m
    )?)?;
    m.add_function(wrap_pyfunction!(
        postprocess_ops::flatten_single_branch_directories,
        m
    )?)?;
    m.add_function(wrap_pyfunction!(postprocess_ops::delete_files_batch, m)?)?;
    m.add_function(wrap_pyfunction!(
        password_7z::seven_zip_fast_verify_passwords,
        m
    )?)?;
    m.add_function(wrap_pyfunction!(
        password_7z::seven_zip_fast_verify_passwords_from_ranges,
        m
    )?)?;
    m.add_function(wrap_pyfunction!(
        password_rar::rar_fast_verify_passwords,
        m
    )?)?;
    m.add_function(wrap_pyfunction!(
        password_rar::rar_fast_verify_passwords_from_ranges,
        m
    )?)?;
    m.add_function(wrap_pyfunction!(
        password_zip::zip_fast_verify_passwords,
        m
    )?)?;
    m.add_function(wrap_pyfunction!(
        password_zip::zip_fast_verify_passwords_from_ranges,
        m
    )?)?;
    m.add_function(wrap_pyfunction!(repair_io::repair_read_file_range, m)?)?;
    m.add_function(wrap_pyfunction!(
        repair_io::repair_concat_ranges_to_bytes,
        m
    )?)?;
    m.add_function(wrap_pyfunction!(repair_io::repair_write_candidate, m)?)?;
    m.add_function(wrap_pyfunction!(repair_io::repair_copy_range_to_file, m)?)?;
    m.add_function(wrap_pyfunction!(
        repair_io::repair_concat_ranges_to_file,
        m
    )?)?;
    m.add_function(wrap_pyfunction!(repair_io::repair_patch_file, m)?)?;
    m.add_function(wrap_pyfunction!(
        archive_state_ops::archive_state_to_bytes_native,
        m
    )?)?;
    m.add_function(wrap_pyfunction!(
        archive_state_ops::archive_state_size_native,
        m
    )?)?;
    m.add_function(wrap_pyfunction!(
        archive_state_ops::archive_state_write_to_file_native,
        m
    )?)?;
    m.add_function(wrap_pyfunction!(
        archive_state_ops::archive_state_zip_manifest_native,
        m
    )?)?;
    m.add_function(wrap_pyfunction!(
        zip_deep_repair::zip_deep_partial_recovery,
        m
    )?)?;
    m.add_function(wrap_pyfunction!(
        zip_deep_repair::zip_rebuild_from_local_headers,
        m
    )?)?;
    m.add_function(wrap_pyfunction!(
        zip_deep_repair::zip_directory_field_repair,
        m
    )?)?;
    m.add_function(wrap_pyfunction!(
        zip_deep_repair::zip_conflict_resolver_rebuild,
        m
    )?)?;
    m.add_function(wrap_pyfunction!(
        compression_stream_repair::gzip_footer_fix_repair,
        m
    )?)?;
    m.add_function(wrap_pyfunction!(
        compression_stream_repair::gzip_deflate_member_resync_repair,
        m
    )?)?;
    m.add_function(wrap_pyfunction!(
        compression_stream_repair::zstd_frame_salvage_repair,
        m
    )?)?;
    m.add_function(wrap_pyfunction!(
        compression_stream_repair::tar_boundary_repair,
        m
    )?)?;
    m.add_function(wrap_pyfunction!(
        compression_stream_repair::tar_sparse_pax_longname_repair,
        m
    )?)?;
    m.add_function(wrap_pyfunction!(
        compression_stream_repair::compression_stream_partial_recovery,
        m
    )?)?;
    m.add_function(wrap_pyfunction!(
        compression_stream_repair::compression_stream_trailing_junk_trim,
        m
    )?)?;
    m.add_function(wrap_pyfunction!(
        compression_stream_repair::tar_compressed_partial_recovery,
        m
    )?)?;
    m.add_function(wrap_pyfunction!(
        compression_stream_repair::tar_metadata_downgrade_recovery,
        m
    )?)?;
    m.add_function(wrap_pyfunction!(
        archive_deep_repair::archive_carrier_crop_recovery,
        m
    )?)?;
    m.add_function(wrap_pyfunction!(
        archive_deep_repair::seven_zip_precise_boundary_repair,
        m
    )?)?;
    m.add_function(wrap_pyfunction!(
        archive_deep_repair::seven_zip_crc_field_repair,
        m
    )?)?;
    m.add_function(wrap_pyfunction!(
        archive_deep_repair::seven_zip_next_header_field_repair,
        m
    )?)?;
    m.add_function(wrap_pyfunction!(
        archive_deep_repair::seven_zip_solid_block_partial_salvage,
        m
    )?)?;
    m.add_function(wrap_pyfunction!(
        archive_deep_repair::rar_file_quarantine_rebuild,
        m
    )?)?;
    m.add_function(wrap_pyfunction!(
        archive_deep_repair::archive_nested_payload_salvage,
        m
    )?)?;
    m.add_function(wrap_pyfunction!(
        archive_deep_repair::rar_block_chain_trim_recovery,
        m
    )?)?;
    m.add_function(wrap_pyfunction!(
        archive_deep_repair::rar_end_block_repair,
        m
    )?)?;
    Ok(())
}
