use pyo3::prelude::*;

mod analysis;
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
mod repair_io;
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
        let path = std::env::temp_dir().join(format!("smart_unpacker_native_{name}_{nonce}.bin"));
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
fn smart_unpacker_native(m: &Bound<'_, PyModule>) -> PyResult<()> {
    m.add_function(wrap_pyfunction!(native_available, m)?)?;
    m.add_function(wrap_pyfunction!(scanner_version, m)?)?;
    m.add_class::<analysis::AnalysisBinaryView>()?;
    m.add_function(wrap_pyfunction!(magic::scan_after_markers, m)?)?;
    m.add_function(wrap_pyfunction!(magic::scan_magics_anywhere, m)?)?;
    m.add_function(wrap_pyfunction!(carrier::scan_carrier_archive, m)?)?;
    m.add_function(wrap_pyfunction!(
        zip_names::scan_zip_central_directory_names,
        m
    )?)?;
    m.add_function(wrap_pyfunction!(directory_scan::scan_directory_entries, m)?)?;
    m.add_function(wrap_pyfunction!(
        directory_scan::list_regular_files_in_directory,
        m
    )?)?;
    m.add_function(wrap_pyfunction!(
        file_crc::compute_directory_crc_manifest,
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
        zip_deep_repair::zip_deep_partial_recovery,
        m
    )?)?;
    m.add_function(wrap_pyfunction!(
        compression_stream_repair::compression_stream_partial_recovery,
        m
    )?)?;
    Ok(())
}
