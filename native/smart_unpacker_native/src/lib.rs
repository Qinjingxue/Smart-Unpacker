use pyo3::prelude::*;

mod carrier;
mod directory_scan;
mod magic;
mod util;
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
    m.add_function(wrap_pyfunction!(magic::scan_after_markers, m)?)?;
    m.add_function(wrap_pyfunction!(magic::scan_magics_anywhere, m)?)?;
    m.add_function(wrap_pyfunction!(carrier::scan_carrier_archive, m)?)?;
    m.add_function(wrap_pyfunction!(
        zip_names::scan_zip_central_directory_names,
        m
    )?)?;
    m.add_function(wrap_pyfunction!(directory_scan::scan_directory_entries, m)?)?;
    Ok(())
}
