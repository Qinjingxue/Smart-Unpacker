use pyo3::exceptions::{PyOSError, PyRuntimeError};
use pyo3::prelude::*;
use pyo3::types::PyDict;
use std::path::Path;

#[derive(Debug)]
pub(crate) struct WatchFileObservation {
    pub(crate) file_id: String,
    pub(crate) change_usn: i64,
    pub(crate) change_reasons: u32,
    pub(crate) change_reasons_without_close: u32,
    pub(crate) change_reasons_known: bool,
    pub(crate) change_reason_error: String,
}

#[cfg(windows)]
mod windows;

#[cfg(windows)]
pub(crate) fn watch_file_observation(
    path: &Path,
    since_usn: Option<i64>,
) -> PyResult<WatchFileObservation> {
    windows::watch_file_observation(path, since_usn).map_err(os_error)
}

#[cfg(not(windows))]
pub(crate) fn watch_file_observation(
    _path: &Path,
    _since_usn: Option<i64>,
) -> PyResult<WatchFileObservation> {
    Err(PyRuntimeError::new_err("watch mode requires Windows NTFS"))
}

#[pyfunction]
pub(crate) fn watch_filesystem_type(path: &str) -> PyResult<String> {
    #[cfg(windows)]
    {
        return windows::filesystem_type(Path::new(path)).map_err(os_error);
    }
    #[cfg(not(windows))]
    {
        let _ = path;
        Err(PyRuntimeError::new_err("watch mode requires Windows NTFS"))
    }
}

#[pyfunction]
pub(crate) fn validate_ntfs_watch_root(path: &str) -> PyResult<()> {
    #[cfg(windows)]
    {
        let path = Path::new(path);
        let filesystem = windows::filesystem_type(path).map_err(os_error)?;
        if !filesystem.eq_ignore_ascii_case("NTFS") {
            return Err(PyRuntimeError::new_err(format!(
                "watch mode requires NTFS: '{}' is on {}",
                path.display(),
                filesystem
            )));
        }
        windows::watch_file_observation(path, None).map_err(|error| {
            PyRuntimeError::new_err(format!(
                "watch mode requires an active readable NTFS USN journal for '{}': {}",
                path.display(),
                error
            ))
        })?;
        windows::validate_volume_journal(path).map_err(|error| {
            PyRuntimeError::new_err(format!(
                "watch mode requires volume-level NTFS USN journal access for '{}': {}",
                path.display(),
                error
            ))
        })?;
        return Ok(());
    }
    #[cfg(not(windows))]
    {
        let _ = path;
        Err(PyRuntimeError::new_err("watch mode requires Windows NTFS"))
    }
}

#[pyfunction]
pub(crate) fn watch_filesystem_resource_stats(py: Python<'_>) -> PyResult<Py<PyDict>> {
    let dict = PyDict::new(py);
    #[cfg(windows)]
    let volume_context_stats = windows::volume_context_stats();
    #[cfg(not(windows))]
    let volume_context_stats = (0usize, 0usize, 0u64, 0u64);
    #[cfg(windows)]
    {
        dict.set_item("volume_contexts", volume_context_stats.count)?;
        dict.set_item("volume_context_capacity", volume_context_stats.capacity)?;
        dict.set_item("volume_context_evictions", volume_context_stats.evictions)?;
        dict.set_item(
            "volume_context_transient_fallbacks",
            volume_context_stats.transient_fallbacks,
        )?;
    }
    #[cfg(not(windows))]
    {
        dict.set_item("volume_contexts", volume_context_stats.0)?;
        dict.set_item("volume_context_capacity", volume_context_stats.1)?;
        dict.set_item("volume_context_evictions", volume_context_stats.2)?;
        dict.set_item("volume_context_transient_fallbacks", volume_context_stats.3)?;
    }
    Ok(dict.unbind())
}

#[pyfunction]
pub(crate) fn clear_watch_filesystem_resources() -> PyResult<usize> {
    #[cfg(windows)]
    {
        return Ok(windows::clear_volume_contexts());
    }
    #[cfg(not(windows))]
    {
        Ok(0)
    }
}

#[pyfunction]
pub(crate) fn watch_file_is_ready(path: &str) -> PyResult<bool> {
    #[cfg(windows)]
    {
        return windows::watch_file_is_ready(Path::new(path)).map_err(os_error);
    }
    #[cfg(not(windows))]
    {
        let _ = path;
        Err(PyRuntimeError::new_err("watch mode requires Windows NTFS"))
    }
}

fn os_error(error: std::io::Error) -> PyErr {
    PyOSError::new_err(error.to_string())
}
