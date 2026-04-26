use pyo3::prelude::*;
use pyo3::types::{PyDict, PyList};
use std::fs::File;
use std::io::Read;
use std::path::{Path, PathBuf};
use std::sync::OnceLock;

const BUFFER_SIZE: usize = 1024 * 1024;

#[pyfunction]
pub(crate) fn compute_directory_crc_manifest(
    py: Python<'_>,
    output_dir: &str,
    max_files: Option<usize>,
) -> PyResult<Py<PyDict>> {
    let root = PathBuf::from(output_dir);
    let result = PyDict::new(py);
    let files = PyList::empty(py);
    let errors = PyList::empty(py);
    result.set_item("files", &files)?;
    result.set_item("errors", &errors)?;

    if !root.exists() {
        result.set_item("status", "missing")?;
        return Ok(result.unbind());
    }
    if !root.is_dir() {
        result.set_item("status", "not_directory")?;
        return Ok(result.unbind());
    }

    let limit = max_files.unwrap_or(usize::MAX);
    let mut total_files = 0usize;
    let mut scanned_files = 0usize;
    walk_directory(py, &root, &root, limit, &mut total_files, &mut scanned_files, &files, &errors)?;
    result.set_item("status", "ok")?;
    result.set_item("total_files", total_files)?;
    result.set_item("scanned_files", scanned_files)?;
    result.set_item("truncated", scanned_files < total_files)?;
    Ok(result.unbind())
}

fn walk_directory(
    py: Python<'_>,
    root: &Path,
    current: &Path,
    limit: usize,
    total_files: &mut usize,
    scanned_files: &mut usize,
    files: &Bound<'_, PyList>,
    errors: &Bound<'_, PyList>,
) -> PyResult<()> {
    let entries = match std::fs::read_dir(current) {
        Ok(entries) => entries,
        Err(err) => {
            append_error(py, errors, current, root, &err.to_string())?;
            return Ok(());
        }
    };

    for entry in entries {
        let entry = match entry {
            Ok(entry) => entry,
            Err(err) => {
                append_error(py, errors, current, root, &err.to_string())?;
                continue;
            }
        };
        let path = entry.path();
        let metadata = match entry.metadata() {
            Ok(metadata) => metadata,
            Err(err) => {
                append_error(py, errors, &path, root, &err.to_string())?;
                continue;
            }
        };
        if metadata.is_dir() {
            walk_directory(py, root, &path, limit, total_files, scanned_files, files, errors)?;
            continue;
        }
        if !metadata.is_file() {
            continue;
        }
        *total_files += 1;
        if *scanned_files >= limit {
            continue;
        }
        match crc32_file(&path) {
            Ok(crc32) => {
                let item = PyDict::new(py);
                item.set_item("path", relative_path(&path, root))?;
                item.set_item("size", metadata.len())?;
                item.set_item("crc32", crc32)?;
                files.append(item)?;
                *scanned_files += 1;
            }
            Err(err) => append_error(py, errors, &path, root, &err.to_string())?,
        }
    }
    Ok(())
}

fn append_error(
    py: Python<'_>,
    errors: &Bound<'_, PyList>,
    path: &Path,
    root: &Path,
    message: &str,
) -> PyResult<()> {
    let item = PyDict::new(py);
    item.set_item("path", relative_path(path, root))?;
    item.set_item("message", message)?;
    errors.append(item)
}

fn relative_path(path: &Path, root: &Path) -> String {
    path.strip_prefix(root)
        .unwrap_or(path)
        .to_string_lossy()
        .replace('\\', "/")
}

fn crc32_file(path: &Path) -> std::io::Result<u32> {
    let mut file = File::open(path)?;
    let mut crc = 0xFFFF_FFFFu32;
    let mut buffer = vec![0u8; BUFFER_SIZE];
    loop {
        let read = file.read(&mut buffer)?;
        if read == 0 {
            break;
        }
        crc = crc32_update(crc, &buffer[..read]);
    }
    Ok(!crc)
}

fn crc32_update(mut crc: u32, bytes: &[u8]) -> u32 {
    let table = crc32_table();
    for byte in bytes {
        let index = ((crc ^ u32::from(*byte)) & 0xFF) as usize;
        crc = (crc >> 8) ^ table[index];
    }
    crc
}

fn crc32_table() -> &'static [u32; 256] {
    static TABLE: OnceLock<[u32; 256]> = OnceLock::new();
    TABLE.get_or_init(|| {
        let mut table = [0u32; 256];
        for i in 0..256u32 {
            let mut crc = i;
            for _ in 0..8 {
                if crc & 1 != 0 {
                    crc = (crc >> 1) ^ 0xEDB8_8320;
                } else {
                    crc >>= 1;
                }
            }
            table[i as usize] = crc;
        }
        table
    })
}
