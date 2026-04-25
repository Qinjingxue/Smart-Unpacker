use pyo3::prelude::*;
use std::fs::File;
use std::io::{Read, Seek, SeekFrom};

pub(crate) const STREAM_CHUNK_SIZE: usize = 1024 * 1024;

pub(crate) fn read_range(path: &str, start: u64, len: u64) -> PyResult<Vec<u8>> {
    let mut file = File::open(path)?;
    file.seek(SeekFrom::Start(start))?;
    let mut buffer = vec![0; len as usize];
    file.read_exact(&mut buffer)?;
    Ok(buffer)
}

pub(crate) fn normalize_ext(ext: &str) -> String {
    let trimmed = ext.trim().to_ascii_lowercase();
    if trimmed.starts_with('.') {
        trimmed
    } else {
        format!(".{trimmed}")
    }
}
