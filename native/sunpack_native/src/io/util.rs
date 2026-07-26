use crate::io::reader::ManagedReader;
use pyo3::prelude::*;

pub(crate) const STREAM_CHUNK_SIZE: usize = 1024 * 1024;

pub(crate) fn read_range(path: &str, start: u64, len: u64) -> PyResult<Vec<u8>> {
    let reader = ManagedReader::open(path)?;
    Ok(reader.read_exact_at(start, len as usize)?)
}

pub(crate) fn read_source_range(
    path: &str,
    start: u64,
    end: Option<u64>,
    max_bytes: Option<u64>,
    limit_error: &str,
) -> Result<Vec<u8>, String> {
    let reader = ManagedReader::open(path).map_err(|err| err.to_string())?;
    let file_size = reader.len();
    if start > file_size {
        return Err("range start is beyond input size".to_string());
    }
    let effective_end = end.unwrap_or(file_size).min(file_size);
    if effective_end < start {
        return Err("range end is before range start".to_string());
    }
    let len = effective_end - start;
    if max_bytes.is_some_and(|limit| len > limit) {
        return Err(limit_error.to_string());
    }
    reader
        .read_at(start, len as usize)
        .map_err(|err| err.to_string())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_support::temp_file;

    #[test]
    fn source_ranges_preserve_clamping_and_validation() {
        let path = temp_file("managed_source_range", b"abcdef");
        let path = path.to_string_lossy();
        assert_eq!(
            read_source_range(&path, 2, Some(20), None, "limit").unwrap(),
            b"cdef"
        );
        assert_eq!(
            read_source_range(&path, 7, None, None, "limit").unwrap_err(),
            "range start is beyond input size"
        );
        assert_eq!(
            read_source_range(&path, 4, Some(3), None, "limit").unwrap_err(),
            "range end is before range start"
        );
        assert_eq!(
            read_source_range(&path, 0, None, Some(5), "limit").unwrap_err(),
            "limit"
        );
        let _ = std::fs::remove_file(path.as_ref());
    }
}
