use pyo3::prelude::*;
use pyo3::types::{PyBytes, PyDict, PyList};
use std::fs::{self, File};
use std::io::{Read, Seek, SeekFrom, Write};
use std::path::{Path, PathBuf};

const COPY_CHUNK_SIZE: usize = 1024 * 1024;

#[pyfunction]
#[pyo3(signature = (path, start=0, end=None))]
pub(crate) fn repair_read_file_range(
    py: Python<'_>,
    path: &str,
    start: u64,
    end: Option<u64>,
) -> PyResult<Py<PyBytes>> {
    let bytes = read_file_range(path, start, end)?;
    Ok(PyBytes::new(py, &bytes).unbind())
}

#[pyfunction]
pub(crate) fn repair_concat_ranges_to_bytes(
    py: Python<'_>,
    ranges: &Bound<'_, PyList>,
) -> PyResult<Py<PyBytes>> {
    let parsed = parse_ranges(ranges)?;
    let mut output = Vec::new();
    for range in parsed {
        let chunk = read_file_range(&range.path, range.start, range.end)?;
        output.extend_from_slice(&chunk);
    }
    Ok(PyBytes::new(py, &output).unbind())
}

#[pyfunction]
pub(crate) fn repair_write_candidate(
    data: &Bound<'_, PyBytes>,
    workspace: &str,
    filename: &str,
) -> PyResult<String> {
    let path = Path::new(workspace).join(filename);
    atomic_write(&path, data.as_bytes())?;
    Ok(path.to_string_lossy().to_string())
}

#[pyfunction]
#[pyo3(signature = (source_path, start, end, output_path))]
pub(crate) fn repair_copy_range_to_file(
    source_path: &str,
    start: u64,
    end: Option<u64>,
    output_path: &str,
) -> PyResult<String> {
    let output = Path::new(output_path);
    ensure_parent(output)?;
    let temp = temp_path(output);
    let result = (|| -> PyResult<()> {
        let mut source = File::open(source_path)?;
        source.seek(SeekFrom::Start(start))?;
        let mut target = File::create(&temp)?;
        copy_limited(
            &mut source,
            &mut target,
            end.map(|value| value.saturating_sub(start)),
        )?;
        target.flush()?;
        Ok(())
    })();
    finish_atomic_write(result, &temp, output)?;
    Ok(output.to_string_lossy().to_string())
}

#[pyfunction]
pub(crate) fn repair_concat_ranges_to_file(
    ranges: &Bound<'_, PyList>,
    output_path: &str,
) -> PyResult<String> {
    let parsed = parse_ranges(ranges)?;
    let output = Path::new(output_path);
    ensure_parent(output)?;
    let temp = temp_path(output);
    let result = (|| -> PyResult<()> {
        let mut target = File::create(&temp)?;
        for range in parsed {
            let mut source = File::open(&range.path)?;
            source.seek(SeekFrom::Start(range.start))?;
            copy_limited(
                &mut source,
                &mut target,
                range.end.map(|value| value.saturating_sub(range.start)),
            )?;
        }
        target.flush()?;
        Ok(())
    })();
    finish_atomic_write(result, &temp, output)?;
    Ok(output.to_string_lossy().to_string())
}

#[pyfunction]
pub(crate) fn repair_patch_file(
    source_path: &str,
    patches: &Bound<'_, PyList>,
    output_path: &str,
) -> PyResult<String> {
    let parsed = parse_patches(patches)?;
    let output = Path::new(output_path);
    ensure_parent(output)?;
    let temp = temp_path(output);
    let result = (|| -> PyResult<()> {
        fs::copy(source_path, &temp)?;
        let mut target = File::options().read(true).write(true).open(&temp)?;
        for patch in &parsed {
            target.seek(SeekFrom::Start(patch.offset))?;
            target.write_all(&patch.data)?;
        }
        target.flush()?;
        Ok(())
    })();
    finish_atomic_write(result, &temp, output)?;
    Ok(output.to_string_lossy().to_string())
}

#[derive(Debug)]
struct RangeSpec {
    path: String,
    start: u64,
    end: Option<u64>,
}

#[derive(Debug)]
struct PatchSpec {
    offset: u64,
    data: Vec<u8>,
}

fn read_file_range(path: &str, start: u64, end: Option<u64>) -> PyResult<Vec<u8>> {
    let mut file = File::open(path)?;
    file.seek(SeekFrom::Start(start))?;
    let mut output = Vec::new();
    match end {
        Some(end) => {
            if end < start {
                return Err(pyo3::exceptions::PyValueError::new_err(
                    "range end is before range start",
                ));
            }
            let mut limited = file.take(end - start);
            limited.read_to_end(&mut output)?;
        }
        None => {
            file.read_to_end(&mut output)?;
        }
    }
    Ok(output)
}

fn copy_limited(source: &mut File, target: &mut File, limit: Option<u64>) -> PyResult<u64> {
    let mut copied = 0u64;
    let mut buffer = vec![0u8; COPY_CHUNK_SIZE];
    loop {
        let wanted = match limit {
            Some(limit) => {
                if copied >= limit {
                    break;
                }
                (limit - copied).min(COPY_CHUNK_SIZE as u64) as usize
            }
            None => COPY_CHUNK_SIZE,
        };
        let read = source.read(&mut buffer[..wanted])?;
        if read == 0 {
            break;
        }
        target.write_all(&buffer[..read])?;
        copied += read as u64;
    }
    Ok(copied)
}

fn parse_ranges(ranges: &Bound<'_, PyList>) -> PyResult<Vec<RangeSpec>> {
    ranges
        .iter()
        .map(|item| {
            let dict = item.cast::<PyDict>()?;
            let path = get_required_string(dict, "path")?;
            let start = get_optional_u64(dict, "start")?.unwrap_or(0);
            let end = get_optional_u64(dict, "end")?;
            Ok(RangeSpec { path, start, end })
        })
        .collect()
}

fn parse_patches(patches: &Bound<'_, PyList>) -> PyResult<Vec<PatchSpec>> {
    patches
        .iter()
        .map(|item| {
            let dict = item.cast::<PyDict>()?;
            let offset = get_required_u64(dict, "offset")?;
            let data_obj = dict
                .get_item("data")?
                .ok_or_else(|| pyo3::exceptions::PyKeyError::new_err("missing patch data"))?;
            let data = data_obj.extract::<Vec<u8>>()?;
            Ok(PatchSpec { offset, data })
        })
        .collect()
}

fn get_required_string(dict: &Bound<'_, PyDict>, key: &str) -> PyResult<String> {
    dict.get_item(key)?
        .ok_or_else(|| pyo3::exceptions::PyKeyError::new_err(format!("missing {key}")))?
        .extract::<String>()
}

fn get_required_u64(dict: &Bound<'_, PyDict>, key: &str) -> PyResult<u64> {
    dict.get_item(key)?
        .ok_or_else(|| pyo3::exceptions::PyKeyError::new_err(format!("missing {key}")))?
        .extract::<u64>()
}

fn get_optional_u64(dict: &Bound<'_, PyDict>, key: &str) -> PyResult<Option<u64>> {
    match dict.get_item(key)? {
        Some(value) if !value.is_none() => Ok(Some(value.extract::<u64>()?)),
        _ => Ok(None),
    }
}

fn atomic_write(path: &Path, data: &[u8]) -> PyResult<()> {
    ensure_parent(path)?;
    let temp = temp_path(path);
    let result = (|| -> PyResult<()> {
        let mut file = File::create(&temp)?;
        file.write_all(data)?;
        file.flush()?;
        Ok(())
    })();
    finish_atomic_write(result, &temp, path)
}

fn ensure_parent(path: &Path) -> PyResult<()> {
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent)?;
    }
    Ok(())
}

fn temp_path(path: &Path) -> PathBuf {
    let name = path
        .file_name()
        .and_then(|value| value.to_str())
        .unwrap_or("candidate");
    path.with_file_name(format!(".{name}.tmp"))
}

fn finish_atomic_write(result: PyResult<()>, temp: &Path, output: &Path) -> PyResult<()> {
    if let Err(err) = result {
        let _ = fs::remove_file(temp);
        return Err(err);
    }
    if output.exists() {
        fs::remove_file(output)?;
    }
    fs::rename(temp, output)?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_support::temp_file;
    use std::fs;
    use std::time::{SystemTime, UNIX_EPOCH};

    #[test]
    fn read_file_range_reads_bounded_slice() {
        let source = temp_file("repair_read_range", b"0123456789");

        let data = read_file_range(source.to_str().unwrap(), 2, Some(6)).unwrap();

        assert_eq!(data, b"2345");
        let _ = fs::remove_file(source);
    }

    #[test]
    fn copy_limited_copies_exact_range() {
        let source = temp_file("repair_copy_range_source", b"abcdefghij");
        let output = temp_output("repair_copy_range_output");

        repair_copy_range_to_file(
            source.to_str().unwrap(),
            3,
            Some(8),
            output.to_str().unwrap(),
        )
        .unwrap();

        assert_eq!(fs::read(&output).unwrap(), b"defgh");
        let _ = fs::remove_file(source);
        let _ = fs::remove_file(output);
    }

    #[test]
    fn patch_file_writes_sparse_offsets() {
        let source = temp_file("repair_patch_source", b"abcdef");
        let output = temp_output("repair_patch_output");
        Python::initialize();
        let gil = Python::attach(|py| {
            let patches = PyList::empty(py);
            let patch = PyDict::new(py);
            patch.set_item("offset", 2u64).unwrap();
            patch.set_item("data", PyBytes::new(py, b"ZZ")).unwrap();
            patches.append(patch).unwrap();
            repair_patch_file(source.to_str().unwrap(), &patches, output.to_str().unwrap())
                .unwrap();
        });
        let _ = gil;

        assert_eq!(fs::read(&output).unwrap(), b"abZZef");
        let _ = fs::remove_file(source);
        let _ = fs::remove_file(output);
    }

    fn temp_output(name: &str) -> PathBuf {
        let nonce = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("time should be monotonic enough for tests")
            .as_nanos();
        std::env::temp_dir().join(format!("smart_unpacker_native_{name}_{nonce}.bin"))
    }
}
