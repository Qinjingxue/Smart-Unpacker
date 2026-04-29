use crate::magic::rfind_subslice;
use crate::util::read_range;
use pyo3::prelude::*;
use pyo3::types::{PyBytes, PyDict, PyList};
use std::fs::File;
use std::io::{Seek, SeekFrom};

const ZIP_EOCD_SIGNATURE: &[u8] = b"PK\x05\x06";
const ZIP_CENTRAL_DIRECTORY_SIGNATURE: &[u8] = b"PK\x01\x02";
const ZIP_UTF8_FLAG: u16 = 0x800;
const ZIP64_MARKER: u32 = 0xFFFF_FFFF;
const ZIP_EOCD_LENGTH: usize = 22;
const ZIP_CENTRAL_HEADER_LENGTH: usize = 46;
const MAX_ZIP_COMMENT_BYTES: u64 = 65_535;

#[derive(Debug, Clone, PartialEq, Eq)]
struct ZipNameScan {
    status: &'static str,
    raw_names: Vec<Vec<u8>>,
    utf8_marked: usize,
    truncated: bool,
}

impl ZipNameScan {
    fn status(status: &'static str) -> Self {
        Self {
            status,
            raw_names: Vec::new(),
            utf8_marked: 0,
            truncated: false,
        }
    }

    fn into_py_dict(self, py: Python<'_>) -> PyResult<Py<PyDict>> {
        let dict = PyDict::new(py);
        let names = PyList::empty(py);
        for raw_name in self.raw_names {
            names.append(PyBytes::new(py, &raw_name))?;
        }
        dict.set_item("status", self.status)?;
        dict.set_item("raw_names", names)?;
        dict.set_item("utf8_marked", self.utf8_marked)?;
        dict.set_item("truncated", self.truncated)?;
        Ok(dict.unbind())
    }
}

#[pyfunction]
#[pyo3(signature = (path, max_samples, max_filename_bytes))]
pub(crate) fn scan_zip_central_directory_names(
    py: Python<'_>,
    path: &str,
    max_samples: usize,
    max_filename_bytes: usize,
) -> PyResult<Py<PyDict>> {
    let scan = scan_zip_names(path, max_samples, max_filename_bytes)?;
    scan.into_py_dict(py)
}

fn scan_zip_names(
    path: &str,
    max_samples: usize,
    max_filename_bytes: usize,
) -> PyResult<ZipNameScan> {
    let mut file = File::open(path)?;
    let file_size = file.seek(SeekFrom::End(0))?;
    if file_size < ZIP_EOCD_LENGTH as u64 {
        return Ok(ZipNameScan::status("file_too_small"));
    }

    let search_size = file_size.min(MAX_ZIP_COMMENT_BYTES + ZIP_EOCD_LENGTH as u64);
    let tail = read_range(path, file_size - search_size, search_size)?;
    let Some(eocd_index) = rfind_subslice(&tail, ZIP_EOCD_SIGNATURE) else {
        return Ok(ZipNameScan::status("eocd_not_found"));
    };
    if eocd_index + ZIP_EOCD_LENGTH > tail.len() {
        return Ok(ZipNameScan::status("eocd_incomplete"));
    }

    let eocd = &tail[eocd_index..eocd_index + ZIP_EOCD_LENGTH];
    let total_entries = read_u16_le(eocd, 10) as usize;
    let central_size = read_u32_le(eocd, 12);
    let central_offset = read_u32_le(eocd, 16);
    if central_offset == ZIP64_MARKER || central_size == ZIP64_MARKER {
        return Ok(ZipNameScan::status("zip64"));
    }

    let central_size_u64 = central_size as u64;
    let central_offset_u64 = central_offset as u64;
    if central_offset_u64
        .checked_add(central_size_u64)
        .is_none_or(|end| end > file_size)
    {
        return Ok(ZipNameScan::status("central_range_invalid"));
    }

    let read_size = central_size_u64
        .min(max_filename_bytes as u64 + (ZIP_CENTRAL_HEADER_LENGTH as u64 * max_samples as u64));
    let central = read_range(path, central_offset_u64, read_size)?;
    Ok(collect_zip_names(
        &central,
        total_entries,
        max_samples,
        max_filename_bytes,
    ))
}

fn collect_zip_names(
    central: &[u8],
    total_entries: usize,
    max_samples: usize,
    max_filename_bytes: usize,
) -> ZipNameScan {
    let mut raw_names: Vec<Vec<u8>> = Vec::new();
    let mut utf8_marked = 0;
    let mut filename_bytes = 0;
    let mut offset = 0;
    let expected_entries = if total_entries == 0 {
        max_samples
    } else {
        total_entries.min(max_samples)
    };
    let mut truncated = false;

    while offset + ZIP_CENTRAL_HEADER_LENGTH <= central.len() && raw_names.len() < expected_entries
    {
        if &central[offset..offset + 4] != ZIP_CENTRAL_DIRECTORY_SIGNATURE {
            break;
        }

        let flags = read_u16_le(central, offset + 8);
        let name_len = read_u16_le(central, offset + 28) as usize;
        let extra_len = read_u16_le(central, offset + 30) as usize;
        let comment_len = read_u16_le(central, offset + 32) as usize;
        let name_start = offset + ZIP_CENTRAL_HEADER_LENGTH;
        let name_end = name_start + name_len;
        let next_offset = name_end + extra_len + comment_len;
        if name_end > central.len() {
            truncated = true;
            break;
        }

        let raw_name = &central[name_start..name_end];
        if !raw_name.is_empty() {
            raw_names.push(raw_name.to_vec());
            filename_bytes += raw_name.len();
            if flags & ZIP_UTF8_FLAG != 0 {
                utf8_marked += 1;
            }
        }
        offset = next_offset;
        if filename_bytes >= max_filename_bytes {
            truncated = true;
            break;
        }
    }

    ZipNameScan {
        status: "ok",
        raw_names,
        utf8_marked,
        truncated,
    }
}

fn read_u16_le(bytes: &[u8], offset: usize) -> u16 {
    u16::from_le_bytes([bytes[offset], bytes[offset + 1]])
}

fn read_u32_le(bytes: &[u8], offset: usize) -> u32 {
    u32::from_le_bytes([
        bytes[offset],
        bytes[offset + 1],
        bytes[offset + 2],
        bytes[offset + 3],
    ])
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_support::temp_file;
    use std::fs;

    #[test]
    fn zip_scan_collects_central_directory_names() {
        let raw_name = "中文/说明.txt".as_bytes();
        let local = b"local payload before central directory".to_vec();
        let central_offset = local.len() as u32;
        let mut central = vec![0; ZIP_CENTRAL_HEADER_LENGTH];
        central[0..4].copy_from_slice(ZIP_CENTRAL_DIRECTORY_SIGNATURE);
        central[8..10].copy_from_slice(&ZIP_UTF8_FLAG.to_le_bytes());
        central[28..30].copy_from_slice(&(raw_name.len() as u16).to_le_bytes());
        central[42..46].copy_from_slice(&0u32.to_le_bytes());
        central.extend_from_slice(raw_name);
        let eocd = [
            b"PK\x05\x06".as_slice(),
            &[0, 0, 0, 0],
            &1u16.to_le_bytes(),
            &1u16.to_le_bytes(),
            &(central.len() as u32).to_le_bytes(),
            &central_offset.to_le_bytes(),
            &[0, 0],
        ]
        .concat();
        let contents = [local, central, eocd].concat();
        let path = temp_file("zip_names", &contents);

        let scan = scan_zip_names(path.to_str().unwrap(), 2000, 1024 * 1024).unwrap();

        assert_eq!(scan.status, "ok");
        assert_eq!(scan.raw_names, vec![raw_name.to_vec()]);
        assert_eq!(scan.utf8_marked, 1);
        assert!(!scan.truncated);
        let _ = fs::remove_file(path);
    }
}
