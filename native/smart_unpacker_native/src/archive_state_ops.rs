use base64::Engine;
use pyo3::prelude::*;
use pyo3::types::{PyBytes, PyDict, PyList};
use std::fs::{self, File};
use std::io::{Read, Seek, SeekFrom, Write};
use std::path::{Path, PathBuf};

const COPY_CHUNK_SIZE: usize = 1024 * 1024;
const EOCD_SIG: &[u8] = b"PK\x05\x06";
const CD_SIG: &[u8] = b"PK\x01\x02";
const LFH_SIG: &[u8] = b"PK\x03\x04";

#[pyfunction]
pub(crate) fn archive_state_to_bytes_native(
    py: Python<'_>,
    source: &Bound<'_, PyDict>,
    patches: &Bound<'_, PyList>,
) -> PyResult<Py<PyBytes>> {
    let data = materialize_archive_state(source, patches)?;
    Ok(PyBytes::new(py, &data).unbind())
}

#[pyfunction]
pub(crate) fn archive_state_size_native(
    source: &Bound<'_, PyDict>,
    patches: &Bound<'_, PyList>,
) -> PyResult<u64> {
    Ok(build_segments(source, patches)?
        .iter()
        .map(|segment| segment.len())
        .sum())
}

#[pyfunction]
pub(crate) fn archive_state_write_to_file_native(
    source: &Bound<'_, PyDict>,
    patches: &Bound<'_, PyList>,
    output_path: &str,
) -> PyResult<String> {
    let segments = build_segments(source, patches)?;
    let output = Path::new(output_path);
    ensure_parent(output)?;
    let temp = temp_path(output);
    let result = (|| -> PyResult<()> {
        let mut target = File::create(&temp)?;
        for segment in &segments {
            write_segment(&mut target, segment)?;
        }
        target.flush()?;
        Ok(())
    })();
    finish_atomic_write(result, &temp, output)?;
    Ok(output.to_string_lossy().to_string())
}

#[pyfunction]
#[pyo3(signature = (source, patches, max_items=200000, password=None))]
pub(crate) fn archive_state_zip_manifest_native(
    py: Python<'_>,
    source: &Bound<'_, PyDict>,
    patches: &Bound<'_, PyList>,
    max_items: usize,
    password: Option<&str>,
) -> PyResult<Py<PyDict>> {
    let data = materialize_archive_state(source, patches)?;
    zip_manifest_from_bytes(py, &data, max_items, password).map(|value| value.unbind())
}

pub(crate) fn materialize_archive_state(
    source: &Bound<'_, PyDict>,
    patches: &Bound<'_, PyList>,
) -> PyResult<Vec<u8>> {
    let segments = build_segments(source, patches)?;
    let total: u64 = segments.iter().map(|segment| segment.len()).sum();
    let mut output = Vec::with_capacity(total.min(COPY_CHUNK_SIZE as u64) as usize);
    for segment in &segments {
        append_segment(&mut output, segment)?;
    }
    Ok(output)
}

#[derive(Debug, Clone)]
enum Segment {
    Range { path: String, start: u64, len: u64 },
    Bytes(Vec<u8>),
}

impl Segment {
    fn len(&self) -> u64 {
        match self {
            Segment::Range { len, .. } => *len,
            Segment::Bytes(data) => data.len() as u64,
        }
    }
}

fn build_segments(
    source: &Bound<'_, PyDict>,
    patches: &Bound<'_, PyList>,
) -> PyResult<Vec<Segment>> {
    let mut segments = source_segments(source)?;
    for patch in patches.iter() {
        let patch = patch.cast::<PyDict>()?;
        let Some(operations_obj) = patch.get_item("operations")? else {
            continue;
        };
        let operations = operations_obj.cast::<PyList>()?;
        for operation in operations.iter() {
            let operation = operation.cast::<PyDict>()?;
            if optional_string(operation, "target")?.unwrap_or_else(|| "logical".to_string())
                != "logical"
            {
                return Err(pyo3::exceptions::PyValueError::new_err(
                    "unsupported patch target for native archive state view",
                ));
            }
            let op =
                optional_string(operation, "op")?.unwrap_or_else(|| "replace_range".to_string());
            let offset = optional_u64(operation, "offset")?.unwrap_or(0);
            match op.as_str() {
                "replace_range" => {
                    let data = operation_data(operation)?;
                    let size = optional_u64(operation, "size")?.unwrap_or(data.len() as u64);
                    if size != data.len() as u64 {
                        return Err(pyo3::exceptions::PyValueError::new_err(
                            "replace_range patch must not change logical size",
                        ));
                    }
                    segments = replace_segments(&segments, offset, size, Segment::Bytes(data))?;
                }
                "truncate" => {
                    segments = slice_segments(&segments, 0, offset)?;
                }
                "append" => {
                    let data = operation_data(operation)?;
                    if !data.is_empty() {
                        segments.push(Segment::Bytes(data));
                    }
                }
                "insert" => {
                    let data = operation_data(operation)?;
                    if !data.is_empty() {
                        segments = insert_segments(&segments, offset, Segment::Bytes(data))?;
                    }
                }
                "delete" => {
                    let size = optional_u64(operation, "size")?.ok_or_else(|| {
                        pyo3::exceptions::PyValueError::new_err("delete patch requires size")
                    })?;
                    let total = segments_size(&segments);
                    if offset.checked_add(size).is_none_or(|end| end > total) {
                        return Err(pyo3::exceptions::PyValueError::new_err(
                            "delete patch is outside the current virtual archive",
                        ));
                    }
                    let before = slice_segments(&segments, 0, offset)?;
                    let after = slice_segments(&segments, offset + size, total)?;
                    segments = [before, after].concat();
                }
                _ => {
                    return Err(pyo3::exceptions::PyValueError::new_err(format!(
                        "unknown patch operation: {op}"
                    )))
                }
            }
        }
    }
    Ok(segments
        .into_iter()
        .filter(|segment| segment.len() > 0)
        .collect())
}

fn source_segments(source: &Bound<'_, PyDict>) -> PyResult<Vec<Segment>> {
    let entry_path = optional_string(source, "entry_path")?.unwrap_or_default();
    let open_mode = optional_string(source, "open_mode")?.unwrap_or_else(|| "file".to_string());
    if open_mode == "file_range" {
        if let Some(parts) = source.get_item("parts")? {
            let parts = parts.cast::<PyList>()?;
            if let Some(first) = parts.iter().next() {
                let item = first.cast::<PyDict>()?;
                let path = optional_string(item, "path")?.unwrap_or_else(|| entry_path.clone());
                let start = optional_u64(item, "start")?.unwrap_or(0);
                let end = optional_u64(item, "end")?;
                return Ok(vec![range_segment(&path, start, end)?]);
            }
        }
        if let Some(segment) = source.get_item("segment")? {
            let segment = segment.cast::<PyDict>()?;
            let start = optional_u64(segment, "start")?.unwrap_or(0);
            let end = optional_u64(segment, "end")?;
            return Ok(vec![range_segment(&entry_path, start, end)?]);
        }
    }
    if open_mode == "concat_ranges" {
        if let Some(ranges) = source.get_item("ranges")? {
            let ranges = ranges.cast::<PyList>()?;
            let mut output = Vec::new();
            for item in ranges.iter() {
                let item = item.cast::<PyDict>()?;
                let path = optional_string(item, "path")?.unwrap_or_else(|| entry_path.clone());
                let start = optional_u64(item, "start")?.unwrap_or(0);
                let end = optional_u64(item, "end")?;
                output.push(range_segment(&path, start, end)?);
            }
            if !output.is_empty() {
                return Ok(output);
            }
        }
    }
    if let Some(parts) = source.get_item("parts")? {
        let parts = parts.cast::<PyList>()?;
        let mut output = Vec::new();
        for item in parts.iter() {
            let item = item.cast::<PyDict>()?;
            let path = optional_string(item, "path")?.unwrap_or_else(|| entry_path.clone());
            let start = optional_u64(item, "start")?.unwrap_or(0);
            let end = optional_u64(item, "end")?;
            if start != 0 || end.is_some() {
                output.push(range_segment(&path, start, end)?);
            } else if !path.is_empty() {
                output.push(range_segment(&path, 0, None)?);
            }
        }
        if !output.is_empty() {
            return Ok(output);
        }
    }
    Ok(vec![range_segment(&entry_path, 0, None)?])
}

fn range_segment(path: &str, start: u64, end: Option<u64>) -> PyResult<Segment> {
    let size = fs::metadata(path)?.len();
    if start > size {
        return Err(pyo3::exceptions::PyValueError::new_err(
            "range start is beyond input size",
        ));
    }
    let effective_end = end.unwrap_or(size).min(size);
    if effective_end < start {
        return Err(pyo3::exceptions::PyValueError::new_err(
            "range end is before range start",
        ));
    }
    Ok(Segment::Range {
        path: path.to_string(),
        start,
        len: effective_end - start,
    })
}

fn replace_segments(
    segments: &[Segment],
    offset: u64,
    size: u64,
    replacement: Segment,
) -> PyResult<Vec<Segment>> {
    let total = segments_size(segments);
    if offset.checked_add(size).is_none_or(|end| end > total) {
        return Err(pyo3::exceptions::PyValueError::new_err(
            "replace_range patch is outside the current virtual archive",
        ));
    }
    let before = slice_segments(segments, 0, offset)?;
    let after = slice_segments(segments, offset + size, total)?;
    Ok([before, vec![replacement], after].concat())
}

fn insert_segments(segments: &[Segment], offset: u64, inserted: Segment) -> PyResult<Vec<Segment>> {
    let total = segments_size(segments);
    if offset > total {
        return Err(pyo3::exceptions::PyValueError::new_err(
            "insert patch is outside the current virtual archive",
        ));
    }
    let before = slice_segments(segments, 0, offset)?;
    let after = slice_segments(segments, offset, total)?;
    Ok([before, vec![inserted], after].concat())
}

fn slice_segments(segments: &[Segment], start: u64, end: u64) -> PyResult<Vec<Segment>> {
    let mut output = Vec::new();
    let mut cursor = 0u64;
    for segment in segments {
        let segment_start = cursor;
        let segment_end = cursor + segment.len();
        cursor = segment_end;
        if segment_end <= start {
            continue;
        }
        if segment_start >= end {
            break;
        }
        let take_start = start.max(segment_start) - segment_start;
        let take_end = end.min(segment_end) - segment_start;
        if take_end <= take_start {
            continue;
        }
        match segment {
            Segment::Bytes(data) => output.push(Segment::Bytes(
                data[take_start as usize..take_end as usize].to_vec(),
            )),
            Segment::Range {
                path,
                start: source_start,
                ..
            } => output.push(Segment::Range {
                path: path.clone(),
                start: source_start + take_start,
                len: take_end - take_start,
            }),
        }
    }
    Ok(output)
}

fn segments_size(segments: &[Segment]) -> u64 {
    segments.iter().map(|segment| segment.len()).sum()
}

fn append_segment(output: &mut Vec<u8>, segment: &Segment) -> PyResult<()> {
    match segment {
        Segment::Bytes(data) => output.extend_from_slice(data),
        Segment::Range { path, start, len } => {
            let mut file = File::open(path)?;
            file.seek(SeekFrom::Start(*start))?;
            let mut limited = file.take(*len);
            limited.read_to_end(output)?;
        }
    }
    Ok(())
}

fn write_segment(target: &mut File, segment: &Segment) -> PyResult<()> {
    match segment {
        Segment::Bytes(data) => target.write_all(data)?,
        Segment::Range { path, start, len } => {
            let mut source = File::open(path)?;
            source.seek(SeekFrom::Start(*start))?;
            let mut limited = source.take(*len);
            let mut buffer = vec![0u8; COPY_CHUNK_SIZE];
            loop {
                let read = limited.read(&mut buffer)?;
                if read == 0 {
                    break;
                }
                target.write_all(&buffer[..read])?;
            }
        }
    }
    Ok(())
}

fn operation_data(operation: &Bound<'_, PyDict>) -> PyResult<Vec<u8>> {
    if optional_string(operation, "data_ref")?.is_some_and(|value| !value.is_empty()) {
        return Err(pyo3::exceptions::PyValueError::new_err(
            "data_ref patch payloads are not supported by native archive state view yet",
        ));
    }
    let Some(data_b64) = optional_string(operation, "data_b64")? else {
        return Ok(Vec::new());
    };
    if data_b64.is_empty() {
        return Ok(Vec::new());
    }
    base64::engine::general_purpose::STANDARD
        .decode(data_b64.as_bytes())
        .map_err(|err| pyo3::exceptions::PyValueError::new_err(err.to_string()))
}

fn zip_manifest_from_bytes<'py>(
    py: Python<'py>,
    data: &[u8],
    max_items: usize,
    password: Option<&str>,
) -> PyResult<Bound<'py, PyDict>> {
    let result = PyDict::new(py);
    result.set_item("source", "archive_state_native_zip_central_directory")?;
    result.set_item("state_aware", true)?;
    result.set_item("archive_type", "zip")?;
    let Some(eocd) = find_eocd(data) else {
        result.set_item("status", 2)?;
        result.set_item("is_archive", looks_like_zip(data))?;
        result.set_item("damaged", true)?;
        result.set_item("checksum_error", false)?;
        result.set_item("item_count", 0)?;
        result.set_item("file_count", 0)?;
        result.set_item("files", PyList::empty(py))?;
        result.set_item(
            "message",
            "Patched archive state is not a readable ZIP: EOCD not found",
        )?;
        return Ok(result);
    };
    let mut cursor = eocd.cd_offset as usize;
    let expected_end = cursor.saturating_add(eocd.cd_size as usize);
    let files = PyList::empty(py);
    let mut item_count = 0usize;
    let mut file_count = 0usize;
    let mut damaged = false;
    let mut checksum_error = false;
    let mut message = "Archive-state ZIP manifest loaded by native parser".to_string();
    while cursor + 46 <= data.len() && cursor < expected_end {
        if &data[cursor..cursor + 4] != CD_SIG {
            damaged = true;
            message = "Patched archive state ZIP central directory stopped before expected end"
                .to_string();
            break;
        }
        let flags = u16_le(data, cursor + 8);
        let method = u16_le(data, cursor + 10);
        let crc32 = u32_le(data, cursor + 16);
        let compressed_size = u32_le(data, cursor + 20) as u64;
        let uncompressed_size = u32_le(data, cursor + 24) as u64;
        let name_len = u16_le(data, cursor + 28) as usize;
        let extra_len = u16_le(data, cursor + 30) as usize;
        let comment_len = u16_le(data, cursor + 32) as usize;
        let local_offset = u32_le(data, cursor + 42) as usize;
        let name_start = cursor + 46;
        let name_end = name_start + name_len;
        let record_end = name_end + extra_len + comment_len;
        if record_end > data.len() || record_end > expected_end {
            damaged = true;
            message = "Patched archive state ZIP central directory entry is truncated".to_string();
            break;
        }
        item_count += 1;
        let name = String::from_utf8_lossy(&data[name_start..name_end]).to_string();
        if !name.ends_with('/') && file_count < max_items {
            let item = PyDict::new(py);
            item.set_item("path", &name)?;
            item.set_item("size", uncompressed_size)?;
            item.set_item("packed_size", compressed_size)?;
            item.set_item("has_crc", true)?;
            item.set_item("crc32", crc32)?;
            item.set_item("source", "patched_state_zip_central_directory_native")?;
            files.append(item)?;
            file_count += 1;
        }
        if flags & 0x1 == 0 || password.is_some() {
            if matches!(method, 0 | 8)
                && !verify_zip_payload(
                    data,
                    local_offset,
                    method,
                    crc32,
                    compressed_size,
                    uncompressed_size,
                )
            {
                damaged = true;
                checksum_error = true;
                message = format!("Patched archive state ZIP payload CRC failed at: {name}");
            }
        }
        cursor = record_end;
    }
    if cursor != expected_end {
        damaged = true;
    }
    result.set_item("status", if damaged { 2 } else { 0 })?;
    result.set_item("is_archive", true)?;
    result.set_item("damaged", damaged)?;
    result.set_item("checksum_error", checksum_error)?;
    result.set_item("item_count", item_count)?;
    result.set_item("file_count", file_count)?;
    result.set_item("files", files)?;
    result.set_item("message", message)?;
    Ok(result)
}

#[derive(Debug)]
struct EocdRecord {
    cd_size: u32,
    cd_offset: u32,
}

fn find_eocd(data: &[u8]) -> Option<EocdRecord> {
    let mut pos = find_last(data, EOCD_SIG, data.len())?;
    loop {
        if pos + 22 <= data.len() {
            let comment_len = u16_le(data, pos + 20) as usize;
            let end = pos + 22 + comment_len;
            if end <= data.len() {
                return Some(EocdRecord {
                    cd_size: u32_le(data, pos + 12),
                    cd_offset: u32_le(data, pos + 16),
                });
            }
        }
        if pos == 0 {
            return None;
        }
        pos = find_last(data, EOCD_SIG, pos)?;
    }
}

fn verify_zip_payload(
    data: &[u8],
    local_offset: usize,
    method: u16,
    expected_crc: u32,
    compressed_size: u64,
    uncompressed_size: u64,
) -> bool {
    if local_offset + 30 > data.len() || &data[local_offset..local_offset + 4] != LFH_SIG {
        return false;
    }
    let name_len = u16_le(data, local_offset + 26) as usize;
    let extra_len = u16_le(data, local_offset + 28) as usize;
    let data_start = local_offset + 30 + name_len + extra_len;
    let data_end = data_start.saturating_add(compressed_size as usize);
    if data_end > data.len() {
        return false;
    }
    match method {
        0 => {
            let payload = &data[data_start..data_end];
            payload.len() as u64 == uncompressed_size && crc32(payload) == expected_crc
        }
        8 => verify_deflate(&data[data_start..data_end], expected_crc, uncompressed_size),
        _ => true,
    }
}

fn verify_deflate(input: &[u8], expected_crc: u32, expected_size: u64) -> bool {
    use flate2::{Decompress, FlushDecompress, Status};
    let mut decompressor = Decompress::new(false);
    let mut output = Vec::with_capacity(64 * 1024);
    let mut crc = Crc32::new();
    loop {
        let before_in = decompressor.total_in();
        let before_out = decompressor.total_out();
        let before_len = output.len();
        let input_offset = before_in as usize;
        if input_offset > input.len() {
            return false;
        }
        let Ok(status) =
            decompressor.decompress_vec(&input[input_offset..], &mut output, FlushDecompress::None)
        else {
            return false;
        };
        if output.len() > before_len {
            crc.update(&output[before_len..]);
        }
        if status == Status::StreamEnd {
            return decompressor.total_in() as usize == input.len()
                && decompressor.total_out() == expected_size
                && crc.finish() == expected_crc;
        }
        if decompressor.total_in() as usize >= input.len() {
            return false;
        }
        if before_in == decompressor.total_in() && before_out == decompressor.total_out() {
            return false;
        }
        if output.len() > COPY_CHUNK_SIZE {
            output.clear();
        }
    }
}

fn looks_like_zip(data: &[u8]) -> bool {
    data.starts_with(LFH_SIG)
        || data.starts_with(EOCD_SIG)
        || find_last(data, EOCD_SIG, data.len()).is_some()
}

struct Crc32 {
    state: u32,
}

impl Crc32 {
    fn new() -> Self {
        Self { state: 0xFFFF_FFFF }
    }

    fn update(&mut self, bytes: &[u8]) {
        for byte in bytes {
            self.state ^= *byte as u32;
            for _ in 0..8 {
                let mask = (self.state & 1).wrapping_neg();
                self.state = (self.state >> 1) ^ (0xEDB8_8320 & mask);
            }
        }
    }

    fn finish(self) -> u32 {
        !self.state
    }
}

fn crc32(bytes: &[u8]) -> u32 {
    let mut crc = Crc32::new();
    crc.update(bytes);
    crc.finish()
}

fn find_last(data: &[u8], needle: &[u8], before: usize) -> Option<usize> {
    if needle.is_empty() || before < needle.len() || data.len() < needle.len() {
        return None;
    }
    let mut pos = before.min(data.len()) - needle.len();
    loop {
        if &data[pos..pos + needle.len()] == needle {
            return Some(pos);
        }
        if pos == 0 {
            return None;
        }
        pos -= 1;
    }
}

fn u16_le(data: &[u8], offset: usize) -> u16 {
    let mut bytes = [0u8; 2];
    bytes.copy_from_slice(&data[offset..offset + 2]);
    u16::from_le_bytes(bytes)
}

fn u32_le(data: &[u8], offset: usize) -> u32 {
    let mut bytes = [0u8; 4];
    bytes.copy_from_slice(&data[offset..offset + 4]);
    u32::from_le_bytes(bytes)
}

fn optional_string(dict: &Bound<'_, PyDict>, key: &str) -> PyResult<Option<String>> {
    match dict.get_item(key)? {
        Some(value) if !value.is_none() => Ok(Some(value.extract::<String>()?)),
        _ => Ok(None),
    }
}

fn optional_u64(dict: &Bound<'_, PyDict>, key: &str) -> PyResult<Option<u64>> {
    match dict.get_item(key)? {
        Some(value) if !value.is_none() => Ok(Some(value.extract::<u64>()?)),
        _ => Ok(None),
    }
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
