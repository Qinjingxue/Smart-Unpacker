use pyo3::prelude::*;
use pyo3::types::{PyDict, PyList};
use std::fs::File;
use std::io::{Read, Seek, SeekFrom};

#[derive(Clone, Debug)]
pub(crate) struct RangeSpec {
    path: String,
    start: u64,
    len: u64,
    virtual_start: u64,
}

pub(crate) fn parse_ranges(ranges: &Bound<'_, PyList>) -> PyResult<Vec<RangeSpec>> {
    let mut parsed = Vec::new();
    let mut cursor = 0u64;
    for item in ranges.iter() {
        let dict = item.cast::<PyDict>()?;
        let path = dict
            .get_item("path")?
            .ok_or_else(|| PyErr::new::<pyo3::exceptions::PyValueError, _>("range path is required"))?
            .extract::<String>()?;
        let start = dict
            .get_item("start")?
            .map(|value| value.extract::<u64>())
            .transpose()?
            .unwrap_or(0);
        let end = dict
            .get_item("end")?
            .map(|value| value.extract::<u64>())
            .transpose()?;
        let file_len = std::fs::metadata(&path)?.len();
        if start > file_len {
            return Err(PyErr::new::<pyo3::exceptions::PyValueError, _>("range start is beyond file length"));
        }
        let effective_end = end.unwrap_or(file_len).min(file_len);
        if effective_end < start {
            return Err(PyErr::new::<pyo3::exceptions::PyValueError, _>("range end is before start"));
        }
        let len = effective_end - start;
        if len == 0 {
            continue;
        }
        parsed.push(RangeSpec {
            path,
            start,
            len,
            virtual_start: cursor,
        });
        cursor = cursor.saturating_add(len);
    }
    Ok(parsed)
}

pub(crate) fn ranges_total_len(ranges: &[RangeSpec]) -> u64 {
    ranges.last().map(|item| item.virtual_start + item.len).unwrap_or(0)
}

pub(crate) fn read_prefix_from_ranges(ranges: &[RangeSpec], max_len: usize) -> std::io::Result<Vec<u8>> {
    let mut reader = VirtualRangeReader::new(ranges.to_vec());
    let mut data = vec![0u8; max_len.min(ranges_total_len(ranges) as usize)];
    let len = reader.read(&mut data)?;
    data.truncate(len);
    Ok(data)
}

pub(crate) struct VirtualRangeReader {
    ranges: Vec<RangeSpec>,
    position: u64,
    total_len: u64,
}

impl VirtualRangeReader {
    pub(crate) fn new(ranges: Vec<RangeSpec>) -> Self {
        let total_len = ranges_total_len(&ranges);
        Self {
            ranges,
            position: 0,
            total_len,
        }
    }

    fn current_range(&self) -> Option<&RangeSpec> {
        self.ranges
            .iter()
            .find(|range| self.position >= range.virtual_start && self.position < range.virtual_start + range.len)
    }
}

impl Read for VirtualRangeReader {
    fn read(&mut self, mut buf: &mut [u8]) -> std::io::Result<usize> {
        if buf.is_empty() || self.position >= self.total_len {
            return Ok(0);
        }
        let mut total_read = 0usize;
        while !buf.is_empty() && self.position < self.total_len {
            let Some(range) = self.current_range().cloned() else {
                break;
            };
            let local_offset = self.position - range.virtual_start;
            let available = (range.len - local_offset) as usize;
            let to_read = available.min(buf.len());
            let mut file = File::open(&range.path)?;
            file.seek(SeekFrom::Start(range.start + local_offset))?;
            let read_now = file.read(&mut buf[..to_read])?;
            if read_now == 0 {
                break;
            }
            self.position += read_now as u64;
            total_read += read_now;
            let (_, rest) = buf.split_at_mut(read_now);
            buf = rest;
        }
        Ok(total_read)
    }
}

impl Seek for VirtualRangeReader {
    fn seek(&mut self, pos: SeekFrom) -> std::io::Result<u64> {
        let next = match pos {
            SeekFrom::Start(value) => value as i128,
            SeekFrom::End(value) => self.total_len as i128 + value as i128,
            SeekFrom::Current(value) => self.position as i128 + value as i128,
        };
        if next < 0 {
            return Err(std::io::Error::new(std::io::ErrorKind::InvalidInput, "negative seek"));
        }
        self.position = (next as u64).min(self.total_len);
        Ok(self.position)
    }
}
