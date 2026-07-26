use crate::io::reader::ManagedReader;
use pyo3::prelude::*;
use pyo3::types::{PyDict, PyList};
use std::io::{Read, Seek, SeekFrom};
use std::sync::Arc;

#[derive(Clone)]
pub(crate) struct RangeSpec {
    reader: ManagedReader,
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
            .ok_or_else(|| {
                PyErr::new::<pyo3::exceptions::PyValueError, _>("range path is required")
            })?
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
        let reader = ManagedReader::open(&path)?;
        let file_len = reader.len();
        if start > file_len {
            return Err(PyErr::new::<pyo3::exceptions::PyValueError, _>(
                "range start is beyond file length",
            ));
        }
        let effective_end = end.unwrap_or(file_len).min(file_len);
        if effective_end < start {
            return Err(PyErr::new::<pyo3::exceptions::PyValueError, _>(
                "range end is before start",
            ));
        }
        let len = effective_end - start;
        if len == 0 {
            continue;
        }
        parsed.push(RangeSpec {
            reader,
            start,
            len,
            virtual_start: cursor,
        });
        cursor = cursor.saturating_add(len);
    }
    Ok(parsed)
}

pub(crate) fn ranges_total_len(ranges: &[RangeSpec]) -> u64 {
    ranges
        .last()
        .map(|item| item.virtual_start + item.len)
        .unwrap_or(0)
}

pub(crate) fn read_prefix_from_ranges(
    ranges: &[RangeSpec],
    max_len: usize,
) -> std::io::Result<Vec<u8>> {
    let mut reader = VirtualRangeReader::new(Arc::from(ranges));
    let mut data = vec![0u8; max_len.min(ranges_total_len(ranges) as usize)];
    let len = reader.read(&mut data)?;
    data.truncate(len);
    Ok(data)
}

pub(crate) struct VirtualRangeReader {
    ranges: Arc<[RangeSpec]>,
    position: u64,
    total_len: u64,
}

impl VirtualRangeReader {
    pub(crate) fn new(ranges: Arc<[RangeSpec]>) -> Self {
        let total_len = ranges_total_len(&ranges);
        Self {
            ranges,
            position: 0,
            total_len,
        }
    }

    fn current_range(&self) -> Option<&RangeSpec> {
        let index = self
            .ranges
            .partition_point(|range| range.virtual_start + range.len <= self.position);
        self.ranges.get(index).filter(|range| {
            self.position >= range.virtual_start && self.position < range.virtual_start + range.len
        })
    }
}

impl Read for VirtualRangeReader {
    fn read(&mut self, mut buf: &mut [u8]) -> std::io::Result<usize> {
        if buf.is_empty() || self.position >= self.total_len {
            return Ok(0);
        }
        let mut total_read = 0usize;
        while !buf.is_empty() && self.position < self.total_len {
            let Some(range) = self.current_range() else {
                break;
            };
            let local_offset = self.position - range.virtual_start;
            let available = (range.len - local_offset) as usize;
            let to_read = available.min(buf.len());
            let physical_offset = range.start + local_offset;
            let reader = range.reader.clone();
            let read_now = reader.read_into_at(physical_offset, &mut buf[..to_read])?;
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
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                "negative seek",
            ));
        }
        self.position = (next as u64).min(self.total_len);
        Ok(self.position)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_support::temp_file;

    #[test]
    fn virtual_ranges_read_and_seek_across_files() {
        let first = temp_file("password_range_first", b"012345");
        let second = temp_file("password_range_second", b"abcdef");
        let ranges: Arc<[RangeSpec]> = vec![
            RangeSpec {
                reader: ManagedReader::open(&first).unwrap(),
                start: 2,
                len: 3,
                virtual_start: 0,
            },
            RangeSpec {
                reader: ManagedReader::open(&second).unwrap(),
                start: 1,
                len: 4,
                virtual_start: 3,
            },
        ]
        .into();
        let mut reader = VirtualRangeReader::new(ranges);
        let mut all = [0u8; 7];
        reader.read_exact(&mut all).unwrap();
        assert_eq!(&all, b"234bcde");
        reader.seek(SeekFrom::Start(2)).unwrap();
        let mut middle = [0u8; 3];
        reader.read_exact(&mut middle).unwrap();
        assert_eq!(&middle, b"4bc");
        let _ = std::fs::remove_file(first);
        let _ = std::fs::remove_file(second);
    }
}
