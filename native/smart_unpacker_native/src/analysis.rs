use pyo3::prelude::*;
use pyo3::types::{PyBytes, PyDict, PyList};
use std::collections::{HashMap, VecDeque};
use std::fs::File;
use std::io::{Read, Seek, SeekFrom};
use std::sync::{Condvar, Mutex, MutexGuard};

const ZIP_LOCAL: &[u8] = b"PK\x03\x04";
const ZIP_CENTRAL: &[u8] = b"PK\x01\x02";
const ZIP_EOCD: &[u8] = b"PK\x05\x06";
const RAR4: &[u8] = b"Rar!\x1a\x07\x00";
const RAR5: &[u8] = b"Rar!\x1a\x07\x01\x00";
const SEVEN_ZIP: &[u8] = b"7z\xbc\xaf\x27\x1c";

#[pyclass]
pub(crate) struct AnalysisBinaryView {
    inner: Mutex<AnalysisBinaryViewInner>,
    read_gate: ReadGate,
}

struct AnalysisBinaryViewInner {
    path: String,
    size: u64,
    cache_bytes: usize,
    max_read_bytes: Option<u64>,
    cache: HashMap<(u64, usize), Vec<u8>>,
    order: VecDeque<(u64, usize)>,
    cache_size: usize,
    read_bytes: u64,
    cache_hits: u64,
}

struct ReadGate {
    limit: usize,
    active: Mutex<usize>,
    available: Condvar,
}

struct ReadPermit<'a> {
    gate: &'a ReadGate,
}

#[pymethods]
impl AnalysisBinaryView {
    #[new]
    #[pyo3(signature = (path, cache_bytes=67108864, max_read_bytes=None, max_concurrent_reads=1))]
    fn new(
        path: String,
        cache_bytes: usize,
        max_read_bytes: Option<u64>,
        max_concurrent_reads: usize,
    ) -> PyResult<Self> {
        let metadata = std::fs::metadata(&path)?;
        Ok(Self {
            inner: Mutex::new(AnalysisBinaryViewInner {
                path,
                size: metadata.len(),
                cache_bytes,
                max_read_bytes,
                cache: HashMap::new(),
                order: VecDeque::new(),
                cache_size: 0,
                read_bytes: 0,
                cache_hits: 0,
            }),
            read_gate: ReadGate {
                limit: max_concurrent_reads.max(1),
                active: Mutex::new(0),
                available: Condvar::new(),
            },
        })
    }

    #[getter]
    fn size(&self) -> PyResult<u64> {
        Ok(self.lock()?.size)
    }

    #[getter]
    fn path(&self) -> PyResult<String> {
        Ok(self.lock()?.path.clone())
    }

    fn read_at<'py>(&self, py: Python<'py>, offset: u64, size: usize) -> PyResult<Bound<'py, PyBytes>> {
        let data = self.read_at_bytes(offset, size)?;
        Ok(PyBytes::new(py, &data))
    }

    fn read_tail<'py>(&self, py: Python<'py>, size: usize) -> PyResult<Bound<'py, PyBytes>> {
        let view_size = self.lock()?.size;
        let read_size = size.min(view_size as usize);
        let offset = view_size.saturating_sub(read_size as u64);
        let data = self.read_at_bytes(offset, read_size)?;
        Ok(PyBytes::new(py, &data))
    }

    fn stats(&self, py: Python<'_>) -> PyResult<Py<PyDict>> {
        let inner = self.lock()?;
        let dict = PyDict::new(py);
        dict.set_item("read_bytes", inner.read_bytes)?;
        dict.set_item("cache_hits", inner.cache_hits)?;
        Ok(dict.unbind())
    }

    #[pyo3(signature = (eocd_offset, max_cd_entries_to_walk=64))]
    fn probe_zip(
        &self,
        py: Python<'_>,
        eocd_offset: u64,
        max_cd_entries_to_walk: usize,
    ) -> PyResult<Py<PyDict>> {
        let result = PyDict::new(py);
        result.set_item("format", "zip")?;
        result.set_item("plausible", false)?;
        result.set_item("magic_matched", false)?;
        result.set_item("error", "")?;
        result.set_item("eocd_offset", eocd_offset)?;
        result.set_item("archive_offset", 0u64)?;
        result.set_item("segment_end", 0u64)?;
        result.set_item("central_directory_offset", 0u64)?;
        result.set_item("central_directory_size", 0u64)?;
        result.set_item("total_entries", 0u16)?;
        result.set_item("central_directory_present", false)?;
        result.set_item("central_directory_walk_ok", false)?;
        result.set_item("central_directory_entries_checked", 0usize)?;
        result.set_item("local_header_links_ok", false)?;
        result.set_item("local_header_links_checked", 0usize)?;
        result.set_item("evidence", PyList::empty(py))?;

        let eocd = self.read_at_bytes(eocd_offset, 22)?;
        if eocd.len() < 22 {
            result.set_item("error", "eocd_too_small")?;
            return Ok(result.unbind());
        }
        if &eocd[0..4] != ZIP_EOCD {
            result.set_item("error", "bad_eocd_signature")?;
            return Ok(result.unbind());
        }
        result.set_item("magic_matched", true)?;
        let disk_number = u16_le(&eocd, 4);
        let central_directory_disk = u16_le(&eocd, 6);
        let disk_entries = u16_le(&eocd, 8);
        let total_entries = u16_le(&eocd, 10);
        let central_directory_size = u32_le(&eocd, 12) as u64;
        let central_directory_offset = u32_le(&eocd, 16) as u64;
        let comment_length = u16_le(&eocd, 20) as u64;
        let segment_end = eocd_offset + 22 + comment_length;
        result.set_item("segment_end", segment_end)?;
        result.set_item("central_directory_size", central_directory_size)?;
        result.set_item("total_entries", total_entries)?;
        if disk_number != 0 || central_directory_disk != 0 || disk_entries != total_entries {
            result.set_item("error", "multi_disk_or_entry_mismatch")?;
            return Ok(result.unbind());
        }
        if eocd_offset < central_directory_size {
            result.set_item("error", "central_directory_size_out_of_range")?;
            return Ok(result.unbind());
        }
        let physical_central_offset = eocd_offset - central_directory_size;
        if physical_central_offset < central_directory_offset {
            result.set_item("error", "archive_offset_underflow")?;
            return Ok(result.unbind());
        }
        let archive_offset = physical_central_offset - central_directory_offset;
        result.set_item("archive_offset", archive_offset)?;
        result.set_item("central_directory_offset", physical_central_offset)?;
        if physical_central_offset + central_directory_size != eocd_offset {
            result.set_item("error", "central_directory_size_mismatch")?;
            return Ok(result.unbind());
        }
        if total_entries == 0 && central_directory_size == 0 {
            result.set_item("plausible", true)?;
            result.set_item("central_directory_walk_ok", true)?;
            result.set_item("local_header_links_ok", true)?;
            return Ok(result.unbind());
        }

        let central_sig = self.read_at_bytes(physical_central_offset, 4)?;
        if central_sig.len() < 4 || central_sig.as_slice() != ZIP_CENTRAL {
            result.set_item("error", "bad_central_directory_signature")?;
            return Ok(result.unbind());
        }
        result.set_item("central_directory_present", true)?;
        let (entries_checked, cd_ok, links_checked, links_ok, error) = self.walk_zip_central_directory(
            archive_offset,
            physical_central_offset,
            central_directory_size,
            total_entries as usize,
            max_cd_entries_to_walk,
        )?;
        result.set_item("central_directory_entries_checked", entries_checked)?;
        result.set_item("central_directory_walk_ok", cd_ok)?;
        result.set_item("local_header_links_checked", links_checked)?;
        result.set_item("local_header_links_ok", links_ok)?;
        if error.is_empty() {
            result.set_item("plausible", true)?;
            let evidence = PyList::empty(py);
            evidence.append("zip:eocd")?;
            evidence.append("zip:central_directory")?;
            if cd_ok {
                evidence.append("zip:central_directory_walk")?;
            }
            if links_ok {
                evidence.append("zip:local_header_links")?;
            }
            result.set_item("evidence", evidence)?;
        } else {
            result.set_item("error", error)?;
        }
        Ok(result.unbind())
    }

    #[pyo3(signature = (start_offset, max_blocks_to_walk=4096))]
    fn probe_rar(
        &self,
        py: Python<'_>,
        start_offset: u64,
        max_blocks_to_walk: usize,
    ) -> PyResult<Py<PyDict>> {
        let result = PyDict::new(py);
        result.set_item("format", "rar")?;
        result.set_item("plausible", false)?;
        result.set_item("magic_matched", false)?;
        result.set_item("strong_accept", false)?;
        result.set_item("error", "")?;
        result.set_item("archive_offset", start_offset)?;
        result.set_item("segment_end", 0u64)?;
        result.set_item("version", 0u8)?;
        result.set_item("blocks_checked", 0usize)?;
        result.set_item("end_block_found", false)?;
        result.set_item("evidence", PyList::empty(py))?;

        let header = self.read_at_bytes(start_offset, RAR5.len())?;
        if header.starts_with(RAR5) {
            result.set_item("magic_matched", true)?;
            result.set_item("version", 5u8)?;
            self.probe_rar5(py, &result, start_offset, max_blocks_to_walk)?;
        } else if header.starts_with(RAR4) {
            result.set_item("magic_matched", true)?;
            result.set_item("version", 4u8)?;
            self.probe_rar4(py, &result, start_offset, max_blocks_to_walk)?;
        } else if header.starts_with(b"Rar!") {
            result.set_item("magic_matched", true)?;
            result.set_item("error", "rar_signature_incomplete_or_unknown")?;
        } else {
            result.set_item("error", "rar_signature_not_found")?;
        }
        Ok(result.unbind())
    }

    #[pyo3(signature = (start_offset, max_next_header_check_bytes=1048576))]
    fn probe_seven_zip(
        &self,
        py: Python<'_>,
        start_offset: u64,
        max_next_header_check_bytes: u64,
    ) -> PyResult<Py<PyDict>> {
        let result = PyDict::new(py);
        result.set_item("format", "7z")?;
        result.set_item("plausible", false)?;
        result.set_item("magic_matched", false)?;
        result.set_item("strong_accept", false)?;
        result.set_item("error", "")?;
        result.set_item("archive_offset", start_offset)?;
        result.set_item("segment_end", 0u64)?;
        result.set_item("next_header_offset", 0u64)?;
        result.set_item("next_header_size", 0u64)?;
        result.set_item("start_header_crc_ok", false)?;
        result.set_item("next_header_crc_checked", false)?;
        result.set_item("next_header_crc_ok", false)?;
        result.set_item("next_header_nid", 0u8)?;
        result.set_item("next_header_nid_valid", false)?;
        result.set_item("evidence", PyList::empty(py))?;

        let header = self.read_at_bytes(start_offset, 32)?;
        if header.len() < 32 {
            result.set_item("error", "7z_header_too_small")?;
            result.set_item("magic_matched", header.starts_with(SEVEN_ZIP))?;
            return Ok(result.unbind());
        }
        if &header[0..6] != SEVEN_ZIP {
            result.set_item("error", "7z_signature_not_found")?;
            return Ok(result.unbind());
        }
        result.set_item("magic_matched", true)?;
        if header[6] != 0 {
            result.set_item("error", "unsupported_version")?;
            return Ok(result.unbind());
        }
        let stored_start_crc = u32_le(&header, 8);
        let start_header = &header[12..32];
        let computed_start_crc = crc32(start_header);
        result.set_item("start_header_crc_ok", stored_start_crc == computed_start_crc)?;
        if stored_start_crc != computed_start_crc {
            result.set_item("error", "start_header_crc_mismatch")?;
            return Ok(result.unbind());
        }
        let next_header_offset = u64_le(start_header, 0);
        let next_header_size = u64_le(start_header, 8);
        let next_header_crc = u32_le(start_header, 16);
        let next_header_start = start_offset + 32 + next_header_offset;
        let segment_end = next_header_start + next_header_size;
        result.set_item("next_header_offset", next_header_offset)?;
        result.set_item("next_header_size", next_header_size)?;
        result.set_item("segment_end", segment_end)?;
        if next_header_size == 0 {
            result.set_item("error", "invalid_next_header_range")?;
            return Ok(result.unbind());
        }
        let size = self.lock()?.size;
        if segment_end > size {
            result.set_item("error", "next_header_out_of_range")?;
            return Ok(result.unbind());
        }
        result.set_item("plausible", true)?;
        let evidence = PyList::empty(py);
        evidence.append("7z:signature")?;
        evidence.append("7z:start_header_crc")?;
        evidence.append("7z:next_header_range")?;
        if next_header_size <= max_next_header_check_bytes {
            let next_header = self.read_at_bytes(next_header_start, next_header_size as usize)?;
            let crc_ok = crc32(&next_header) == next_header_crc;
            let nid = next_header.first().copied().unwrap_or(0);
            let nid_valid = nid == 0x01 || nid == 0x17;
            result.set_item("next_header_crc_checked", true)?;
            result.set_item("next_header_crc_ok", crc_ok)?;
            result.set_item("next_header_nid", nid)?;
            result.set_item("next_header_nid_valid", nid_valid)?;
            if crc_ok {
                evidence.append("7z:next_header_crc")?;
                if nid_valid {
                    result.set_item("strong_accept", true)?;
                    evidence.append("7z:next_header_nid")?;
                } else {
                    result.set_item("error", "next_header_nid_unrecognized")?;
                }
            } else {
                result.set_item("error", "next_header_crc_mismatch")?;
            }
        }
        result.set_item("evidence", evidence)?;
        Ok(result.unbind())
    }

    #[pyo3(signature = (head_bytes=1048576, tail_bytes=1048576))]
    fn signature_prepass(
        &self,
        py: Python<'_>,
        head_bytes: usize,
        tail_bytes: usize,
    ) -> PyResult<Py<PyDict>> {
        let size = self.lock()?.size;
        let head_len = head_bytes.min(size as usize);
        let tail_len = tail_bytes.min(size as usize);
        let tail_start = size.saturating_sub(tail_len as u64);
        let head = self.read_at_bytes(0, head_len)?;
        let tail = self.read_at_bytes(tail_start, tail_len)?;

        let mut hits = Vec::new();
        collect_hits(&mut hits, "zip_local", 0, &head, ZIP_LOCAL);
        collect_hits(&mut hits, "zip_eocd", 0, &head, ZIP_EOCD);
        collect_hits(&mut hits, "rar4", 0, &head, RAR4);
        collect_hits(&mut hits, "rar5", 0, &head, RAR5);
        collect_hits(&mut hits, "7z", 0, &head, SEVEN_ZIP);
        collect_hits(&mut hits, "zip_local", tail_start, &tail, ZIP_LOCAL);
        collect_hits(&mut hits, "zip_eocd", tail_start, &tail, ZIP_EOCD);
        collect_hits(&mut hits, "rar4", tail_start, &tail, RAR4);
        collect_hits(&mut hits, "rar5", tail_start, &tail, RAR5);
        collect_hits(&mut hits, "7z", tail_start, &tail, SEVEN_ZIP);
        hits.sort_by_key(|(_, offset)| *offset);
        hits.dedup();

        let dict = PyDict::new(py);
        let py_hits = PyList::empty(py);
        let mut formats = Vec::new();
        for (name, offset) in hits {
            let hit = PyDict::new(py);
            hit.set_item("name", name)?;
            hit.set_item("offset", offset)?;
            py_hits.append(hit)?;
            let format = format_for_hit(name);
            if !formats.contains(&format) {
                formats.push(format);
            }
        }
        formats.sort();
        dict.set_item("hits", py_hits)?;
        dict.set_item("formats", formats)?;
        dict.set_item("head_bytes", head.len())?;
        dict.set_item("tail_bytes", tail.len())?;
        Ok(dict.unbind())
    }
}

impl AnalysisBinaryView {
    fn lock(&self) -> PyResult<MutexGuard<'_, AnalysisBinaryViewInner>> {
        self.inner
            .lock()
            .map_err(|_| pyo3::exceptions::PyRuntimeError::new_err("analysis binary view lock poisoned"))
    }

    fn read_at_bytes(&self, offset: u64, size: usize) -> PyResult<Vec<u8>> {
        let (path, read_offset, read_size) = {
            let mut inner = self.lock()?;
            if offset >= inner.size || size == 0 {
                return Ok(Vec::new());
            }
            let read_size = size.min((inner.size - offset) as usize);
            let key = (offset, read_size);
            if let Some(data) = inner.cache.get(&key).cloned() {
                inner.cache_hits += 1;
                return Ok(data);
            }
            if let Some(max_read_bytes) = inner.max_read_bytes {
                if inner.read_bytes + read_size as u64 > max_read_bytes {
                    return Err(pyo3::exceptions::PyRuntimeError::new_err(
                        "archive analysis read budget exceeded",
                    ));
                }
            }
            (inner.path.clone(), offset, read_size)
        };

        let _permit = self.read_gate.acquire()?;
        let mut file = File::open(&path)?;
        file.seek(SeekFrom::Start(read_offset))?;
        let mut data = vec![0; read_size];
        file.read_exact(&mut data)?;

        let mut inner = self.lock()?;
        inner.read_bytes += data.len() as u64;
        inner.store_cache_entry((read_offset, read_size), data.clone());
        Ok(data)
    }

    fn walk_zip_central_directory(
        &self,
        archive_offset: u64,
        physical_central_offset: u64,
        central_directory_size: u64,
        total_entries: usize,
        max_entries: usize,
    ) -> PyResult<(usize, bool, usize, bool, &'static str)> {
        let mut cursor = physical_central_offset;
        let end = physical_central_offset + central_directory_size;
        let limit = total_entries.min(max_entries);
        let mut links_checked = 0usize;
        for index in 0..limit {
            if cursor + 46 > end {
                return Ok((index, false, links_checked, false, "central_directory_entry_out_of_range"));
            }
            let header = self.read_at_bytes(cursor, 46)?;
            if header.len() < 46 || &header[0..4] != ZIP_CENTRAL {
                return Ok((index, false, links_checked, false, "bad_central_directory_entry_signature"));
            }
            let filename_len = u16_le(&header, 28) as u64;
            let extra_len = u16_le(&header, 30) as u64;
            let comment_len = u16_le(&header, 32) as u64;
            let local_header_offset = u32_le(&header, 42) as u64;
            let entry_size = 46 + filename_len + extra_len + comment_len;
            if cursor + entry_size > end {
                return Ok((index, false, links_checked, false, "central_directory_variable_fields_out_of_range"));
            }
            if links_checked < max_entries {
                let local_sig = self.read_at_bytes(archive_offset + local_header_offset, 4)?;
                if local_sig.len() < 4 || local_sig.as_slice() != ZIP_LOCAL {
                    return Ok((index + 1, true, links_checked, false, "local_header_link_mismatch"));
                }
                links_checked += 1;
            }
            cursor += entry_size;
        }
        Ok((limit, true, links_checked, true, ""))
    }

    fn probe_rar4(
        &self,
        py: Python<'_>,
        result: &Bound<'_, PyDict>,
        start_offset: u64,
        max_blocks: usize,
    ) -> PyResult<()> {
        let mut cursor = start_offset + RAR4.len() as u64;
        let size = self.lock()?.size;
        let evidence = PyList::empty(py);
        evidence.append("rar4:signature")?;
        for index in 0..max_blocks {
            if cursor + 7 > size {
                result.set_item("blocks_checked", index)?;
                result.set_item("error", "rar4_block_header_out_of_range")?;
                return Ok(());
            }
            let fixed = self.read_at_bytes(cursor, 7)?;
            let header_crc = u16_le(&fixed, 0);
            let header_type = fixed[2];
            let header_flags = u16_le(&fixed, 3);
            let header_size = u16_le(&fixed, 5) as u64;
            if !matches!(header_type, 0x72..=0x7B) {
                result.set_item("blocks_checked", index)?;
                result.set_item("error", "rar4_block_unknown_type")?;
                return Ok(());
            }
            if header_size < 7 || cursor + header_size > size {
                result.set_item("blocks_checked", index)?;
                result.set_item("error", "rar4_block_size_out_of_range")?;
                return Ok(());
            }
            let full_header = self.read_at_bytes(cursor, header_size as usize)?;
            if (crc32(&full_header[2..]) & 0xFFFF) != header_crc as u32 {
                result.set_item("blocks_checked", index)?;
                result.set_item("error", "rar4_block_crc_mismatch")?;
                return Ok(());
            }
            let mut block_size = header_size;
            if header_flags & 0x8000 != 0 {
                if header_size < 11 {
                    result.set_item("blocks_checked", index)?;
                    result.set_item("error", "rar4_block_add_size_missing")?;
                    return Ok(());
                }
                block_size += u32_le(&full_header, 7) as u64;
            }
            let next_cursor = cursor + block_size;
            if next_cursor > size {
                result.set_item("blocks_checked", index)?;
                result.set_item("error", "rar4_block_payload_out_of_range")?;
                return Ok(());
            }
            if index == 0 && header_type != 0x73 {
                result.set_item("blocks_checked", 1usize)?;
                result.set_item("error", "rar4_main_header_missing")?;
                return Ok(());
            }
            if index == 0 {
                evidence.append("rar4:main_header")?;
            }
            if header_type == 0x7B {
                evidence.append("rar4:end_block")?;
                result.set_item("plausible", true)?;
                result.set_item("strong_accept", true)?;
                result.set_item("blocks_checked", index + 1)?;
                result.set_item("end_block_found", true)?;
                result.set_item("segment_end", next_cursor)?;
                result.set_item("evidence", evidence)?;
                return Ok(());
            }
            cursor = next_cursor;
        }
        result.set_item("blocks_checked", max_blocks)?;
        result.set_item("segment_end", cursor)?;
        result.set_item("plausible", true)?;
        result.set_item("error", "rar4_block_walk_limit_reached")?;
        result.set_item("evidence", evidence)?;
        Ok(())
    }

    fn probe_rar5(
        &self,
        py: Python<'_>,
        result: &Bound<'_, PyDict>,
        start_offset: u64,
        max_blocks: usize,
    ) -> PyResult<()> {
        let mut cursor = start_offset + RAR5.len() as u64;
        let size = self.lock()?.size;
        let evidence = PyList::empty(py);
        evidence.append("rar5:signature")?;
        for index in 0..max_blocks {
            if cursor + 6 > size {
                result.set_item("blocks_checked", index)?;
                result.set_item("error", "rar5_block_header_out_of_range")?;
                return Ok(());
            }
            let first = self.read_at_bytes(cursor, 64)?;
            let Some((header_size, after_size)) = read_vint(&first, 4) else {
                result.set_item("blocks_checked", index)?;
                result.set_item("error", "rar5_header_size_vint_missing")?;
                return Ok(());
            };
            let header_total_size = 4 + (after_size - 4) as u64 + header_size;
            if header_size == 0 || cursor + header_total_size > size {
                result.set_item("blocks_checked", index)?;
                result.set_item("error", "rar5_header_size_out_of_range")?;
                return Ok(());
            }
            let full = self.read_at_bytes(cursor, header_total_size as usize)?;
            let Some((header_type, after_type)) = read_vint(&full, after_size) else {
                result.set_item("blocks_checked", index)?;
                result.set_item("error", "rar5_header_type_vint_missing")?;
                return Ok(());
            };
            let Some((header_flags, after_flags)) = read_vint(&full, after_type) else {
                result.set_item("blocks_checked", index)?;
                result.set_item("error", "rar5_header_flags_vint_missing")?;
                return Ok(());
            };
            if !matches!(header_type, 1..=5) {
                result.set_item("blocks_checked", index)?;
                result.set_item("error", "rar5_block_unknown_type")?;
                return Ok(());
            }
            let stored_crc = u32_le(&full, 0);
            if crc32(&full[4..]) != stored_crc {
                result.set_item("blocks_checked", index)?;
                result.set_item("error", "rar5_block_crc_mismatch")?;
                return Ok(());
            }
            let mut field_cursor = after_flags;
            if header_flags & 0x0001 != 0 {
                let Some((_, after_extra)) = read_vint(&full, field_cursor) else {
                    result.set_item("blocks_checked", index)?;
                    result.set_item("error", "rar5_extra_area_size_vint_missing")?;
                    return Ok(());
                };
                field_cursor = after_extra;
            }
            let mut data_size = 0u64;
            if header_flags & 0x0002 != 0 {
                let Some((value, _after_data)) = read_vint(&full, field_cursor) else {
                    result.set_item("blocks_checked", index)?;
                    result.set_item("error", "rar5_data_size_vint_missing")?;
                    return Ok(());
                };
                data_size = value;
            }
            let next_cursor = cursor + header_total_size + data_size;
            if next_cursor > size {
                result.set_item("blocks_checked", index)?;
                result.set_item("error", "rar5_block_payload_out_of_range")?;
                return Ok(());
            }
            if index == 0 && header_type != 1 {
                result.set_item("blocks_checked", 1usize)?;
                result.set_item("error", "rar5_main_header_missing")?;
                return Ok(());
            }
            if index == 0 {
                evidence.append("rar5:main_header")?;
            }
            if header_type == 5 {
                evidence.append("rar5:end_block")?;
                result.set_item("plausible", true)?;
                result.set_item("strong_accept", true)?;
                result.set_item("blocks_checked", index + 1)?;
                result.set_item("end_block_found", true)?;
                result.set_item("segment_end", next_cursor)?;
                result.set_item("evidence", evidence)?;
                return Ok(());
            }
            cursor = next_cursor;
        }
        result.set_item("blocks_checked", max_blocks)?;
        result.set_item("segment_end", cursor)?;
        result.set_item("plausible", true)?;
        result.set_item("error", "rar5_block_walk_limit_reached")?;
        result.set_item("evidence", evidence)?;
        Ok(())
    }
}

impl AnalysisBinaryViewInner {
    fn store_cache_entry(&mut self, key: (u64, usize), data: Vec<u8>) {
        if self.cache_bytes == 0 || data.len() > self.cache_bytes {
            return;
        }
        if let Some(old) = self.cache.insert(key, data) {
            self.cache_size = self.cache_size.saturating_sub(old.len());
            self.order.retain(|existing| *existing != key);
        }
        self.cache_size += self.cache.get(&key).map(|value| value.len()).unwrap_or(0);
        self.order.push_back(key);
        while self.cache_size > self.cache_bytes {
            let Some(old_key) = self.order.pop_front() else {
                break;
            };
            if let Some(old) = self.cache.remove(&old_key) {
                self.cache_size = self.cache_size.saturating_sub(old.len());
            }
        }
    }
}

impl ReadGate {
    fn acquire(&self) -> PyResult<ReadPermit<'_>> {
        let mut active = self
            .active
            .lock()
            .map_err(|_| pyo3::exceptions::PyRuntimeError::new_err("analysis read gate lock poisoned"))?;
        while *active >= self.limit {
            active = self
                .available
                .wait(active)
                .map_err(|_| pyo3::exceptions::PyRuntimeError::new_err("analysis read gate lock poisoned"))?;
        }
        *active += 1;
        Ok(ReadPermit { gate: self })
    }
}

impl Drop for ReadPermit<'_> {
    fn drop(&mut self) {
        if let Ok(mut active) = self.gate.active.lock() {
            *active = active.saturating_sub(1);
            self.gate.available.notify_one();
        }
    }
}

fn collect_hits(target: &mut Vec<(&'static str, u64)>, name: &'static str, base: u64, data: &[u8], needle: &[u8]) {
    if needle.is_empty() || data.len() < needle.len() {
        return;
    }
    let mut start = 0usize;
    while let Some(index) = find_bytes(&data[start..], needle) {
        let absolute = start + index;
        target.push((name, base + absolute as u64));
        start = absolute + 1;
        if start >= data.len() {
            break;
        }
    }
}

fn find_bytes(haystack: &[u8], needle: &[u8]) -> Option<usize> {
    haystack.windows(needle.len()).position(|window| window == needle)
}

fn format_for_hit(name: &str) -> &'static str {
    if name.starts_with("zip_") {
        "zip"
    } else if name.starts_with("rar") {
        "rar"
    } else {
        "7z"
    }
}

fn u16_le(bytes: &[u8], offset: usize) -> u16 {
    u16::from_le_bytes([bytes[offset], bytes[offset + 1]])
}

fn u32_le(bytes: &[u8], offset: usize) -> u32 {
    u32::from_le_bytes([
        bytes[offset],
        bytes[offset + 1],
        bytes[offset + 2],
        bytes[offset + 3],
    ])
}

fn u64_le(bytes: &[u8], offset: usize) -> u64 {
    u64::from_le_bytes([
        bytes[offset],
        bytes[offset + 1],
        bytes[offset + 2],
        bytes[offset + 3],
        bytes[offset + 4],
        bytes[offset + 5],
        bytes[offset + 6],
        bytes[offset + 7],
    ])
}

fn read_vint(data: &[u8], offset: usize) -> Option<(u64, usize)> {
    let mut value = 0u64;
    let mut shift = 0;
    for index in offset..data.len().min(offset + 10) {
        let byte = data[index];
        value |= ((byte & 0x7F) as u64) << shift;
        if byte & 0x80 == 0 {
            return Some((value, index + 1));
        }
        shift += 7;
    }
    None
}

fn crc32(bytes: &[u8]) -> u32 {
    let mut crc = 0xFFFF_FFFFu32;
    for byte in bytes {
        crc ^= *byte as u32;
        for _ in 0..8 {
            let mask = (crc & 1).wrapping_neg();
            crc = (crc >> 1) ^ (0xEDB8_8320 & mask);
        }
    }
    !crc
}
