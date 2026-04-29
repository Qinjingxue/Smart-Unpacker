use crate::binary_profile::{
    fuzzy_binary_profile as build_fuzzy_binary_profile, BinaryProfileConfig,
};
use bzip2::read::BzDecoder;
use flate2::read::GzDecoder;
use pyo3::prelude::*;
use pyo3::types::{PyBytes, PyDict, PyList};
use std::collections::{HashMap, VecDeque};
use std::fs::File;
use std::io::{Cursor, Read, Seek, SeekFrom};
use std::sync::{Condvar, Mutex, MutexGuard};
use xz2::read::XzDecoder;
use zstd::stream::read::Decoder as ZstdDecoder;

const ZIP_LOCAL: &[u8] = b"PK\x03\x04";
const ZIP_CENTRAL: &[u8] = b"PK\x01\x02";
const ZIP_EOCD: &[u8] = b"PK\x05\x06";
const RAR4: &[u8] = b"Rar!\x1a\x07\x00";
const RAR5: &[u8] = b"Rar!\x1a\x07\x01\x00";
const SEVEN_ZIP: &[u8] = b"7z\xbc\xaf\x27\x1c";
const GZIP: &[u8] = b"\x1f\x8b\x08";
const BZIP2: &[u8] = b"BZh";
const XZ: &[u8] = b"\xfd7zXZ\x00";
const ZSTD: &[u8] = b"\x28\xb5\x2f\xfd";
const TAR_USTAR: &[u8] = b"ustar";
const TAR_BLOCK_SIZE: usize = 512;

const ANALYSIS_SIGNATURES_P: &[(&str, &[u8])] = &[("zip_local", ZIP_LOCAL), ("zip_eocd", ZIP_EOCD)];
const ANALYSIS_SIGNATURES_R: &[(&str, &[u8])] = &[("rar4", RAR4), ("rar5", RAR5)];
const ANALYSIS_SIGNATURES_7: &[(&str, &[u8])] = &[("7z", SEVEN_ZIP)];
const ANALYSIS_SIGNATURES_GZIP: &[(&str, &[u8])] = &[("gzip", GZIP)];
const ANALYSIS_SIGNATURES_BZIP2: &[(&str, &[u8])] = &[("bzip2", BZIP2)];
const ANALYSIS_SIGNATURES_XZ: &[(&str, &[u8])] = &[("xz", XZ)];
const ANALYSIS_SIGNATURES_ZSTD: &[(&str, &[u8])] = &[("zstd", ZSTD)];
const ANALYSIS_SIGNATURES_TAR: &[(&str, &[u8])] = &[("tar_ustar", TAR_USTAR)];

#[pyclass]
pub(crate) struct AnalysisBinaryView {
    inner: Mutex<AnalysisBinaryViewInner>,
    read_gate: ReadGate,
}

#[pyclass]
pub(crate) struct AnalysisMultiVolumeView {
    inner: Mutex<AnalysisMultiVolumeViewInner>,
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

struct AnalysisMultiVolumeViewInner {
    path: String,
    size: u64,
    volumes: Vec<VolumeRange>,
    cache_bytes: usize,
    max_read_bytes: Option<u64>,
    cache: HashMap<(u64, usize), Vec<u8>>,
    order: VecDeque<(u64, usize)>,
    cache_size: usize,
    read_bytes: u64,
    cache_hits: u64,
}

#[derive(Clone)]
struct VolumeRange {
    start: u64,
    end: u64,
    path: String,
}

#[derive(Clone)]
struct VolumeRead {
    path: String,
    start: u64,
    size: usize,
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

    fn read_at<'py>(
        &self,
        py: Python<'py>,
        offset: u64,
        size: usize,
    ) -> PyResult<Bound<'py, PyBytes>> {
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
        result.set_item("content_integrity_warning", "")?;
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
        let (entries_checked, cd_ok, links_checked, links_ok, error) = self
            .walk_zip_central_directory(
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
            result.set_item(
                "content_integrity_warning",
                self.zip_content_integrity_warning(
                    archive_offset,
                    physical_central_offset,
                    total_entries as usize,
                    max_cd_entries_to_walk,
                )?,
            )?;
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
        result.set_item(
            "start_header_crc_ok",
            stored_start_crc == computed_start_crc,
        )?;
        if stored_start_crc != computed_start_crc {
            result.set_item("error", "start_header_crc_mismatch")?;
            return Ok(result.unbind());
        }
        let next_header_offset = u64_le(start_header, 0);
        let next_header_size = u64_le(start_header, 8);
        let next_header_crc = u32_le(start_header, 16);
        let Some(next_header_start) = start_offset
            .checked_add(32)
            .and_then(|value| value.checked_add(next_header_offset))
        else {
            result.set_item("error", "next_header_out_of_range")?;
            return Ok(result.unbind());
        };
        let Some(segment_end) = next_header_start.checked_add(next_header_size) else {
            result.set_item("error", "next_header_out_of_range")?;
            return Ok(result.unbind());
        };
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

    #[pyo3(signature = (start_offset=0, max_entries_to_walk=64))]
    fn probe_tar(
        &self,
        py: Python<'_>,
        start_offset: u64,
        max_entries_to_walk: usize,
    ) -> PyResult<Py<PyDict>> {
        let result = self.walk_tar(py, start_offset, max_entries_to_walk)?;
        Ok(result.unbind())
    }

    fn probe_compression_stream(&self, py: Python<'_>, format: &str) -> PyResult<Py<PyDict>> {
        let result = self.probe_compression(py, format)?;
        Ok(result.unbind())
    }

    #[pyo3(signature = (format, max_probe_bytes=4194304))]
    fn probe_compressed_tar(
        &self,
        py: Python<'_>,
        format: &str,
        max_probe_bytes: usize,
    ) -> PyResult<Py<PyDict>> {
        let stream = self.probe_compression(py, format)?;
        stream.set_item("container", format)?;
        stream.set_item("inner_format", "tar")?;
        stream.set_item("inner_tar_verified", false)?;
        stream.set_item("tar_plausible", false)?;
        stream.set_item("tar_probe_error", "")?;
        if !stream
            .get_item("magic_matched")?
            .unwrap()
            .extract::<bool>()?
        {
            return Ok(stream.unbind());
        }
        let read_size = (self.lock()?.size as usize).min(max_probe_bytes);
        let data = self.read_at_bytes(0, read_size)?;
        match decompress_sample(format, &data, TAR_BLOCK_SIZE * 2) {
            Ok(sample) => {
                if sample.len() < TAR_BLOCK_SIZE {
                    stream.set_item("tar_probe_error", "inner_sample_too_small")?;
                    return Ok(stream.unbind());
                }
                let (ok, error, member_size, ustar) =
                    tar_header_plausible(&sample[..TAR_BLOCK_SIZE]);
                stream.set_item("inner_tar_verified", ok)?;
                stream.set_item("tar_plausible", ok)?;
                stream.set_item("tar_probe_error", error)?;
                stream.set_item("inner_tar_member_size", member_size)?;
                stream.set_item("inner_tar_ustar", ustar)?;
            }
            Err(error) => {
                stream.set_item("tar_probe_error", error)?;
            }
        }
        Ok(stream.unbind())
    }

    #[pyo3(signature = (
        window_bytes=65536,
        max_windows=8,
        max_sample_bytes=1048576,
        entropy_high_threshold=6.8,
        entropy_low_threshold=3.5,
        entropy_jump_threshold=1.25,
        ngram_top_k=8,
        max_ngram_sample_bytes=262144
    ))]
    fn fuzzy_binary_profile(
        &self,
        py: Python<'_>,
        window_bytes: usize,
        max_windows: usize,
        max_sample_bytes: usize,
        entropy_high_threshold: f64,
        entropy_low_threshold: f64,
        entropy_jump_threshold: f64,
        ngram_top_k: usize,
        max_ngram_sample_bytes: usize,
    ) -> PyResult<Py<PyDict>> {
        let file_size = self.lock()?.size;
        let window_bytes = window_bytes.max(1024);
        let config = BinaryProfileConfig {
            window_bytes,
            max_windows: max_windows.max(1),
            max_sample_bytes: max_sample_bytes.max(window_bytes),
            entropy_high_threshold,
            entropy_low_threshold,
            entropy_jump_threshold,
            ngram_top_k: ngram_top_k.max(1),
            max_ngram_sample_bytes,
        };
        build_fuzzy_binary_profile(
            py,
            file_size,
            |offset, size| self.read_at_bytes(offset, size),
            config,
        )
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
        let head_end = head_len as u64;
        let scan_start = 0u64;
        let tail_end = size;
        let (scan_start, scan_len, scanned_head, scanned_tail) = if tail_start <= head_end {
            let end = head_end.max(tail_end);
            (
                scan_start,
                end.saturating_sub(scan_start) as usize,
                head_len,
                tail_len,
            )
        } else {
            (0u64, head_len, head_len, 0usize)
        };

        let mut hits = Vec::new();
        if tail_start <= head_end {
            let data = self.read_at_bytes(scan_start, scan_len)?;
            collect_signature_hits(&mut hits, scan_start, &data);
        } else {
            let head = self.read_at_bytes(0, head_len)?;
            collect_signature_hits(&mut hits, 0, &head);
            let tail = self.read_at_bytes(tail_start, tail_len)?;
            collect_signature_hits(&mut hits, tail_start, &tail);
        }
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
        dict.set_item("head_bytes", scanned_head)?;
        dict.set_item(
            "tail_bytes",
            if scanned_tail == 0 {
                tail_len
            } else {
                scanned_tail
            },
        )?;
        Ok(dict.unbind())
    }
}

#[pymethods]
impl AnalysisMultiVolumeView {
    #[new]
    #[pyo3(signature = (paths, cache_bytes=67108864, max_read_bytes=None, max_concurrent_reads=1))]
    fn new(
        paths: Vec<String>,
        cache_bytes: usize,
        max_read_bytes: Option<u64>,
        max_concurrent_reads: usize,
    ) -> PyResult<Self> {
        let paths = paths
            .into_iter()
            .filter(|path| !path.is_empty())
            .collect::<Vec<_>>();
        if paths.is_empty() {
            return Err(pyo3::exceptions::PyValueError::new_err(
                "AnalysisMultiVolumeView requires at least one volume",
            ));
        }
        let mut cursor = 0u64;
        let mut volumes = Vec::with_capacity(paths.len());
        for path in &paths {
            let size = std::fs::metadata(path)?.len();
            let end = cursor.checked_add(size).ok_or_else(|| {
                pyo3::exceptions::PyOverflowError::new_err("multi-volume archive size overflow")
            })?;
            volumes.push(VolumeRange {
                start: cursor,
                end,
                path: path.clone(),
            });
            cursor = end;
        }
        Ok(Self {
            inner: Mutex::new(AnalysisMultiVolumeViewInner {
                path: paths[0].clone(),
                size: cursor,
                volumes,
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

    fn read_at<'py>(
        &self,
        py: Python<'py>,
        offset: u64,
        size: usize,
    ) -> PyResult<Bound<'py, PyBytes>> {
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

    #[pyo3(signature = (
        window_bytes=65536,
        max_windows=8,
        max_sample_bytes=1048576,
        entropy_high_threshold=6.8,
        entropy_low_threshold=3.5,
        entropy_jump_threshold=1.25,
        ngram_top_k=8,
        max_ngram_sample_bytes=262144
    ))]
    fn fuzzy_binary_profile(
        &self,
        py: Python<'_>,
        window_bytes: usize,
        max_windows: usize,
        max_sample_bytes: usize,
        entropy_high_threshold: f64,
        entropy_low_threshold: f64,
        entropy_jump_threshold: f64,
        ngram_top_k: usize,
        max_ngram_sample_bytes: usize,
    ) -> PyResult<Py<PyDict>> {
        let file_size = self.lock()?.size;
        let window_bytes = window_bytes.max(1024);
        let config = BinaryProfileConfig {
            window_bytes,
            max_windows: max_windows.max(1),
            max_sample_bytes: max_sample_bytes.max(window_bytes),
            entropy_high_threshold,
            entropy_low_threshold,
            entropy_jump_threshold,
            ngram_top_k: ngram_top_k.max(1),
            max_ngram_sample_bytes,
        };
        build_fuzzy_binary_profile(
            py,
            file_size,
            |offset, size| self.read_at_bytes(offset, size),
            config,
        )
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
        let head_end = head_len as u64;
        let mut hits = Vec::new();
        let scanned_head = head_len;
        let scanned_tail = tail_len;

        if tail_start <= head_end {
            let data = self.read_at_bytes(0, size as usize)?;
            collect_signature_hits(&mut hits, 0, &data);
        } else {
            let head = self.read_at_bytes(0, head_len)?;
            collect_signature_hits(&mut hits, 0, &head);
            let tail = self.read_at_bytes(tail_start, tail_len)?;
            collect_signature_hits(&mut hits, tail_start, &tail);
        }
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
        dict.set_item("head_bytes", scanned_head)?;
        dict.set_item("tail_bytes", scanned_tail)?;
        Ok(dict.unbind())
    }
}

impl AnalysisBinaryView {
    fn lock(&self) -> PyResult<MutexGuard<'_, AnalysisBinaryViewInner>> {
        self.inner.lock().map_err(|_| {
            pyo3::exceptions::PyRuntimeError::new_err("analysis binary view lock poisoned")
        })
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

    fn read_tail_bytes(&self, size: usize) -> PyResult<Vec<u8>> {
        let view_size = self.lock()?.size;
        let read_size = size.min(view_size as usize);
        let offset = view_size.saturating_sub(read_size as u64);
        self.read_at_bytes(offset, read_size)
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
                return Ok((
                    index,
                    false,
                    links_checked,
                    false,
                    "central_directory_entry_out_of_range",
                ));
            }
            let header = self.read_at_bytes(cursor, 46)?;
            if header.len() < 46 || &header[0..4] != ZIP_CENTRAL {
                return Ok((
                    index,
                    false,
                    links_checked,
                    false,
                    "bad_central_directory_entry_signature",
                ));
            }
            let filename_len = u16_le(&header, 28) as u64;
            let extra_len = u16_le(&header, 30) as u64;
            let comment_len = u16_le(&header, 32) as u64;
            let local_header_offset = u32_le(&header, 42) as u64;
            let entry_size = 46 + filename_len + extra_len + comment_len;
            if cursor + entry_size > end {
                return Ok((
                    index,
                    false,
                    links_checked,
                    false,
                    "central_directory_variable_fields_out_of_range",
                ));
            }
            if links_checked < max_entries {
                let local_sig = self.read_at_bytes(archive_offset + local_header_offset, 4)?;
                if local_sig.len() < 4 || local_sig.as_slice() != ZIP_LOCAL {
                    return Ok((
                        index + 1,
                        true,
                        links_checked,
                        false,
                        "local_header_link_mismatch",
                    ));
                }
                links_checked += 1;
            }
            cursor += entry_size;
        }
        Ok((limit, true, links_checked, true, ""))
    }

    fn zip_content_integrity_warning(
        &self,
        archive_offset: u64,
        physical_central_offset: u64,
        total_entries: usize,
        max_entries: usize,
    ) -> PyResult<&'static str> {
        let mut cursor = physical_central_offset;
        for _ in 0..total_entries.min(max_entries).min(8) {
            let header = self.read_at_bytes(cursor, 46)?;
            if header.len() < 46 || &header[0..4] != ZIP_CENTRAL {
                return Ok("");
            }
            let cd_crc = u32_le(&header, 16);
            let filename_len = u16_le(&header, 28) as u64;
            let extra_len = u16_le(&header, 30) as u64;
            let comment_len = u16_le(&header, 32) as u64;
            let local_header_offset = u32_le(&header, 42) as u64;
            let local = self.read_at_bytes(archive_offset + local_header_offset, 30)?;
            if local.len() >= 30 && &local[0..4] == ZIP_LOCAL {
                let flags = u16_le(&local, 6);
                let local_crc = u32_le(&local, 14);
                if flags & 0x0008 != 0 {
                    return Ok("data_descriptor_or_deferred_crc");
                }
                if local_crc != cd_crc {
                    return Ok("local_header_crc_mismatch");
                }
            }
            cursor += 46 + filename_len + extra_len + comment_len;
        }
        Ok("")
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

    fn walk_tar<'py>(
        &self,
        py: Python<'py>,
        start_offset: u64,
        max_entries: usize,
    ) -> PyResult<Bound<'py, PyDict>> {
        let result = PyDict::new(py);
        result.set_item("format", "tar")?;
        result.set_item("plausible", false)?;
        result.set_item("error", "")?;
        result.set_item("entries_checked", 0usize)?;
        result.set_item("entry_walk_ok", false)?;
        result.set_item("end_zero_blocks", false)?;
        result.set_item("segment_end", py.None())?;
        result.set_item("boundary_confidence", "none")?;
        result.set_item("integrity_confidence", "unknown")?;
        result.set_item("evidence", PyList::empty(py))?;

        let size = self.lock()?.size;
        let mut cursor = start_offset;
        let mut checked = 0usize;
        let mut zero_blocks = 0usize;
        while checked < max_entries && cursor + TAR_BLOCK_SIZE as u64 <= size {
            let header = self.read_at_bytes(cursor, TAR_BLOCK_SIZE)?;
            if header.len() < TAR_BLOCK_SIZE {
                result.set_item("error", "short_tar_header")?;
                break;
            }
            if header.iter().all(|byte| *byte == 0) {
                zero_blocks += 1;
                cursor += TAR_BLOCK_SIZE as u64;
                if zero_blocks >= 2 {
                    result.set_item("plausible", checked > 0)?;
                    result.set_item("entries_checked", checked)?;
                    result.set_item("entry_walk_ok", checked > 0)?;
                    result.set_item("end_zero_blocks", true)?;
                    result.set_item("segment_end", cursor)?;
                    result.set_item("boundary_confidence", "high")?;
                    result.set_item(
                        "evidence",
                        PyList::new(
                            py,
                            [
                                "tar:header_checksum",
                                "tar:block_walk",
                                "tar:end_zero_blocks",
                            ],
                        )?,
                    )?;
                    return Ok(result);
                }
                continue;
            }
            zero_blocks = 0;
            let (ok, error, member_size, ustar) = tar_header_plausible(&header);
            if !ok {
                result.set_item("entries_checked", checked)?;
                result.set_item("error", error)?;
                if checked > 0 {
                    result.set_item("plausible", true)?;
                    result.set_item("entry_walk_ok", true)?;
                    result.set_item("segment_end", cursor)?;
                    result.set_item("boundary_confidence", "medium")?;
                    result.set_item(
                        "evidence",
                        PyList::new(py, ["tar:header_checksum", "tar:block_walk_prefix"])?,
                    )?;
                }
                return Ok(result);
            }
            checked += 1;
            cursor += TAR_BLOCK_SIZE as u64 + member_size + tar_padding(member_size);
            result.set_item(
                "evidence",
                PyList::new(
                    py,
                    [
                        "tar:header_checksum",
                        if ustar {
                            "tar:ustar_magic"
                        } else {
                            "tar:v7_header"
                        },
                    ],
                )?,
            )?;
        }
        if checked > 0 {
            result.set_item("plausible", true)?;
            result.set_item("entries_checked", checked)?;
            result.set_item("entry_walk_ok", true)?;
            result.set_item("segment_end", cursor)?;
            result.set_item("boundary_confidence", "medium")?;
            result.set_item("error", "tar_end_zero_blocks_not_found")?;
            result.set_item(
                "evidence",
                PyList::new(py, ["tar:header_checksum", "tar:block_walk_prefix"])?,
            )?;
        }
        Ok(result)
    }

    fn probe_compression<'py>(
        &self,
        py: Python<'py>,
        format: &str,
    ) -> PyResult<Bound<'py, PyDict>> {
        let result = PyDict::new(py);
        result.set_item("format", format)?;
        result.set_item("magic_matched", false)?;
        result.set_item("plausible", false)?;
        result.set_item("error", "")?;
        result.set_item("confidence", 0.0f64)?;
        result.set_item("boundary_confidence", "medium")?;
        result.set_item("integrity_confidence", "unknown")?;
        result.set_item("evidence", PyList::empty(py))?;
        let header = self.read_at_bytes(0, 64)?;
        match format {
            "gzip" => {
                if !header.starts_with(GZIP) {
                    result.set_item("error", "gzip_magic_not_found")?;
                    return Ok(result);
                }
                result.set_item("magic_matched", true)?;
                if header.len() < 10 || header[3] & 0xE0 != 0 {
                    result.set_item("error", "gzip_reserved_flags_set")?;
                    return Ok(result);
                }
                result.set_item("plausible", true)?;
                result.set_item("confidence", 0.90f64)?;
                let evidence = PyList::new(
                    py,
                    ["gzip:magic", "gzip:method:deflate", "gzip:flags_valid"],
                )?;
                if self.lock()?.size >= 18 {
                    let tail = self.read_tail_bytes(4)?;
                    if tail.len() == 4 {
                        result.set_item("isize", u32_le(&tail, 0))?;
                        evidence.append("gzip:trailer")?;
                    }
                }
                result.set_item("evidence", evidence)?;
            }
            "bzip2" => {
                if !header.starts_with(BZIP2) {
                    result.set_item("error", "bzip2_magic_not_found")?;
                    return Ok(result);
                }
                result.set_item("magic_matched", true)?;
                let ok = header.len() >= 10
                    && b"123456789".contains(&header[3])
                    && (&header[4..10] == b"\x31\x41\x59\x26\x53\x59"
                        || &header[4..10] == b"\x17\x72\x45\x38\x50\x90");
                if !ok {
                    result.set_item("error", "bzip2_block_marker_not_found")?;
                    return Ok(result);
                }
                result.set_item("plausible", true)?;
                result.set_item("confidence", 0.92f64)?;
                result.set_item(
                    "evidence",
                    PyList::new(py, ["bzip2:magic", "bzip2:block_marker"])?,
                )?;
            }
            "xz" => {
                if !header.starts_with(XZ) {
                    result.set_item("error", "xz_magic_not_found")?;
                    return Ok(result);
                }
                result.set_item("magic_matched", true)?;
                let footer = self.read_tail_bytes(12)?;
                if footer.len() == 12 && &footer[10..12] == b"YZ" {
                    result.set_item("plausible", true)?;
                    result.set_item("confidence", 0.95f64)?;
                    result.set_item("boundary_confidence", "high")?;
                    result.set_item(
                        "evidence",
                        PyList::new(py, ["xz:magic", "xz:footer_magic"])?,
                    )?;
                } else {
                    result.set_item("plausible", true)?;
                    result.set_item("confidence", 0.72f64)?;
                    result.set_item("error", "xz_footer_magic_not_found")?;
                    result.set_item("evidence", PyList::new(py, ["xz:magic"])?)?;
                }
            }
            "zstd" => {
                if !header.starts_with(ZSTD) {
                    result.set_item("error", "zstd_magic_not_found")?;
                    return Ok(result);
                }
                result.set_item("magic_matched", true)?;
                if header.len() < 6 || header[4] & 0x08 != 0 {
                    result.set_item("error", "zstd_reserved_bit_set")?;
                    return Ok(result);
                }
                result.set_item("plausible", true)?;
                result.set_item("confidence", 0.88f64)?;
                result.set_item(
                    "evidence",
                    PyList::new(py, ["zstd:magic", "zstd:frame_descriptor"])?,
                )?;
            }
            _ => {
                result.set_item("error", "unsupported_compression_format")?;
            }
        }
        Ok(result)
    }
}

impl AnalysisMultiVolumeView {
    fn lock(&self) -> PyResult<MutexGuard<'_, AnalysisMultiVolumeViewInner>> {
        self.inner.lock().map_err(|_| {
            pyo3::exceptions::PyRuntimeError::new_err("analysis multi-volume view lock poisoned")
        })
    }

    fn read_at_bytes(&self, offset: u64, size: usize) -> PyResult<Vec<u8>> {
        let (reads, read_offset, read_size) = {
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
            let end_offset = offset + read_size as u64;
            let mut reads = Vec::new();
            for volume in &inner.volumes {
                if offset >= volume.end || end_offset <= volume.start {
                    continue;
                }
                let local_start = offset.max(volume.start);
                let local_end = end_offset.min(volume.end);
                reads.push(VolumeRead {
                    path: volume.path.clone(),
                    start: local_start - volume.start,
                    size: (local_end - local_start) as usize,
                });
            }
            (reads, offset, read_size)
        };

        let _permit = self.read_gate.acquire()?;
        let mut data = Vec::with_capacity(read_size);
        for read in reads {
            let mut file = File::open(&read.path)?;
            file.seek(SeekFrom::Start(read.start))?;
            let mut chunk = vec![0; read.size];
            file.read_exact(&mut chunk)?;
            data.extend_from_slice(&chunk);
        }

        let mut inner = self.lock()?;
        inner.read_bytes += data.len() as u64;
        inner.store_cache_entry((read_offset, read_size), data.clone());
        Ok(data)
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

impl AnalysisMultiVolumeViewInner {
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
        let mut active = self.active.lock().map_err(|_| {
            pyo3::exceptions::PyRuntimeError::new_err("analysis read gate lock poisoned")
        })?;
        while *active >= self.limit {
            active = self.available.wait(active).map_err(|_| {
                pyo3::exceptions::PyRuntimeError::new_err("analysis read gate lock poisoned")
            })?;
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

fn collect_signature_hits(target: &mut Vec<(&'static str, u64)>, base: u64, data: &[u8]) {
    if data.is_empty() {
        return;
    }
    for (index, byte) in data.iter().enumerate() {
        let candidates = signatures_for_first_byte(*byte);
        if candidates.is_empty() {
            continue;
        }
        for (name, signature) in candidates {
            let end = index + signature.len();
            if end <= data.len() && &data[index..end] == *signature {
                target.push((*name, base + index as u64));
            }
        }
    }
}

fn signatures_for_first_byte(byte: u8) -> &'static [(&'static str, &'static [u8])] {
    match byte {
        b'P' => ANALYSIS_SIGNATURES_P,
        b'R' => ANALYSIS_SIGNATURES_R,
        b'7' => ANALYSIS_SIGNATURES_7,
        0x1f => ANALYSIS_SIGNATURES_GZIP,
        b'B' => ANALYSIS_SIGNATURES_BZIP2,
        0xfd => ANALYSIS_SIGNATURES_XZ,
        b'(' => ANALYSIS_SIGNATURES_ZSTD,
        b'u' => ANALYSIS_SIGNATURES_TAR,
        _ => &[],
    }
}

fn format_for_hit(name: &str) -> &'static str {
    if name.starts_with("zip_") {
        "zip"
    } else if name.starts_with("rar") {
        "rar"
    } else if name == "7z" {
        "7z"
    } else if name == "tar_ustar" {
        "tar"
    } else if name == "gzip" {
        "gzip"
    } else if name == "bzip2" {
        "bzip2"
    } else if name == "xz" {
        "xz"
    } else if name == "zstd" {
        "zstd"
    } else {
        ""
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

fn tar_header_plausible(header: &[u8]) -> (bool, &'static str, u64, bool) {
    if header.len() < TAR_BLOCK_SIZE {
        return (false, "short_tar_header", 0, false);
    }
    let Some(stored_checksum) = parse_octal(&header[148..156]) else {
        return (false, "invalid_checksum_field", 0, false);
    };
    let Some(member_size) = parse_octal(&header[124..136]) else {
        return (false, "invalid_size_field", 0, false);
    };
    if stored_checksum != tar_checksum(header) {
        return (false, "checksum_mismatch", 0, false);
    }
    (
        true,
        "",
        member_size,
        matches!(&header[257..263], b"ustar\x00" | b"ustar "),
    )
}

fn parse_octal(field: &[u8]) -> Option<u64> {
    let text = field
        .iter()
        .copied()
        .filter(|byte| *byte != 0 && *byte != b' ')
        .collect::<Vec<_>>();
    if text.is_empty() {
        return Some(0);
    }
    std::str::from_utf8(&text)
        .ok()
        .and_then(|value| u64::from_str_radix(value.trim(), 8).ok())
}

fn tar_checksum(header: &[u8]) -> u64 {
    header[..148].iter().map(|byte| *byte as u64).sum::<u64>()
        + 32 * 8
        + header[156..].iter().map(|byte| *byte as u64).sum::<u64>()
}

fn tar_padding(size: u64) -> u64 {
    let remainder = size % TAR_BLOCK_SIZE as u64;
    if remainder == 0 {
        0
    } else {
        TAR_BLOCK_SIZE as u64 - remainder
    }
}

fn decompress_sample(
    format: &str,
    data: &[u8],
    max_output: usize,
) -> Result<Vec<u8>, &'static str> {
    let cursor = Cursor::new(data);
    let mut output = Vec::new();
    let result = match format {
        "gzip" => GzDecoder::new(cursor)
            .take(max_output as u64)
            .read_to_end(&mut output),
        "bzip2" => BzDecoder::new(cursor)
            .take(max_output as u64)
            .read_to_end(&mut output),
        "xz" => XzDecoder::new(cursor)
            .take(max_output as u64)
            .read_to_end(&mut output),
        "zstd" => {
            let decoder = ZstdDecoder::new(cursor).map_err(|_| "zstd_decoder_init_failed")?;
            decoder.take(max_output as u64).read_to_end(&mut output)
        }
        _ => return Err("unsupported_compression_format"),
    };
    result.map_err(|_| "decompression_probe_failed")?;
    Ok(output)
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
