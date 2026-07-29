use crate::io::reader::{ManagedReader, SourceCursor};
use crate::io::util::STREAM_CHUNK_SIZE;
use aho_corasick::{packed, AhoCorasick};
use crc32fast::{hash as crc32, Hasher};
use flate2::read::DeflateDecoder;
use pyo3::prelude::*;
use pyo3::types::{PyDict, PyList};
use std::io::{self, Read};
use std::sync::{mpsc, Arc, Mutex, OnceLock};

use rayon::prelude::*;

const ZIP_LOCAL: &[u8] = b"PK\x03\x04";
const ZIP_EOCD: &[u8] = b"PK\x05\x06";
const SEVEN_ZIP: &[u8] = b"7z\xbc\xaf\x27\x1c";
const RAR4: &[u8] = b"Rar!\x1a\x07\x00";
const RAR5: &[u8] = b"Rar!\x1a\x07\x01\x00";
const GZIP: &[u8] = b"\x1f\x8b\x08";
const BZIP2: &[u8] = b"BZh";
const XZ: &[u8] = b"\xfd7zXZ\x00";
const ZSTD: &[u8] = b"\x28\xb5\x2f\xfd";
const TAR_USTAR: &[u8] = b"ustar";

type PatternSpec = (&'static [u8], &'static str, &'static str);

const PATTERNS: [PatternSpec; 10] = [
    (ZIP_LOCAL, "zip_local", "zip"),
    (ZIP_EOCD, "zip_eocd", "zip_eocd"),
    (SEVEN_ZIP, "7z", "7z"),
    (RAR4, "rar4", "rar4"),
    (RAR5, "rar5", "rar5"),
    (GZIP, "gzip", "gzip"),
    (BZIP2, "bzip2", "bzip2"),
    (XZ, "xz", "xz"),
    (ZSTD, "zstd", "zstd"),
    (TAR_USTAR, "tar_ustar", "tar"),
];
const XZ_PATTERN_INDEX: usize = 7;
const ZSTD_PATTERN_INDEX: usize = 8;

static EMBEDDED_MATCHER: OnceLock<AhoCorasick> = OnceLock::new();
static EMBEDDED_PACKED_MATCHER: OnceLock<Option<packed::Searcher>> = OnceLock::new();

// More workers reduce throughput once their simultaneous scans compete for
// memory bandwidth. Keep this local to embedded scanning: candidate
// validation and unrelated Rayon users retain the full global pool.
const MAX_SCAN_WORKERS: usize = 8;
const EMBEDDED_CHUNK_SIZE: usize = STREAM_CHUNK_SIZE;

#[derive(Debug, Clone, PartialEq)]
struct EmbeddedCandidate {
    format: &'static str,
    detected_ext: &'static str,
    offset: u64,
    end_offset: Option<u64>,
    confidence: f64,
    validation: &'static str,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct RawHit {
    hit_name: &'static str,
    kind: &'static str,
    offset: u64,
}

struct ScanChunk {
    buffer: Vec<u8>,
    sample_len: usize,
    carry_len: usize,
    base_offset: u64,
}

struct NativeScanResult {
    file_size: u64,
    raw_hits: Vec<RawHit>,
    candidates: Vec<EmbeddedCandidate>,
}

/// Scan one physical byte stream once for every supported embedded format.
///
/// Raw signatures are never returned directly: each hit must pass the format's
/// structural header checks. The scan deliberately has no hit or byte budget;
/// callers select which files receive this reliable pass before invoking it.
#[pyfunction]
pub(crate) fn scan_embedded_archives(py: Python<'_>, path: &str) -> PyResult<Py<PyDict>> {
    let owned_path = path.to_owned();
    let reader = py.detach(move || ManagedReader::open(&owned_path))?;
    scan_embedded_archives_with_reader(py, &reader)
}

pub(crate) fn scan_embedded_archives_with_reader(
    py: Python<'_>,
    reader: &ManagedReader,
) -> PyResult<Py<PyDict>> {
    let reader = reader.clone();
    let scan = py.detach(move || scan_embedded_archives_native(reader))?;

    let result = PyDict::new(py);
    result.set_item("complete", true)?;
    result.set_item("file_size", scan.file_size)?;
    result.set_item("read_bytes", scan.file_size)?;
    let hit_rows = PyList::empty(py);
    for hit in scan.raw_hits {
        let row = PyDict::new(py);
        row.set_item("name", hit.hit_name)?;
        row.set_item(
            "offset",
            if hit.kind == "tar" {
                hit.offset + 257
            } else {
                hit.offset
            },
        )?;
        row.set_item("source", "detection_embedded_scan")?;
        hit_rows.append(row)?;
    }
    result.set_item("hits", hit_rows)?;
    let rows = PyList::empty(py);
    for candidate in scan.candidates {
        let row = PyDict::new(py);
        row.set_item("format", candidate.format)?;
        row.set_item("detected_ext", candidate.detected_ext)?;
        row.set_item("offset", candidate.offset)?;
        row.set_item("end_offset", candidate.end_offset)?;
        row.set_item("confidence", candidate.confidence)?;
        row.set_item("validation", candidate.validation)?;
        rows.append(row)?;
    }
    result.set_item("candidates", rows)?;
    Ok(result.unbind())
}

fn embedded_matcher() -> &'static AhoCorasick {
    EMBEDDED_MATCHER.get_or_init(|| {
        AhoCorasick::new(PATTERNS.iter().map(|(magic, _, _)| *magic))
            .expect("embedded archive signatures are valid")
    })
}

fn embedded_packed_matcher() -> Option<&'static packed::Searcher> {
    EMBEDDED_PACKED_MATCHER
        .get_or_init(|| packed::Searcher::new(PATTERNS.iter().map(|(magic, _, _)| *magic)))
        .as_ref()
}

fn scan_embedded_archives_native(reader: ManagedReader) -> io::Result<NativeScanResult> {
    let file_size = reader.len();
    let mut raw_hits = if let Some(mapped) = reader.map_read_only()? {
        scan_raw_hits_mapped(&mapped)
    } else {
        let mut scan_file = reader.stream_cursor();
        scan_raw_hits(&mut scan_file)?
    };
    raw_hits.sort_by_key(|hit| (hit.offset, hit.hit_name));

    let validation_file = reader;
    let validation_results: Vec<io::Result<Option<EmbeddedCandidate>>> = raw_hits
        .par_iter()
        .map(|hit| validate_candidate(&validation_file, file_size, hit.kind, hit.offset))
        .collect();
    let mut candidates = Vec::new();
    for result in validation_results {
        if let Some(candidate) = result? {
            candidates.push(candidate);
        }
    }
    candidates.sort_by_key(|candidate| (candidate.offset, candidate.format));
    candidates.dedup_by_key(|candidate| (candidate.offset, candidate.format));

    Ok(NativeScanResult {
        file_size,
        raw_hits,
        candidates,
    })
}

fn scan_raw_hits_mapped(data: &[u8]) -> Vec<RawHit> {
    if data.is_empty() {
        return Vec::new();
    }
    let overlap = PATTERNS
        .iter()
        .map(|(magic, _, _)| magic.len())
        .max()
        .unwrap_or(1)
        .saturating_sub(1);
    let chunk_count = data.len().div_ceil(EMBEDDED_CHUNK_SIZE);
    let worker_count = rayon::current_num_threads()
        .clamp(1, MAX_SCAN_WORKERS)
        .min(chunk_count);
    if worker_count == 1 {
        return scan_mapped_worker(data, overlap, 0, 1, chunk_count);
    }

    std::thread::scope(|scope| {
        let workers = (0..worker_count)
            .map(|worker| {
                scope.spawn(move || {
                    scan_mapped_worker(data, overlap, worker, worker_count, chunk_count)
                })
            })
            .collect::<Vec<_>>();
        let mut hits = Vec::new();
        for worker in workers {
            hits.extend(worker.join().expect("embedded mmap worker did not panic"));
        }
        hits
    })
}

fn scan_mapped_worker(
    data: &[u8],
    overlap: usize,
    first_chunk: usize,
    stride: usize,
    chunk_count: usize,
) -> Vec<RawHit> {
    let mut hits = Vec::new();
    for chunk in (first_chunk..chunk_count).step_by(stride) {
        let start = chunk * EMBEDDED_CHUNK_SIZE;
        let end = (start + EMBEDDED_CHUNK_SIZE).min(data.len());
        let sample_start = start.saturating_sub(overlap);
        hits.extend(scan_sample(
            &data[sample_start..end],
            start - sample_start,
            sample_start as u64,
        ));
    }
    hits
}

fn scan_raw_hits(file: &mut SourceCursor) -> io::Result<Vec<RawHit>> {
    let overlap = PATTERNS
        .iter()
        .map(|(magic, _, _)| magic.len())
        .max()
        .unwrap_or(1)
        .saturating_sub(1);
    let worker_count = rayon::current_num_threads().clamp(1, MAX_SCAN_WORKERS);
    if worker_count == 1 {
        return scan_raw_hits_sequential(file, overlap);
    }
    let buffer_count = (worker_count * 2).clamp(2, 64);
    let (free_tx, free_rx) = mpsc::sync_channel::<Vec<u8>>(buffer_count);
    let (job_tx, job_rx) = mpsc::sync_channel::<ScanChunk>(buffer_count);
    let (hits_tx, hits_rx) = mpsc::channel::<Vec<RawHit>>();
    let job_rx = Arc::new(Mutex::new(job_rx));

    for _ in 0..buffer_count {
        free_tx
            .send(vec![0u8; EMBEDDED_CHUNK_SIZE + overlap])
            .expect("embedded scan buffer receiver is alive");
    }

    let read_error = rayon::scope(move |scope| {
        let mut carry = vec![0u8; overlap];
        let mut carry_len = 0usize;
        let mut current_offset = 0u64;
        let mut read_error = None;
        for _ in 0..worker_count {
            let job_rx = Arc::clone(&job_rx);
            let free_tx = free_tx.clone();
            let hits_tx = hits_tx.clone();
            scope.spawn(move |_| loop {
                let job = {
                    let receiver = job_rx
                        .lock()
                        .expect("embedded scan job receiver lock is not poisoned");
                    receiver.recv()
                };
                let Ok(mut job) = job else {
                    break;
                };
                let hits = scan_chunk(&job);
                let _ = hits_tx.send(hits);
                job.buffer.clear();
                // The producer drops free_rx as soon as it reaches EOF. A
                // failed buffer recycle must not stop this worker: jobs that
                // were already queued still need to be scanned exactly once.
                let _ = free_tx.send(job.buffer);
            });
        }

        loop {
            let Ok(mut buffer) = free_rx.recv() else {
                break;
            };
            buffer.resize(EMBEDDED_CHUNK_SIZE + overlap, 0);
            if carry_len > 0 {
                buffer[..carry_len].copy_from_slice(&carry[..carry_len]);
            }

            let mut bytes_read = 0usize;
            while bytes_read < EMBEDDED_CHUNK_SIZE {
                match file
                    .read(&mut buffer[carry_len + bytes_read..carry_len + EMBEDDED_CHUNK_SIZE])
                {
                    Ok(0) => break,
                    Ok(count) => bytes_read += count,
                    Err(error) => {
                        read_error = Some(error);
                        break;
                    }
                }
            }
            if read_error.is_some() || bytes_read == 0 {
                break;
            }

            let sample_len = carry_len + bytes_read;
            let next_carry_len = overlap.min(sample_len);
            carry[..next_carry_len]
                .copy_from_slice(&buffer[sample_len - next_carry_len..sample_len]);
            let job = ScanChunk {
                buffer,
                sample_len,
                carry_len,
                base_offset: current_offset.saturating_sub(carry_len as u64),
            };
            if job_tx.send(job).is_err() {
                break;
            }
            carry_len = next_carry_len;
            current_offset += bytes_read as u64;
        }
        drop(job_tx);
        read_error
    });

    if let Some(error) = read_error {
        return Err(error);
    }
    let mut raw_hits = Vec::new();
    for mut hits in hits_rx {
        raw_hits.append(&mut hits);
    }
    Ok(raw_hits)
}

fn scan_raw_hits_sequential(file: &mut SourceCursor, overlap: usize) -> io::Result<Vec<RawHit>> {
    let mut buffer = vec![0u8; EMBEDDED_CHUNK_SIZE + overlap];
    let mut carry = vec![0u8; overlap];
    let mut carry_len = 0usize;
    let mut current_offset = 0u64;
    let mut raw_hits = Vec::new();

    loop {
        if carry_len > 0 {
            buffer[..carry_len].copy_from_slice(&carry[..carry_len]);
        }
        let mut bytes_read = 0usize;
        while bytes_read < EMBEDDED_CHUNK_SIZE {
            let target = &mut buffer[carry_len + bytes_read..carry_len + EMBEDDED_CHUNK_SIZE];
            match file.read(target)? {
                0 => break,
                count => bytes_read += count,
            }
        }
        if bytes_read == 0 {
            break;
        }

        let sample_len = carry_len + bytes_read;
        raw_hits.extend(scan_sample(
            &buffer[..sample_len],
            carry_len,
            current_offset.saturating_sub(carry_len as u64),
        ));

        let next_carry_len = overlap.min(sample_len);
        carry[..next_carry_len].copy_from_slice(&buffer[sample_len - next_carry_len..sample_len]);
        carry_len = next_carry_len;
        current_offset += bytes_read as u64;
    }
    Ok(raw_hits)
}

fn scan_chunk(job: &ScanChunk) -> Vec<RawHit> {
    let sample = &job.buffer[..job.sample_len];
    scan_sample(sample, job.carry_len, job.base_offset)
}

fn scan_sample(sample: &[u8], carry_len: usize, base_offset: u64) -> Vec<RawHit> {
    let mut hits = Vec::new();
    if let Some(matcher) = embedded_packed_matcher() {
        for matched in matcher.find_iter(sample) {
            let pattern = matched.pattern().as_usize();
            record_raw_hit(
                &mut hits,
                carry_len,
                base_offset,
                pattern,
                matched.start(),
                matched.end(),
            );

            // Packed search is deliberately non-overlapping. The current
            // signature set has exactly one proper suffix/prefix overlap:
            // Zstd ends in FD and XZ begins with FD. Recover that one match
            // explicitly so this path is exactly equivalent to Standard
            // Aho-Corasick overlapping semantics.
            if pattern == ZSTD_PATTERN_INDEX {
                let xz_start = matched.end() - 1;
                let xz_end = xz_start + XZ.len();
                if sample.get(xz_start..xz_end) == Some(XZ) {
                    record_raw_hit(
                        &mut hits,
                        carry_len,
                        base_offset,
                        XZ_PATTERN_INDEX,
                        xz_start,
                        xz_end,
                    );
                }
            }
        }
    } else {
        for matched in embedded_matcher().find_overlapping_iter(sample) {
            record_raw_hit(
                &mut hits,
                carry_len,
                base_offset,
                matched.pattern().as_usize(),
                matched.start(),
                matched.end(),
            );
        }
    }
    hits
}

fn record_raw_hit(
    hits: &mut Vec<RawHit>,
    carry_len: usize,
    base_offset: u64,
    pattern: usize,
    start: usize,
    end: usize,
) {
    // A match contained entirely in carry was already owned by the preceding
    // chunk. Cross-boundary matches end in newly read bytes and are retained
    // exactly once.
    if end <= carry_len {
        return;
    }
    let (_, hit_name, kind) = PATTERNS[pattern];
    let absolute = base_offset + start as u64;
    let candidate_offset = if kind == "tar" {
        let Some(value) = absolute.checked_sub(257) else {
            return;
        };
        value
    } else {
        absolute
    };
    hits.push(RawHit {
        hit_name,
        kind,
        offset: candidate_offset,
    });
}

fn validate_candidate(
    file: &ManagedReader,
    file_size: u64,
    kind: &str,
    offset: u64,
) -> std::io::Result<Option<EmbeddedCandidate>> {
    match kind {
        "zip" => validate_zip(file, file_size, offset),
        "zip_eocd" => validate_zip_eocd(file, file_size, offset),
        "7z" => validate_seven_zip(file, file_size, offset),
        "rar4" => validate_rar4(file, file_size, offset),
        "rar5" => validate_rar5(file, file_size, offset),
        "gzip" => validate_gzip(file, file_size, offset),
        "bzip2" => validate_bzip2(file, file_size, offset),
        "xz" => validate_xz(file, file_size, offset),
        "zstd" => validate_zstd(file, file_size, offset),
        "tar" => validate_tar(file, file_size, offset),
        _ => Ok(None),
    }
}

fn validate_zip_eocd(
    file: &ManagedReader,
    size: u64,
    eocd_offset: u64,
) -> std::io::Result<Option<EmbeddedCandidate>> {
    let header = read_at(file, eocd_offset, 22)?;
    if header.len() < 22 || &header[..4] != ZIP_EOCD {
        return Ok(None);
    }
    let comment_len = u16::from_le_bytes([header[20], header[21]]) as u64;
    let Some(end) = eocd_offset.checked_add(22 + comment_len) else {
        return Ok(None);
    };
    if end > size {
        return Ok(None);
    }
    let disk = u16::from_le_bytes([header[4], header[5]]);
    let cd_disk = u16::from_le_bytes([header[6], header[7]]);
    if disk != 0 || cd_disk != 0 {
        return Ok(None);
    }
    let cd_size = u32::from_le_bytes(header[12..16].try_into().unwrap()) as u64;
    let recorded_cd_offset = u32::from_le_bytes(header[16..20].try_into().unwrap()) as u64;
    if cd_size == u32::MAX as u64 || recorded_cd_offset == u32::MAX as u64 || cd_size > eocd_offset
    {
        // ZIP64 is still represented by its validated local-header candidate;
        // its locator/record are handed to analysis through the full hit map.
        return Ok(None);
    }
    let mut directory_end = eocd_offset;
    if eocd_offset >= 76 {
        let zip64_pair = read_at(file, eocd_offset - 76, 76)?;
        if zip64_pair.len() == 76
            && &zip64_pair[..4] == b"PK\x06\x06"
            && u64::from_le_bytes(zip64_pair[4..12].try_into().unwrap()) == 44
            && &zip64_pair[56..60] == b"PK\x06\x07"
        {
            directory_end = eocd_offset - 76;
        }
    }
    if cd_size > directory_end {
        return Ok(None);
    }
    let actual_cd_start = directory_end - cd_size;
    let Some(archive_offset) = actual_cd_start.checked_sub(recorded_cd_offset) else {
        return Ok(None);
    };
    if archive_offset == 0 {
        return Ok(None);
    }
    let cd_magic = read_at(file, actual_cd_start, 4)?;
    if cd_size > 0 && cd_magic.as_slice() != b"PK\x01\x02" {
        return Ok(None);
    }
    Ok(Some(candidate(
        "zip",
        ".zip",
        archive_offset,
        Some(end),
        1.0,
        "eocd_and_central_directory",
    )))
}

fn read_at(file: &ManagedReader, offset: u64, len: usize) -> std::io::Result<Vec<u8>> {
    file.read_at(offset, len)
}

struct PositionalReader<'a> {
    file: &'a ManagedReader,
    offset: u64,
}

impl Read for PositionalReader<'_> {
    fn read(&mut self, buffer: &mut [u8]) -> io::Result<usize> {
        let count = self.file.read_direct_into_at(self.offset, buffer)?;
        self.offset = self.offset.saturating_add(count as u64);
        Ok(count)
    }
}

fn validate_zip(
    file: &ManagedReader,
    size: u64,
    offset: u64,
) -> std::io::Result<Option<EmbeddedCandidate>> {
    let header = read_at(file, offset, 30)?;
    if header.len() < 30 || &header[..4] != ZIP_LOCAL {
        return Ok(None);
    }
    let version = u16::from_le_bytes([header[4], header[5]]);
    let flags = u16::from_le_bytes([header[6], header[7]]);
    let compressed_32 = u32::from_le_bytes(header[18..22].try_into().unwrap());
    let uncompressed_32 = u32::from_le_bytes(header[22..26].try_into().unwrap());
    let name_len = u16::from_le_bytes([header[26], header[27]]) as u64;
    let extra_len = u16::from_le_bytes([header[28], header[29]]) as u64;
    let header_end = offset
        .saturating_add(30)
        .saturating_add(name_len)
        .saturating_add(extra_len);
    if version > 100 || flags & 0xc000 != 0 || name_len == 0 || header_end > size {
        return Ok(None);
    }
    let mut compressed_size = compressed_32 as u64;
    let mut validation = "local_header_and_data_range";
    let mut confidence = 0.94;
    if compressed_32 == u32::MAX || uncompressed_32 == u32::MAX {
        let extra_start = offset + 30 + name_len;
        let extra = read_at(file, extra_start, extra_len as usize)?;
        let mut cursor = 0usize;
        let mut zip64 = None;
        while cursor + 4 <= extra.len() {
            let id = u16::from_le_bytes(extra[cursor..cursor + 2].try_into().unwrap());
            let field_size =
                u16::from_le_bytes(extra[cursor + 2..cursor + 4].try_into().unwrap()) as usize;
            cursor += 4;
            if cursor + field_size > extra.len() {
                return Ok(None);
            }
            if id == 0x0001 {
                zip64 = Some(&extra[cursor..cursor + field_size]);
                break;
            }
            cursor += field_size;
        }
        let Some(zip64) = zip64 else { return Ok(None) };
        let mut value_cursor = 0usize;
        if uncompressed_32 == u32::MAX {
            if zip64.len() < value_cursor + 8 {
                return Ok(None);
            }
            value_cursor += 8;
        }
        if compressed_32 == u32::MAX {
            if zip64.len() < value_cursor + 8 {
                return Ok(None);
            }
            compressed_size =
                u64::from_le_bytes(zip64[value_cursor..value_cursor + 8].try_into().unwrap());
        }
        validation = "zip64_local_header_and_data_range";
        confidence = 0.99;
    }
    let Some(data_end) = header_end.checked_add(compressed_size) else {
        return Ok(None);
    };
    if flags & 0x0008 == 0 && data_end > size {
        return Ok(None);
    }
    Ok(Some(candidate(
        "zip", ".zip", offset, None, confidence, validation,
    )))
}

fn validate_seven_zip(
    file: &ManagedReader,
    size: u64,
    offset: u64,
) -> std::io::Result<Option<EmbeddedCandidate>> {
    let header = read_at(file, offset, 32)?;
    if header.len() < 32 || &header[..6] != SEVEN_ZIP || header[6] != 0 {
        return Ok(None);
    }
    let stored_start_crc = u32::from_le_bytes(header[8..12].try_into().unwrap());
    if crc32(&header[12..32]) != stored_start_crc {
        return Ok(None);
    }
    let next_offset = u64::from_le_bytes(header[12..20].try_into().unwrap());
    let next_size = u64::from_le_bytes(header[20..28].try_into().unwrap());
    let next_crc = u32::from_le_bytes(header[28..32].try_into().unwrap());
    let next_start = offset.saturating_add(32).saturating_add(next_offset);
    let Some(end) = next_start.checked_add(next_size) else {
        return Ok(None);
    };
    if end > size || next_size > usize::MAX as u64 {
        return Ok(None);
    }
    let next = read_at(file, next_start, next_size as usize)?;
    if next.len() != next_size as usize || crc32(&next) != next_crc {
        return Ok(None);
    }
    Ok(Some(candidate(
        "7z",
        ".7z",
        offset,
        Some(end),
        1.0,
        "start_and_next_header_crc",
    )))
}

fn validate_rar4(
    file: &ManagedReader,
    size: u64,
    offset: u64,
) -> std::io::Result<Option<EmbeddedCandidate>> {
    let prefix = read_at(file, offset + RAR4.len() as u64, 11)?;
    if prefix.len() < 7 {
        return Ok(None);
    }
    let header_size = u16::from_le_bytes([prefix[5], prefix[6]]) as usize;
    if header_size < 7 || offset + RAR4.len() as u64 + header_size as u64 > size {
        return Ok(None);
    }
    let header = read_at(file, offset + RAR4.len() as u64, header_size)?;
    let stored = u16::from_le_bytes([header[0], header[1]]) as u32;
    if !matches!(header[2], 0x73..=0x7b) || crc32(&header[2..]) & 0xffff != stored {
        return Ok(None);
    }
    Ok(Some(candidate(
        "rar",
        ".rar",
        offset,
        None,
        1.0,
        "rar4_header_crc",
    )))
}

fn validate_rar5(
    file: &ManagedReader,
    size: u64,
    offset: u64,
) -> std::io::Result<Option<EmbeddedCandidate>> {
    let start = offset + RAR5.len() as u64;
    let prefix = read_at(file, start, 32)?;
    if prefix.len() < 7 {
        return Ok(None);
    }
    let stored = u32::from_le_bytes(prefix[..4].try_into().unwrap());
    let Some((header_size, size_len)) = read_vint(&prefix[4..]) else {
        return Ok(None);
    };
    let total = 4u64 + size_len as u64 + header_size;
    if header_size == 0 || start + total > size || total > usize::MAX as u64 {
        return Ok(None);
    }
    let header = read_at(file, start + 4, (size_len as u64 + header_size) as usize)?;
    if crc32(&header) != stored {
        return Ok(None);
    }
    let Some((header_type, _)) = read_vint(&header[size_len..]) else {
        return Ok(None);
    };
    if !(1..=5).contains(&header_type) {
        return Ok(None);
    }
    Ok(Some(candidate(
        "rar",
        ".rar",
        offset,
        None,
        1.0,
        "rar5_header_crc",
    )))
}

fn validate_gzip(
    file: &ManagedReader,
    size: u64,
    offset: u64,
) -> std::io::Result<Option<EmbeddedCandidate>> {
    let fixed = read_at(file, offset, 10)?;
    if fixed.len() < 10 || &fixed[..3] != GZIP || fixed[3] & 0xe0 != 0 || offset + 18 > size {
        return Ok(None);
    }
    let flags = fixed[3];
    let mut header = fixed;
    let mut cursor = offset + 10;
    if flags & 0x04 != 0 {
        let length_bytes = read_at(file, cursor, 2)?;
        if length_bytes.len() != 2 {
            return Ok(None);
        }
        let length = u16::from_le_bytes(length_bytes[..2].try_into().unwrap()) as usize;
        header.extend_from_slice(&length_bytes);
        cursor += 2;
        let extra = read_at(file, cursor, length)?;
        if extra.len() != length {
            return Ok(None);
        }
        header.extend_from_slice(&extra);
        cursor += length as u64;
    }
    for flag in [0x08, 0x10] {
        if flags & flag != 0 && !read_gzip_c_string(file, size, &mut cursor, &mut header)? {
            return Ok(None);
        }
    }
    if flags & 0x02 != 0 {
        let stored = read_at(file, cursor, 2)?;
        if stored.len() != 2
            || (crc32(&header) & 0xffff) as u16
                != u16::from_le_bytes(stored[..2].try_into().unwrap())
        {
            return Ok(None);
        }
        cursor += 2;
    }

    let mut compressed_reader = PositionalReader {
        file,
        offset: cursor,
    };
    let mut decoder = DeflateDecoder::new(&mut compressed_reader);
    let mut output_crc = Hasher::new();
    let mut output_size = 0u64;
    let mut buffer = [0u8; 64 * 1024];
    loop {
        let count = match decoder.read(&mut buffer) {
            Ok(count) => count,
            Err(_) => return Ok(None),
        };
        if count == 0 {
            break;
        }
        output_crc.update(&buffer[..count]);
        output_size = output_size.wrapping_add(count as u64);
    }
    let compressed_size = decoder.total_in();
    drop(decoder);
    let Some(trailer_offset) = cursor.checked_add(compressed_size) else {
        return Ok(None);
    };
    let trailer = read_at(file, trailer_offset, 8)?;
    if trailer.len() != 8
        || u32::from_le_bytes(trailer[..4].try_into().unwrap()) != output_crc.finalize()
        || u32::from_le_bytes(trailer[4..8].try_into().unwrap()) != output_size as u32
    {
        return Ok(None);
    }
    Ok(Some(candidate(
        "gzip",
        ".gz",
        offset,
        Some(trailer_offset + 8),
        1.0,
        "rfc1952_stream_crc_and_size",
    )))
}

fn read_gzip_c_string(
    file: &ManagedReader,
    size: u64,
    cursor: &mut u64,
    header: &mut Vec<u8>,
) -> std::io::Result<bool> {
    while *cursor < size {
        let byte = read_at(file, *cursor, 1)?;
        if byte.is_empty() {
            return Ok(false);
        }
        *cursor += 1;
        header.push(byte[0]);
        if byte[0] == 0 {
            return Ok(true);
        }
    }
    Ok(false)
}

fn validate_bzip2(
    file: &ManagedReader,
    size: u64,
    offset: u64,
) -> std::io::Result<Option<EmbeddedCandidate>> {
    let header = read_at(file, offset, 10)?;
    if header.len() < 10
        || &header[..3] != BZIP2
        || !(b'1'..=b'9').contains(&header[3])
        || &header[4..10] != b"1AY&SY"
        || offset + 14 > size
    {
        return Ok(None);
    }
    Ok(Some(candidate(
        "bzip2",
        ".bz2",
        offset,
        None,
        0.98,
        "stream_and_block_header",
    )))
}

fn validate_xz(
    file: &ManagedReader,
    size: u64,
    offset: u64,
) -> std::io::Result<Option<EmbeddedCandidate>> {
    let header = read_at(file, offset, 12)?;
    if header.len() < 12
        || &header[..6] != XZ
        || header[6] != 0
        || header[7] & 0xf0 != 0
        || offset + 24 > size
    {
        return Ok(None);
    }
    let stored = u32::from_le_bytes(header[8..12].try_into().unwrap());
    if crc32(&header[6..8]) != stored {
        return Ok(None);
    }
    Ok(Some(candidate(
        "xz",
        ".xz",
        offset,
        None,
        1.0,
        "stream_header_crc",
    )))
}

fn validate_zstd(
    file: &ManagedReader,
    size: u64,
    offset: u64,
) -> std::io::Result<Option<EmbeddedCandidate>> {
    let header = read_at(file, offset, 18)?;
    if header.len() < 6 || &header[..4] != ZSTD || header[4] & 0x18 != 0 {
        return Ok(None);
    }
    let descriptor = header[4];
    let single_segment = descriptor & 0x20 != 0;
    let dictionary_size = match descriptor & 0x03 {
        0 => 0,
        1 => 1,
        2 => 2,
        _ => 4,
    };
    let content_flag = descriptor >> 6;
    let content_size = match (content_flag, single_segment) {
        (0, false) => 0,
        (0, true) => 1,
        (1, _) => 2,
        (2, _) => 4,
        _ => 8,
    };
    let frame_header_size = 5usize + usize::from(!single_segment) + dictionary_size + content_size;
    if header.len() < frame_header_size + 3 {
        return Ok(None);
    }
    let block = &header[frame_header_size..frame_header_size + 3];
    let block_header =
        u32::from(block[0]) | (u32::from(block[1]) << 8) | (u32::from(block[2]) << 16);
    let block_type = (block_header >> 1) & 0x03;
    let block_size = (block_header >> 3) as u64;
    let encoded_block_size = if block_type == 1 {
        u64::from(block_size > 0)
    } else {
        block_size
    };
    if block_type == 3 || offset + frame_header_size as u64 + 3 + encoded_block_size > size {
        return Ok(None);
    }
    Ok(Some(candidate(
        "zstd",
        ".zst",
        offset,
        None,
        0.98,
        "rfc8878_frame_and_block_header",
    )))
}

fn validate_tar(
    file: &ManagedReader,
    size: u64,
    offset: u64,
) -> std::io::Result<Option<EmbeddedCandidate>> {
    if offset + 512 > size {
        return Ok(None);
    }
    let header = read_at(file, offset, 512)?;
    if header.len() < 512 || &header[257..262] != TAR_USTAR {
        return Ok(None);
    }
    let Some(stored) = parse_octal(&header[148..156]) else {
        return Ok(None);
    };
    let mut sum = 0u64;
    for (index, byte) in header.iter().enumerate() {
        sum += if (148..156).contains(&index) {
            b' ' as u64
        } else {
            *byte as u64
        };
    }
    if stored != sum {
        return Ok(None);
    }
    Ok(Some(candidate(
        "tar",
        ".tar",
        offset,
        None,
        1.0,
        "ustar_checksum",
    )))
}

fn candidate(
    format: &'static str,
    ext: &'static str,
    offset: u64,
    end: Option<u64>,
    confidence: f64,
    validation: &'static str,
) -> EmbeddedCandidate {
    EmbeddedCandidate {
        format,
        detected_ext: ext,
        offset,
        end_offset: end,
        confidence,
        validation,
    }
}

fn read_vint(data: &[u8]) -> Option<(u64, usize)> {
    let mut value = 0u64;
    for (index, byte) in data.iter().copied().take(10).enumerate() {
        value |= u64::from(byte & 0x7f) << (index * 7);
        if byte & 0x80 == 0 {
            return Some((value, index + 1));
        }
    }
    None
}

fn parse_octal(data: &[u8]) -> Option<u64> {
    let text = std::str::from_utf8(data)
        .ok()?
        .trim_matches(|c| c == '\0' || c == ' ');
    if text.is_empty() {
        return None;
    }
    u64::from_str_radix(text, 8).ok()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_support::temp_file;
    use bzip2::write::BzEncoder;
    use bzip2::Compression as BzCompression;
    use flate2::write::GzEncoder;
    use flate2::Compression;
    use std::fs;
    use std::io::Write;
    use xz2::write::XzEncoder;

    fn reference_raw_hits(data: &[u8]) -> Vec<RawHit> {
        let mut hits = Vec::new();
        for matched in embedded_matcher().find_overlapping_iter(data) {
            let (_, hit_name, kind) = PATTERNS[matched.pattern().as_usize()];
            let absolute = matched.start() as u64;
            let candidate_offset = if kind == "tar" {
                let Some(value) = absolute.checked_sub(257) else {
                    continue;
                };
                value
            } else {
                absolute
            };
            hits.push(RawHit {
                hit_name,
                kind,
                offset: candidate_offset,
            });
        }
        hits.sort_by_key(|hit| (hit.offset, hit.hit_name));
        hits
    }

    fn optimized_raw_hits(data: &[u8]) -> Vec<RawHit> {
        let mut hits = scan_sample(data, 0, 0);
        hits.sort_by_key(|hit| (hit.offset, hit.hit_name));
        hits
    }

    #[test]
    fn packed_search_preserves_every_signature_overlap() {
        let mut data = vec![0x11; 512];
        for (left_index, (left, _, _)) in PATTERNS.iter().enumerate() {
            for (right_index, (right, _, _)) in PATTERNS.iter().enumerate() {
                for overlap in 1..left.len().min(right.len()) {
                    if left[left.len() - overlap..] != right[..overlap] {
                        continue;
                    }
                    let start = data.len();
                    data.extend_from_slice(left);
                    data.extend_from_slice(&right[overlap..]);
                    data.extend_from_slice(&[0x11; 32]);
                    assert_eq!(
                        (left_index, right_index, overlap),
                        (ZSTD_PATTERN_INDEX, XZ_PATTERN_INDEX, 1),
                        "the packed compensation must cover every overlap",
                    );
                    assert!(start > 0);
                }
            }
        }
        assert_eq!(optimized_raw_hits(&data), reference_raw_hits(&data));
    }

    #[test]
    fn packed_search_matches_overlapping_aho_on_randomized_layouts() {
        let mut state = 0x9e37_79b9_7f4a_7c15u64;
        let mut data = vec![0u8; 2 * 1024 * 1024];
        for byte in &mut data {
            state ^= state << 13;
            state ^= state >> 7;
            state ^= state << 17;
            *byte = state as u8;
        }
        for round in 0..2048usize {
            state ^= state << 13;
            state ^= state >> 7;
            state ^= state << 17;
            let pattern = round % PATTERNS.len();
            let magic = PATTERNS[pattern].0;
            let start = 300 + (state as usize % (data.len() - 600 - magic.len()));
            data[start..start + magic.len()].copy_from_slice(magic);
        }
        // Force the only overlap in the set in addition to any accidental
        // overlaps generated by the randomized corpus.
        let overlap = b"\x28\xb5\x2f\xfd7zXZ\x00";
        data[128..128 + overlap.len()].copy_from_slice(overlap);

        assert_eq!(optimized_raw_hits(&data), reference_raw_hits(&data));
    }

    #[test]
    fn finds_multiple_structurally_valid_embedded_streams() {
        let mut data = b"carrier".to_vec();
        let zip_offset = data.len() as u64;
        data.extend_from_slice(ZIP_LOCAL);
        data.extend_from_slice(&20u16.to_le_bytes());
        data.extend_from_slice(&0u16.to_le_bytes());
        data.extend_from_slice(&0u16.to_le_bytes());
        data.extend_from_slice(&0u16.to_le_bytes());
        data.extend_from_slice(&0u16.to_le_bytes());
        data.extend_from_slice(&0u32.to_le_bytes());
        data.extend_from_slice(&0u32.to_le_bytes());
        data.extend_from_slice(&0u32.to_le_bytes());
        data.extend_from_slice(&1u16.to_le_bytes());
        data.extend_from_slice(&0u16.to_le_bytes());
        data.push(b'x');
        data.extend_from_slice(b"gap");
        let gzip_offset = data.len() as u64;
        let mut gzip = GzEncoder::new(Vec::new(), Compression::fast());
        gzip.write_all(b"payload").unwrap();
        data.extend_from_slice(&gzip.finish().unwrap());
        let path = temp_file("embedded_multi", &data);
        Python::initialize();
        Python::attach(|py| {
            let result = scan_embedded_archives(py, path.to_str().unwrap()).unwrap();
            let bound = result.bind(py);
            let rows = bound
                .get_item("candidates")
                .unwrap()
                .unwrap()
                .cast_into::<PyList>()
                .unwrap();
            assert_eq!(rows.len(), 2);
            assert_eq!(
                rows.get_item(0)
                    .unwrap()
                    .get_item("offset")
                    .unwrap()
                    .extract::<u64>()
                    .unwrap(),
                zip_offset
            );
            assert_eq!(
                rows.get_item(1)
                    .unwrap()
                    .get_item("offset")
                    .unwrap()
                    .extract::<u64>()
                    .unwrap(),
                gzip_offset
            );
        });
        let _ = fs::remove_file(path);
    }

    #[test]
    fn finds_primary_and_later_stream_across_invalid_gap() {
        let mut first = GzEncoder::new(Vec::new(), Compression::fast());
        first.write_all(b"first payload").unwrap();
        let first = first.finish().unwrap();
        let gap = b"invalid bytes between valid streams";
        let second_offset = (first.len() + gap.len()) as u64;
        let mut second = GzEncoder::new(Vec::new(), Compression::fast());
        second.write_all(b"second payload").unwrap();

        let mut data = first;
        data.extend_from_slice(gap);
        data.extend_from_slice(&second.finish().unwrap());
        let path = temp_file("embedded_primary_gap_stream", &data);
        let result = scan_embedded_archives_native(ManagedReader::open(&path).unwrap()).unwrap();
        let gzip_offsets = result
            .candidates
            .iter()
            .filter(|candidate| candidate.format == "gzip")
            .map(|candidate| candidate.offset)
            .collect::<Vec<_>>();

        assert_eq!(gzip_offsets, [0, second_offset]);
        let _ = fs::remove_file(path);
    }

    #[test]
    fn validates_supported_stream_headers_in_one_pass() {
        let mut data = b"carrier".to_vec();
        let mut bzip = BzEncoder::new(Vec::new(), BzCompression::fast());
        bzip.write_all(b"bzip payload").unwrap();
        data.extend_from_slice(&bzip.finish().unwrap());
        let mut xz = XzEncoder::new(Vec::new(), 1);
        xz.write_all(b"xz payload").unwrap();
        data.extend_from_slice(&xz.finish().unwrap());
        data.extend_from_slice(&zstd::stream::encode_all(&b"zstd payload"[..], 1).unwrap());
        let path = temp_file("embedded_streams", &data);
        Python::initialize();
        Python::attach(|py| {
            let result = scan_embedded_archives(py, path.to_str().unwrap()).unwrap();
            let bound = result.bind(py);
            let rows = bound
                .get_item("candidates")
                .unwrap()
                .unwrap()
                .cast_into::<PyList>()
                .unwrap();
            let formats: Vec<String> = rows
                .iter()
                .map(|row| row.get_item("format").unwrap().extract::<String>().unwrap())
                .collect();
            assert_eq!(formats, ["bzip2", "xz", "zstd"]);
        });
        let _ = fs::remove_file(path);
    }

    #[test]
    fn finds_signature_split_across_reused_buffer_boundary() {
        let mut gzip = GzEncoder::new(Vec::new(), Compression::fast());
        gzip.write_all(b"cross-boundary payload").unwrap();
        let gzip_bytes = gzip.finish().unwrap();
        let gzip_offset = EMBEDDED_CHUNK_SIZE - 2;
        let mut data = vec![b'x'; gzip_offset];
        data.extend_from_slice(&gzip_bytes);
        let path = temp_file("embedded_cross_boundary", &data);
        Python::initialize();
        Python::attach(|py| {
            let result = scan_embedded_archives(py, path.to_str().unwrap()).unwrap();
            let bound = result.bind(py);
            let rows = bound
                .get_item("candidates")
                .unwrap()
                .unwrap()
                .cast_into::<PyList>()
                .unwrap();
            assert_eq!(rows.len(), 1);
            assert_eq!(
                rows.get_item(0)
                    .unwrap()
                    .get_item("offset")
                    .unwrap()
                    .extract::<u64>()
                    .unwrap(),
                gzip_offset as u64
            );
        });
        let _ = fs::remove_file(path);
    }

    #[test]
    fn parallel_chunks_match_one_contiguous_overlapping_scan_exactly() {
        let mut data = vec![0x11; EMBEDDED_CHUNK_SIZE * (PATTERNS.len() + 2)];
        for (index, (magic, _, _)) in PATTERNS.iter().enumerate() {
            let boundary = EMBEDDED_CHUNK_SIZE * (index + 1);
            let start = boundary - magic.len().saturating_sub(1);
            data[start..start + magic.len()].copy_from_slice(magic);
        }
        // This short signature is wholly contained in the next chunk's carry
        // and used to be observed twice before HashSet de-duplication.
        let duplicate_prone = EMBEDDED_CHUNK_SIZE * (PATTERNS.len() + 1) - 6;
        data[duplicate_prone..duplicate_prone + GZIP.len()].copy_from_slice(GZIP);

        let expected = reference_raw_hits(&data);
        let path = temp_file("embedded_parallel_equivalence", &data);
        let reader = ManagedReader::open(&path).unwrap();
        let mut file = reader.stream_cursor();
        let mut actual = scan_raw_hits(&mut file).unwrap();
        actual.sort_by_key(|hit| (hit.offset, hit.hit_name));

        assert_eq!(actual, expected);
        let _ = fs::remove_file(path);
    }

    #[test]
    fn one_thread_pool_uses_non_blocking_sequential_scan() {
        let mut data = vec![0x11; EMBEDDED_CHUNK_SIZE * 3];
        let start = EMBEDDED_CHUNK_SIZE - 2;
        data[start..start + SEVEN_ZIP.len()].copy_from_slice(SEVEN_ZIP);
        let expected = reference_raw_hits(&data);
        let path = temp_file("embedded_single_thread", &data);
        let actual = rayon::ThreadPoolBuilder::new()
            .num_threads(1)
            .build()
            .unwrap()
            .install(|| {
                let reader = ManagedReader::open(&path).unwrap();
                let mut file = reader.stream_cursor();
                let mut hits = scan_raw_hits(&mut file).unwrap();
                hits.sort_by_key(|hit| (hit.offset, hit.hit_name));
                hits
            });

        assert_eq!(actual, expected);
        let _ = fs::remove_file(path);
    }
}
