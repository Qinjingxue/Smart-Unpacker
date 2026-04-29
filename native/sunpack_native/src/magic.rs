use crate::util::{read_range, STREAM_CHUNK_SIZE};
use pyo3::prelude::*;
use pyo3::types::PyDict;
use std::fs::File;
use std::io::{Read, Seek, SeekFrom};

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct ScanHit {
    pub(crate) detected_ext: String,
    pub(crate) offset: u64,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum TailScanResult {
    Hit(ScanHit),
    MarkerWithoutMagic,
    NoMarker,
}

impl ScanHit {
    pub(crate) fn into_py_dict(self, py: Python<'_>, scan_scope: &str) -> PyResult<Py<PyDict>> {
        let dict = PyDict::new(py);
        dict.set_item("detected_ext", self.detected_ext)?;
        dict.set_item("offset", self.offset)?;
        dict.set_item("scan_scope", scan_scope)?;
        Ok(dict.unbind())
    }
}

#[pyfunction]
#[pyo3(signature = (path, markers, archive_magics, tail_start, file_size, allow_full_scan))]
pub(crate) fn scan_after_markers(
    py: Python<'_>,
    path: &str,
    markers: Vec<Vec<u8>>,
    archive_magics: Vec<(Vec<u8>, String)>,
    tail_start: u64,
    file_size: u64,
    allow_full_scan: bool,
) -> PyResult<Option<Py<PyDict>>> {
    let markers = non_empty_patterns(markers);
    let archive_magics = non_empty_magics(archive_magics);
    if markers.is_empty() || archive_magics.is_empty() || file_size == 0 {
        return Ok(None);
    }

    let tail_start = tail_start.min(file_size);
    match find_tail_hit(path, &markers, &archive_magics, tail_start, file_size)? {
        TailScanResult::Hit(hit) => return Ok(Some(hit.into_py_dict(py, "tail")?)),
        TailScanResult::MarkerWithoutMagic if !allow_full_scan => return Ok(None),
        TailScanResult::MarkerWithoutMagic => {}
        TailScanResult::NoMarker => {}
    }

    if !allow_full_scan {
        return Ok(None);
    }

    let full_scan_end = if tail_start == 0 {
        file_size
    } else {
        tail_start
    };
    if let Some(hit) = find_full_hit(path, &markers, &archive_magics, full_scan_end)? {
        return Ok(Some(hit.into_py_dict(py, "full")?));
    }

    Ok(None)
}

#[pyfunction]
#[pyo3(signature = (path, archive_magics, min_offset, max_hits, end_offset=None))]
pub(crate) fn scan_magics_anywhere(
    py: Python<'_>,
    path: &str,
    archive_magics: Vec<(Vec<u8>, String)>,
    min_offset: u64,
    max_hits: usize,
    end_offset: Option<u64>,
) -> PyResult<Vec<Py<PyDict>>> {
    let archive_magics = non_empty_magics(archive_magics);
    if archive_magics.is_empty() || max_hits == 0 {
        return Ok(Vec::new());
    }

    let hits = stream_find_magic_hits(path, &archive_magics, min_offset, end_offset, max_hits)?;
    hits.into_iter()
        .map(|hit| hit.into_py_dict(py, ""))
        .collect()
}

pub(crate) fn non_empty_patterns(patterns: Vec<Vec<u8>>) -> Vec<Vec<u8>> {
    patterns
        .into_iter()
        .filter(|pattern| !pattern.is_empty())
        .collect()
}

pub(crate) fn non_empty_magics(archive_magics: Vec<(Vec<u8>, String)>) -> Vec<(Vec<u8>, String)> {
    archive_magics
        .into_iter()
        .filter(|(magic, detected_ext)| !magic.is_empty() && !detected_ext.is_empty())
        .collect()
}

pub(crate) fn find_tail_hit(
    path: &str,
    markers: &[Vec<u8>],
    archive_magics: &[(Vec<u8>, String)],
    tail_start: u64,
    file_size: u64,
) -> PyResult<TailScanResult> {
    if file_size <= tail_start {
        return Ok(TailScanResult::NoMarker);
    }

    let sample = read_range(path, tail_start, file_size - tail_start)?;
    let mut marker_found = false;
    let mut search_end = sample.len();
    while search_end > 0 {
        let Some((marker_index, marker_len)) =
            find_last_pattern_before(&sample, markers, search_end)
        else {
            break;
        };
        marker_found = true;
        let search_start = marker_index + marker_len;
        if let Some((detected_ext, relative_index)) =
            match_magic(&sample, archive_magics, search_start)
        {
            return Ok(TailScanResult::Hit(ScanHit {
                detected_ext,
                offset: tail_start + relative_index as u64,
            }));
        }
        search_end = marker_index;
    }

    if marker_found {
        return Ok(TailScanResult::MarkerWithoutMagic);
    }

    Ok(TailScanResult::NoMarker)
}

pub(crate) fn find_full_hit(
    path: &str,
    markers: &[Vec<u8>],
    archive_magics: &[(Vec<u8>, String)],
    end_offset: u64,
) -> PyResult<Option<ScanHit>> {
    let Some((marker_offset, marker_len)) =
        stream_find_first_pattern(path, markers, 0, Some(end_offset))?
    else {
        return Ok(None);
    };
    stream_find_magic_from_offset(
        path,
        archive_magics,
        marker_offset + marker_len as u64,
        None,
    )
}

fn find_last_pattern_before(
    sample: &[u8],
    patterns: &[Vec<u8>],
    end: usize,
) -> Option<(usize, usize)> {
    let end = end.min(sample.len());
    if end == 0 {
        return None;
    }
    find_last_pattern(&sample[..end], patterns)
}

fn stream_find_first_pattern(
    path: &str,
    patterns: &[Vec<u8>],
    start_offset: u64,
    end_offset: Option<u64>,
) -> PyResult<Option<(u64, usize)>> {
    let mut file = File::open(path)?;
    file.seek(SeekFrom::Start(start_offset))?;
    let overlap = max_pattern_len(patterns).saturating_sub(1);
    let mut carry: Vec<u8> = Vec::new();
    let mut current_offset = start_offset;

    loop {
        if end_offset.is_some_and(|end| current_offset >= end) {
            return Ok(None);
        }

        let mut read_size = STREAM_CHUNK_SIZE;
        if let Some(end) = end_offset {
            read_size = read_size.min(end.saturating_sub(current_offset) as usize);
        }
        if read_size == 0 {
            return Ok(None);
        }

        let mut chunk = vec![0; read_size];
        let bytes_read = file.read(&mut chunk)?;
        if bytes_read == 0 {
            return Ok(None);
        }
        chunk.truncate(bytes_read);

        let mut sample = Vec::with_capacity(carry.len() + chunk.len());
        sample.extend_from_slice(&carry);
        sample.extend_from_slice(&chunk);
        let base_offset = current_offset.saturating_sub(carry.len() as u64);

        if let Some((relative_index, pattern_len)) = find_first_pattern(&sample, patterns, 0) {
            let absolute = base_offset + relative_index as u64;
            if absolute >= start_offset && end_offset.is_none_or(|end| absolute < end) {
                return Ok(Some((absolute, pattern_len)));
            }
        }

        carry = trailing_overlap(&sample, overlap);
        current_offset += bytes_read as u64;
    }
}

pub(crate) fn stream_find_magic_from_offset(
    path: &str,
    archive_magics: &[(Vec<u8>, String)],
    start_offset: u64,
    end_offset: Option<u64>,
) -> PyResult<Option<ScanHit>> {
    let patterns: Vec<Vec<u8>> = archive_magics
        .iter()
        .map(|(magic, _)| magic.clone())
        .collect();
    let mut file = File::open(path)?;
    file.seek(SeekFrom::Start(start_offset))?;
    let overlap = max_pattern_len(&patterns).saturating_sub(1);
    let mut carry: Vec<u8> = Vec::new();
    let mut current_offset = start_offset;

    loop {
        if end_offset.is_some_and(|end| current_offset >= end) {
            return Ok(None);
        }

        let mut read_size = STREAM_CHUNK_SIZE;
        if let Some(end) = end_offset {
            read_size = read_size.min(end.saturating_sub(current_offset) as usize);
        }
        if read_size == 0 {
            return Ok(None);
        }

        let mut chunk = vec![0; read_size];
        let bytes_read = file.read(&mut chunk)?;
        if bytes_read == 0 {
            return Ok(None);
        }
        chunk.truncate(bytes_read);

        let mut sample = Vec::with_capacity(carry.len() + chunk.len());
        sample.extend_from_slice(&carry);
        sample.extend_from_slice(&chunk);
        let base_offset = current_offset.saturating_sub(carry.len() as u64);

        if let Some((detected_ext, relative_index)) = match_magic(&sample, archive_magics, 0) {
            let absolute = base_offset + relative_index as u64;
            if absolute >= start_offset && end_offset.is_none_or(|end| absolute < end) {
                return Ok(Some(ScanHit {
                    detected_ext,
                    offset: absolute,
                }));
            }
        }

        carry = trailing_overlap(&sample, overlap);
        current_offset += bytes_read as u64;
    }
}

pub(crate) fn stream_find_magic_hits(
    path: &str,
    archive_magics: &[(Vec<u8>, String)],
    min_offset: u64,
    end_offset: Option<u64>,
    max_hits: usize,
) -> PyResult<Vec<ScanHit>> {
    let patterns: Vec<Vec<u8>> = archive_magics
        .iter()
        .map(|(magic, _)| magic.clone())
        .collect();
    let mut file = File::open(path)?;
    file.seek(SeekFrom::Start(min_offset))?;
    let overlap = max_pattern_len(&patterns).saturating_sub(1);
    let mut carry: Vec<u8> = Vec::new();
    let mut current_offset = min_offset;
    let mut hits: Vec<ScanHit> = Vec::new();

    while hits.len() < max_hits {
        if end_offset.is_some_and(|end| current_offset >= end) {
            break;
        }

        let mut read_size = STREAM_CHUNK_SIZE;
        if let Some(end) = end_offset {
            read_size = read_size.min(end.saturating_sub(current_offset) as usize);
        }
        if read_size == 0 {
            break;
        }

        let mut chunk = vec![0; read_size];
        let bytes_read = file.read(&mut chunk)?;
        if bytes_read == 0 {
            break;
        }
        chunk.truncate(bytes_read);

        let mut sample = Vec::with_capacity(carry.len() + chunk.len());
        sample.extend_from_slice(&carry);
        sample.extend_from_slice(&chunk);
        let base_offset = current_offset.saturating_sub(carry.len() as u64);
        let mut search_start = 0;

        while hits.len() < max_hits {
            let Some((detected_ext, relative_index)) =
                match_magic(&sample, archive_magics, search_start)
            else {
                break;
            };
            let absolute = base_offset + relative_index as u64;
            if absolute >= min_offset && end_offset.is_none_or(|end| absolute < end) {
                hits.push(ScanHit {
                    detected_ext,
                    offset: absolute,
                });
            }
            search_start = relative_index + 1;
        }

        carry = trailing_overlap(&sample, overlap);
        current_offset += bytes_read as u64;
    }

    Ok(hits)
}

fn match_magic(
    sample: &[u8],
    archive_magics: &[(Vec<u8>, String)],
    start: usize,
) -> Option<(String, usize)> {
    for (magic, detected_ext) in archive_magics {
        if let Some(index) = find_subslice(sample, magic, start) {
            return Some((detected_ext.clone(), index));
        }
    }
    None
}

fn find_last_pattern(sample: &[u8], patterns: &[Vec<u8>]) -> Option<(usize, usize)> {
    let mut last_match: Option<(usize, usize)> = None;
    for pattern in patterns {
        if let Some(index) = rfind_subslice(sample, pattern) {
            if last_match.is_none_or(|(last_index, _)| index > last_index) {
                last_match = Some((index, pattern.len()));
            }
        }
    }
    last_match
}

fn find_first_pattern(sample: &[u8], patterns: &[Vec<u8>], start: usize) -> Option<(usize, usize)> {
    let mut first_match: Option<(usize, usize)> = None;
    for pattern in patterns {
        if let Some(index) = find_subslice(sample, pattern, start) {
            if first_match.is_none_or(|(first_index, _)| index < first_index) {
                first_match = Some((index, pattern.len()));
            }
        }
    }
    first_match
}

fn find_subslice(haystack: &[u8], needle: &[u8], start: usize) -> Option<usize> {
    if needle.is_empty() || start > haystack.len() || haystack.len() < needle.len() {
        return None;
    }
    memchr::memmem::find(&haystack[start..], needle).map(|index| start + index)
}

pub(crate) fn rfind_subslice(haystack: &[u8], needle: &[u8]) -> Option<usize> {
    if needle.is_empty() || haystack.len() < needle.len() {
        return None;
    }
    memchr::memmem::rfind(haystack, needle)
}

fn max_pattern_len(patterns: &[Vec<u8>]) -> usize {
    patterns.iter().map(Vec::len).max().unwrap_or(0)
}

fn trailing_overlap(sample: &[u8], overlap: usize) -> Vec<u8> {
    if overlap == 0 {
        return Vec::new();
    }
    let start = sample.len().saturating_sub(overlap);
    sample[start..].to_vec()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_support::temp_file;
    use std::fs;

    fn magics() -> Vec<(Vec<u8>, String)> {
        vec![
            (b"7z\xbc\xaf\x27\x1c".to_vec(), ".7z".to_string()),
            (b"PK\x03\x04".to_vec(), ".zip".to_string()),
        ]
    }

    #[test]
    fn tail_hit_uses_last_marker() {
        let path = temp_file("tail_hit", b"aaENDnoiseEND7z\xbc\xaf\x27\x1cpayload");
        let hit = find_tail_hit(
            path.to_str().unwrap(),
            &[b"END".to_vec()],
            &magics(),
            0,
            fs::metadata(&path).unwrap().len(),
        )
        .unwrap();

        assert_eq!(
            hit,
            TailScanResult::Hit(ScanHit {
                detected_ext: ".7z".to_string(),
                offset: 13,
            })
        );
        let _ = fs::remove_file(path);
    }

    #[test]
    fn full_hit_scans_after_first_marker() {
        let path = temp_file("full_hit", b"prefixENDxxxxPK\x03\x04tail");
        let hit = find_full_hit(path.to_str().unwrap(), &[b"END".to_vec()], &magics(), 20)
            .unwrap()
            .unwrap();

        assert_eq!(hit.detected_ext, ".zip");
        assert_eq!(hit.offset, 13);
        let _ = fs::remove_file(path);
    }

    #[test]
    fn no_marker_returns_none() {
        let path = temp_file("no_marker", b"prefixPK\x03\x04tail");
        let hit = find_tail_hit(
            path.to_str().unwrap(),
            &[b"END".to_vec()],
            &magics(),
            0,
            fs::metadata(&path).unwrap().len(),
        )
        .unwrap();

        assert_eq!(hit, TailScanResult::NoMarker);
        let _ = fs::remove_file(path);
    }

    #[test]
    fn streaming_finds_magic_after_offset() {
        let mut contents = vec![b'a'; STREAM_CHUNK_SIZE + 3];
        contents.extend_from_slice(b"PK\x03\x04");
        let path = temp_file("stream_magic", &contents);
        let hit = stream_find_magic_from_offset(path.to_str().unwrap(), &magics(), 1, None)
            .unwrap()
            .unwrap();

        assert_eq!(hit.detected_ext, ".zip");
        assert_eq!(hit.offset, (STREAM_CHUNK_SIZE + 3) as u64);
        let _ = fs::remove_file(path);
    }

    #[test]
    fn streaming_collects_magic_hits_with_limits() {
        let mut contents = vec![b'a'; STREAM_CHUNK_SIZE - 2];
        contents.extend_from_slice(b"PK\x03\x04middle7z\xbc\xaf\x27\x1cendPK\x03\x04");
        let path = temp_file("stream_hits", &contents);
        let hits = stream_find_magic_hits(path.to_str().unwrap(), &magics(), 0, None, 2).unwrap();

        assert_eq!(hits.len(), 2);
        assert_eq!(hits[0].detected_ext, ".7z");
        assert_eq!(hits[0].offset, (STREAM_CHUNK_SIZE + 8) as u64);
        assert_eq!(hits[1].detected_ext, ".zip");
        assert_eq!(hits[1].offset, (STREAM_CHUNK_SIZE + 17) as u64);
        let _ = fs::remove_file(path);
    }

    #[test]
    fn tail_marker_without_following_magic_is_explicit() {
        let path = temp_file("tail_last_marker", b"prefix\xff\xd9payload");
        let hit = find_tail_hit(
            path.to_str().unwrap(),
            &[b"\xff\xd9".to_vec()],
            &magics(),
            0,
            fs::metadata(&path).unwrap().len(),
        )
        .unwrap();
        assert_eq!(hit, TailScanResult::MarkerWithoutMagic);
        let _ = fs::remove_file(path);
    }

    #[test]
    fn tail_scan_uses_earlier_marker_when_later_marker_has_no_magic() {
        let path = temp_file(
            "tail_earlier_marker",
            b"\xff\xd97z\xbc\xaf\x27\x1cpayload\xff\xd9",
        );
        let hit = find_tail_hit(
            path.to_str().unwrap(),
            &[b"\xff\xd9".to_vec()],
            &magics(),
            0,
            fs::metadata(&path).unwrap().len(),
        )
        .unwrap();

        assert_eq!(
            hit,
            TailScanResult::Hit(ScanHit {
                detected_ext: ".7z".to_string(),
                offset: 2,
            })
        );
        let _ = fs::remove_file(path);
    }
}
