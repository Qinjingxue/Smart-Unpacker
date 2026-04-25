use crate::magic::{
    find_full_hit, find_tail_hit, non_empty_magics, stream_find_magic_from_offset, ScanHit,
    TailScanResult,
};
use crate::util::normalize_ext;
use pyo3::prelude::*;
use pyo3::types::PyDict;
use std::fs::File;
use std::io::{Read, Seek, SeekFrom};

#[pyfunction]
#[pyo3(signature = (path, carrier_ext, archive_magics, file_size, tail_window, prefix_window, full_scan_max, deep_scan))]
pub(crate) fn scan_carrier_archive(
    py: Python<'_>,
    path: &str,
    carrier_ext: &str,
    archive_magics: Vec<(Vec<u8>, String)>,
    file_size: u64,
    tail_window: u64,
    prefix_window: u64,
    full_scan_max: u64,
    deep_scan: bool,
) -> PyResult<Option<Py<PyDict>>> {
    let archive_magics = non_empty_magics(archive_magics);
    if archive_magics.is_empty() || file_size == 0 {
        return Ok(None);
    }

    let normalized_ext = normalize_ext(carrier_ext);
    let hit = match normalized_ext.as_str() {
        ".jpg" | ".jpeg" => scan_marker_carrier(
            path,
            &[b"\xff\xd9".as_slice()],
            &archive_magics,
            file_size,
            tail_window,
            prefix_window,
            full_scan_max,
            deep_scan,
        )?,
        ".png" => scan_marker_carrier(
            path,
            &[b"IEND\xaeB`\x82".as_slice()],
            &archive_magics,
            file_size,
            tail_window,
            prefix_window,
            full_scan_max,
            deep_scan,
        )?,
        ".pdf" => scan_marker_carrier(
            path,
            &[
                b"%%EOF\r\n".as_slice(),
                b"%%EOF\n".as_slice(),
                b"%%EOF".as_slice(),
            ],
            &archive_magics,
            file_size,
            tail_window,
            prefix_window,
            full_scan_max,
            deep_scan,
        )?,
        ".gif" => {
            let Some(trailer_offset) = gif_trailer_offset(path)? else {
                return Ok(None);
            };
            stream_find_magic_from_offset(path, &archive_magics, trailer_offset + 1, None)?
                .map(|hit| (hit, "after_gif_trailer"))
        }
        ".webp" => {
            let Some(payload_end) = webp_payload_end(path, file_size)? else {
                return Ok(None);
            };
            stream_find_magic_from_offset(path, &archive_magics, payload_end, None)?
                .map(|hit| (hit, "after_webp_payload"))
        }
        _ => None,
    };

    hit.map(|(hit, scope)| hit.into_py_dict(py, scope))
        .transpose()
}

fn scan_marker_carrier(
    path: &str,
    markers: &[&[u8]],
    archive_magics: &[(Vec<u8>, String)],
    file_size: u64,
    tail_window: u64,
    prefix_window: u64,
    full_scan_max: u64,
    deep_scan: bool,
) -> PyResult<Option<(ScanHit, &'static str)>> {
    let markers: Vec<Vec<u8>> = markers.iter().map(|marker| marker.to_vec()).collect();
    let tail_start = file_size.saturating_sub(tail_window);
    let should_full_scan = deep_scan || (full_scan_max > 0 && file_size <= full_scan_max);
    let mut tail_marker_found = false;

    match find_tail_hit(path, &markers, archive_magics, tail_start, file_size)? {
        TailScanResult::Hit(hit) => return Ok(Some((hit, "tail"))),
        TailScanResult::MarkerWithoutMagic => tail_marker_found = true,
        TailScanResult::NoMarker => {}
    }

    if prefix_window > 0 && tail_start > 0 {
        let prefix_end = file_size.min(prefix_window);
        match find_tail_hit(path, &markers, archive_magics, 0, prefix_end)? {
            TailScanResult::Hit(hit) => return Ok(Some((hit, "prefix"))),
            TailScanResult::MarkerWithoutMagic | TailScanResult::NoMarker => {}
        }
    }

    if tail_marker_found || !should_full_scan {
        return Ok(None);
    }

    let full_scan_end = if tail_start == 0 {
        file_size
    } else {
        tail_start
    };
    Ok(find_full_hit(path, &markers, archive_magics, full_scan_end)?.map(|hit| (hit, "full")))
}

fn gif_trailer_offset(path: &str) -> PyResult<Option<u64>> {
    let mut file = File::open(path)?;
    let mut header = [0u8; 13];
    if file.read_exact(&mut header).is_err() {
        return Ok(None);
    }
    if &header[..6] != b"GIF87a" && &header[..6] != b"GIF89a" {
        return Ok(None);
    }

    if header[10] & 0x80 != 0 {
        let color_table_size = 3u64 * (1u64 << ((header[10] & 0x07) + 1));
        file.seek(SeekFrom::Current(color_table_size as i64))?;
    }

    loop {
        let mut introducer = [0u8; 1];
        if file.read(&mut introducer)? == 0 {
            return Ok(None);
        }
        match introducer[0] {
            0x3B => return Ok(Some(file.stream_position()? - 1)),
            0x2C => {
                let mut image_descriptor = [0u8; 9];
                if file.read_exact(&mut image_descriptor).is_err() {
                    return Ok(None);
                }
                if image_descriptor[8] & 0x80 != 0 {
                    let color_table_size = 3u64 * (1u64 << ((image_descriptor[8] & 0x07) + 1));
                    file.seek(SeekFrom::Current(color_table_size as i64))?;
                }
                if !skip_gif_sub_blocks(&mut file, true)? {
                    return Ok(None);
                }
            }
            0x21 => {
                let mut label = [0u8; 1];
                if file.read_exact(&mut label).is_err() {
                    return Ok(None);
                }
                if !skip_gif_sub_blocks(&mut file, false)? {
                    return Ok(None);
                }
            }
            _ => return Ok(None),
        }
    }
}

fn skip_gif_sub_blocks(file: &mut File, skip_lzw_minimum: bool) -> PyResult<bool> {
    if skip_lzw_minimum {
        let mut lzw_minimum = [0u8; 1];
        if file.read_exact(&mut lzw_minimum).is_err() {
            return Ok(false);
        }
    }

    loop {
        let mut size = [0u8; 1];
        if file.read_exact(&mut size).is_err() {
            return Ok(false);
        }
        let block_size = size[0];
        if block_size == 0 {
            return Ok(true);
        }
        file.seek(SeekFrom::Current(block_size as i64))?;
    }
}

fn webp_payload_end(path: &str, file_size: u64) -> PyResult<Option<u64>> {
    let mut file = File::open(path)?;
    let mut header = [0u8; 12];
    if file.read_exact(&mut header).is_err() {
        return Ok(None);
    }
    if &header[..4] != b"RIFF" || &header[8..12] != b"WEBP" {
        return Ok(None);
    }
    let riff_size = u32::from_le_bytes([header[4], header[5], header[6], header[7]]) as u64;
    let payload_end = 8u64.saturating_add(riff_size);
    if payload_end > file_size {
        return Ok(None);
    }
    Ok(Some(payload_end))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::magic::stream_find_magic_from_offset;
    use crate::test_support::temp_file;
    use std::fs;

    fn magics() -> Vec<(Vec<u8>, String)> {
        vec![
            (b"7z\xbc\xaf\x27\x1c".to_vec(), ".7z".to_string()),
            (b"PK\x03\x04".to_vec(), ".zip".to_string()),
        ]
    }

    #[test]
    fn marker_carrier_detects_png_tail_payload() {
        let path = temp_file(
            "png_carrier",
            b"\x89PNGdataIEND\xaeB`\x827z\xbc\xaf\x27\x1cpayload",
        );
        let hit = scan_marker_carrier(
            path.to_str().unwrap(),
            &[b"IEND\xaeB`\x82".as_slice()],
            &magics(),
            fs::metadata(&path).unwrap().len(),
            128,
            0,
            0,
            false,
        )
        .unwrap()
        .unwrap();

        assert_eq!(hit.0.detected_ext, ".7z");
        assert_eq!(hit.1, "tail");
        let _ = fs::remove_file(path);
    }

    #[test]
    fn gif_trailer_scan_ignores_semicolon_inside_blocks() {
        let path = temp_file(
            "gif_carrier",
            b"GIF89a\x01\x00\x01\x00\x00\x00\x00,\x00\x00\x00\x00\x01\x00\x01\x00\x00\x02\x03;\x00\x00\x00;PK\x03\x04payload",
        );
        let trailer = gif_trailer_offset(path.to_str().unwrap()).unwrap().unwrap();
        let hit =
            stream_find_magic_from_offset(path.to_str().unwrap(), &magics(), trailer + 1, None)
                .unwrap()
                .unwrap();

        let contents = fs::read(&path).unwrap();
        assert_eq!(contents[trailer as usize], b';');
        assert_eq!(hit.detected_ext, ".zip");
        assert_eq!(hit.offset, trailer + 1);
        let _ = fs::remove_file(path);
    }

    #[test]
    fn webp_payload_end_uses_riff_size() {
        let path = temp_file(
            "webp_carrier",
            b"RIFF\x04\x00\x00\x00WEBP7z\xbc\xaf\x27\x1cpayload",
        );
        let payload_end =
            webp_payload_end(path.to_str().unwrap(), fs::metadata(&path).unwrap().len())
                .unwrap()
                .unwrap();
        let hit =
            stream_find_magic_from_offset(path.to_str().unwrap(), &magics(), payload_end, None)
                .unwrap()
                .unwrap();

        assert_eq!(payload_end, 12);
        assert_eq!(hit.detected_ext, ".7z");
        assert_eq!(hit.offset, 12);
        let _ = fs::remove_file(path);
    }
}
