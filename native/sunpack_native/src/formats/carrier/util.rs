fn find_subslice(data: &[u8], needle: &[u8]) -> Option<usize> {
    data.windows(needle.len())
        .position(|window| window == needle)
}

fn ensure_parent(path: &Path) -> std::io::Result<()> {
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

fn get_required_string(dict: &Bound<'_, PyDict>, key: &str) -> PyResult<String> {
    dict.get_item(key)?
        .ok_or_else(|| pyo3::exceptions::PyKeyError::new_err(format!("missing {key}")))?
        .extract::<String>()
}

fn get_optional_string(dict: &Bound<'_, PyDict>, key: &str) -> PyResult<Option<String>> {
    match dict.get_item(key)? {
        Some(value) if !value.is_none() => Ok(Some(value.extract::<String>()?)),
        _ => Ok(None),
    }
}

fn get_optional_u64(dict: &Bound<'_, PyDict>, key: &str) -> PyResult<Option<u64>> {
    match dict.get_item(key)? {
        Some(value) if !value.is_none() => Ok(Some(value.extract::<u64>()?)),
        _ => Ok(None),
    }
}

fn mb_to_bytes(value: f64) -> Option<u64> {
    if value <= 0.0 {
        None
    } else {
        Some((value * 1024.0 * 1024.0) as u64)
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

fn read_vint(data: &[u8], offset: usize) -> Option<(u64, usize)> {
    let mut value = 0u64;
    let mut shift = 0;
    for index in offset..data.len().min(offset + 10) {
        let byte = data[index];
        if index == offset + 9 && (byte & 0x7e) != 0 {
            return None;
        }
        value |= ((byte & 0x7f) as u64) << shift;
        if byte & 0x80 == 0 {
            return Some((value, index + 1));
        }
        shift += 7;
    }
    None
}

fn crc32(bytes: &[u8]) -> u32 {
    crc32fast::hash(bytes)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn precise_7z_boundary_finds_embedded_archive_end() {
        let archive = seven_zip_bytes();
        let data = [b"carrier".as_slice(), archive.as_slice(), b"junk"].concat();

        let candidates = scan_archive_signatures(&data, TargetFormat::SevenZip, false, 8);
        let selected = candidates.first().unwrap();

        assert_eq!(selected.offset, 7);
        assert_eq!(selected.archive_end, 7 + archive.len());
        assert!(selected.start_crc_ok);
        assert!(selected.next_header_crc_ok);
    }

    #[test]
    fn carrier_crop_ignores_archive_at_zero() {
        let archive = seven_zip_bytes();
        let candidates = scan_archive_signatures(&archive, TargetFormat::SevenZip, true, 8);

        assert!(candidates.is_empty());
    }

    fn seven_zip_bytes() -> Vec<u8> {
        let next_header = b"\x01";
        let gap = b"abcde";
        let start_header = [
            (gap.len() as u64).to_le_bytes().as_slice(),
            (next_header.len() as u64).to_le_bytes().as_slice(),
            crc32(next_header).to_le_bytes().as_slice(),
        ]
        .concat();
        [
            b"7z\xbc\xaf\x27\x1c".as_slice(),
            b"\x00\x04".as_slice(),
            crc32(&start_header).to_le_bytes().as_slice(),
            start_header.as_slice(),
            gap.as_slice(),
            next_header.as_slice(),
        ]
        .concat()
    }
}
