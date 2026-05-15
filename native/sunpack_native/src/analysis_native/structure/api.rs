#[pyfunction]
pub(crate) fn inspect_zip_local_header(
    py: Python<'_>,
    path: &str,
    offset: i64,
) -> PyResult<Py<PyDict>> {
    let offset = offset.max(0) as u64;
    let result = dict(py)?;
    result.set_item("offset", offset)?;
    result.set_item("magic_matched", false)?;
    result.set_item("plausible", false)?;
    result.set_item("error", "")?;

    let Ok((file_size, header)) = read_at(path, offset, ZIP_LOCAL_HEADER_LENGTH) else {
        result.set_item("error", "os_error")?;
        return Ok(result.unbind());
    };
    if header.len() < ZIP_LOCAL_HEADER_LENGTH {
        result.set_item("magic_matched", header.starts_with(b"PK"))?;
        result.set_item("error", "short_header")?;
        return Ok(result.unbind());
    }
    if &header[0..4] != b"PK\x03\x04" {
        result.set_item(
            "magic_matched",
            header.starts_with(b"PK\x03\x04")
                || header.starts_with(b"PK\x05\x06")
                || header.starts_with(b"PK\x07\x08"),
        )?;
        result.set_item("error", "bad_signature")?;
        return Ok(result.unbind());
    }

    let version_needed = u16_le(&header, 4);
    let compression_method = u16_le(&header, 8);
    let filename_len = u16_le(&header, 26) as u64;
    let extra_len = u16_le(&header, 28) as u64;
    if version_needed > 63 {
        result.set_item("error", "unsupported_version")?;
        return Ok(result.unbind());
    }
    if !matches!(
        compression_method,
        0 | 1 | 6 | 8 | 9 | 12 | 14 | 95 | 96 | 98 | 99
    ) {
        result.set_item("error", "unknown_compression_method")?;
        return Ok(result.unbind());
    }
    if filename_len == 0 || filename_len > 4096 {
        result.set_item("error", "invalid_filename_length")?;
        return Ok(result.unbind());
    }
    if offset + ZIP_LOCAL_HEADER_LENGTH as u64 + filename_len + extra_len > file_size {
        result.set_item("error", "header_exceeds_file_size")?;
        return Ok(result.unbind());
    }
    result.set_item("magic_matched", true)?;
    result.set_item("plausible", true)?;
    result.set_item("version_needed", version_needed)?;
    result.set_item("compression_method", compression_method)?;
    result.set_item("filename_len", filename_len)?;
    result.set_item("extra_len", extra_len)?;
    Ok(result.unbind())
}

#[pyfunction]
#[pyo3(signature = (path, max_cd_entries_to_walk=16))]
pub(crate) fn inspect_zip_eocd_structure(
    py: Python<'_>,
    path: &str,
    max_cd_entries_to_walk: usize,
) -> PyResult<Py<PyDict>> {
    let mut result = zip_eocd_empty(py, "")?;
    let Ok(mut file) = File::open(path) else {
        result.set_item("error", "os_error")?;
        return Ok(result.unbind());
    };
    let file_size = file.seek(SeekFrom::End(0))?;
    if file_size < ZIP_EOCD_MIN_SIZE as u64 {
        result.set_item("error", "file_too_small")?;
        return Ok(result.unbind());
    }
    let read_size = file_size.min(ZIP_EOCD_MIN_SIZE as u64 + ZIP_EOCD_MAX_COMMENT);
    let mut tail = vec![0; read_size as usize];
    file.seek(SeekFrom::Start(file_size - read_size))?;
    file.read_exact(&mut tail)?;
    let Some((eocd_offset, eocd)) = find_eocd(&tail, file_size, read_size) else {
        result.set_item("error", "eocd_not_found")?;
        return Ok(result.unbind());
    };
    let disk_number = u16_le(eocd, 4);
    let central_directory_disk = u16_le(eocd, 6);
    let disk_entries = u16_le(eocd, 8);
    let total_entries = u16_le(eocd, 10);
    let central_directory_size = u32_le(eocd, 12) as u64;
    let central_directory_offset = u32_le(eocd, 16) as u64;
    let comment_length = u16_le(eocd, 20) as u64;
    let eocd_end = eocd_offset + ZIP_EOCD_MIN_SIZE as u64 + comment_length;
    let trailing_bytes_after_eocd = file_size.saturating_sub(eocd_end);
    if file_size - eocd_offset - ZIP_EOCD_MIN_SIZE as u64 != comment_length {
        result.set_item("error", "comment_length_mismatch")?;
        result.set_item("eocd_offset", eocd_offset)?;
        result.set_item("comment_length", comment_length)?;
        result.set_item("declared_central_directory_offset", central_directory_offset)?;
        result.set_item("declared_central_directory_size", central_directory_size)?;
        result.set_item("declared_total_entries", total_entries)?;
        result.set_item("trailing_bytes_after_eocd", trailing_bytes_after_eocd)?;
        return Ok(result.unbind());
    }
    if disk_number != 0 || central_directory_disk != 0 || disk_entries != total_entries {
        result.set_item("error", "multi_disk_or_entry_mismatch")?;
        result.set_item("eocd_offset", eocd_offset)?;
        result.set_item("central_directory_offset", central_directory_offset)?;
        result.set_item("central_directory_size", central_directory_size)?;
        result.set_item("total_entries", total_entries)?;
        result.set_item("comment_length", comment_length)?;
        result.set_item("declared_central_directory_offset", central_directory_offset)?;
        result.set_item("declared_central_directory_size", central_directory_size)?;
        result.set_item("declared_total_entries", total_entries)?;
        result.set_item("trailing_bytes_after_eocd", trailing_bytes_after_eocd)?;
        return Ok(result.unbind());
    }
    let physical_central_offset = eocd_offset.saturating_sub(central_directory_size);
    let archive_offset = physical_central_offset.saturating_sub(central_directory_offset);
    result = dict(py)?;
    result.set_item("plausible", false)?;
    result.set_item("error", "")?;
    result.set_item("magic_matched", true)?;
    result.set_item("eocd_offset", eocd_offset)?;
    result.set_item("central_directory_offset", physical_central_offset)?;
    result.set_item("central_directory_size", central_directory_size)?;
    result.set_item("declared_central_directory_offset", central_directory_offset)?;
    result.set_item("declared_central_directory_size", central_directory_size)?;
    result.set_item("declared_total_entries", total_entries)?;
    result.set_item("physical_central_directory_offset", physical_central_offset)?;
    result.set_item("inferred_central_directory_offset", physical_central_offset)?;
    result.set_item("inferred_central_directory_size", eocd_offset.saturating_sub(physical_central_offset))?;
    result.set_item(
        "central_directory_offset_delta",
        physical_central_offset as i64 - central_directory_offset as i64,
    )?;
    result.set_item(
        "central_directory_size_delta",
        eocd_offset.saturating_sub(physical_central_offset) as i64 - central_directory_size as i64,
    )?;
    result.set_item("entry_count_delta", 0i64)?;
    result.set_item("trailing_bytes_after_eocd", trailing_bytes_after_eocd)?;
    result.set_item("archive_offset", archive_offset)?;
    result.set_item("total_entries", total_entries)?;
    result.set_item("comment_length", comment_length)?;
    result.set_item("central_directory_present", false)?;
    result.set_item("central_directory_entries_checked", 0)?;
    result.set_item("central_directory_walk_ok", false)?;
    result.set_item("local_header_links_checked", 0)?;
    result.set_item("local_header_links_ok", false)?;
    result.set_item("local_header_links_ok_count", 0)?;
    result.set_item("local_header_links_error_count", 0)?;
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
    if central_directory_size < 4 {
        result.set_item("error", "central_directory_too_small")?;
        return Ok(result.unbind());
    }
    file.seek(SeekFrom::Start(physical_central_offset))?;
    let mut sig = [0u8; 4];
    file.read_exact(&mut sig)?;
    if sig != ZIP_CENTRAL_DIRECTORY_SIGNATURE {
        result.set_item("error", "bad_central_directory_signature")?;
        result.set_item("bad_central_directory_signature_offset", physical_central_offset)?;
        return Ok(result.unbind());
    }
    result.set_item("plausible", true)?;
    result.set_item("central_directory_present", true)?;
    let walk = walk_zip_central_directory(
        &mut file,
        file_size,
        archive_offset,
        physical_central_offset,
        central_directory_size,
        total_entries as usize,
        max_cd_entries_to_walk,
    )?;
    result.set_item("central_directory_entries_checked", walk.0)?;
    result.set_item("central_directory_walk_ok", walk.1)?;
    result.set_item("entry_count_delta", walk.0 as i64 - total_entries as i64)?;
    result.set_item("local_header_links_checked", walk.2)?;
    result.set_item("local_header_links_ok", walk.3)?;
    result.set_item("local_header_links_ok_count", walk.2)?;
    result.set_item("local_header_links_error_count", if walk.3 { 0usize } else { 1usize })?;
    if !walk.4.is_empty() {
        result.set_item("error", walk.4)?;
        result.set_item("plausible", false)?;
    }
    Ok(result.unbind())
}

#[pyfunction]
#[pyo3(signature = (path, max_entries=128))]
pub(crate) fn inspect_zip_directory_consistency(
    py: Python<'_>,
    path: &str,
    max_entries: usize,
) -> PyResult<Py<PyDict>> {
    crate::formats::zip::inspect_zip_directory_consistency(py, path, max_entries)
}

#[pyfunction]
#[pyo3(signature = (path, magic_bytes=None, max_next_header_check_bytes=1048576))]
pub(crate) fn inspect_seven_zip_structure(
    py: Python<'_>,
    path: &str,
    magic_bytes: Option<&[u8]>,
    max_next_header_check_bytes: u64,
) -> PyResult<Py<PyDict>> {
    let Ok(mut file) = File::open(path) else {
        return Ok(seven_empty(py, "os_error")?.unbind());
    };
    let file_size = file.seek(SeekFrom::End(0))?;
    let mut header = magic_bytes.unwrap_or(&[]).to_vec();
    if header.len() < SEVEN_Z_HEADER_SIZE {
        header.resize(SEVEN_Z_HEADER_SIZE, 0);
        file.seek(SeekFrom::Start(0))?;
        let len = file.read(&mut header)?;
        header.truncate(len);
    }
    if file_size < SEVEN_Z_HEADER_SIZE as u64 {
        let out = seven_empty(py, "file_too_small")?;
        if header.starts_with(SEVEN_Z_SIGNATURE) {
            out.set_item("magic_matched", true)?;
            out.set_item("format", "7z")?;
            out.set_item("detected_ext", ".7z")?;
            out.set_item("evidence", PyList::new(py, ["7z:signature"])?)?;
        }
        return Ok(out.unbind());
    }
    if !header.starts_with(SEVEN_Z_SIGNATURE) {
        return Ok(seven_empty(py, "7z_signature_not_found")?.unbind());
    }
    let stored_start_crc = u32_le(&header, 8);
    let start_header = &header[12..32];
    let computed_start_crc = crc32(start_header);
    let next_header_offset = u64_le(start_header, 0);
    let next_header_size = u64_le(start_header, 8);
    let next_header_crc = u32_le(start_header, 16);
    let result = dict(py)?;
    result.set_item("plausible", false)?;
    result.set_item("error", "")?;
    result.set_item("magic_matched", true)?;
    result.set_item("format", "7z")?;
    result.set_item("detected_ext", ".7z")?;
    result.set_item("version_major", header[6])?;
    result.set_item("version_minor", header[7])?;
    result.set_item("next_header_offset", next_header_offset)?;
    result.set_item("next_header_size", next_header_size)?;
    result.set_item("next_header_crc", next_header_crc)?;
    result.set_item(
        "start_header_crc_ok",
        stored_start_crc == computed_start_crc,
    )?;
    result.set_item("next_header_crc_checked", false)?;
    result.set_item("next_header_crc_ok", false)?;
    result.set_item("next_header_nid", 0)?;
    result.set_item("next_header_nid_valid", false)?;
    result.set_item("next_header_semantic_ok", false)?;
    result.set_item("strong_accept", false)?;
    result.set_item("confidence", "none")?;
    let evidence = PyList::new(py, ["7z:signature"])?;
    result.set_item("evidence", &evidence)?;
    if header[6] != 0 {
        result.set_item("error", "unsupported_version")?;
        return Ok(result.unbind());
    }
    if stored_start_crc != computed_start_crc {
        result.set_item("error", "start_header_crc_mismatch")?;
        return Ok(result.unbind());
    }
    let Some(next_header_start) = (SEVEN_Z_HEADER_SIZE as u64).checked_add(next_header_offset)
    else {
        result.set_item("error", "next_header_out_of_range")?;
        return Ok(result.unbind());
    };
    if next_header_size == 0 || next_header_start < SEVEN_Z_HEADER_SIZE as u64 {
        result.set_item("error", "invalid_next_header_range")?;
        return Ok(result.unbind());
    }
    let Some(next_header_end) = next_header_start.checked_add(next_header_size) else {
        result.set_item("error", "next_header_out_of_range")?;
        return Ok(result.unbind());
    };
    if next_header_end > file_size {
        result.set_item("error", "next_header_out_of_range")?;
        return Ok(result.unbind());
    }
    result.set_item("plausible", true)?;
    result.set_item("confidence", "strong")?;
    evidence.append("7z:start_header_crc")?;
    evidence.append("7z:next_header_range")?;
    if next_header_size <= max_next_header_check_bytes {
        let mut next_header = vec![0; next_header_size as usize];
        file.seek(SeekFrom::Start(next_header_start))?;
        file.read_exact(&mut next_header)?;
        let crc_ok = crc32(&next_header) == next_header_crc;
        let nid = next_header.first().copied().unwrap_or(0);
        let nid_valid = nid == 0x01 || nid == 0x17;
        result.set_item("next_header_crc_checked", true)?;
        result.set_item("next_header_crc_ok", crc_ok)?;
        result.set_item("next_header_nid", nid)?;
        result.set_item("next_header_nid_valid", nid_valid)?;
        result.set_item("next_header_semantic_ok", crc_ok && nid_valid)?;
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
    Ok(result.unbind())
}

#[pyfunction]
#[pyo3(signature = (path, magic_bytes=None, max_first_header_check_bytes=1048576))]
pub(crate) fn inspect_rar_structure(
    py: Python<'_>,
    path: &str,
    magic_bytes: Option<&[u8]>,
    max_first_header_check_bytes: u64,
) -> PyResult<Py<PyDict>> {
    let Ok(mut file) = File::open(path) else {
        return Ok(rar_empty(py, "os_error")?.unbind());
    };
    let file_size = file.seek(SeekFrom::End(0))?;
    let mut data = magic_bytes.unwrap_or(&[]).to_vec();
    if data.len() < 64 {
        data.resize(64, 0);
        file.seek(SeekFrom::Start(0))?;
        let len = file.read(&mut data)?;
        data.truncate(len);
    }
    if data.starts_with(RAR4_SIGNATURE) && data.len() >= RAR4_SIGNATURE.len() + 7 {
        let header_size = u16_le(&data, RAR4_SIGNATURE.len() + 5) as u64;
        let read_size = file_size
            .min(RAR4_SIGNATURE.len() as u64 + header_size + 64)
            .min(max_first_header_check_bytes);
        if data.len() < read_size as usize {
            data.resize(read_size as usize, 0);
            file.seek(SeekFrom::Start(0))?;
            let len = file.read(&mut data)?;
            data.truncate(len);
        }
    } else if data.starts_with(RAR5_SIGNATURE) {
        if let Some((header_size, _)) = read_vint(&data, RAR5_SIGNATURE.len() + 4) {
            let read_size = file_size
                .min(RAR5_SIGNATURE.len() as u64 + 4 + header_size + 64)
                .min(max_first_header_check_bytes);
            if data.len() < read_size as usize {
                data.resize(read_size as usize, 0);
                file.seek(SeekFrom::Start(0))?;
                let len = file.read(&mut data)?;
                data.truncate(len);
            }
        }
    }
    if data.starts_with(RAR5_SIGNATURE) {
        return inspect_rar5(py, &data, file_size);
    }
    if data.starts_with(RAR4_SIGNATURE) {
        return inspect_rar4(py, &data, file_size);
    }
    if data.starts_with(b"Rar!") {
        let out = rar_empty(py, "rar_signature_incomplete_or_unknown")?;
        out.set_item("magic_matched", true)?;
        out.set_item("format", "rar")?;
        out.set_item("detected_ext", ".rar")?;
        out.set_item("evidence", PyList::new(py, ["rar:signature"])?)?;
        return Ok(out.unbind());
    }
    Ok(rar_empty(py, "rar_signature_not_found")?.unbind())
}

#[pyfunction]
#[pyo3(signature = (path, max_entries_to_walk=8))]
pub(crate) fn inspect_tar_header_structure(
    py: Python<'_>,
    path: &str,
    max_entries_to_walk: usize,
) -> PyResult<Py<PyDict>> {
    let Ok(mut file) = File::open(path) else {
        return Ok(tar_empty(py, "os_error")?.unbind());
    };
    let file_size = file.seek(SeekFrom::End(0))?;
    if file_size < TAR_BLOCK_SIZE as u64 {
        return Ok(tar_empty(py, "file_too_small")?.unbind());
    }
    let mut header = vec![0; TAR_BLOCK_SIZE];
    file.seek(SeekFrom::Start(0))?;
    file.read_exact(&mut header)?;
    let result = tar_empty(py, "")?;
    result.set_item("file_size", file_size)?;
    if header.iter().all(|b| *b == 0) {
        result.set_item("error", "leading_zero_block")?;
        result.set_item("zero_block", true)?;
        return Ok(result.unbind());
    }
    let stored_checksum = parse_octal(&header[148..156]);
    let member_size = parse_octal(&header[124..136]);
    let computed = tar_checksum(&header);
    result.set_item("stored_checksum", stored_checksum.unwrap_or(0))?;
    result.set_item("computed_checksum", computed)?;
    result.set_item("member_size", member_size.unwrap_or(0))?;
    result.set_item(
        "ustar_magic",
        matches!(&header[257..263], b"ustar\x00" | b"ustar "),
    )?;
    if stored_checksum.is_none() {
        result.set_item("error", "invalid_checksum_field")?;
        return Ok(result.unbind());
    }
    if member_size.is_none() {
        result.set_item("error", "invalid_size_field")?;
        return Ok(result.unbind());
    }
    if stored_checksum.unwrap() != computed {
        result.set_item("error", "checksum_mismatch")?;
        return Ok(result.unbind());
    }
    result.set_item("plausible", true)?;
    result.set_item(
        "format",
        if matches!(&header[257..263], b"ustar\x00" | b"ustar ") {
            "ustar"
        } else {
            "tar"
        },
    )?;
    let walk = walk_tar(&mut file, file_size, max_entries_to_walk)?;
    result.set_item("entries_checked", walk.0)?;
    result.set_item("entry_walk_ok", walk.1)?;
    result.set_item("end_zero_blocks", walk.2)?;
    if !walk.3.is_empty() {
        result.set_item("error", walk.3)?;
        result.set_item("plausible", false)?;
    }
    Ok(result.unbind())
}

#[pyfunction]
pub(crate) fn inspect_compression_stream_structure(
    py: Python<'_>,
    path: &str,
) -> PyResult<Py<PyDict>> {
    let Ok((file_size, header)) = read_at(path, 0, 32) else {
        return compression_empty(py, "os_error", "", "", false);
    };
    if header.starts_with(b"\x1f\x8b") {
        return inspect_gzip(py, &header, file_size);
    }
    if header.starts_with(b"BZh") {
        return inspect_bzip2(py, &header, file_size);
    }
    if header.starts_with(XZ_MAGIC) {
        return inspect_xz(py, path, &header, file_size);
    }
    if header.starts_with(ZSTD_MAGIC) {
        return inspect_zstd(py, &header, file_size);
    }
    compression_empty(py, "compression_stream_magic_not_found", "", "", false)
}

#[pyfunction]
pub(crate) fn inspect_archive_container_structure(
    py: Python<'_>,
    path: &str,
) -> PyResult<Py<PyDict>> {
    let Ok((file_size, header)) = read_at(path, 0, 4096) else {
        return container_empty(py, "os_error");
    };
    if header.starts_with(b"MSCF\x00\x00\x00\x00") {
        return inspect_cab(py, &header, file_size);
    }
    if header.starts_with(b"\x60\xea") {
        return inspect_arj(py, &header, file_size);
    }
    if header.starts_with(b"070701") || header.starts_with(b"070702") {
        return inspect_cpio(py, &header, file_size);
    }
    container_empty(py, "archive_container_magic_not_found")
}
