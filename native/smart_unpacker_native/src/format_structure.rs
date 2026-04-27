use crate::magic::rfind_subslice;
use pyo3::prelude::*;
use pyo3::types::{PyDict, PyList};
use std::fs::File;
use std::io::{Read, Seek, SeekFrom};

const ZIP_EOCD_SIGNATURE: &[u8] = b"PK\x05\x06";
const ZIP_CENTRAL_DIRECTORY_SIGNATURE: &[u8] = b"PK\x01\x02";
const ZIP_EOCD_MIN_SIZE: usize = 22;
const ZIP_EOCD_MAX_COMMENT: u64 = 65_535;
const ZIP_CENTRAL_DIRECTORY_HEADER_SIZE: usize = 46;
const ZIP_LOCAL_HEADER_LENGTH: usize = 30;
const TAR_BLOCK_SIZE: usize = 512;
const SEVEN_Z_SIGNATURE: &[u8] = b"7z\xbc\xaf\x27\x1c";
const SEVEN_Z_HEADER_SIZE: usize = 32;
const RAR4_SIGNATURE: &[u8] = b"Rar!\x1a\x07\x00";
const RAR5_SIGNATURE: &[u8] = b"Rar!\x1a\x07\x01\x00";
const XZ_MAGIC: &[u8] = b"\xfd7zXZ\x00";
const ZSTD_MAGIC: &[u8] = b"\x28\xb5\x2f\xfd";

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
    if !matches!(compression_method, 0 | 1 | 6 | 8 | 9 | 12 | 14 | 95 | 96 | 98 | 99) {
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
    if file_size - eocd_offset - ZIP_EOCD_MIN_SIZE as u64 != comment_length {
        result.set_item("error", "comment_length_mismatch")?;
        result.set_item("eocd_offset", eocd_offset)?;
        result.set_item("comment_length", comment_length)?;
        return Ok(result.unbind());
    }
    if disk_number != 0 || central_directory_disk != 0 || disk_entries != total_entries {
        result.set_item("error", "multi_disk_or_entry_mismatch")?;
        result.set_item("eocd_offset", eocd_offset)?;
        result.set_item("central_directory_offset", central_directory_offset)?;
        result.set_item("central_directory_size", central_directory_size)?;
        result.set_item("total_entries", total_entries)?;
        result.set_item("comment_length", comment_length)?;
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
    result.set_item("archive_offset", archive_offset)?;
    result.set_item("total_entries", total_entries)?;
    result.set_item("comment_length", comment_length)?;
    result.set_item("central_directory_present", false)?;
    result.set_item("central_directory_entries_checked", 0)?;
    result.set_item("central_directory_walk_ok", false)?;
    result.set_item("local_header_links_checked", 0)?;
    result.set_item("local_header_links_ok", false)?;
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
    result.set_item("local_header_links_checked", walk.2)?;
    result.set_item("local_header_links_ok", walk.3)?;
    if !walk.4.is_empty() {
        result.set_item("error", walk.4)?;
        result.set_item("plausible", false)?;
    }
    Ok(result.unbind())
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
    result.set_item("start_header_crc_ok", stored_start_crc == computed_start_crc)?;
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
    let next_header_start = SEVEN_Z_HEADER_SIZE as u64 + next_header_offset;
    if next_header_size == 0 || next_header_start < SEVEN_Z_HEADER_SIZE as u64 {
        result.set_item("error", "invalid_next_header_range")?;
        return Ok(result.unbind());
    }
    if next_header_start + next_header_size > file_size {
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
    result.set_item("ustar_magic", matches!(&header[257..263], b"ustar\x00" | b"ustar "))?;
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
pub(crate) fn inspect_compression_stream_structure(py: Python<'_>, path: &str) -> PyResult<Py<PyDict>> {
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
pub(crate) fn inspect_archive_container_structure(py: Python<'_>, path: &str) -> PyResult<Py<PyDict>> {
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

fn dict<'py>(py: Python<'py>) -> PyResult<Bound<'py, PyDict>> {
    Ok(PyDict::new(py))
}

fn read_at(path: &str, offset: u64, max_len: usize) -> std::io::Result<(u64, Vec<u8>)> {
    let mut file = File::open(path)?;
    let file_size = file.seek(SeekFrom::End(0))?;
    file.seek(SeekFrom::Start(offset))?;
    let len = max_len.min(file_size.saturating_sub(offset) as usize);
    let mut buffer = vec![0; len];
    file.read_exact(&mut buffer)?;
    Ok((file_size, buffer))
}

fn find_eocd(tail: &[u8], file_size: u64, read_size: u64) -> Option<(u64, &[u8])> {
    let mut search_end = tail.len();
    loop {
        let index = rfind_subslice(&tail[..search_end], ZIP_EOCD_SIGNATURE)?;
        if tail.len() - index >= ZIP_EOCD_MIN_SIZE {
            let eocd = &tail[index..index + ZIP_EOCD_MIN_SIZE];
            let comment_length = u16_le(eocd, 20) as u64;
            let eocd_offset = file_size - read_size + index as u64;
            if file_size - eocd_offset - ZIP_EOCD_MIN_SIZE as u64 == comment_length {
                return Some((eocd_offset, eocd));
            }
        }
        if index == 0 {
            return None;
        }
        search_end = index;
    }
}

fn walk_zip_central_directory(
    file: &mut File,
    file_size: u64,
    archive_offset: u64,
    central_directory_offset: u64,
    central_directory_size: u64,
    total_entries: usize,
    max_entries: usize,
) -> PyResult<(usize, bool, usize, bool, &'static str)> {
    if total_entries == 0 || central_directory_size == 0 {
        return Ok((0, total_entries == 0 && central_directory_size == 0, 0, false, ""));
    }
    let limit = total_entries.min(max_entries);
    if limit == 0 {
        return Ok((0, false, 0, false, ""));
    }
    let mut cursor = central_directory_offset;
    let central_end = central_directory_offset + central_directory_size;
    let mut checked = 0;
    for _ in 0..limit {
        if cursor + ZIP_CENTRAL_DIRECTORY_HEADER_SIZE as u64 > central_end
            || cursor + ZIP_CENTRAL_DIRECTORY_HEADER_SIZE as u64 > file_size
        {
            return Ok((checked, false, checked, false, "central_entry_out_of_range"));
        }
        let mut header = [0u8; ZIP_CENTRAL_DIRECTORY_HEADER_SIZE];
        file.seek(SeekFrom::Start(cursor))?;
        file.read_exact(&mut header)?;
        if &header[0..4] != ZIP_CENTRAL_DIRECTORY_SIGNATURE {
            return Ok((checked, false, checked, false, "bad_central_entry_signature"));
        }
        let filename_len = u16_le(&header, 28) as u64;
        let extra_len = u16_le(&header, 30) as u64;
        let comment_len = u16_le(&header, 32) as u64;
        let disk_start = u16_le(&header, 34);
        let local_header_offset = u32_le(&header, 42) as u64;
        let entry_size = ZIP_CENTRAL_DIRECTORY_HEADER_SIZE as u64 + filename_len + extra_len + comment_len;
        if disk_start != 0 {
            return Ok((checked, false, checked, false, "central_entry_multi_disk"));
        }
        if filename_len == 0 || filename_len > 4096 {
            return Ok((checked, false, checked, false, "central_entry_invalid_filename_length"));
        }
        if entry_size <= ZIP_CENTRAL_DIRECTORY_HEADER_SIZE as u64 || cursor + entry_size > central_end {
            return Ok((checked, false, checked, false, "central_entry_size_out_of_range"));
        }
        let local_header_position = archive_offset + local_header_offset;
        if local_header_position < archive_offset || local_header_position + 4 > central_directory_offset {
            return Ok((checked, false, checked, false, "local_header_offset_out_of_range"));
        }
        let mut sig = [0u8; 4];
        file.seek(SeekFrom::Start(local_header_position))?;
        file.read_exact(&mut sig)?;
        if &sig != b"PK\x03\x04" {
            return Ok((checked, false, checked, false, "local_header_link_bad_signature"));
        }
        checked += 1;
        cursor += entry_size;
    }
    Ok((checked, checked > 0, checked, true, ""))
}

fn zip_eocd_empty<'py>(py: Python<'py>, error: &str) -> PyResult<Bound<'py, PyDict>> {
    let d = dict(py)?;
    for (key, value) in [
        ("plausible", false),
        ("magic_matched", false),
        ("central_directory_present", false),
        ("central_directory_walk_ok", false),
        ("local_header_links_ok", false),
    ] {
        d.set_item(key, value)?;
    }
    d.set_item("error", error)?;
    for key in [
        "eocd_offset",
        "central_directory_offset",
        "central_directory_size",
        "archive_offset",
        "total_entries",
        "comment_length",
        "central_directory_entries_checked",
        "local_header_links_checked",
    ] {
        d.set_item(key, 0)?;
    }
    Ok(d)
}

fn seven_empty<'py>(py: Python<'py>, error: &str) -> PyResult<Bound<'py, PyDict>> {
    let d = dict(py)?;
    d.set_item("plausible", false)?;
    d.set_item("error", error)?;
    d.set_item("magic_matched", false)?;
    d.set_item("format", "")?;
    d.set_item("detected_ext", "")?;
    for key in [
        "version_major",
        "version_minor",
        "next_header_offset",
        "next_header_size",
        "next_header_crc",
        "next_header_nid",
    ] {
        d.set_item(key, 0)?;
    }
    for key in [
        "start_header_crc_ok",
        "next_header_crc_checked",
        "next_header_crc_ok",
        "next_header_nid_valid",
        "next_header_semantic_ok",
        "strong_accept",
    ] {
        d.set_item(key, false)?;
    }
    d.set_item("confidence", "none")?;
    d.set_item("evidence", PyList::empty(py))?;
    Ok(d)
}

fn rar_empty<'py>(py: Python<'py>, error: &str) -> PyResult<Bound<'py, PyDict>> {
    let d = dict(py)?;
    d.set_item("plausible", false)?;
    d.set_item("error", error)?;
    d.set_item("magic_matched", false)?;
    d.set_item("format", "")?;
    d.set_item("detected_ext", "")?;
    for key in [
        "version",
        "first_header_offset",
        "first_header_size",
        "first_header_type",
        "second_block_type",
        "second_block_size",
    ] {
        d.set_item(key, 0)?;
    }
    for key in [
        "header_crc_checked",
        "header_crc_ok",
        "second_block_checked",
        "second_block_ok",
        "block_walk_ok",
        "strong_accept",
    ] {
        d.set_item(key, false)?;
    }
    d.set_item("confidence", "none")?;
    d.set_item("evidence", PyList::empty(py))?;
    Ok(d)
}

fn inspect_rar4(py: Python<'_>, data: &[u8], file_size: u64) -> PyResult<Py<PyDict>> {
    let first_header_offset = RAR4_SIGNATURE.len();
    if file_size < first_header_offset as u64 + 7 || data.len() < first_header_offset + 7 {
        return Ok(rar_empty(py, "rar4_first_header_too_small")?.unbind());
    }
    let header_crc = u16_le(data, first_header_offset);
    let header_type = data[first_header_offset + 2];
    let header_size = u16_le(data, first_header_offset + 5) as u64;
    let d = rar_empty(py, "")?;
    d.set_item("magic_matched", true)?;
    d.set_item("format", "rar")?;
    d.set_item("detected_ext", ".rar")?;
    d.set_item("version", 4)?;
    d.set_item("first_header_offset", first_header_offset)?;
    d.set_item("first_header_size", header_size)?;
    d.set_item("first_header_type", header_type)?;
    let evidence = PyList::new(py, ["rar4:signature"])?;
    d.set_item("evidence", &evidence)?;
    if !matches!(header_type, 0x73..=0x7B) {
        d.set_item("error", "rar4_unknown_first_header_type")?;
        return Ok(d.unbind());
    }
    if header_size < 7 || first_header_offset as u64 + header_size > file_size {
        d.set_item("error", "rar4_first_header_size_out_of_range")?;
        return Ok(d.unbind());
    }
    d.set_item("plausible", true)?;
    d.set_item("confidence", "strong")?;
    evidence.append("rar4:first_header")?;
    if data.len() >= first_header_offset + header_size as usize {
        let full_header = &data[first_header_offset..first_header_offset + header_size as usize];
        let crc_ok = (crc32(&full_header[2..]) & 0xFFFF) == header_crc as u32;
        d.set_item("header_crc_checked", true)?;
        d.set_item("header_crc_ok", crc_ok)?;
        if crc_ok {
            evidence.append("rar4:header_crc")?;
        } else if header_type == 0x73 {
            d.set_item("error", "rar4_header_crc_mismatch")?;
        }
    }
    let second_offset = first_header_offset + header_size as usize;
    if header_type == 0x73 && d.get_item("header_crc_ok")?.unwrap().extract::<bool>()? && second_offset < file_size as usize {
        let second = inspect_rar4_block(data, second_offset, file_size);
        d.set_item("second_block_checked", true)?;
        d.set_item("second_block_ok", second.0)?;
        d.set_item("second_block_type", second.1)?;
        d.set_item("second_block_size", second.2)?;
        d.set_item("block_walk_ok", second.0)?;
        if second.0 {
            evidence.append("rar4:second_block")?;
        } else {
            d.set_item("error", second.3)?;
        }
    }
    if header_type == 0x73
        && d.get_item("header_crc_ok")?.unwrap().extract::<bool>()?
        && (second_offset >= file_size as usize || d.get_item("block_walk_ok")?.unwrap().extract::<bool>()?)
    {
        d.set_item("strong_accept", true)?;
    }
    Ok(d.unbind())
}

fn inspect_rar4_block(data: &[u8], offset: usize, file_size: u64) -> (bool, u8, u64, &'static str) {
    if offset >= file_size as usize || data.len() < offset + 7 {
        return (false, 0, 0, "rar4_second_block_too_small");
    }
    let header_crc = u16_le(data, offset);
    let header_type = data[offset + 2];
    let header_flags = u16_le(data, offset + 3);
    let header_size = u16_le(data, offset + 5) as u64;
    if !matches!(header_type, 0x73..=0x7B) {
        return (false, header_type, header_size, "rar4_second_block_unknown_type");
    }
    if header_size < 7 || offset as u64 + header_size > file_size || data.len() < offset + header_size as usize {
        return (false, header_type, header_size, "rar4_second_block_size_out_of_range");
    }
    let full_header = &data[offset..offset + header_size as usize];
    if (crc32(&full_header[2..]) & 0xFFFF) != header_crc as u32 {
        return (false, header_type, header_size, "rar4_second_block_crc_mismatch");
    }
    let mut block_size = header_size;
    if header_flags & 0x8000 != 0 {
        if header_size < 11 {
            return (false, header_type, block_size, "rar4_second_block_add_size_missing");
        }
        block_size += u32_le(full_header, 7) as u64;
        if offset as u64 + block_size > file_size {
            return (false, header_type, block_size, "rar4_second_block_payload_out_of_range");
        }
    }
    (true, header_type, block_size, "")
}

fn inspect_rar5(py: Python<'_>, data: &[u8], file_size: u64) -> PyResult<Py<PyDict>> {
    let first_header_offset = RAR5_SIGNATURE.len();
    if file_size < first_header_offset as u64 + 6 || data.len() < first_header_offset + 6 {
        return Ok(rar_empty(py, "rar5_first_header_too_small")?.unbind());
    }
    let Some((header_size, after_size)) = read_vint(data, first_header_offset + 4) else {
        return Ok(rar_empty(py, "rar5_header_size_vint_missing")?.unbind());
    };
    let Some((header_type, _)) = read_vint(data, after_size) else {
        return Ok(rar_empty(py, "rar5_header_type_vint_missing")?.unbind());
    };
    let d = rar_empty(py, "")?;
    d.set_item("magic_matched", true)?;
    d.set_item("format", "rar")?;
    d.set_item("detected_ext", ".rar")?;
    d.set_item("version", 5)?;
    d.set_item("first_header_offset", first_header_offset)?;
    d.set_item("first_header_size", header_size)?;
    d.set_item("first_header_type", header_type)?;
    let evidence = PyList::new(py, ["rar5:signature"])?;
    d.set_item("evidence", &evidence)?;
    let first_header_total_size = 4 + (after_size - (first_header_offset + 4)) as u64 + header_size;
    if header_size == 0 || first_header_offset as u64 + first_header_total_size > file_size {
        d.set_item("error", "rar5_first_header_size_out_of_range")?;
        return Ok(d.unbind());
    }
    d.set_item("plausible", true)?;
    d.set_item("confidence", "strong")?;
    evidence.append("rar5:first_header")?;
    if data.len() >= first_header_offset + first_header_total_size as usize {
        let stored_crc = u32_le(data, first_header_offset);
        let header_data = &data[first_header_offset + 4..first_header_offset + first_header_total_size as usize];
        let crc_ok = crc32(header_data) == stored_crc;
        d.set_item("header_crc_checked", true)?;
        d.set_item("header_crc_ok", crc_ok)?;
        if crc_ok {
            evidence.append("rar5:header_crc")?;
        } else if header_type == 1 {
            d.set_item("error", "rar5_header_crc_mismatch")?;
        }
    }
    let second_offset = first_header_offset + first_header_total_size as usize;
    if header_type == 1 && d.get_item("header_crc_ok")?.unwrap().extract::<bool>()? && second_offset < file_size as usize {
        let second = inspect_rar5_block(data, second_offset, file_size);
        d.set_item("second_block_checked", true)?;
        d.set_item("second_block_ok", second.0)?;
        d.set_item("second_block_type", second.1)?;
        d.set_item("second_block_size", second.2)?;
        d.set_item("block_walk_ok", second.0)?;
        if second.0 {
            evidence.append("rar5:second_header")?;
        } else {
            d.set_item("error", second.3)?;
        }
    }
    if header_type == 1
        && d.get_item("header_crc_ok")?.unwrap().extract::<bool>()?
        && (second_offset >= file_size as usize || d.get_item("block_walk_ok")?.unwrap().extract::<bool>()?)
    {
        d.set_item("strong_accept", true)?;
    }
    Ok(d.unbind())
}

fn inspect_rar5_block(data: &[u8], offset: usize, file_size: u64) -> (bool, u64, u64, &'static str) {
    if offset >= file_size as usize || data.len() < offset + 6 {
        return (false, 0, 0, "rar5_second_header_too_small");
    }
    let Some((header_size, after_size)) = read_vint(data, offset + 4) else {
        return (false, 0, 0, "rar5_second_header_size_vint_missing");
    };
    let Some((header_type, _)) = read_vint(data, after_size) else {
        return (false, 0, header_size, "rar5_second_header_type_vint_missing");
    };
    if !matches!(header_type, 1..=5) {
        return (false, header_type, header_size, "rar5_second_header_unknown_type");
    }
    let header_total_size = 4 + (after_size - (offset + 4)) as u64 + header_size;
    if header_size == 0 || offset as u64 + header_total_size > file_size || data.len() < offset + header_total_size as usize {
        return (false, header_type, header_size, "rar5_second_header_size_out_of_range");
    }
    let stored_crc = u32_le(data, offset);
    let header_data = &data[offset + 4..offset + header_total_size as usize];
    if crc32(header_data) != stored_crc {
        return (false, header_type, header_size, "rar5_second_header_crc_mismatch");
    }
    (true, header_type, header_total_size, "")
}

fn tar_empty<'py>(py: Python<'py>, error: &str) -> PyResult<Bound<'py, PyDict>> {
    let d = dict(py)?;
    d.set_item("plausible", false)?;
    d.set_item("error", error)?;
    d.set_item("format", "")?;
    for key in ["stored_checksum", "computed_checksum", "file_size", "member_size", "entries_checked"] {
        d.set_item(key, 0)?;
    }
    for key in ["ustar_magic", "zero_block", "entry_walk_ok", "end_zero_blocks"] {
        d.set_item(key, false)?;
    }
    Ok(d)
}

fn walk_tar(file: &mut File, file_size: u64, max_entries: usize) -> PyResult<(usize, bool, bool, &'static str)> {
    if max_entries == 0 {
        return Ok((0, false, false, ""));
    }
    let mut offset = 0u64;
    let mut zero_blocks = 0usize;
    let mut checked = 0usize;
    while checked < max_entries && offset + TAR_BLOCK_SIZE as u64 <= file_size {
        let mut header = vec![0; TAR_BLOCK_SIZE];
        file.seek(SeekFrom::Start(offset))?;
        file.read_exact(&mut header)?;
        if header.iter().all(|b| *b == 0) {
            zero_blocks += 1;
            offset += TAR_BLOCK_SIZE as u64;
            if zero_blocks >= 2 {
                return Ok((checked, checked > 0, true, ""));
            }
            continue;
        }
        zero_blocks = 0;
        let (ok, error, member_size, _) = tar_header_plausible(&header);
        if !ok {
            return Ok((checked, false, false, error));
        }
        let next_offset = offset + TAR_BLOCK_SIZE as u64 + member_size + padding_for_size(member_size);
        if next_offset > file_size {
            return Ok((checked, false, false, "member_payload_out_of_range"));
        }
        checked += 1;
        offset = next_offset;
    }
    Ok((checked, checked > 0, false, ""))
}

fn tar_header_plausible(header: &[u8]) -> (bool, &'static str, u64, bool) {
    if header.len() < TAR_BLOCK_SIZE {
        return (false, "short_header", 0, false);
    }
    if header.iter().all(|b| *b == 0) {
        return (false, "zero_block", 0, false);
    }
    let stored_checksum = parse_octal(&header[148..156]);
    let member_size = parse_octal(&header[124..136]);
    if stored_checksum.is_none() {
        return (false, "invalid_checksum_field", 0, false);
    }
    if member_size.is_none() {
        return (false, "invalid_size_field", 0, false);
    }
    if stored_checksum.unwrap() != tar_checksum(header) {
        return (false, "checksum_mismatch", member_size.unwrap(), false);
    }
    (
        true,
        "",
        member_size.unwrap(),
        matches!(&header[257..263], b"ustar\x00" | b"ustar "),
    )
}

fn compression_empty(py: Python<'_>, error: &str, format: &str, ext: &str, magic: bool) -> PyResult<Py<PyDict>> {
    let d = dict(py)?;
    d.set_item("plausible", false)?;
    d.set_item("error", error)?;
    d.set_item("magic_matched", magic)?;
    d.set_item("format", format)?;
    d.set_item("detected_ext", ext)?;
    d.set_item("confidence", "none")?;
    let evidence = PyList::empty(py);
    if !format.is_empty() && magic {
        evidence.append(format!("{format}:magic"))?;
    }
    d.set_item("evidence", evidence)?;
    Ok(d.unbind())
}

fn compression_ok(py: Python<'_>, format: &str, ext: &str, confidence: &str, evidence_items: &[&str]) -> PyResult<Py<PyDict>> {
    let d = dict(py)?;
    d.set_item("plausible", true)?;
    d.set_item("error", "")?;
    d.set_item("magic_matched", true)?;
    d.set_item("format", format)?;
    d.set_item("detected_ext", ext)?;
    d.set_item("confidence", confidence)?;
    d.set_item("evidence", PyList::new(py, evidence_items)?)?;
    Ok(d.unbind())
}

fn inspect_gzip(py: Python<'_>, header: &[u8], file_size: u64) -> PyResult<Py<PyDict>> {
    if file_size < 18 {
        return compression_empty(py, "gzip_too_small", "gzip", ".gz", true);
    }
    if header.len() < 10 {
        return compression_empty(py, "short_gzip_header", "gzip", ".gz", header.starts_with(b"\x1f\x8b"));
    }
    if !header.starts_with(b"\x1f\x8b\x08") {
        return compression_empty(py, "gzip_magic_not_found", "", "", false);
    }
    if header[3] & 0xE0 != 0 {
        return compression_empty(py, "gzip_reserved_flags_set", "gzip", ".gz", true);
    }
    compression_ok(py, "gzip", ".gz", "medium", &["gzip:magic", "gzip:method:deflate", "gzip:flags_valid"])
}

fn inspect_bzip2(py: Python<'_>, header: &[u8], file_size: u64) -> PyResult<Py<PyDict>> {
    if file_size < 14 {
        return compression_empty(py, "bzip2_too_small", "bzip2", ".bz2", true);
    }
    if header.len() < 10 {
        return compression_empty(py, "short_bzip2_header", "bzip2", ".bz2", header.starts_with(b"BZh"));
    }
    if !header.starts_with(b"BZh") || !b"123456789".contains(&header[3]) {
        return compression_empty(py, "bzip2_magic_not_found", "bzip2", ".bz2", header.starts_with(b"BZh"));
    }
    if !matches!(&header[4..10], b"\x31\x41\x59\x26\x53\x59" | b"\x17\x72\x45\x38\x50\x90") {
        return compression_empty(py, "bzip2_block_marker_not_found", "bzip2", ".bz2", true);
    }
    compression_ok(py, "bzip2", ".bz2", "strong", &["bzip2:magic", "bzip2:block_marker"])
}

fn inspect_xz(py: Python<'_>, path: &str, header: &[u8], file_size: u64) -> PyResult<Py<PyDict>> {
    if file_size < 24 {
        return compression_empty(py, "xz_too_small", "xz", ".xz", true);
    }
    if header.len() < 12 || !header.starts_with(XZ_MAGIC) {
        return compression_empty(py, "xz_magic_not_found", "xz", ".xz", header.starts_with(XZ_MAGIC));
    }
    let stream_flags = &header[6..8];
    if u32_le(header, 8) != crc32(stream_flags) {
        return compression_empty(py, "xz_header_crc_mismatch", "xz", ".xz", true);
    }
    let Ok((_, footer)) = read_at(path, file_size - 12, 12) else {
        return compression_empty(py, "os_error", "xz", ".xz", true);
    };
    if footer.len() != 12 || &footer[10..12] != b"YZ" {
        return compression_empty(py, "xz_footer_magic_not_found", "xz", ".xz", true);
    }
    if u32_le(&footer, 0) != crc32(&footer[4..10]) {
        return compression_empty(py, "xz_footer_crc_mismatch", "xz", ".xz", true);
    }
    if &footer[8..10] != stream_flags {
        return compression_empty(py, "xz_stream_flags_mismatch", "xz", ".xz", true);
    }
    compression_ok(py, "xz", ".xz", "strong", &["xz:magic", "xz:header_crc", "xz:footer_crc"])
}

fn inspect_zstd(py: Python<'_>, header: &[u8], file_size: u64) -> PyResult<Py<PyDict>> {
    if file_size < 6 {
        return compression_empty(py, "zstd_too_small", "zstd", ".zst", true);
    }
    if !header.starts_with(ZSTD_MAGIC) {
        return compression_empty(py, "zstd_magic_not_found", "", "", false);
    }
    if header[4] & 0x08 != 0 {
        return compression_empty(py, "zstd_reserved_bit_set", "zstd", ".zst", true);
    }
    if header[4] & 0x20 == 0 && header.len() < 6 {
        return compression_empty(py, "zstd_window_descriptor_missing", "zstd", ".zst", true);
    }
    compression_ok(py, "zstd", ".zst", "medium", &["zstd:magic", "zstd:frame_descriptor"])
}

fn container_empty(py: Python<'_>, error: &str) -> PyResult<Py<PyDict>> {
    let d = dict(py)?;
    d.set_item("plausible", false)?;
    d.set_item("error", error)?;
    d.set_item("format", "")?;
    d.set_item("detected_ext", "")?;
    d.set_item("confidence", "none")?;
    d.set_item("evidence", PyList::empty(py))?;
    Ok(d.unbind())
}

fn container_ok(py: Python<'_>, format: &str, ext: &str, evidence_items: &[&str]) -> PyResult<Py<PyDict>> {
    let d = dict(py)?;
    d.set_item("plausible", true)?;
    d.set_item("error", "")?;
    d.set_item("format", format)?;
    d.set_item("detected_ext", ext)?;
    d.set_item("confidence", "strong")?;
    d.set_item("evidence", PyList::new(py, evidence_items)?)?;
    Ok(d.unbind())
}

fn inspect_cab(py: Python<'_>, header: &[u8], file_size: u64) -> PyResult<Py<PyDict>> {
    if file_size < 36 || header.len() < 36 {
        return container_empty(py, "cab_too_small");
    }
    let cab_size = u32_le(header, 8) as u64;
    let files_offset = u32_le(header, 16) as u64;
    let folder_count = u16_le(header, 26);
    let file_count = u16_le(header, 28);
    if header[25] != 1 || header[24] > 4 {
        return container_empty(py, "cab_version_unsupported");
    }
    if cab_size < 36 || cab_size > file_size {
        return container_empty(py, "cab_size_out_of_range");
    }
    if folder_count == 0 || file_count == 0 {
        return container_empty(py, "cab_empty_folder_or_file_count");
    }
    if files_offset < 36 || files_offset >= cab_size {
        return container_empty(py, "cab_files_offset_out_of_range");
    }
    container_ok(py, "cab", ".cab", &["cab:magic", "cab:header_fields"])
}

fn inspect_arj(py: Python<'_>, header: &[u8], file_size: u64) -> PyResult<Py<PyDict>> {
    if file_size < 10 || header.len() < 10 {
        return container_empty(py, "arj_too_small");
    }
    let header_size = u16_le(header, 2) as usize;
    let header_end = 4 + header_size;
    if header_size < 30 || header_end + 4 > file_size as usize || header_end + 4 > header.len() {
        return container_empty(py, "arj_header_size_out_of_range");
    }
    if u32_le(header, header_end) != crc32(&header[4..header_end]) {
        return container_empty(py, "arj_header_crc_mismatch");
    }
    container_ok(py, "arj", ".arj", &["arj:magic", "arj:header_crc"])
}

fn inspect_cpio(py: Python<'_>, header: &[u8], file_size: u64) -> PyResult<Py<PyDict>> {
    if file_size < 110 || header.len() < 110 {
        return container_empty(py, "cpio_too_small");
    }
    let namesize = parse_hex(&header[94..102]);
    let member_size = parse_hex(&header[54..62]);
    let mode = parse_hex(&header[14..22]);
    if namesize.is_none_or(|v| v == 0 || v > 4096) {
        return container_empty(py, "cpio_invalid_namesize");
    }
    if member_size.is_none() {
        return container_empty(py, "cpio_invalid_filesize");
    }
    if mode.is_none() {
        return container_empty(py, "cpio_invalid_mode");
    }
    if 110 + namesize.unwrap() > file_size {
        return container_empty(py, "cpio_name_out_of_range");
    }
    container_ok(py, "cpio", ".cpio", &["cpio:newc_magic", "cpio:hex_fields"])
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

fn parse_octal(field: &[u8]) -> Option<u64> {
    let text = field
        .iter()
        .copied()
        .take_while(|b| *b != 0)
        .collect::<Vec<_>>();
    let trimmed = std::str::from_utf8(&text).ok()?.trim();
    if trimmed.is_empty() {
        return Some(0);
    }
    u64::from_str_radix(trimmed, 8).ok()
}

fn parse_hex(field: &[u8]) -> Option<u64> {
    std::str::from_utf8(field).ok().and_then(|s| u64::from_str_radix(s, 16).ok())
}

fn tar_checksum(header: &[u8]) -> u64 {
    header[..148].iter().map(|b| *b as u64).sum::<u64>()
        + 32 * 8
        + header[156..].iter().map(|b| *b as u64).sum::<u64>()
}

fn padding_for_size(size: u64) -> u64 {
    let remainder = size % TAR_BLOCK_SIZE as u64;
    if remainder == 0 {
        0
    } else {
        TAR_BLOCK_SIZE as u64 - remainder
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
