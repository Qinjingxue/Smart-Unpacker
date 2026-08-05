use crate::io::reader::ManagedReader;
use crate::password::input::{
    parse_ranges, parse_volumes, ranges_total_len, VirtualRangeReader, VolumeSet,
};
use pbkdf2::pbkdf2_hmac;
use pyo3::prelude::*;
use pyo3::types::{PyDict, PyList};
use rayon::prelude::*;
use sha1::Sha1;
use std::io::{Read, Seek, SeekFrom};

const ZIP_LOCAL: &[u8] = b"PK\x03\x04";
const ZIP_CENTRAL: &[u8] = b"PK\x01\x02";
const ZIP_EOCD: &[u8] = b"PK\x05\x06";
const MAX_PREFIX_SCAN: usize = 1024 * 1024;
const MAX_EOCD_SCAN: usize = 65_557;
const MAX_CENTRAL_SCAN: u64 = 16 * 1024 * 1024;
const AES_PARALLEL_PASSWORD_THRESHOLD: usize = 4;
const ZIPCRYPTO_PARALLEL_PASSWORD_THRESHOLD: usize = 256;

#[pyfunction]
pub(crate) fn zip_fast_verify_passwords(
    py: Python<'_>,
    archive_path: String,
    passwords: &Bound<'_, PyList>,
) -> PyResult<Py<PyAny>> {
    let reader = ManagedReader::open(&archive_path)?;
    zip_fast_verify_passwords_with_reader(py, &reader, passwords)
}

pub(crate) fn zip_fast_verify_passwords_with_reader(
    py: Python<'_>,
    reader: &ManagedReader,
    passwords: &Bound<'_, PyList>,
) -> PyResult<Py<PyAny>> {
    let candidates = passwords
        .iter()
        .map(|item| item.extract::<String>())
        .collect::<PyResult<Vec<_>>>()?;

    let total_len = reader.len();
    verify_zip_stream(py, &mut reader.cursor(), total_len, &candidates)
}

#[pyfunction]
pub(crate) fn zip_fast_verify_passwords_from_ranges(
    py: Python<'_>,
    ranges: &Bound<'_, PyList>,
    passwords: &Bound<'_, PyList>,
) -> PyResult<Py<PyAny>> {
    let candidates = passwords
        .iter()
        .map(|item| item.extract::<String>())
        .collect::<PyResult<Vec<_>>>()?;
    let parsed = parse_ranges(ranges)?;
    let total_len = ranges_total_len(&parsed);
    let mut reader = VirtualRangeReader::new(parsed.into());
    verify_zip_stream(py, &mut reader, total_len, &candidates)
}

#[pyfunction]
pub(crate) fn zip_fast_verify_passwords_from_volumes(
    py: Python<'_>,
    parts: &Bound<'_, PyList>,
    passwords: &Bound<'_, PyList>,
) -> PyResult<Py<PyAny>> {
    let candidates = passwords
        .iter()
        .map(|item| item.extract::<String>())
        .collect::<PyResult<Vec<_>>>()?;
    let volumes = VolumeSet::new(parse_volumes(parts)?);
    verify_zip_volumes(py, &volumes, &candidates)
}

fn verify_zip_volumes(
    py: Python<'_>,
    volumes: &VolumeSet,
    candidates: &[String],
) -> PyResult<Py<PyAny>> {
    let tail = volumes.read_last_tail(MAX_EOCD_SCAN)?;
    let Some(eocd_offset) = find_last_signature(&tail, ZIP_EOCD) else {
        return simple_status(
            py,
            "unknown_need_fallback",
            0,
            "zip EOCD was not found in terminal volume",
        );
    };
    if eocd_offset + 22 > tail.len() {
        return simple_status(py, "damaged", 0, "zip EOCD is incomplete");
    }
    let disk_number = le_u16(&tail, eocd_offset + 4).unwrap_or(u16::MAX) as usize;
    let central_disk = le_u16(&tail, eocd_offset + 6).unwrap_or(u16::MAX) as usize;
    let total_entries = le_u16(&tail, eocd_offset + 10).unwrap_or(u16::MAX) as usize;
    let central_size = le_u32(&tail, eocd_offset + 12).unwrap_or(u32::MAX) as u64;
    let central_offset = le_u32(&tail, eocd_offset + 16).unwrap_or(u32::MAX) as u64;
    if disk_number + 1 != volumes.len() {
        return simple_status(
            py,
            "unknown_need_fallback",
            0,
            "zip volume set is incomplete or misnumbered",
        );
    }
    if total_entries == u16::MAX as usize
        || central_size == u32::MAX as u64
        || central_offset == u32::MAX as u64
    {
        return simple_status(
            py,
            "unknown_need_fallback",
            0,
            "zip64 spanned password probing is not supported",
        );
    }
    if central_size > MAX_CENTRAL_SCAN {
        return simple_status(
            py,
            "unknown_need_fallback",
            0,
            "zip central directory exceeds bounded probe budget",
        );
    }

    let mut disk = central_disk;
    let mut offset = central_offset;
    for _ in 0..total_entries {
        let fixed = volumes.read_disk_spanning(disk, offset, 46)?;
        if fixed.len() < 46 || &fixed[..4] != ZIP_CENTRAL {
            return simple_status(py, "damaged", 0, "zip central directory entry is malformed");
        }
        let flags = le_u16(&fixed, 8).unwrap_or(0);
        let name_len = le_u16(&fixed, 28).unwrap_or(0) as u64;
        let extra_len = le_u16(&fixed, 30).unwrap_or(0) as u64;
        let comment_len = le_u16(&fixed, 32).unwrap_or(0) as u64;
        let entry_disk = le_u16(&fixed, 34).unwrap_or(u16::MAX) as usize;
        let local_offset = le_u32(&fixed, 42).unwrap_or(u32::MAX) as u64;
        if flags & 0x0001 != 0 {
            if entry_disk == u16::MAX as usize || local_offset == u32::MAX as u64 {
                return simple_status(
                    py,
                    "unknown_need_fallback",
                    0,
                    "zip64 encrypted entry location requires fallback",
                );
            }
            return verify_zip_volume_entry(py, volumes, entry_disk, local_offset, candidates);
        }
        let record_len = 46u64 + name_len + extra_len + comment_len;
        let Some(next) = volumes.advance_disk_offset(disk, offset, record_len) else {
            return simple_status(
                py,
                "damaged",
                0,
                "zip central directory crosses a missing volume",
            );
        };
        (disk, offset) = next;
    }
    simple_status(py, "unsupported_method", 0, "zip has no encrypted entries")
}

fn verify_zip_volume_entry(
    py: Python<'_>,
    volumes: &VolumeSet,
    disk: usize,
    local_offset: u64,
    candidates: &[String],
) -> PyResult<Py<PyAny>> {
    let fixed = volumes.read_disk_spanning(disk, local_offset, 30)?;
    if fixed.len() < 30 || &fixed[..4] != ZIP_LOCAL {
        return simple_status(py, "damaged", 0, "zip local header link is invalid");
    }
    let flags = le_u16(&fixed, 6).unwrap_or(0);
    let method = le_u16(&fixed, 8).unwrap_or(0);
    let mod_time = le_u16(&fixed, 10).unwrap_or(0);
    let crc32 = le_u32(&fixed, 14).unwrap_or(0);
    let name_len = le_u16(&fixed, 26).unwrap_or(0) as u64;
    let extra_len = le_u16(&fixed, 28).unwrap_or(0) as u64;
    let Some((variable_disk, variable_offset)) =
        volumes.advance_disk_offset(disk, local_offset, 30)
    else {
        return simple_status(
            py,
            "damaged",
            0,
            "zip local header crosses a missing volume",
        );
    };
    let variable = volumes.read_disk_spanning(
        variable_disk,
        variable_offset,
        (name_len + extra_len) as usize,
    )?;
    if variable.len() != (name_len + extra_len) as usize {
        return simple_status(
            py,
            "damaged",
            0,
            "zip local header fields cross a missing volume",
        );
    }
    let extra = &variable[name_len as usize..];
    let data_delta = 30 + name_len + extra_len;
    let Some((data_disk, data_offset)) =
        volumes.advance_disk_offset(disk, local_offset, data_delta)
    else {
        return simple_status(
            py,
            "damaged",
            0,
            "zip encrypted data starts beyond available volumes",
        );
    };
    if method == 99 {
        let Some(strength) = parse_winzip_aes_strength(extra) else {
            return simple_status(
                py,
                "unsupported_method",
                0,
                "winzip AES extra field not found",
            );
        };
        let Some((salt_len, _)) = aes_lengths(strength) else {
            return simple_status(
                py,
                "unsupported_method",
                0,
                "unsupported winzip AES strength",
            );
        };
        let material = volumes.read_disk_spanning(data_disk, data_offset, salt_len + 2)?;
        return verify_winzip_aes_material(py, candidates, strength, &material);
    }
    let material = volumes.read_disk_spanning(data_disk, data_offset, 12)?;
    if material.len() != 12 {
        return simple_status(py, "damaged", 0, "zip encryption header is incomplete");
    }
    let mut header = [0u8; 12];
    header.copy_from_slice(&material);
    let check_byte = if flags & 0x0008 != 0 {
        (mod_time >> 8) as u8
    } else {
        (crc32 >> 24) as u8
    };
    verify_zipcrypto_material(py, candidates, &header, check_byte)
}

fn verify_zip_stream<R: Read + Seek>(
    py: Python<'_>,
    file: &mut R,
    total_len: u64,
    candidates: &[String],
) -> PyResult<Py<PyAny>> {
    let result = PyDict::new(py);
    if let Ok(Some(header)) = locate_encrypted_entry_from_central_directory(file, total_len) {
        return verify_zip_header(py, file, candidates, &header);
    }
    // Central-directory probing leaves the shared/range reader near the end.
    // Rewind before the bounded local-header fallback; otherwise an
    // unencrypted ZIP (or an inconclusive central scan) reads from EOF and
    // leaks `failed to fill whole buffer` into the watch completion path.
    file.seek(SeekFrom::Start(0))?;
    let scan_len = total_len.min(MAX_PREFIX_SCAN as u64) as usize;
    let mut prefix = vec![0u8; scan_len];
    file.read_exact(&mut prefix)?;

    let Some(local_offset) = find_signature(&prefix, ZIP_LOCAL) else {
        result.set_item("status", "unsupported_method")?;
        result.set_item("matched_index", -1)?;
        result.set_item("attempts", 0)?;
        result.set_item("message", "zip local header not found in prefix")?;
        return Ok(result.into());
    };

    let Some(header) = parse_local_header(&prefix, local_offset) else {
        result.set_item("status", "damaged")?;
        result.set_item("matched_index", -1)?;
        result.set_item("attempts", 0)?;
        result.set_item("message", "zip local header is incomplete or malformed")?;
        return Ok(result.into());
    };

    verify_zip_header(py, file, candidates, &header)
}

fn verify_zip_header<R: Read + Seek>(
    py: Python<'_>,
    file: &mut R,
    candidates: &[String],
    header: &ZipLocalHeader,
) -> PyResult<Py<PyAny>> {
    let result = PyDict::new(py);
    if !header.encrypted {
        result.set_item("status", "unsupported_method")?;
        result.set_item("matched_index", -1)?;
        result.set_item("attempts", 0)?;
        result.set_item("message", "zip entry is not encrypted")?;
        return Ok(result.into());
    }
    if header.method == 99 {
        return verify_winzip_aes(py, file, candidates, header);
    }

    let mut encryption_header = [0u8; 12];
    file.seek(SeekFrom::Start(header.data_offset))?;
    if file.read_exact(&mut encryption_header).is_err() {
        result.set_item("status", "damaged")?;
        result.set_item("matched_index", -1)?;
        result.set_item("attempts", 0)?;
        result.set_item("message", "zip encryption header is incomplete")?;
        return Ok(result.into());
    }

    verify_zipcrypto_material(py, candidates, &encryption_header, header.check_byte)
}

struct ZipLocalHeader {
    encrypted: bool,
    method: u16,
    aes_strength: Option<u8>,
    check_byte: u8,
    data_offset: u64,
}

fn parse_local_header(bytes: &[u8], offset: usize) -> Option<ZipLocalHeader> {
    if offset.checked_add(30)? > bytes.len() {
        return None;
    }
    let flags = le_u16(bytes, offset + 6)?;
    let method = le_u16(bytes, offset + 8)?;
    let mod_time = le_u16(bytes, offset + 10)?;
    let crc32 = le_u32(bytes, offset + 14)?;
    let name_len = le_u16(bytes, offset + 26)? as usize;
    let extra_len = le_u16(bytes, offset + 28)? as usize;
    let extra_offset = offset.checked_add(30)?.checked_add(name_len)?;
    let data_offset = offset
        .checked_add(30)?
        .checked_add(name_len)?
        .checked_add(extra_len)?;
    if data_offset > bytes.len() {
        return None;
    }
    let aes_strength = parse_winzip_aes_strength(bytes.get(extra_offset..data_offset)?);
    let check_byte = if flags & 0x0008 != 0 {
        (mod_time >> 8) as u8
    } else {
        (crc32 >> 24) as u8
    };
    Some(ZipLocalHeader {
        encrypted: flags & 0x0001 != 0,
        method,
        aes_strength,
        check_byte,
        data_offset: data_offset as u64,
    })
}

fn verify_winzip_aes(
    py: Python<'_>,
    file: &mut (impl Read + Seek),
    candidates: &[String],
    header: &ZipLocalHeader,
) -> PyResult<Py<PyAny>> {
    let result = PyDict::new(py);
    let Some(strength) = header.aes_strength else {
        result.set_item("status", "unsupported_method")?;
        result.set_item("matched_index", -1)?;
        result.set_item("attempts", 0)?;
        result.set_item("message", "winzip aes extra field not found")?;
        return Ok(result.into());
    };
    let Some((salt_len, _key_len)) = aes_lengths(strength) else {
        result.set_item("status", "unsupported_method")?;
        result.set_item("matched_index", -1)?;
        result.set_item("attempts", 0)?;
        result.set_item("message", "unsupported winzip aes strength")?;
        return Ok(result.into());
    };
    let mut salt_and_verifier = vec![0u8; salt_len + 2];
    file.seek(SeekFrom::Start(header.data_offset))?;
    if file.read_exact(&mut salt_and_verifier).is_err() {
        result.set_item("status", "damaged")?;
        result.set_item("matched_index", -1)?;
        result.set_item("attempts", 0)?;
        result.set_item(
            "message",
            "winzip aes salt or password verifier is incomplete",
        )?;
        return Ok(result.into());
    }
    verify_winzip_aes_material(py, candidates, strength, &salt_and_verifier)
}

fn locate_encrypted_entry_from_central_directory<R: Read + Seek>(
    file: &mut R,
    total_len: u64,
) -> Result<Option<ZipLocalHeader>, ()> {
    let tail_len = MAX_EOCD_SCAN.min(total_len as usize);
    let tail_start = total_len.saturating_sub(tail_len as u64);
    let mut tail = vec![0u8; tail_len];
    file.seek(SeekFrom::Start(tail_start)).map_err(|_| ())?;
    file.read_exact(&mut tail).map_err(|_| ())?;
    let eocd = find_last_signature(&tail, ZIP_EOCD).ok_or(())?;
    if eocd + 22 > tail.len()
        || le_u16(&tail, eocd + 4) != Some(0)
        || le_u16(&tail, eocd + 6) != Some(0)
    {
        return Err(());
    }
    let total_entries = le_u16(&tail, eocd + 10).ok_or(())? as usize;
    let central_size = le_u32(&tail, eocd + 12).ok_or(())? as u64;
    let central_offset = le_u32(&tail, eocd + 16).ok_or(())? as u64;
    if total_entries == u16::MAX as usize
        || central_size == u32::MAX as u64
        || central_offset == u32::MAX as u64
        || central_size > MAX_CENTRAL_SCAN
    {
        return Err(());
    }
    let mut cursor = central_offset;
    for _ in 0..total_entries {
        let mut fixed = [0u8; 46];
        file.seek(SeekFrom::Start(cursor)).map_err(|_| ())?;
        file.read_exact(&mut fixed).map_err(|_| ())?;
        if &fixed[..4] != ZIP_CENTRAL {
            return Err(());
        }
        let flags = le_u16(&fixed, 8).ok_or(())?;
        let name_len = le_u16(&fixed, 28).ok_or(())? as u64;
        let extra_len = le_u16(&fixed, 30).ok_or(())? as u64;
        let comment_len = le_u16(&fixed, 32).ok_or(())? as u64;
        if flags & 0x0001 != 0 {
            let local_offset = le_u32(&fixed, 42).ok_or(())? as u64;
            if local_offset == u32::MAX as u64 {
                return Err(());
            }
            let mut local_fixed = [0u8; 30];
            file.seek(SeekFrom::Start(local_offset)).map_err(|_| ())?;
            file.read_exact(&mut local_fixed).map_err(|_| ())?;
            if &local_fixed[..4] != ZIP_LOCAL {
                return Err(());
            }
            let local_name_len = le_u16(&local_fixed, 26).ok_or(())? as usize;
            let local_extra_len = le_u16(&local_fixed, 28).ok_or(())? as usize;
            let mut local = Vec::with_capacity(30 + local_name_len + local_extra_len);
            local.extend_from_slice(&local_fixed);
            local.resize(30 + local_name_len + local_extra_len, 0);
            file.read_exact(&mut local[30..]).map_err(|_| ())?;
            let mut header = parse_local_header(&local, 0).ok_or(())?;
            header.data_offset = header.data_offset.saturating_add(local_offset);
            return Ok(Some(header));
        }
        cursor = cursor
            .checked_add(46 + name_len + extra_len + comment_len)
            .ok_or(())?;
    }
    Ok(None)
}

fn verify_winzip_aes_material(
    py: Python<'_>,
    candidates: &[String],
    strength: u8,
    salt_and_verifier: &[u8],
) -> PyResult<Py<PyAny>> {
    let result = PyDict::new(py);
    let Some((salt_len, key_len)) = aes_lengths(strength) else {
        return simple_status(
            py,
            "unsupported_method",
            0,
            "unsupported winzip AES strength",
        );
    };
    if salt_and_verifier.len() != salt_len + 2 {
        return simple_status(
            py,
            "damaged",
            0,
            "winzip AES salt or password verifier is incomplete",
        );
    }
    let salt = &salt_and_verifier[..salt_len];
    let verifier = &salt_and_verifier[salt_len..];
    let mut matched_indices = if candidates.len() >= AES_PARALLEL_PASSWORD_THRESHOLD {
        candidates
            .par_iter()
            .enumerate()
            .filter_map(|(index, password)| {
                winzip_aes_verifier_matches(password.as_bytes(), salt, verifier, key_len)
                    .then_some(index as i32)
            })
            .collect::<Vec<_>>()
    } else {
        candidates
            .iter()
            .enumerate()
            .filter_map(|(index, password)| {
                winzip_aes_verifier_matches(password.as_bytes(), salt, verifier, key_len)
                    .then_some(index as i32)
            })
            .collect::<Vec<_>>()
    };
    matched_indices.sort_unstable();
    if let Some(first) = matched_indices.first().copied() {
        result.set_item("status", "match")?;
        result.set_item("matched_index", first)?;
        result.set_item("matched_indices", matched_indices)?;
        result.set_item("attempts", candidates.len() as i32)?;
        result.set_item("match_evidence", "winzip_aes_password_verifier")?;
        result.set_item("message", "winzip aes password verifiers matched")?;
        return Ok(result.into());
    }
    result.set_item("status", "no_match")?;
    result.set_item("matched_index", -1)?;
    result.set_item("attempts", candidates.len() as i32)?;
    result.set_item("message", "winzip aes password verifier did not match")?;
    Ok(result.into())
}

fn verify_zipcrypto_material(
    py: Python<'_>,
    candidates: &[String],
    encryption_header: &[u8; 12],
    check_byte: u8,
) -> PyResult<Py<PyAny>> {
    let result = PyDict::new(py);
    let mut matched_indices = if candidates.len() >= ZIPCRYPTO_PARALLEL_PASSWORD_THRESHOLD {
        candidates
            .par_iter()
            .enumerate()
            .filter_map(|(index, password)| {
                zipcrypto_header_matches(password.as_bytes(), encryption_header, check_byte)
                    .then_some(index as i32)
            })
            .collect::<Vec<_>>()
    } else {
        candidates
            .iter()
            .enumerate()
            .filter_map(|(index, password)| {
                zipcrypto_header_matches(password.as_bytes(), encryption_header, check_byte)
                    .then_some(index as i32)
            })
            .collect::<Vec<_>>()
    };
    matched_indices.sort_unstable();
    if let Some(first) = matched_indices.first().copied() {
        result.set_item("status", "match")?;
        result.set_item("matched_index", first)?;
        result.set_item("matched_indices", matched_indices)?;
        result.set_item("attempts", candidates.len() as i32)?;
        result.set_item("match_evidence", "zipcrypto_header_byte")?;
        result.set_item("message", "zipcrypto password headers matched")?;
        return Ok(result.into());
    }
    result.set_item("status", "no_match")?;
    result.set_item("matched_index", -1)?;
    result.set_item("attempts", candidates.len() as i32)?;
    result.set_item("message", "zipcrypto password header did not match")?;
    Ok(result.into())
}

fn parse_winzip_aes_strength(extra: &[u8]) -> Option<u8> {
    let mut offset = 0usize;
    while offset.checked_add(4)? <= extra.len() {
        let header_id = le_u16(extra, offset)?;
        let data_size = le_u16(extra, offset + 2)? as usize;
        let data_offset = offset.checked_add(4)?;
        let next = data_offset.checked_add(data_size)?;
        if next > extra.len() {
            return None;
        }
        if header_id == 0x9901 && data_size >= 7 {
            if extra.get(data_offset + 2..data_offset + 4)? != b"AE" {
                return None;
            }
            return extra.get(data_offset + 4).copied();
        }
        offset = next;
    }
    None
}

fn aes_lengths(strength: u8) -> Option<(usize, usize)> {
    match strength {
        1 => Some((8, 16)),
        2 => Some((12, 24)),
        3 => Some((16, 32)),
        _ => None,
    }
}

fn winzip_aes_verifier_matches(
    password: &[u8],
    salt: &[u8],
    verifier: &[u8],
    key_len: usize,
) -> bool {
    let mut derived = vec![0u8; key_len * 2 + 2];
    pbkdf2_hmac::<Sha1>(password, salt, 1000, &mut derived);
    &derived[key_len * 2..key_len * 2 + 2] == verifier
}

fn zipcrypto_header_matches(password: &[u8], encrypted_header: &[u8; 12], expected: u8) -> bool {
    let mut state = ZipCryptoState::new();
    for byte in password {
        state.update_keys(*byte);
    }
    let mut plain = [0u8; 12];
    for (idx, encrypted) in encrypted_header.iter().enumerate() {
        let decrypted = encrypted ^ state.decrypt_byte();
        state.update_keys(decrypted);
        plain[idx] = decrypted;
    }
    plain[11] == expected
}

struct ZipCryptoState {
    key0: u32,
    key1: u32,
    key2: u32,
}

impl ZipCryptoState {
    fn new() -> Self {
        Self {
            key0: 0x1234_5678,
            key1: 0x2345_6789,
            key2: 0x3456_7890,
        }
    }

    fn update_keys(&mut self, byte: u8) {
        self.key0 = crc32_update(self.key0, byte);
        self.key1 = self.key1.wrapping_add(self.key0 & 0xff);
        self.key1 = self.key1.wrapping_mul(134775813).wrapping_add(1);
        self.key2 = crc32_update(self.key2, (self.key1 >> 24) as u8);
    }

    fn decrypt_byte(&self) -> u8 {
        let temp = (self.key2 | 2) as u16;
        (((temp.wrapping_mul(temp ^ 1)) >> 8) & 0xff) as u8
    }
}

fn crc32_update(crc: u32, byte: u8) -> u32 {
    let mut value = crc ^ byte as u32;
    for _ in 0..8 {
        if value & 1 != 0 {
            value = (value >> 1) ^ 0xedb8_8320;
        } else {
            value >>= 1;
        }
    }
    value
}

fn find_signature(bytes: &[u8], signature: &[u8]) -> Option<usize> {
    bytes
        .windows(signature.len())
        .position(|window| window == signature)
}

fn find_last_signature(bytes: &[u8], signature: &[u8]) -> Option<usize> {
    bytes
        .windows(signature.len())
        .rposition(|window| window == signature)
}

fn simple_status(
    py: Python<'_>,
    status: &str,
    attempts: i32,
    message: &str,
) -> PyResult<Py<PyAny>> {
    let result = PyDict::new(py);
    result.set_item("status", status)?;
    result.set_item("matched_index", -1)?;
    result.set_item("attempts", attempts)?;
    result.set_item("message", message)?;
    Ok(result.into())
}

fn le_u16(bytes: &[u8], offset: usize) -> Option<u16> {
    Some(u16::from_le_bytes([
        *bytes.get(offset)?,
        *bytes.get(offset + 1)?,
    ]))
}

fn le_u32(bytes: &[u8], offset: usize) -> Option<u32> {
    Some(u32::from_le_bytes([
        *bytes.get(offset)?,
        *bytes.get(offset + 1)?,
        *bytes.get(offset + 2)?,
        *bytes.get(offset + 3)?,
    ]))
}
