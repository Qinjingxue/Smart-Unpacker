use crate::password_input::{parse_ranges, ranges_total_len, VirtualRangeReader};
use pbkdf2::pbkdf2_hmac;
use pyo3::prelude::*;
use pyo3::types::{PyDict, PyList};
use sha1::Sha1;
use std::fs::File;
use std::io::{Read, Seek, SeekFrom};

const ZIP_LOCAL: &[u8] = b"PK\x03\x04";
const MAX_PREFIX_SCAN: usize = 1024 * 1024;

#[pyfunction]
pub(crate) fn zip_fast_verify_passwords(
    py: Python<'_>,
    archive_path: String,
    passwords: &Bound<'_, PyList>,
) -> PyResult<Py<PyAny>> {
    let candidates = passwords
        .iter()
        .map(|item| item.extract::<String>())
        .collect::<PyResult<Vec<_>>>()?;

    let mut file = File::open(&archive_path)?;
    let metadata = file.metadata()?;
    verify_zip_stream(py, &mut file, metadata.len(), &candidates)
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
    let mut reader = VirtualRangeReader::new(parsed);
    verify_zip_stream(py, &mut reader, total_len, &candidates)
}

fn verify_zip_stream<R: Read + Seek>(
    py: Python<'_>,
    file: &mut R,
    total_len: u64,
    candidates: &[String],
) -> PyResult<Py<PyAny>> {
    let result = PyDict::new(py);
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

    if !header.encrypted {
        result.set_item("status", "unsupported_method")?;
        result.set_item("matched_index", -1)?;
        result.set_item("attempts", 0)?;
        result.set_item("message", "zip entry is not encrypted")?;
        return Ok(result.into());
    }
    if header.method == 99 {
        return verify_winzip_aes(py, file, &candidates, &header);
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

    for (index, password) in candidates.iter().enumerate() {
        if zipcrypto_header_matches(password.as_bytes(), &encryption_header, header.check_byte) {
            result.set_item("status", "match")?;
            result.set_item("matched_index", index as i32)?;
            result.set_item("attempts", (index + 1) as i32)?;
            result.set_item("message", "zipcrypto password header matched")?;
            return Ok(result.into());
        }
    }

    result.set_item("status", "no_match")?;
    result.set_item("matched_index", -1)?;
    result.set_item("attempts", candidates.len() as i32)?;
    result.set_item("message", "zipcrypto password header did not match")?;
    Ok(result.into())
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
    let Some((salt_len, key_len)) = aes_lengths(strength) else {
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
    let salt = &salt_and_verifier[..salt_len];
    let verifier = &salt_and_verifier[salt_len..];
    for (index, password) in candidates.iter().enumerate() {
        if winzip_aes_verifier_matches(password.as_bytes(), salt, verifier, key_len) {
            result.set_item("status", "match")?;
            result.set_item("matched_index", index as i32)?;
            result.set_item("attempts", (index + 1) as i32)?;
            result.set_item("message", "winzip aes password verifier matched")?;
            return Ok(result.into());
        }
    }
    result.set_item("status", "no_match")?;
    result.set_item("matched_index", -1)?;
    result.set_item("attempts", candidates.len() as i32)?;
    result.set_item("message", "winzip aes password verifier did not match")?;
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
