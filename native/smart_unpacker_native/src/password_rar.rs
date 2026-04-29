use crate::password_input::{parse_ranges, read_prefix_from_ranges};
use aes::cipher::{block_padding::NoPadding, BlockModeDecrypt, KeyIvInit};
use aes::Aes128;
use cbc::Decryptor;
use hmac::{Hmac, Mac};
use pyo3::prelude::*;
use pyo3::types::{PyDict, PyList};
use sha1::{Digest, Sha1};
use sha2::Sha256;
use std::fs::File;
use std::io::Read;

const RAR4_SIGNATURE: &[u8] = b"Rar!\x1a\x07\x00";
const RAR5_SIGNATURE: &[u8] = b"Rar!\x1a\x07\x01\x00";
const MAX_RAR_PREFIX_SCAN: usize = 1024 * 1024;
const RAR3_KDF_ITERATIONS: u32 = 0x40000;
const RAR4_MIN_HEADER_SIZE: usize = 7;
const RAR4_HP_DECRYPT_LIMIT: usize = 4096;

type HmacSha256 = Hmac<Sha256>;
type Aes128CbcDecryptor = Decryptor<Aes128>;

#[pyfunction]
pub(crate) fn rar_fast_verify_passwords(
    py: Python<'_>,
    archive_path: String,
    passwords: &Bound<'_, PyList>,
) -> PyResult<Py<PyAny>> {
    let candidates = passwords
        .iter()
        .map(|item| item.extract::<String>())
        .collect::<PyResult<Vec<_>>>()?;
    let mut file = File::open(&archive_path)?;
    let mut data = vec![0u8; MAX_RAR_PREFIX_SCAN];
    let len = file.read(&mut data)?;
    data.truncate(len);

    if data.starts_with(RAR5_SIGNATURE) {
        return verify_rar5(py, &data, &candidates);
    }
    if data.starts_with(RAR4_SIGNATURE) {
        return verify_rar4(py, &data, &candidates);
    }
    if data.starts_with(b"Rar!") {
        return status(
            py,
            "damaged",
            -1,
            0,
            "rar signature is incomplete or unknown",
        );
    }
    status(py, "unsupported_method", -1, 0, "rar signature not found")
}

#[pyfunction]
pub(crate) fn rar_fast_verify_passwords_from_ranges(
    py: Python<'_>,
    ranges: &Bound<'_, PyList>,
    passwords: &Bound<'_, PyList>,
) -> PyResult<Py<PyAny>> {
    let candidates = passwords
        .iter()
        .map(|item| item.extract::<String>())
        .collect::<PyResult<Vec<_>>>()?;
    let parsed = parse_ranges(ranges)?;
    let data = read_prefix_from_ranges(&parsed, MAX_RAR_PREFIX_SCAN)?;
    if data.starts_with(RAR5_SIGNATURE) {
        return verify_rar5(py, &data, &candidates);
    }
    if data.starts_with(RAR4_SIGNATURE) {
        return verify_rar4(py, &data, &candidates);
    }
    if data.starts_with(b"Rar!") {
        return status(
            py,
            "damaged",
            -1,
            0,
            "rar signature is incomplete or unknown",
        );
    }
    status(py, "unsupported_method", -1, 0, "rar signature not found")
}

fn verify_rar4(py: Python<'_>, data: &[u8], candidates: &[String]) -> PyResult<Py<PyAny>> {
    let payload = &data[RAR4_SIGNATURE.len()..];
    if parse_rar4_plain_header(payload).is_some() {
        return status(
            py,
            "unknown_need_fallback",
            -1,
            0,
            "rar3/rar4 headers are not encrypted; fast verifier only supports -hp encrypted headers",
        );
    }
    if payload.len() < 8 + 16 {
        return status(
            py,
            "unknown_need_fallback",
            -1,
            0,
            "rar3/rar4 encrypted header data is too short for fast verification",
        );
    }

    let mut salt = [0u8; 8];
    salt.copy_from_slice(&payload[..8]);
    let encrypted = &payload[8..];
    let decrypt_len = encrypted.len().min(RAR4_HP_DECRYPT_LIMIT) & !0x0f;
    if decrypt_len == 0 {
        return status(
            py,
            "unknown_need_fallback",
            -1,
            0,
            "rar3/rar4 encrypted header data has no complete AES block",
        );
    }
    let encrypted_prefix = &encrypted[..decrypt_len];

    for (index, password) in candidates.iter().enumerate() {
        if rar3_hp_password_matches(password, &salt, encrypted_prefix) {
            return status(
                py,
                "match",
                index as i32,
                (index + 1) as i32,
                "rar3/rar4 -hp encrypted header matched",
            );
        }
    }
    status(
        py,
        "no_match",
        -1,
        candidates.len() as i32,
        "rar3/rar4 -hp encrypted header did not match",
    )
}

fn rar3_hp_password_matches(password: &str, salt: &[u8; 8], encrypted_prefix: &[u8]) -> bool {
    let (key, iv) = derive_rar3_key_iv(password, salt);
    let mut plaintext = encrypted_prefix.to_vec();
    let decrypted = match Aes128CbcDecryptor::new(&key.into(), &iv.into())
        .decrypt_padded::<NoPadding>(&mut plaintext)
    {
        Ok(decrypted) => decrypted,
        Err(_) => return false,
    };
    parse_rar4_plain_header(decrypted).is_some()
}

fn derive_rar3_key_iv(password: &str, salt: &[u8; 8]) -> ([u8; 16], [u8; 16]) {
    let mut password_bytes = Vec::with_capacity(password.len() * 2 + salt.len());
    for unit in password.encode_utf16() {
        password_bytes.extend_from_slice(&unit.to_le_bytes());
    }
    password_bytes.extend_from_slice(salt);

    let mut sha = Sha1::new();
    let mut iv = [0u8; 16];
    for i in 0..RAR3_KDF_ITERATIONS {
        sha.update(&password_bytes);
        sha.update(&i.to_le_bytes()[..3]);
        if i & 0x3fff == 0 {
            let digest = sha.clone().finalize();
            iv[(i / 0x4000) as usize] = digest[19];
        }
    }
    let digest = sha.finalize();
    let mut key = [0u8; 16];
    for chunk in 0..4 {
        let src = chunk * 4;
        key[src] = digest[src + 3];
        key[src + 1] = digest[src + 2];
        key[src + 2] = digest[src + 1];
        key[src + 3] = digest[src];
    }
    (key, iv)
}

fn parse_rar4_plain_header(data: &[u8]) -> Option<Rar4Header> {
    if data.len() < RAR4_MIN_HEADER_SIZE {
        return None;
    }
    let stored_crc = u16::from_le_bytes([data[0], data[1]]);
    let header_type = data[2];
    if !(0x72..=0x7b).contains(&header_type) {
        return None;
    }
    let header_size = u16::from_le_bytes([data[5], data[6]]) as usize;
    if !(RAR4_MIN_HEADER_SIZE..=data.len()).contains(&header_size) {
        return None;
    }
    let computed_crc = (crc32(&data[2..header_size]) & 0xffff) as u16;
    if computed_crc != stored_crc {
        return None;
    }
    Some(Rar4Header {
        header_type,
        header_size,
    })
}

struct Rar4Header {
    #[allow(dead_code)]
    header_type: u8,
    #[allow(dead_code)]
    header_size: usize,
}

fn verify_rar5(py: Python<'_>, data: &[u8], candidates: &[String]) -> PyResult<Py<PyAny>> {
    let Some(header) = find_rar5_encryption_header(data) else {
        return status(
            py,
            "unknown_need_fallback",
            -1,
            0,
            "rar5 password check header not found",
        );
    };
    if !header.has_password_check {
        return status(
            py,
            "unknown_need_fallback",
            -1,
            0,
            "rar5 encryption header has no password check",
        );
    }
    for (index, password) in candidates.iter().enumerate() {
        if rar5_password_check_matches(password, &header) {
            return status(
                py,
                "match",
                index as i32,
                (index + 1) as i32,
                "rar5 password check matched",
            );
        }
    }
    status(
        py,
        "no_match",
        -1,
        candidates.len() as i32,
        "rar5 password check did not match",
    )
}

struct Rar5EncryptionHeader {
    lg2_count: u8,
    salt: Vec<u8>,
    has_password_check: bool,
    password_check: Vec<u8>,
}

fn find_rar5_encryption_header(data: &[u8]) -> Option<Rar5EncryptionHeader> {
    let mut offset = RAR5_SIGNATURE.len();
    while offset + 6 <= data.len() {
        let stored_crc = le_u32(data, offset)?;
        let crc_start = offset + 4;
        let (header_size, after_size) = read_vint(data, crc_start)?;
        let header_size_vint_len = after_size.checked_sub(crc_start)?;
        let total_crc_bytes = header_size_vint_len.checked_add(header_size as usize)?;
        let crc_end = crc_start.checked_add(total_crc_bytes)?;
        if crc_end > data.len() {
            return None;
        }
        if crc32(&data[crc_start..crc_end]) != stored_crc {
            return None;
        }
        let (header_type, after_type) = read_vint(data, after_size)?;
        let (header_flags, mut cursor) = read_vint(data, after_type)?;
        if header_flags & 0x0001 != 0 {
            let (_, next) = read_vint(data, cursor)?;
            cursor = next;
        }
        let data_area_size = if header_flags & 0x0002 != 0 {
            let (value, next) = read_vint(data, cursor)?;
            cursor = next;
            value
        } else {
            0
        };
        if header_type == 4 {
            return parse_rar5_encryption_body(data, cursor, crc_end);
        }
        offset = crc_end.checked_add(data_area_size as usize)?;
    }
    None
}

fn parse_rar5_encryption_body(
    data: &[u8],
    mut offset: usize,
    end: usize,
) -> Option<Rar5EncryptionHeader> {
    let (version, next) = read_vint(data, offset)?;
    if version != 0 {
        return None;
    }
    offset = next;
    let (flags, next) = read_vint(data, offset)?;
    offset = next;
    let lg2_count = *data.get(offset)?;
    offset += 1;
    if offset + 16 > end {
        return None;
    }
    let salt = data[offset..offset + 16].to_vec();
    offset += 16;
    let has_password_check = flags & 0x0001 != 0;
    let password_check = if has_password_check {
        if offset + 12 > end {
            return None;
        }
        data[offset..offset + 8].to_vec()
    } else {
        Vec::new()
    };
    Some(Rar5EncryptionHeader {
        lg2_count,
        salt,
        has_password_check,
        password_check,
    })
}

fn rar5_password_check_matches(password: &str, header: &Rar5EncryptionHeader) -> bool {
    if !header.has_password_check || header.password_check.len() != 8 {
        return false;
    }
    let iterations = 1u32.checked_shl(header.lg2_count as u32).unwrap_or(0);
    if iterations == 0 {
        return false;
    }
    let password_bytes = password.as_bytes();
    let mut salt_extended = header.salt.clone();
    salt_extended.extend_from_slice(&[0, 0, 0, 1]);

    let mut mac = match HmacSha256::new_from_slice(password_bytes) {
        Ok(mac) => mac,
        Err(_) => return false,
    };
    mac.update(&salt_extended);
    let mut block: [u8; 32] = mac.finalize().into_bytes().into();
    let mut final_hash = block;
    let round_counts = [iterations, 17, 17];
    let mut result2 = [0u8; 32];
    for (round_index, count) in round_counts.iter().enumerate() {
        for _ in 1..*count {
            let mut mac = match HmacSha256::new_from_slice(password_bytes) {
                Ok(mac) => mac,
                Err(_) => return false,
            };
            mac.update(&block);
            block = mac.finalize().into_bytes().into();
            for (f, b) in final_hash.iter_mut().zip(block.iter()) {
                *f ^= *b;
            }
        }
        if round_index == 2 {
            result2 = final_hash;
        }
    }
    let mut derived_check = [0u8; 8];
    for (index, byte) in result2.iter().enumerate() {
        derived_check[index % 8] ^= *byte;
    }
    derived_check == header.password_check.as_slice()
}

fn status(
    py: Python<'_>,
    status: &str,
    matched_index: i32,
    attempts: i32,
    message: &str,
) -> PyResult<Py<PyAny>> {
    let result = PyDict::new(py);
    result.set_item("status", status)?;
    result.set_item("matched_index", matched_index)?;
    result.set_item("attempts", attempts)?;
    result.set_item("message", message)?;
    Ok(result.into())
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

fn le_u32(bytes: &[u8], offset: usize) -> Option<u32> {
    Some(u32::from_le_bytes([
        *bytes.get(offset)?,
        *bytes.get(offset + 1)?,
        *bytes.get(offset + 2)?,
        *bytes.get(offset + 3)?,
    ]))
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
