use std::io::{Read, Seek, SeekFrom};

use crc32fast::hash as crc32;
use memchr::memmem;
use pyo3::prelude::*;
use pyo3::types::{PyDict, PyList};

use crate::io::reader::ManagedReader;

const SEVEN_ZIP: &[u8] = b"7z\xbc\xaf'\x1c";
const RAR4: &[u8] = b"Rar!\x1a\x07\x00";
const RAR5: &[u8] = b"Rar!\x1a\x07\x01\x00";
const ZIP_LOCAL: &[u8] = b"PK\x03\x04";
const ZIP_EOCD: &[u8] = b"PK\x05\x06";
const ZIP_EMPTY: &[u8] = b"PK\x05\x06";
const DEFAULT_PREFIX_LIMIT: usize = 1024 * 1024;
const DEFAULT_TAIL_LIMIT: usize = 65_557;

#[derive(Debug, Clone, Default)]
pub(crate) struct VolumeAnchor {
    pub(crate) path: String,
    pub(crate) size: u64,
    pub(crate) format: String,
    pub(crate) confidence: String,
    pub(crate) standalone: bool,
    pub(crate) multivolume: bool,
    pub(crate) anchor_roles: Vec<&'static str>,
    pub(crate) internal_volume_number: Option<u32>,
    pub(crate) structure_offset: Option<u64>,
    pub(crate) expected_logical_size: Option<u64>,
    pub(crate) continuation_from_previous: bool,
    pub(crate) continuation_to_next: bool,
    pub(crate) sfx: bool,
    pub(crate) evidence: Vec<&'static str>,
    pub(crate) error: String,
    pub(crate) bytes_read: u64,
}

impl VolumeAnchor {
    fn into_dict(self, py: Python<'_>) -> PyResult<Py<PyDict>> {
        let out = PyDict::new(py);
        out.set_item("path", self.path)?;
        out.set_item("size", self.size)?;
        out.set_item("format", self.format)?;
        out.set_item("confidence", self.confidence)?;
        out.set_item("standalone", self.standalone)?;
        out.set_item("multivolume", self.multivolume)?;
        out.set_item("anchor_roles", PyList::new(py, self.anchor_roles)?)?;
        out.set_item("internal_volume_number", self.internal_volume_number)?;
        out.set_item("structure_offset", self.structure_offset)?;
        out.set_item("expected_logical_size", self.expected_logical_size)?;
        out.set_item(
            "continuation_from_previous",
            self.continuation_from_previous,
        )?;
        out.set_item("continuation_to_next", self.continuation_to_next)?;
        out.set_item("sfx", self.sfx)?;
        out.set_item("evidence", PyList::new(py, self.evidence)?)?;
        out.set_item("error", self.error)?;
        out.set_item("bytes_read", self.bytes_read)?;
        Ok(out.unbind())
    }
}

#[pyfunction]
#[pyo3(signature = (paths, prefix_limit=DEFAULT_PREFIX_LIMIT, tail_limit=DEFAULT_TAIL_LIMIT))]
pub(crate) fn probe_volume_anchors(
    py: Python<'_>,
    paths: Vec<String>,
    prefix_limit: usize,
    tail_limit: usize,
) -> PyResult<Vec<Py<PyDict>>> {
    py.detach(|| probe_volume_anchor_paths(&paths, prefix_limit, tail_limit))
        .into_iter()
        .map(|anchor| anchor.into_dict(py))
        .collect()
}

pub(crate) fn probe_volume_anchor_paths(
    paths: &[String],
    prefix_limit: usize,
    tail_limit: usize,
) -> Vec<VolumeAnchor> {
    paths
        .iter()
        .map(|path| probe_path(path, prefix_limit, tail_limit))
        .collect()
}

fn probe_path(path: &str, prefix_limit: usize, tail_limit: usize) -> VolumeAnchor {
    let mut result = VolumeAnchor {
        path: path.to_string(),
        ..VolumeAnchor::default()
    };
    let reader = match ManagedReader::open(path) {
        Ok(reader) => reader,
        Err(error) => {
            result.error = error.to_string();
            return result;
        }
    };
    let size = reader.len();
    let mut file = reader.cursor();
    result.size = size;
    // Most formats put their identifying structure in the first few hundred
    // bytes.  Only a validated PE/SFX candidate gets the larger prefix window.
    // This keeps the ordinary directory-wide pass at roughly 512 B + ZIP tail
    // rather than reading 1 MiB from every candidate.
    let base_prefix_len = size.min(512) as usize;
    let mut prefix_len = base_prefix_len;
    let mut prefix = vec![0u8; base_prefix_len];
    if let Err(error) = file.read_exact(&mut prefix) {
        result.error = error.to_string();
        return result;
    }
    result.bytes_read += prefix.len() as u64;
    if prefix.starts_with(b"MZ") && prefix_limit > base_prefix_len {
        prefix_len = size.min(prefix_limit as u64) as usize;
    }
    if prefix_len > base_prefix_len {
        prefix.resize(prefix_len, 0);
        if file.seek(SeekFrom::Start(base_prefix_len as u64)).is_err()
            || file.read_exact(&mut prefix[base_prefix_len..]).is_err()
        {
            result.error = "sfx_prefix_read_failed".to_string();
            return result;
        }
        result.bytes_read += (prefix_len - base_prefix_len) as u64;
    }
    let tail_len = size.min(tail_limit as u64) as usize;
    let tail_start = size.saturating_sub(tail_len as u64);
    let tail = if tail_start == 0 {
        let copied = prefix.len().min(tail_len);
        let mut value = prefix[..copied].to_vec();
        value.resize(tail_len, 0);
        if copied < tail_len {
            if file.seek(SeekFrom::Start(copied as u64)).is_err()
                || file.read_exact(&mut value[copied..]).is_err()
            {
                Vec::new()
            } else {
                result.bytes_read += (tail_len - copied) as u64;
                value
            }
        } else {
            value
        }
    } else {
        let mut value = vec![0u8; tail_len];
        if file.seek(SeekFrom::Start(tail_start)).is_err() || file.read_exact(&mut value).is_err() {
            Vec::new()
        } else {
            result.bytes_read += value.len() as u64;
            value
        }
    };

    let allow_embedded = prefix.starts_with(b"MZ");
    if let Some(offset) = anchored_signature(&prefix, RAR5, allow_embedded)
        .or_else(|| anchored_signature(&prefix, RAR4, allow_embedded))
        .filter(|offset| probe_rar(&prefix, *offset, &mut result))
    {
        let _ = offset;
        return result;
    }
    if let Some(offset) = anchored_signature(&prefix, SEVEN_ZIP, allow_embedded)
        .filter(|offset| probe_seven_zip(&prefix, *offset, size, &mut result))
    {
        let _ = offset;
        return result;
    }
    if probe_zip(&prefix, &tail, tail_start, &mut result) {
        return result;
    }
    probe_standalone_stream(&prefix, &mut result);
    result
}

fn probe_rar(prefix: &[u8], offset: usize, out: &mut VolumeAnchor) -> bool {
    if prefix
        .get(offset..)
        .is_some_and(|value| value.starts_with(RAR5))
    {
        let Some((archive_flags, number)) = rar5_main_volume(prefix, offset + RAR5.len()) else {
            return false;
        };
        initialize_rar_anchor(out, offset);
        out.multivolume = archive_flags & 0x01 != 0;
        if out.multivolume {
            out.internal_volume_number = Some(number.unwrap_or(0).saturating_add(1));
            out.anchor_roles
                .push(if number.is_none() { "first" } else { "member" });
            out.evidence.push("rar5:volume_header");
        } else {
            out.standalone = true;
            out.anchor_roles.push("standalone");
            out.evidence.push("rar5:single_archive_header");
        }
    } else if let Some(flags) = rar4_main_flags(prefix, offset + RAR4.len()) {
        initialize_rar_anchor(out, offset);
        // RAR4 MHD_VOLUME and MHD_FIRSTVOLUME.
        out.multivolume = flags & 0x0001 != 0;
        if out.multivolume {
            out.anchor_roles.push(if flags & 0x0100 != 0 {
                "first"
            } else {
                "member"
            });
            out.internal_volume_number = (flags & 0x0100 != 0).then_some(1);
            out.evidence.push("rar4:volume_header");
        } else {
            out.standalone = true;
            out.anchor_roles.push("standalone");
            out.evidence.push("rar4:single_archive_header");
        }
    } else {
        return false;
    }
    true
}

fn initialize_rar_anchor(out: &mut VolumeAnchor, offset: usize) {
    out.format = "rar".to_string();
    out.confidence = "strong".to_string();
    out.structure_offset = Some(offset as u64);
    out.sfx = offset > 0;
    out.evidence.push(if out.sfx {
        "rar:sfx_signature"
    } else {
        "rar:signature"
    });
    out.anchor_roles.push("any_volume");
}

fn rar5_main_volume(data: &[u8], offset: usize) -> Option<(u64, Option<u32>)> {
    let stored_crc = u32_le(data, offset)?;
    let (header_size, after_size) = read_vint(data, offset + 4)?;
    let total = 4usize
        .checked_add(after_size.checked_sub(offset + 4)?)?
        .checked_add(header_size as usize)?;
    let end = offset.checked_add(total)?;
    let header = data.get(offset + 4..end)?;
    if crc32(header) != stored_crc {
        return None;
    }
    let (header_type, cursor) = read_vint(data, after_size)?;
    if header_type != 1 {
        return None;
    }
    let (header_flags, mut cursor) = read_vint(data, cursor)?;
    if header_flags & 0x01 != 0 {
        cursor = read_vint(data, cursor)?.1;
    }
    if header_flags & 0x02 != 0 {
        cursor = read_vint(data, cursor)?.1;
    }
    let (archive_flags, cursor) = read_vint(data, cursor)?;
    let number = if archive_flags & 0x02 != 0 {
        Some(read_vint(data, cursor)?.0 as u32)
    } else {
        None
    };
    Some((archive_flags, number))
}

fn rar4_main_flags(data: &[u8], offset: usize) -> Option<u16> {
    let stored_crc = u16_le(data, offset)?;
    let header_type = *data.get(offset + 2)?;
    if header_type != 0x73 {
        return None;
    }
    let header_size = u16_le(data, offset + 5)? as usize;
    let header = data.get(offset + 2..offset.checked_add(header_size)?)?;
    if (crc32(header) & 0xffff) as u16 != stored_crc {
        return None;
    }
    u16_le(data, offset + 3)
}

fn probe_seven_zip(prefix: &[u8], offset: usize, size: u64, out: &mut VolumeAnchor) -> bool {
    let Some(header) = prefix.get(offset..offset.saturating_add(32)) else {
        return false;
    };
    let stored_crc = u32::from_le_bytes(header[8..12].try_into().unwrap_or_default());
    if crc32(&header[12..32]) != stored_crc {
        return false;
    }
    out.format = "7z".to_string();
    out.structure_offset = Some(offset as u64);
    out.sfx = offset > 0;
    out.anchor_roles.push("first");
    out.internal_volume_number = Some(1);
    out.evidence.push(if out.sfx {
        "7z:sfx_signature"
    } else {
        "7z:start_signature"
    });
    let next_offset = u64::from_le_bytes(header[12..20].try_into().unwrap_or_default());
    let next_size = u64::from_le_bytes(header[20..28].try_into().unwrap_or_default());
    let logical_size = (offset as u64)
        .saturating_add(32)
        .saturating_add(next_offset)
        .saturating_add(next_size);
    out.expected_logical_size = Some(logical_size);
    out.confidence = "strong".to_string();
    out.evidence.push("7z:start_header_crc");
    if logical_size <= size {
        out.standalone = true;
        out.anchor_roles.push("standalone");
    } else {
        out.multivolume = true;
        out.continuation_to_next = true;
        out.evidence.push("7z:logical_size_exceeds_part");
    }
    true
}

fn probe_zip(prefix: &[u8], tail: &[u8], tail_start: u64, out: &mut VolumeAnchor) -> bool {
    let allow_embedded = prefix.starts_with(b"MZ");
    let start_offset = anchored_signature(prefix, ZIP_LOCAL, allow_embedded)
        .filter(|offset| plausible_zip_local(prefix, *offset))
        .or_else(|| anchored_signature(prefix, ZIP_EMPTY, allow_embedded));
    let eocd_index = memmem::rfind(tail, ZIP_EOCD).filter(|index| {
        tail.get(index + 20..index + 22)
            .map(|bytes| u16::from_le_bytes([bytes[0], bytes[1]]) as usize)
            .is_some_and(|comment_len| index + 22 + comment_len == tail.len())
    });
    if start_offset.is_none() && eocd_index.is_none() {
        return false;
    }
    out.format = "zip".to_string();
    out.confidence = "strong".to_string();
    if let Some(offset) = start_offset {
        out.structure_offset = Some(offset as u64);
        out.sfx = offset > 0;
        out.anchor_roles.push("first");
        out.evidence.push(if out.sfx {
            "zip:sfx_local_header"
        } else {
            "zip:local_header"
        });
    }
    if let Some(index) = eocd_index {
        if let Some(record) = tail.get(index..index + 22) {
            let disk = u16::from_le_bytes([record[4], record[5]]);
            let cd_disk = u16::from_le_bytes([record[6], record[7]]);
            // Old ZIP multi-disk/spanned layouts are intentionally unsupported.
            if disk != 0 || cd_disk != 0 {
                out.error = "unsupported_zip_multidisk".to_string();
                out.confidence = "unsupported".to_string();
                return true;
            }
            out.anchor_roles.push("terminal");
            out.evidence.push("zip:eocd_single_disk");
            out.expected_logical_size = Some(
                tail_start
                    + index as u64
                    + 22
                    + u16::from_le_bytes([record[20], record[21]]) as u64,
            );
        }
    }
    if start_offset.is_some() && eocd_index.is_some() {
        out.standalone = true;
        out.anchor_roles.push("standalone");
    } else {
        out.multivolume = true;
        out.continuation_from_previous = eocd_index.is_some();
        out.continuation_to_next = start_offset.is_some();
    }
    true
}

fn probe_standalone_stream(prefix: &[u8], out: &mut VolumeAnchor) {
    let format = if prefix.starts_with(b"\x1f\x8b") {
        "gzip"
    } else if prefix.starts_with(b"BZh") {
        "bzip2"
    } else if prefix.starts_with(b"\xfd7zXZ\x00") {
        "xz"
    } else if prefix.starts_with(b"\x28\xb5\x2f\xfd") {
        "zstd"
    } else if prefix.starts_with(b"\x1f\x9d") {
        "compress"
    } else if prefix.get(257..262) == Some(b"ustar") {
        "tar"
    } else {
        return;
    };
    out.format = format.to_string();
    out.confidence = "strong".to_string();
    out.standalone = true;
    out.anchor_roles.push("standalone");
    out.anchor_roles.push("first");
    out.evidence.push("stream:leading_structure");
}

fn find_signature(data: &[u8], signature: &[u8]) -> Option<usize> {
    memmem::find(data, signature)
}

fn anchored_signature(data: &[u8], signature: &[u8], allow_embedded: bool) -> Option<usize> {
    if data.starts_with(signature) {
        Some(0)
    } else if allow_embedded {
        find_signature(data, signature)
    } else {
        None
    }
}

fn plausible_zip_local(data: &[u8], offset: usize) -> bool {
    let Some(header) = data.get(offset..offset + 30) else {
        return false;
    };
    let version = u16::from_le_bytes([header[4], header[5]]);
    let method = u16::from_le_bytes([header[8], header[9]]);
    let name_len = u16::from_le_bytes([header[26], header[27]]) as usize;
    let extra_len = u16::from_le_bytes([header[28], header[29]]) as usize;
    version <= 1000
        && method <= 99
        && name_len > 0
        && offset
            .checked_add(30 + name_len + extra_len)
            .is_some_and(|end| end <= data.len())
}

fn u16_le(data: &[u8], offset: usize) -> Option<u16> {
    Some(u16::from_le_bytes(
        data.get(offset..offset + 2)?.try_into().ok()?,
    ))
}

fn u32_le(data: &[u8], offset: usize) -> Option<u32> {
    Some(u32::from_le_bytes(
        data.get(offset..offset + 4)?.try_into().ok()?,
    ))
}

fn read_vint(data: &[u8], mut offset: usize) -> Option<(u64, usize)> {
    let mut value = 0u64;
    let mut shift = 0u32;
    for _ in 0..10 {
        let byte = *data.get(offset)?;
        offset += 1;
        value |= ((byte & 0x7f) as u64).checked_shl(shift)?;
        if byte & 0x80 == 0 {
            return Some((value, offset));
        }
        shift += 7;
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rar4_main_header_requires_its_stored_crc() {
        let mut header = vec![0u8; 13];
        header[2] = 0x73;
        header[3..5].copy_from_slice(&0x0101u16.to_le_bytes());
        let header_len = header.len() as u16;
        header[5..7].copy_from_slice(&header_len.to_le_bytes());
        let stored = (crc32(&header[2..]) & 0xffff) as u16;
        header[..2].copy_from_slice(&stored.to_le_bytes());

        assert_eq!(rar4_main_flags(&header, 0), Some(0x0101));

        header[8] ^= 0x01;
        assert_eq!(rar4_main_flags(&header, 0), None);
    }
}
