fn scan_archive_signatures(
    data: &[u8],
    target: TargetFormat,
    require_carrier_offset: bool,
    max_candidates: usize,
) -> Vec<ArchiveCandidate> {
    let mut output = Vec::new();
    if matches!(target, TargetFormat::SevenZip | TargetFormat::Any) {
        for candidate in crate::formats::seven_zip::carrier_scan_candidates(data, require_carrier_offset, max_candidates) {
            output.push(ArchiveCandidate {
                format: TargetFormat::SevenZip,
                offset: candidate.offset,
                #[cfg(test)]
                archive_end: candidate.archive_end,
                start_crc_ok: candidate.start_crc_ok,
                next_header_crc_ok: candidate.next_header_crc_ok,
                warnings: candidate.warnings,
            });
            if output.len() >= max_candidates {
                return output;
            }
        }
    }
    if matches!(target, TargetFormat::Zip | TargetFormat::Any) {
        for offset in find_all(data, b"PK\x03\x04") {
            if require_carrier_offset && offset == 0 {
                continue;
            }
            if let Some(candidate) = zip_carrier_candidate(data, offset) {
                output.push(candidate);
                if output.len() >= max_candidates {
                    return output;
                }
            }
        }
    }
    if matches!(target, TargetFormat::Rar | TargetFormat::Any) {
        for offset in find_all(data, RAR4_MAGIC) {
            if require_carrier_offset && offset == 0 {
                continue;
            }
            if let Some(candidate) = rar4_candidate(data, offset) {
                output.push(candidate);
                if output.len() >= max_candidates {
                    return output;
                }
            }
        }
        for offset in find_all(data, RAR5_MAGIC) {
            if require_carrier_offset && offset == 0 {
                continue;
            }
            if let Some(candidate) = rar5_candidate(data, offset) {
                output.push(candidate);
                if output.len() >= max_candidates {
                    return output;
                }
            }
        }
    }
    output.sort_by_key(|candidate| candidate.offset);
    output
}

fn rar4_candidate(data: &[u8], offset: usize) -> Option<ArchiveCandidate> {
    let first = offset.checked_add(RAR4_MAGIC.len())?;
    if first.checked_add(7)? > data.len() {
        return None;
    }
    let stored_crc = u16_le(data, first) as u32;
    let header_type = data[first + 2];
    let flags = u16_le(data, first + 3);
    let header_size = u16_le(data, first + 5) as usize;
    if !matches!(header_type, 0x73..=0x7b)
        || header_size < 7
        || first.checked_add(header_size)? > data.len()
    {
        return None;
    }
    let header = &data[first..first + header_size];
    if (crc32(&header[2..]) & 0xffff) != stored_crc {
        return None;
    }
    if flags & 0x8000 != 0 {
        if header_size < 11 {
            return None;
        }
        let add_size = u32_le(header, 7) as usize;
        let archive_end = first.checked_add(header_size)?.checked_add(add_size)?;
        if archive_end > data.len() {
            return None;
        }
        return Some(ArchiveCandidate {
            format: TargetFormat::Rar,
            offset,
            #[cfg(test)]
            archive_end,
            start_crc_ok: true,
            next_header_crc_ok: true,
            warnings: Vec::new(),
        });
    }
    Some(ArchiveCandidate {
        format: TargetFormat::Rar,
        offset,
        #[cfg(test)]
        archive_end: data.len(),
        start_crc_ok: true,
        next_header_crc_ok: true,
        warnings: Vec::new(),
    })
}

fn zip_carrier_candidate(data: &[u8], offset: usize) -> Option<ArchiveCandidate> {
    // Verify a valid ZIP exists after the carrier prefix
    // by searching for the EOCD record to confirm archive bounds
    let eocd_pos = find_eocd_from(&data[offset..])?;
    let absolute_eocd = offset + eocd_pos;
    if absolute_eocd + 22 > data.len() {
        return None;
    }
    let cd_size = u32_le(data, absolute_eocd + 12) as usize;
    let cd_offset = u32_le(data, absolute_eocd + 16) as usize;
    let comment_len = u16_le(data, absolute_eocd + 20) as usize;
    let archive_end = absolute_eocd + 22 + comment_len;
    if archive_end > data.len() {
        return None;
    }
    let absolute_cd_offset = offset.checked_add(cd_offset)?;
    // ZIP EOCD central-directory offsets are relative to the embedded ZIP
    // start, not the outer carrier file.
    if absolute_cd_offset < offset || absolute_cd_offset.checked_add(cd_size)? > absolute_eocd {
        return None;
    }
    Some(ArchiveCandidate {
        format: TargetFormat::Zip,
        offset,
        #[cfg(test)]
        archive_end,
        start_crc_ok: true,
        next_header_crc_ok: true,
        warnings: Vec::new(),
    })
}

fn find_eocd_from(data: &[u8]) -> Option<usize> {
    let needle = b"PK\x05\x06";
    let mut pos = data.len().checked_sub(needle.len())?;
    loop {
        if &data[pos..pos + needle.len()] == needle {
            return Some(pos);
        }
        if pos == 0 {
            return None;
        }
        pos -= 1;
    }
}

fn rar5_candidate(data: &[u8], offset: usize) -> Option<ArchiveCandidate> {
    let first = offset.checked_add(RAR5_MAGIC.len())?;
    if first.checked_add(6)? > data.len() {
        return None;
    }
    let stored_crc = u32_le(data, first);
    let (header_size, after_size) = read_vint(data, first + 4)?;
    let total_size = 4usize
        .checked_add(after_size.checked_sub(first + 4)?)?
        .checked_add(usize::try_from(header_size).ok()?)?;
    let end = first.checked_add(total_size)?;
    if header_size == 0 || end > data.len() {
        return None;
    }
    let header_data = &data[first + 4..end];
    if crc32(header_data) != stored_crc {
        return None;
    }
    let (header_type, _) = read_vint(data, after_size)?;
    if !matches!(header_type, 1..=5) {
        return None;
    }
    Some(ArchiveCandidate {
        format: TargetFormat::Rar,
        offset,
        #[cfg(test)]
        archive_end: data.len(),
        start_crc_ok: true,
        next_header_crc_ok: true,
        warnings: Vec::new(),
    })
}

