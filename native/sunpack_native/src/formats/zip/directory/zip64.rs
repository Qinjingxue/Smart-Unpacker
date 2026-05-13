fn central_local_mismatch_count(data: &[u8]) -> usize {
    let Some(eocd) = find_eocd_record(data, true) else {
        return 0;
    };
    let cd_end = (eocd.cd_offset as usize).saturating_add(eocd.cd_size as usize);
    let entries = parse_central_directory_entries(data, eocd.cd_offset as usize, cd_end);
    entries
        .iter()
        .filter(|entry| {
            let Some(local) = find_local_for_central(data, entry) else {
                return true;
            };
            local.name != entry.name
                || local.method != entry.method
                || (entry.flags & 0x08 == 0
                    && (local.crc32 != entry.crc32
                        || local.compressed_size != entry.compressed_size
                        || local.uncompressed_size != entry.uncompressed_size))
        })
        .count()
}

fn entry_name_key(raw: &[u8]) -> String {
    normalize_zip_name_key(&String::from_utf8_lossy(raw))
}

fn normalize_zip_name_key(name: &str) -> String {
    name.replace('\\', "/").trim_start_matches("./").to_lowercase()
}

fn expected_zip64_values(
    entry: &CentralEntry,
    local: &LocalHeader,
    local_zip64: &Zip64Extra,
) -> Option<Vec<u64>> {
    let mut local_values = local_zip64.values.clone();
    let mut expected = Vec::new();
    if entry.uncompressed_size == 0xFFFF_FFFF {
        if local_values.is_empty() {
            return None;
        }
        expected.push(local_values.remove(0));
    }
    if entry.compressed_size == 0xFFFF_FFFF {
        if local_values.is_empty() {
            return None;
        }
        expected.push(local_values.remove(0));
    }
    if entry.local_header_offset == 0xFFFF_FFFF {
        expected.push(local.offset as u64);
    }
    Some(expected)
}

fn eocd_tail_for_cd(
    data: &[u8],
    cd: &CdWalk,
    source_eocd: Option<EocdInfo>,
) -> Result<Vec<u8>, String> {
    if cd.count > u16::MAX as usize
        || cd.end - cd.offset > u32::MAX as usize
        || cd.offset > u32::MAX as usize
    {
        return Err("ZIP64 central directory rewrite is not supported here".to_string());
    }
    let mut tail = Vec::new();
    tail.extend_from_slice(EOCD_SIG);
    tail.extend_from_slice(&0u16.to_le_bytes());
    tail.extend_from_slice(&0u16.to_le_bytes());
    tail.extend_from_slice(&(cd.count as u16).to_le_bytes());
    tail.extend_from_slice(&(cd.count as u16).to_le_bytes());
    tail.extend_from_slice(&((cd.end - cd.offset) as u32).to_le_bytes());
    tail.extend_from_slice(&(cd.offset as u32).to_le_bytes());
    let comment = source_eocd
        .and_then(|eocd| data.get(eocd.offset + 22..eocd.end))
        .unwrap_or(&[]);
    if comment.len() > u16::MAX as usize {
        return Err("ZIP comment length is out of range".to_string());
    }
    tail.extend_from_slice(&(comment.len() as u16).to_le_bytes());
    tail.extend_from_slice(comment);
    Ok(tail)
}

fn add_zip_patch(bytes: &mut [u8], patches: &mut Vec<BytePatch>, offset: usize, payload: &[u8]) {
    if bytes.get(offset..offset + payload.len()) == Some(payload) {
        return;
    }
    bytes[offset..offset + payload.len()].copy_from_slice(payload);
    patches.push(BytePatch {
        offset: offset as u64,
        data: payload.to_vec(),
    });
}

