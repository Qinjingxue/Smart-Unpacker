fn seven_zip_repair_next_header_target(
    py: Python<'_>,
    data: &[u8],
    workspace: &str,
    target: &str,
    max_scan_bytes: usize,
) -> PyResult<Py<PyDict>> {
    if data.len() < SEVEN_Z_HEADER_SIZE || !data.starts_with(SEVEN_Z_MAGIC) {
        return seven_zip_atomic_status(py, "unrepairable", target, "7z", "", "7z signature is not at the current source start", &[], &[], &[], 0.0, &[], &[]);
    }
    let current_offset = u64_le(data, 12);
    let current_size = u64_le(data, 20);
    let Some((next_offset, next_size)) = find_next_header_candidate(data, max_scan_bytes.max(1))
        .or_else(|| infer_next_header_from_eof(data, target, current_offset, current_size))
        .or_else(|| infer_next_header_repoint_without_crc(data, target, current_offset, current_size, max_scan_bytes.max(1)))
    else {
        return seven_zip_atomic_status(py, "unrepairable", target, "7z", "", "7z next header candidate could not be inferred", &[], &[], &[], 0.0, &["encoded_header_candidate_missing"], &[]);
    };
    let offset_differs = current_offset != next_offset;
    let size_differs = current_size != next_size;
    let allowed = match target {
        "next_header_offset" => offset_differs && !size_differs,
        "next_header_size" => size_differs && !offset_differs,
        "next_header_repoint" => offset_differs && size_differs,
        _ => false,
    };
    if !allowed {
        return seven_zip_atomic_status(py, "unrepairable", target, "7z", "", "7z next header inferred fields do not match requested atomic target", &[], &[], &[], 0.0, &[], &[]);
    }
    let next_crc = u32_le(data, 28);
    let mut start_header = [0u8; 20];
    start_header[0..8].copy_from_slice(&next_offset.to_le_bytes());
    start_header[8..16].copy_from_slice(&next_size.to_le_bytes());
    start_header[16..20].copy_from_slice(&next_crc.to_le_bytes());
    let start_crc = crc32(&start_header);
    let mut candidate = data.to_vec();
    candidate[8..12].copy_from_slice(&start_crc.to_le_bytes());
    candidate[12..20].copy_from_slice(&next_offset.to_le_bytes());
    candidate[20..28].copy_from_slice(&next_size.to_le_bytes());
    let output_path = Path::new(workspace).join(format!("seven_zip_{target}.7z"));
    let output_bytes = match write_slice_candidate(&candidate, &output_path) {
        Ok(bytes) => bytes,
        Err(err) => return seven_zip_atomic_status(py, "unrepairable", target, "7z", "", &format!("7z next header candidate could not be written: {err}"), &[], &[], &[], 0.0, &[], &[]),
    };
    let action = match target {
        "next_header_offset" => "repair_7z_next_header_offset",
        "next_header_size" => "repair_7z_next_header_size",
        _ => "repoint_7z_next_header",
    };
    let selected = WrittenArchiveCandidate {
        name: target.to_string(),
        path: output_path.to_string_lossy().to_string(),
        format: "7z".to_string(),
        status: "repaired".to_string(),
        offset: 0,
        end_offset: candidate.len() as u64,
        output_bytes,
        confidence: 0.9,
        actions: vec![action.to_string(), "recompute_7z_start_header_crc".to_string()],
        warnings: Vec::new(),
    };
    let selected_path = selected.path.clone();
    let result = status_dict_with_candidates(py, "repaired", &selected_path, "7z", "7z next header field was repaired", &[], 0, candidate.len() as u64, output_bytes, 0.9, &[action, "recompute_7z_start_header_crc"], &[selected])?;
    let patch_fact = match target {
        "next_header_offset" => "fixed_field=next_header_offset",
        "next_header_size" => "fixed_field=next_header_size",
        _ => "fixed_field=next_header_repoint",
    };
    set_seven_zip_atomic_fields(py, &result, target, &[patch_fact, "updated_start_header_crc_after_next_header_field", "source_format=7z"], &[])?;
    add_seven_zip_candidate_replace_patch_plans(py, &result, data, target)?;
    Ok(result)
}

fn infer_next_header_from_eof(
    data: &[u8],
    target: &str,
    current_offset: u64,
    current_size: u64,
) -> Option<(u64, u64)> {
    if data.len() <= SEVEN_Z_HEADER_SIZE {
        return None;
    }
    let logical_len = (data.len() - SEVEN_Z_HEADER_SIZE) as u64;
    match target {
        "next_header_offset" => {
            if current_size == 0 || current_size > logical_len {
                return None;
            }
            let inferred_offset = logical_len.checked_sub(current_size)?;
            if inferred_offset == current_offset {
                return None;
            }
            let start = SEVEN_Z_HEADER_SIZE + usize::try_from(inferred_offset).ok()?;
            if !next_header_nid_plausible(data.get(start).copied()) {
                return None;
            }
            Some((inferred_offset, current_size))
        }
        "next_header_size" => {
            if current_offset >= logical_len {
                return None;
            }
            let inferred_size = logical_len.checked_sub(current_offset)?;
            if inferred_size == 0 || inferred_size == current_size {
                return None;
            }
            let start = SEVEN_Z_HEADER_SIZE + usize::try_from(current_offset).ok()?;
            if !next_header_nid_plausible(data.get(start).copied()) {
                return None;
            }
            Some((current_offset, inferred_size))
        }
        _ => None,
    }
}

fn infer_next_header_repoint_without_crc(
    data: &[u8],
    target: &str,
    current_offset: u64,
    current_size: u64,
    max_scan: usize,
) -> Option<(u64, u64)> {
    if target != "next_header_repoint" || data.len() <= SEVEN_Z_HEADER_SIZE {
        return None;
    }
    let scan_end = data.len().min(SEVEN_Z_HEADER_SIZE.saturating_add(max_scan.max(1)));
    let mut candidates: Vec<(u64, u64, usize, u32, u8)> = Vec::new();
    for start in (SEVEN_Z_HEADER_SIZE..scan_end).rev() {
        if !next_header_nid_plausible(data.get(start).copied()) {
            continue;
        }
        for end in seven_zip_candidate_header_ends(data, start, scan_end, current_size, max_scan) {
            let next_offset = (start - SEVEN_Z_HEADER_SIZE) as u64;
            let next_size = (end - start) as u64;
            if next_offset == current_offset || next_size == current_size {
                continue;
            }
            if !next_header_semantically_plausible(
                &data[start..end],
                current_offset,
                current_size,
                next_offset,
                next_size,
            ) {
                continue;
            }
            let Some(syntax_score) = next_header_candidate_syntax_score(&data[start..end]) else {
                continue;
            };
            let nid_priority = if data[start] == SZ_ENCODED_HEADER { 0 } else { 1 };
            let tail_gap = data.len().saturating_sub(end);
            candidates.push((next_offset, next_size, tail_gap, syntax_score, nid_priority));
        }
    }
    candidates.sort_by_key(|(_, size, tail_gap, score, nid_priority)| (*tail_gap, *nid_priority, std::cmp::Reverse(*score), std::cmp::Reverse(*size)));
    candidates.dedup_by_key(|(offset, size, _, _, _)| (*offset, *size));
    if candidates.len() == 1 {
        return Some((candidates[0].0, candidates[0].1));
    }
    let zero_tail: Vec<(u64, u64, usize, u32, u8)> = candidates
        .iter()
        .copied()
        .filter(|(_, _, tail_gap, _, _)| *tail_gap == 0)
        .collect();
    if zero_tail.len() == 1 {
        return Some((zero_tail[0].0, zero_tail[0].1));
    }
    if let Some(best) = candidates.first().copied() {
        let same_score_count = candidates
            .iter()
            .filter(|(_, _, tail_gap, score, nid_priority)| *tail_gap == best.2 && *score == best.3 && *nid_priority == best.4)
            .count();
        if same_score_count == 1 && best.3 >= 40 {
            return Some((best.0, best.1));
        }
    }
    None
}

fn next_header_nid_plausible(value: Option<u8>) -> bool {
    matches!(value, Some(SZ_HEADER) | Some(SZ_ENCODED_HEADER))
}

fn next_header_candidate_syntax_score(raw: &[u8]) -> Option<u32> {
    if raw.is_empty() || raw.last().copied() != Some(SZ_END) {
        return None;
    }
    let mut score = match raw[0] {
        SZ_HEADER => shallow_plain_header_score(raw)?,
        SZ_ENCODED_HEADER => shallow_encoded_header_score(raw)?,
        _ => return None,
    };
    if raw.len() >= 8 {
        score += 4;
    }
    if raw.len() >= 24 {
        score += 4;
    }
    Some(score)
}

fn shallow_plain_header_score(raw: &[u8]) -> Option<u32> {
    let mut pos = 1usize;
    let mut score = 20u32;
    let mut seen_main_streams = false;
    let mut seen_files_info = false;
    loop {
        let nid = *raw.get(pos)?;
        pos += 1;
        match nid {
            SZ_END => {
                return Some(score + if seen_main_streams { 15 } else { 0 } + if seen_files_info { 12 } else { 0 });
            }
            SZ_MAIN_STREAMS_INFO => {
                seen_main_streams = true;
                score += shallow_streams_info_score(raw, &mut pos)?;
            }
            SZ_FILES_INFO => {
                seen_files_info = true;
                score += shallow_files_info_score(raw, &mut pos)?;
            }
            _ => return None,
        }
        if pos > raw.len() {
            return None;
        }
    }
}

fn shallow_encoded_header_score(raw: &[u8]) -> Option<u32> {
    let mut pos = 1usize;
    let mut score = 24u32;
    let mut seen_pack = false;
    let mut seen_unpack = false;
    loop {
        let nid = *raw.get(pos)?;
        pos += 1;
        match nid {
            SZ_END => {
                if !seen_pack {
                    return None;
                }
                return Some(score + if seen_unpack { 20 } else { 0 });
            }
            SZ_PACK_INFO => {
                seen_pack = true;
                score += shallow_pack_info_score(raw, &mut pos)?;
            }
            SZ_UNPACK_INFO => {
                seen_unpack = true;
                score += shallow_unpack_info_score(raw, &mut pos)?;
            }
            SZ_SUB_STREAMS_INFO => {
                score += shallow_property_tree_score(raw, &mut pos)?;
            }
            _ => return None,
        }
        if pos > raw.len() {
            return None;
        }
    }
}

fn shallow_streams_info_score(raw: &[u8], pos: &mut usize) -> Option<u32> {
    let mut score = 0u32;
    loop {
        let nid = *raw.get(*pos)?;
        *pos += 1;
        match nid {
            SZ_END => return Some(score),
            SZ_PACK_INFO => score += shallow_pack_info_score(raw, pos)?,
            SZ_UNPACK_INFO => score += shallow_unpack_info_score(raw, pos)?,
            SZ_SUB_STREAMS_INFO => score += shallow_property_tree_score(raw, pos)?,
            _ => return None,
        }
    }
}

fn shallow_pack_info_score(raw: &[u8], pos: &mut usize) -> Option<u32> {
    let pack_pos = read_sz_vint(raw, pos)?;
    let stream_count = read_sz_vint(raw, pos)?;
    if stream_count.value == 0 || stream_count.value > SEVEN_Z_MAX_HEADER_STREAMS as u64 {
        return None;
    }
    if pack_pos.value > (1u64 << 42) {
        return None;
    }
    let mut score = 16u32;
    loop {
        let nid = *raw.get(*pos)?;
        *pos += 1;
        match nid {
            SZ_END => return Some(score),
            SZ_SIZE => {
                for _ in 0..stream_count.value {
                    let size = read_sz_vint(raw, pos)?;
                    if size.value > (1u64 << 42) {
                        return None;
                    }
                }
                score += 12;
            }
            SZ_CRC => {
                skip_bool_vector_and_crc_values(raw, pos, stream_count.value as usize)?;
                score += 8;
            }
            _ => return None,
        }
    }
}

fn shallow_unpack_info_score(raw: &[u8], pos: &mut usize) -> Option<u32> {
    let mut score = 0u32;
    loop {
        let nid = *raw.get(*pos)?;
        *pos += 1;
        match nid {
            SZ_END => return Some(score),
            SZ_FOLDER => {
                let folder_count = read_sz_vint(raw, pos)?;
                if folder_count.value == 0 || folder_count.value > 4096 {
                    return None;
                }
                let external = *raw.get(*pos)?;
                *pos += 1;
                if external != 0 {
                    return None;
                }
                for _ in 0..folder_count.value {
                    skip_folder(raw, pos)?;
                }
                score += 18;
            }
            SZ_CODERS_UNPACK_SIZE => {
                let mut count = 0usize;
                while *pos < raw.len() {
                    if raw.get(*pos).copied() == Some(SZ_CRC) || raw.get(*pos).copied() == Some(SZ_END) {
                        break;
                    }
                    read_sz_vint(raw, pos)?;
                    count += 1;
                    if count > 8192 {
                        return None;
                    }
                }
                if count == 0 {
                    return None;
                }
                score += 10;
            }
            SZ_CRC => {
                skip_property_payload(raw, pos)?;
                score += 6;
            }
            _ => return None,
        }
    }
}

fn shallow_files_info_score(raw: &[u8], pos: &mut usize) -> Option<u32> {
    let file_count = read_sz_vint(raw, pos)?;
    if file_count.value > SEVEN_Z_MAX_HEADER_FILES {
        return None;
    }
    let mut score = 8u32;
    loop {
        let nid = *raw.get(*pos)?;
        *pos += 1;
        if nid == SZ_END {
            return Some(score);
        }
        let size = read_sz_vint(raw, pos)?;
        let prop_size = usize::try_from(size.value).ok()?;
        let end = pos.checked_add(prop_size)?;
        if end > raw.len() {
            return None;
        }
        if matches!(nid, SZ_EMPTY_STREAM | SZ_EMPTY_FILE | SZ_ANTI) {
            score += 3;
        }
        *pos = end;
    }
}

fn shallow_property_tree_score(raw: &[u8], pos: &mut usize) -> Option<u32> {
    let mut score = 0u32;
    loop {
        let nid = *raw.get(*pos)?;
        *pos += 1;
        match nid {
            SZ_END => return Some(score),
            SZ_SIZE => {
                let mut count = 0usize;
                while *pos < raw.len() {
                    if raw.get(*pos).copied() == Some(SZ_CRC) || raw.get(*pos).copied() == Some(SZ_END) {
                        break;
                    }
                    read_sz_vint(raw, pos)?;
                    count += 1;
                    if count > 8192 {
                        return None;
                    }
                }
                score += 4;
            }
            SZ_CRC => {
                skip_property_payload(raw, pos)?;
                score += 4;
            }
            _ => return None,
        }
    }
}

fn skip_folder(raw: &[u8], pos: &mut usize) -> Option<()> {
    let coders = read_sz_vint(raw, pos)?;
    if coders.value == 0 || coders.value > 64 {
        return None;
    }
    let mut total_in = 0u64;
    let mut total_out = 0u64;
    for _ in 0..coders.value {
        let flags = *raw.get(*pos)?;
        *pos += 1;
        let id_size = usize::from(flags & 0x0f);
        if id_size == 0 || pos.checked_add(id_size)? > raw.len() {
            return None;
        }
        *pos += id_size;
        let mut in_streams = 1u64;
        let mut out_streams = 1u64;
        if flags & 0x10 != 0 {
            in_streams = read_sz_vint(raw, pos)?.value;
            out_streams = read_sz_vint(raw, pos)?.value;
        }
        if in_streams == 0 || out_streams == 0 || in_streams > 64 || out_streams > 64 {
            return None;
        }
        if flags & 0x20 != 0 {
            let props_size = usize::try_from(read_sz_vint(raw, pos)?.value).ok()?;
            if pos.checked_add(props_size)? > raw.len() {
                return None;
            }
            *pos += props_size;
        }
        if flags & 0x80 != 0 {
            return None;
        }
        total_in = total_in.checked_add(in_streams)?;
        total_out = total_out.checked_add(out_streams)?;
    }
    let bind_pairs = total_out.saturating_sub(1);
    for _ in 0..bind_pairs {
        read_sz_vint(raw, pos)?;
        read_sz_vint(raw, pos)?;
    }
    let packed_streams = total_in.saturating_sub(bind_pairs);
    if packed_streams > 1 {
        for _ in 0..packed_streams {
            read_sz_vint(raw, pos)?;
        }
    }
    Some(())
}

fn skip_bool_vector_and_crc_values(raw: &[u8], pos: &mut usize, count: usize) -> Option<()> {
    if count == 0 {
        return Some(());
    }
    let all_defined = *raw.get(*pos)?;
    *pos += 1;
    let defined_count = if all_defined != 0 {
        count
    } else {
        let byte_count = (count + 7) / 8;
        if pos.checked_add(byte_count)? > raw.len() {
            return None;
        }
        let mut defined = 0usize;
        for index in 0..count {
            let byte = raw[*pos + index / 8];
            if (byte & (0x80 >> (index % 8))) != 0 {
                defined += 1;
            }
        }
        *pos += byte_count;
        defined
    };
    if pos.checked_add(defined_count.checked_mul(4)?)? > raw.len() {
        return None;
    }
    *pos += defined_count * 4;
    Some(())
}

fn skip_property_payload(raw: &[u8], pos: &mut usize) -> Option<()> {
    let count = raw.len().saturating_sub(*pos);
    for possible in 0..=count {
        let mut probe = *pos + possible;
        if matches!(raw.get(probe).copied(), Some(SZ_END) | Some(SZ_SIZE) | Some(SZ_CRC)) {
            *pos += possible;
            return Some(());
        }
    }
    None
}
