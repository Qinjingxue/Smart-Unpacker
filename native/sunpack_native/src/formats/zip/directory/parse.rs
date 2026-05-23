fn find_eocd_record(data: &[u8], allow_trailing_junk: bool) -> Option<EocdInfo> {
    let mut pos = data
        .windows(EOCD_SIG.len())
        .rposition(|window| window == EOCD_SIG)?;
    loop {
        if pos + 22 <= data.len() {
            let comment_len = u16_le(data, pos + 20) as usize;
            let end = pos + 22 + comment_len;
            if end <= data.len() && (allow_trailing_junk || end == data.len()) {
                return Some(EocdInfo {
                    offset: pos,
                    end,
                    disk_entries: u16_le(data, pos + 8),
                    total_entries: u16_le(data, pos + 10),
                    cd_size: u32_le(data, pos + 12),
                    cd_offset: u32_le(data, pos + 16),
                });
            }
        }
        if pos == 0 {
            return None;
        }
        pos = data[..pos]
            .windows(EOCD_SIG.len())
            .rposition(|window| window == EOCD_SIG)?;
    }
}

fn find_valid_central_directory(data: &[u8]) -> Option<CdWalk> {
    let mut pos = memmem::find(data, CD_SIG)?;
    let mut best: Option<CdWalk> = None;
    loop {
        let walk = walk_central_directory_range(data, pos, None);
        if walk.valid && best.is_none_or(|current| walk.count > current.count) {
            best = Some(walk);
        }
        let next_start = pos + 4;
        if next_start >= data.len() {
            break;
        }
        let Some(next) = memmem::find(&data[next_start..], CD_SIG) else {
            break;
        };
        pos = next_start + next;
    }
    best
}

fn walk_central_directory_range(data: &[u8], offset: usize, expected_end: Option<usize>) -> CdWalk {
    let mut pos = offset;
    let mut count = 0usize;
    while pos + 46 <= data.len() && &data[pos..pos + 4] == CD_SIG {
        let name_len = u16_le(data, pos + 28) as usize;
        let extra_len = u16_le(data, pos + 30) as usize;
        let comment_len = u16_le(data, pos + 32) as usize;
        let record_len = 46usize
            .saturating_add(name_len)
            .saturating_add(extra_len)
            .saturating_add(comment_len);
        if record_len < 46 || pos + record_len > data.len() {
            break;
        }
        pos += record_len;
        count += 1;
        if expected_end.is_some_and(|end| pos >= end) {
            break;
        }
    }
    CdWalk {
        offset,
        end: pos,
        count,
        valid: count > 0 && expected_end.is_none_or(|end| pos == end),
    }
}

fn parse_central_directory_entries(
    data: &[u8],
    offset: usize,
    expected_end: usize,
) -> Vec<CentralEntry> {
    let mut entries = Vec::new();
    let mut pos = offset;
    while pos + 46 <= data.len() && pos < expected_end && &data[pos..pos + 4] == CD_SIG {
        let name_len = u16_le(data, pos + 28);
        let extra_len = u16_le(data, pos + 30);
        let comment_len = u16_le(data, pos + 32) as usize;
        let name_start = pos + 46;
        let extra_start = name_start + name_len as usize;
        let comment_start = extra_start + extra_len as usize;
        let record_end = comment_start + comment_len;
        if record_end > data.len() || record_end > expected_end {
            break;
        }
        entries.push(CentralEntry {
            offset: pos,
            flags: u16_le(data, pos + 8),
            method: u16_le(data, pos + 10),
            crc32: u32_le(data, pos + 16),
            compressed_size: u32_le(data, pos + 20),
            uncompressed_size: u32_le(data, pos + 24),
            name_len,
            extra_len,
            name: data[name_start..extra_start].to_vec(),
            extra: data[extra_start..comment_start].to_vec(),
            extra_offset: extra_start,
            local_header_offset: u32_le(data, pos + 42),
        });
        pos = record_end;
    }
    entries
}

fn parse_tolerant_central_directory_entries(
    data: &[u8],
    offset: usize,
    expected_end: usize,
) -> Vec<CentralEntry> {
    let mut entries = Vec::new();
    let mut pos = offset;
    let end = expected_end.min(data.len());
    while pos + 46 <= data.len() && pos < end {
        if &data[pos..pos + 4] != CD_SIG {
            let Some(next) = memmem::find(&data[pos.saturating_add(1)..end], CD_SIG) else {
                break;
            };
            pos = pos + 1 + next;
            continue;
        }
        let name_len = u16_le(data, pos + 28);
        let extra_len = u16_le(data, pos + 30);
        let comment_len = u16_le(data, pos + 32) as usize;
        let name_start = pos + 46;
        let extra_start = name_start + name_len as usize;
        let comment_start = extra_start.saturating_add(extra_len as usize);
        let record_end = comment_start.saturating_add(comment_len);
        if extra_start > data.len() {
            break;
        }
        let extra_end = comment_start.min(data.len());
        entries.push(CentralEntry {
            offset: pos,
            flags: u16_le(data, pos + 8),
            method: u16_le(data, pos + 10),
            crc32: u32_le(data, pos + 16),
            compressed_size: u32_le(data, pos + 20),
            uncompressed_size: u32_le(data, pos + 24),
            name_len,
            extra_len,
            name: data[name_start..extra_start].to_vec(),
            extra: data[extra_start..extra_end].to_vec(),
            extra_offset: extra_start,
            local_header_offset: u32_le(data, pos + 42),
        });
        if record_end + 46 <= data.len() && record_end <= end && &data[record_end..record_end + 4] == CD_SIG {
            pos = record_end;
            continue;
        }
        let next_start = pos + 46;
        if next_start >= end || next_start > data.len() {
            break;
        }
        let Some(next) = memmem::find(&data[next_start..end], CD_SIG) else {
            break;
        };
        pos = next_start + next;
    }
    entries
}

fn spurious_descriptor_delete_candidates(
    data: &[u8],
    max_candidates: usize,
    max_entries: usize,
    max_duration: Option<Duration>,
    started: Instant,
) -> Vec<DescriptorDeleteCandidate> {
    let Some(cd) = find_valid_central_directory(data) else {
        return Vec::new();
    };
    let mut entries = parse_central_directory_entries(data, cd.offset, cd.end);
    if entries.len() > max_entries {
        entries.truncate(max_entries);
    }
    entries.sort_by_key(|entry| entry.local_header_offset);
    let mut output = Vec::new();
    for (index, entry) in entries.iter().enumerate() {
        if timed_out(started, max_duration) || output.len() >= max_candidates {
            break;
        }
        let Some(local) = parse_local_header(data, entry.local_header_offset as usize) else {
            continue;
        };
        let Some(delete_candidate) =
            spurious_descriptor_delete_for_entry(data, &entries, index, entry, &local, cd.offset)
        else {
            continue;
        };
        output.push(delete_candidate);
    }
    output
}

fn spurious_descriptor_delete_for_entry(
    data: &[u8],
    entries: &[CentralEntry],
    index: usize,
    entry: &CentralEntry,
    local: &LocalHeader,
    cd_offset: usize,
) -> Option<DescriptorDeleteCandidate> {
    if entry.method != 0 && entry.method != 8 {
        return None;
    }
    let data_start = local
        .offset
        .checked_add(LOCAL_HEADER_LEN)?
        .checked_add(local.name_len as usize)?
        .checked_add(local.extra_len as usize)?;
    let compressed_size = entry.compressed_size as usize;
    if compressed_size == 0 || compressed_size == u32::MAX as usize {
        return None;
    }
    let descriptor_start = data_start.checked_add(compressed_size)?;
    if descriptor_start >= data.len() {
        return None;
    }
    let expected_next_offset = entries
        .get(index + 1)
        .map(|next| next.local_header_offset as usize)
        .unwrap_or(cd_offset);
    if expected_next_offset <= descriptor_start || expected_next_offset > data.len() {
        return None;
    }
    let actual_next_offset = if entries.get(index + 1).is_some() {
        find_signature_at_or_after(data, descriptor_start, LFH_SIG)?
    } else {
        find_signature_at_or_after(data, descriptor_start, CD_SIG)?
    };
    if actual_next_offset <= expected_next_offset || actual_next_offset > data.len() {
        return None;
    }
    let delete_size = actual_next_offset.checked_sub(expected_next_offset)?;
    if !(4..=64).contains(&delete_size) {
        return None;
    }
    if descriptor_start.checked_add(delete_size)? > data.len() {
        return None;
    }
    let descriptor_after_delete = descriptor_start.checked_add(delete_size)?;
    let descriptor_end = descriptor_at_impl(
        data,
        descriptor_after_delete,
        entry.crc32,
        entry.compressed_size as u64,
        entry.uncompressed_size as u64,
    )?;
    if descriptor_end != actual_next_offset {
        return None;
    }
    if descriptor_start + 4 <= data.len() && &data[descriptor_start..descriptor_start + 4] != DD_SIG {
        return None;
    }
    Some(DescriptorDeleteCandidate {
        delete_offset: descriptor_start,
        delete_size,
        descriptor_size: expected_next_offset - descriptor_start,
        expected_next_offset,
        actual_next_offset,
        entry_name: entry.name.clone(),
        confidence: 0.94,
    })
}

fn find_signature_at_or_after(data: &[u8], start: usize, signature: &[u8]) -> Option<usize> {
    memmem::find(&data[start..], signature).map(|offset| start + offset)
}

fn descriptor_delete_patch_facts(candidate: &DescriptorDeleteCandidate) -> Vec<String> {
    vec![
        "removed_spurious_data_descriptor".to_string(),
        format!("descriptor_delete_span={}:{}", candidate.delete_offset, candidate.delete_size),
        format!("stream_offset_delta=-{}", candidate.delete_size),
        "after_descriptor_stream_reconcile".to_string(),
    ]
}

fn descriptor_delete_patch_plan(
    py: Python<'_>,
    data: &[u8],
    candidate: &DescriptorDeleteCandidate,
) -> PyResult<Py<PyDict>> {
    let operation = PyDict::new(py);
    operation.set_item("schema_version", 2)?;
    operation.set_item("op", "delete")?;
    operation.set_item("target", "logical")?;
    operation.set_item("offset", candidate.delete_offset)?;
    operation.set_item("size", candidate.delete_size)?;
    let expected = data
        .get(candidate.delete_offset..candidate.delete_offset.saturating_add(candidate.delete_size))
        .unwrap_or(&[]);
    operation.set_item("expected_b64", BASE64_STANDARD.encode(expected))?;
    let details = PyDict::new(py);
    details.set_item("module", "zip_remove_spurious_data_descriptor")?;
    details.set_item("native_target", "spurious_data_descriptor_delete")?;
    details.set_item("descriptor_size_after_delete", candidate.descriptor_size)?;
    operation.set_item("details", details)?;

    let provenance = PyDict::new(py);
    provenance.set_item("module", "zip_remove_spurious_data_descriptor")?;
    provenance.set_item(
        "actions",
        PyList::new(py, ["detect_spurious_data_descriptor", "delete_descriptor_span"])?,
    )?;
    provenance.set_item("native_target", "spurious_data_descriptor_delete")?;

    let plan = PyDict::new(py);
    plan.set_item("kind", "patch_plan")?;
    plan.set_item("schema_version", 2)?;
    plan.set_item("module", "zip_remove_spurious_data_descriptor")?;
    plan.set_item("format", "zip")?;
    plan.set_item("action_type", "apply_patch")?;
    plan.set_item("operations", PyList::new(py, [operation])?)?;
    plan.set_item("confidence", candidate.confidence)?;
    plan.set_item("provenance", provenance)?;
    Ok(plan.unbind())
}

fn descriptor_delete_validation_details(
    py: Python<'_>,
    candidate: &DescriptorDeleteCandidate,
) -> PyResult<Py<PyDict>> {
    let details = PyDict::new(py);
    details.set_item("native_target", "spurious_data_descriptor_delete")?;
    details.set_item("accepted", true)?;
    details.set_item("delete_offset", candidate.delete_offset)?;
    details.set_item("delete_size", candidate.delete_size)?;
    details.set_item("descriptor_size_after_delete", candidate.descriptor_size)?;
    details.set_item("expected_next_offset", candidate.expected_next_offset)?;
    details.set_item("actual_next_offset", candidate.actual_next_offset)?;
    details.set_item("entry_name", String::from_utf8_lossy(&candidate.entry_name).to_string())?;
    Ok(details.unbind())
}

fn descriptor_delete_status_dict(
    py: Python<'_>,
    status: &str,
    message: &str,
    warnings: &[String],
    fail_reason: Option<&str>,
) -> PyResult<Py<PyDict>> {
    let result = PyDict::new(py);
    result.set_item("status", status)?;
    result.set_item("selected_path", "")?;
    result.set_item("selected_candidate", "")?;
    result.set_item("confidence", 0.0)?;
    result.set_item("format", "zip")?;
    result.set_item("message", message)?;
    result.set_item("actions", PyList::empty(py))?;
    result.set_item("candidate_status", status)?;
    result.set_item("native_target", "spurious_data_descriptor_delete")?;
    result.set_item("patch_facts", PyList::empty(py))?;
    result.set_item("residual_facts", PyList::empty(py))?;
    result.set_item("validation_details", build_validation_details(py, "spurious_data_descriptor_delete", false, &[])?)?;
    result.set_item("warnings", PyList::new(py, warnings)?)?;
    result.set_item("candidates", PyList::empty(py))?;
    result.set_item("workspace_paths", PyList::empty(py))?;
    if let Some(reason) = fail_reason {
        let diagnostics = PyDict::new(py);
        diagnostics.set_item("fail_reason", reason)?;
        result.set_item("diagnostics", diagnostics)?;
    }
    Ok(result.unbind())
}

