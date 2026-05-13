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
        return Ok((
            0,
            total_entries == 0 && central_directory_size == 0,
            0,
            false,
            "",
        ));
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
            return Ok((
                checked,
                false,
                checked,
                false,
                "bad_central_entry_signature",
            ));
        }
        let filename_len = u16_le(&header, 28) as u64;
        let extra_len = u16_le(&header, 30) as u64;
        let comment_len = u16_le(&header, 32) as u64;
        let disk_start = u16_le(&header, 34);
        let local_header_offset = u32_le(&header, 42) as u64;
        let entry_size =
            ZIP_CENTRAL_DIRECTORY_HEADER_SIZE as u64 + filename_len + extra_len + comment_len;
        if disk_start != 0 {
            return Ok((checked, false, checked, false, "central_entry_multi_disk"));
        }
        if filename_len == 0 || filename_len > 4096 {
            return Ok((
                checked,
                false,
                checked,
                false,
                "central_entry_invalid_filename_length",
            ));
        }
        if entry_size <= ZIP_CENTRAL_DIRECTORY_HEADER_SIZE as u64
            || cursor + entry_size > central_end
        {
            return Ok((
                checked,
                false,
                checked,
                false,
                "central_entry_size_out_of_range",
            ));
        }
        let local_header_position = archive_offset + local_header_offset;
        if local_header_position < archive_offset
            || local_header_position + 4 > central_directory_offset
        {
            return Ok((
                checked,
                false,
                checked,
                false,
                "local_header_offset_out_of_range",
            ));
        }
        let mut sig = [0u8; 4];
        file.seek(SeekFrom::Start(local_header_position))?;
        file.read_exact(&mut sig)?;
        if &sig != b"PK\x03\x04" {
            return Ok((
                checked,
                false,
                checked,
                false,
                "local_header_link_bad_signature",
            ));
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
