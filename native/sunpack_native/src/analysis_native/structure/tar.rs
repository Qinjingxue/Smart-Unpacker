fn tar_empty<'py>(py: Python<'py>, error: &str) -> PyResult<Bound<'py, PyDict>> {
    let d = dict(py)?;
    d.set_item("plausible", false)?;
    d.set_item("error", error)?;
    d.set_item("format", "")?;
    for key in [
        "stored_checksum",
        "computed_checksum",
        "file_size",
        "member_size",
        "entries_checked",
    ] {
        d.set_item(key, 0)?;
    }
    for key in [
        "ustar_magic",
        "zero_block",
        "entry_walk_ok",
        "end_zero_blocks",
    ] {
        d.set_item(key, false)?;
    }
    Ok(d)
}

fn walk_tar(
    file: &mut File,
    file_size: u64,
    max_entries: usize,
) -> PyResult<(usize, bool, bool, &'static str)> {
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
        let next_offset =
            offset + TAR_BLOCK_SIZE as u64 + member_size + padding_for_size(member_size);
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
