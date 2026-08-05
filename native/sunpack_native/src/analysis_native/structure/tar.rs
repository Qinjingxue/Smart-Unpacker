const TAR_FIELDS: &[&str] = &[
    "member.header.name",
    "member.header.mode",
    "member.header.uid_gid",
    "member.header.size",
    "member.header.mtime",
    "member.header.checksum",
    "member.header.typeflag",
    "member.header.linkname",
    "member.header.magic_version",
    "member.header.prefix",
    "member.payload.span",
    "member.payload.data",
    "member.padding",
    "member.next_header",
    "pax.header.length",
    "pax.header.records",
    "pax.target_member",
    "gnu.longname",
    "gnu.target_member",
    "sparse.map",
    "sparse.payload",
    "archive.end_zero_blocks",
    "archive.trailing_data",
];

fn tar_text(value: &[u8]) -> String {
    let end = value.iter().position(|b| *b == 0).unwrap_or(value.len());
    String::from_utf8_lossy(&value[..end]).trim().to_string()
}

fn enrich_tar_semantics(
    d: &Bound<'_, PyDict>,
    file: &mut SourceCursor,
    file_size: u64,
    max_entries: usize,
) -> PyResult<()> {
    let mut offset = 0u64;
    let mut entries = 0usize;
    let mut zeros = 0usize;
    let mut pax_lengths = Vec::new();
    let mut pax_records = Vec::new();
    let mut gnu_longname = None::<String>;
    let mut sparse = Vec::new();
    let limit = max_entries.max(1);
    while entries < limit && offset + TAR_BLOCK_SIZE as u64 <= file_size {
        let mut header = [0u8; TAR_BLOCK_SIZE];
        if let Err(fault) = seek_field(
            file,
            offset,
            file_size,
            "tar.member.header",
            FieldLocation::Body,
        )
        .and_then(|_| {
            read_exact_field(
                file,
                &mut header,
                file_size,
                "tar.member.header",
                FieldLocation::Body,
            )
        }) {
            set_read_fault(d, &fault, "member_header_read_failed")?;
            return Ok(());
        }
        if header.iter().all(|b| *b == 0) {
            zeros += 1;
            offset += TAR_BLOCK_SIZE as u64;
            if zeros >= 2 {
                break;
            }
            continue;
        }
        zeros = 0;
        let size = parse_octal(&header[124..136]).unwrap_or(0);
        let padding = padding_for_size(size);
        let payload_start = offset + TAR_BLOCK_SIZE as u64;
        let next = payload_start.saturating_add(size).saturating_add(padding);
        let typeflag = header[156];
        if entries == 0 {
            let stored = parse_octal(&header[148..156]).unwrap_or(0);
            d.set_item("member.header.name", tar_text(&header[0..100]))?;
            d.set_item(
                "member.header.mode",
                parse_octal(&header[100..108]).unwrap_or(0),
            )?;
            d.set_item(
                "member.header.uid_gid",
                format!(
                    "uid={};gid={}",
                    parse_octal(&header[108..116]).unwrap_or(0),
                    parse_octal(&header[116..124]).unwrap_or(0)
                ),
            )?;
            d.set_item("member.header.size", size)?;
            d.set_item(
                "member.header.mtime",
                parse_octal(&header[136..148]).unwrap_or(0),
            )?;
            d.set_item(
                "member.header.checksum",
                format!(
                    "stored={stored};computed={};ok={}",
                    tar_checksum(&header),
                    stored == tar_checksum(&header)
                ),
            )?;
            d.set_item("member.header.typeflag", typeflag as char as u32)?;
            d.set_item("member.header.linkname", tar_text(&header[157..257]))?;
            d.set_item(
                "member.header.magic_version",
                format!(
                    "magic={};version={}",
                    tar_text(&header[257..263]),
                    tar_text(&header[263..265])
                ),
            )?;
            d.set_item("member.header.prefix", tar_text(&header[345..500]))?;
            d.set_item(
                "member.payload.span",
                format!("offset={payload_start};size={size}"),
            )?;
            d.set_item(
                "member.payload.data",
                format!("bytes={size};available={}", next <= file_size),
            )?;
            d.set_item("member.padding", padding)?;
            d.set_item("member.next_header", next <= file_size)?;
        }
        if next > file_size {
            break;
        }
        if matches!(typeflag, b'x' | b'g' | b'L' | b'K' | b'S') && size <= 4 * 1024 * 1024 {
            let mut payload = vec![0u8; size as usize];
            if let Err(fault) = seek_field(
                file,
                payload_start,
                file_size,
                "tar.member.payload",
                FieldLocation::Body,
            )
            .and_then(|_| {
                read_exact_field(
                    file,
                    &mut payload,
                    file_size,
                    "tar.member.payload",
                    FieldLocation::Body,
                )
            }) {
                set_read_fault(d, &fault, "member_payload_read_failed")?;
                return Ok(());
            }
            if matches!(typeflag, b'x' | b'g') {
                let text = String::from_utf8_lossy(&payload);
                for line in text.lines() {
                    if let Some((length, record)) = line.split_once(' ') {
                        if let Ok(length) = length.parse::<u64>() {
                            pax_lengths.push(length);
                        }
                        pax_records.push(record.to_string());
                        if record.starts_with("GNU.sparse.") {
                            sparse.push(record.to_string());
                        }
                    }
                }
            } else if matches!(typeflag, b'L' | b'K') {
                gnu_longname = Some(tar_text(&payload));
            } else if typeflag == b'S' {
                sparse.push(format!("gnu_sparse_header_at={offset}"));
            }
        }
        entries += 1;
        offset = next;
    }
    d.set_item(
        "pax.header.length",
        if pax_lengths.is_empty() {
            "absent".into()
        } else {
            pax_lengths.iter().sum::<u64>().to_string()
        },
    )?;
    d.set_item(
        "pax.header.records",
        if pax_records.is_empty() {
            "absent".into()
        } else {
            pax_records.join(";")
        },
    )?;
    d.set_item(
        "pax.target_member",
        if pax_records.is_empty() {
            "absent"
        } else {
            "next_member"
        },
    )?;
    d.set_item(
        "gnu.longname",
        gnu_longname.clone().unwrap_or_else(|| "absent".into()),
    )?;
    d.set_item(
        "gnu.target_member",
        if gnu_longname.is_some() {
            "next_member"
        } else {
            "absent"
        },
    )?;
    d.set_item(
        "sparse.map",
        if sparse.is_empty() {
            "absent".into()
        } else {
            sparse.join(";")
        },
    )?;
    d.set_item(
        "sparse.payload",
        if sparse.is_empty() {
            "absent"
        } else {
            "sparse_extents_in_member_payload"
        },
    )?;
    d.set_item("archive.end_zero_blocks", zeros)?;
    let zero_fill = file_size.saturating_sub(offset);
    let mut remaining = zero_fill;
    let mut scan_offset = offset;
    let mut nonzero_tail = false;
    let mut buffer = vec![0u8; 64 * 1024];
    while remaining > 0 {
        let length = remaining.min(buffer.len() as u64) as usize;
        if let Err(fault) = seek_field(
            file,
            scan_offset,
            file_size,
            "tar.archive.end_zero_blocks",
            FieldLocation::Tail,
        )
        .and_then(|_| {
            read_exact_field(
                file,
                &mut buffer[..length],
                file_size,
                "tar.archive.end_zero_blocks",
                FieldLocation::Tail,
            )
        }) {
            set_read_fault(d, &fault, "archive_tail_read_failed")?;
            return Ok(());
        }
        if buffer[..length].iter().any(|byte| *byte != 0) {
            nonzero_tail = true;
            break;
        }
        scan_offset += length as u64;
        remaining -= length as u64;
    }
    let trailing = if nonzero_tail { zero_fill } else { 0 };
    d.set_item(
        "archive.zero_fill_after_end",
        if nonzero_tail { 0 } else { zero_fill },
    )?;
    d.set_item("archive.trailing_data", trailing)?;
    let mut flags = Vec::new();
    if zeros < 2 {
        flags.push("missing_end_block");
    }
    if zeros >= 2 && trailing > 0 {
        flags.push("trailing_junk");
    }
    d.set_item("damage_flags", PyList::new(d.py(), flags)?)?;
    finish_fields(d, TAR_FIELDS)?;
    Ok(())
}

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
        "fuzzy_name_nonempty",
        "fuzzy_numeric_fields_valid",
        "fuzzy_typeflag_valid",
        "fuzzy_payload_in_range",
    ] {
        d.set_item(key, false)?;
    }
    Ok(d)
}

fn walk_tar(
    file: &mut SourceCursor,
    file_size: u64,
    max_entries: usize,
) -> Result<(usize, bool, bool, &'static str), ReadFault> {
    if max_entries == 0 {
        return Ok((0, false, false, ""));
    }
    let mut offset = 0u64;
    let mut zero_blocks = 0usize;
    let mut checked = 0usize;
    while checked < max_entries && offset + TAR_BLOCK_SIZE as u64 <= file_size {
        let mut header = vec![0; TAR_BLOCK_SIZE];
        seek_field(
            file,
            offset,
            file_size,
            "tar.member.header",
            FieldLocation::Body,
        )?;
        read_exact_field(
            file,
            &mut header,
            file_size,
            "tar.member.header",
            FieldLocation::Body,
        )?;
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
