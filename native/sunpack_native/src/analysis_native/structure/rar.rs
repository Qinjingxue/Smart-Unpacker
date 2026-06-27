fn rar_empty<'py>(py: Python<'py>, error: &str) -> PyResult<Bound<'py, PyDict>> {
    let d = dict(py)?;
    d.set_item("plausible", false)?;
    d.set_item("error", error)?;
    d.set_item("magic_matched", false)?;
    d.set_item("format", "")?;
    d.set_item("detected_ext", "")?;
    for key in [
        "version",
        "first_header_offset",
        "first_header_size",
        "first_header_type",
        "second_block_type",
        "second_block_size",
    ] {
        d.set_item(key, 0)?;
    }
    for key in [
        "header_crc_checked",
        "header_crc_ok",
        "second_block_checked",
        "second_block_ok",
        "block_walk_ok",
        "strong_accept",
    ] {
        d.set_item(key, false)?;
    }
    d.set_item("confidence", "none")?;
    d.set_item("evidence", PyList::empty(py))?;
    Ok(d)
}

fn inspect_rar4(py: Python<'_>, data: &[u8], file_size: u64) -> PyResult<Py<PyDict>> {
    let first_header_offset = RAR4_SIGNATURE.len();
    if file_size < first_header_offset as u64 + 7 || data.len() < first_header_offset + 7 {
        return Ok(rar_empty(py, "rar4_first_header_too_small")?.unbind());
    }
    let header_crc = u16_le(data, first_header_offset);
    let header_type = data[first_header_offset + 2];
    let header_size = u16_le(data, first_header_offset + 5) as u64;
    let d = rar_empty(py, "")?;
    d.set_item("magic_matched", true)?;
    d.set_item("format", "rar")?;
    d.set_item("detected_ext", ".rar")?;
    d.set_item("version", 4)?;
    d.set_item("first_header_offset", first_header_offset)?;
    d.set_item("first_header_size", header_size)?;
    d.set_item("first_header_type", header_type)?;
    let evidence = PyList::new(py, ["rar4:signature"])?;
    d.set_item("evidence", &evidence)?;
    if !matches!(header_type, 0x73..=0x7B) {
        d.set_item("error", "rar4_unknown_first_header_type")?;
        return Ok(d.unbind());
    }
    if header_size < 7 || first_header_offset as u64 + header_size > file_size {
        d.set_item("error", "rar4_first_header_size_out_of_range")?;
        return Ok(d.unbind());
    }
    d.set_item("plausible", true)?;
    d.set_item("confidence", "strong")?;
    evidence.append("rar4:first_header")?;
    if data.len() >= first_header_offset + header_size as usize {
        let full_header = &data[first_header_offset..first_header_offset + header_size as usize];
        let crc_ok = (crc32(&full_header[2..]) & 0xFFFF) == header_crc as u32;
        d.set_item("header_crc_checked", true)?;
        d.set_item("header_crc_ok", crc_ok)?;
        if crc_ok {
            evidence.append("rar4:header_crc")?;
        } else if header_type == 0x73 {
            d.set_item("error", "rar4_header_crc_mismatch")?;
        }
    }
    let second_offset = first_header_offset + header_size as usize;
    if header_type == 0x73
        && d.get_item("header_crc_ok")?.unwrap().extract::<bool>()?
        && second_offset < file_size as usize
    {
        let second = inspect_rar4_block(data, second_offset, file_size);
        d.set_item("second_block_checked", true)?;
        d.set_item("second_block_ok", second.0)?;
        d.set_item("second_block_type", second.1)?;
        d.set_item("second_block_size", second.2)?;
        d.set_item("block_walk_ok", second.0)?;
        if second.0 {
            evidence.append("rar4:second_block")?;
        } else {
            d.set_item("error", second.3)?;
        }
    }
    if header_type == 0x73
        && d.get_item("header_crc_ok")?.unwrap().extract::<bool>()?
        && (second_offset >= file_size as usize
            || d.get_item("block_walk_ok")?.unwrap().extract::<bool>()?)
    {
        d.set_item("strong_accept", true)?;
    }
    Ok(d.unbind())
}

fn inspect_rar4_block(data: &[u8], offset: usize, file_size: u64) -> (bool, u8, u64, &'static str) {
    if offset >= file_size as usize || data.len() < offset + 7 {
        return (false, 0, 0, "rar4_second_block_too_small");
    }
    let header_crc = u16_le(data, offset);
    let header_type = data[offset + 2];
    let header_flags = u16_le(data, offset + 3);
    let header_size = u16_le(data, offset + 5) as u64;
    if !matches!(header_type, 0x73..=0x7B) {
        return (
            false,
            header_type,
            header_size,
            "rar4_second_block_unknown_type",
        );
    }
    if header_size < 7
        || offset as u64 + header_size > file_size
        || data.len() < offset + header_size as usize
    {
        return (
            false,
            header_type,
            header_size,
            "rar4_second_block_size_out_of_range",
        );
    }
    let full_header = &data[offset..offset + header_size as usize];
    if (crc32(&full_header[2..]) & 0xFFFF) != header_crc as u32 {
        return (
            false,
            header_type,
            header_size,
            "rar4_second_block_crc_mismatch",
        );
    }
    let mut block_size = header_size;
    if header_flags & 0x8000 != 0 {
        if header_size < 11 {
            return (
                false,
                header_type,
                block_size,
                "rar4_second_block_add_size_missing",
            );
        }
        block_size += u32_le(full_header, 7) as u64;
        if offset as u64 + block_size > file_size {
            return (
                false,
                header_type,
                block_size,
                "rar4_second_block_payload_out_of_range",
            );
        }
    }
    (true, header_type, block_size, "")
}

fn inspect_rar5(py: Python<'_>, data: &[u8], file_size: u64) -> PyResult<Py<PyDict>> {
    let first_header_offset = RAR5_SIGNATURE.len();
    if file_size < first_header_offset as u64 + 6 || data.len() < first_header_offset + 6 {
        return Ok(rar_empty(py, "rar5_first_header_too_small")?.unbind());
    }
    let Some((header_size, after_size)) = read_vint(data, first_header_offset + 4) else {
        return Ok(rar_empty(py, "rar5_header_size_vint_missing")?.unbind());
    };
    if after_size.saturating_sub(first_header_offset + 4) > 3 {
        return Ok(rar_empty(py, "rar5_header_size_vint_too_long")?.unbind());
    }
    let Some((header_type, _)) = read_vint(data, after_size) else {
        return Ok(rar_empty(py, "rar5_header_type_vint_missing")?.unbind());
    };
    let d = rar_empty(py, "")?;
    d.set_item("magic_matched", true)?;
    d.set_item("format", "rar")?;
    d.set_item("detected_ext", ".rar")?;
    d.set_item("version", 5)?;
    d.set_item("first_header_offset", first_header_offset)?;
    d.set_item("first_header_size", header_size)?;
    d.set_item("first_header_type", header_type)?;
    let evidence = PyList::new(py, ["rar5:signature"])?;
    d.set_item("evidence", &evidence)?;
    if !matches!(header_type, 1 | 4) {
        d.set_item("error", "rar5_main_or_encryption_header_missing")?;
        return Ok(d.unbind());
    }
    let first_header_total_size = 4 + (after_size - (first_header_offset + 4)) as u64 + header_size;
    if header_size == 0 || first_header_offset as u64 + first_header_total_size > file_size {
        d.set_item("error", "rar5_first_header_size_out_of_range")?;
        return Ok(d.unbind());
    }
    d.set_item("plausible", true)?;
    d.set_item("confidence", "strong")?;
    evidence.append("rar5:first_header")?;
    if data.len() >= first_header_offset + first_header_total_size as usize {
        let stored_crc = u32_le(data, first_header_offset);
        let header_data =
            &data[first_header_offset + 4..first_header_offset + first_header_total_size as usize];
        let crc_ok = crc32(header_data) == stored_crc;
        d.set_item("header_crc_checked", true)?;
        d.set_item("header_crc_ok", crc_ok)?;
        if crc_ok {
            evidence.append("rar5:header_crc")?;
        } else {
            d.set_item("error", "rar5_header_crc_mismatch")?;
        }
    }
    if header_type == 4 && d.get_item("header_crc_ok")?.unwrap().extract::<bool>()? {
        d.set_item("header_encrypted", true)?;
        d.set_item("password_required", true)?;
        d.set_item("strong_accept", true)?;
        d.set_item("block_walk_ok", true)?;
        evidence.append("rar5:archive_encryption_header")?;
        return Ok(d.unbind());
    }
    let second_offset = first_header_offset + first_header_total_size as usize;
    if header_type == 1
        && d.get_item("header_crc_ok")?.unwrap().extract::<bool>()?
        && second_offset < file_size as usize
    {
        let second = inspect_rar5_block(data, second_offset, file_size);
        d.set_item("second_block_checked", true)?;
        d.set_item("second_block_ok", second.0)?;
        d.set_item("second_block_type", second.1)?;
        d.set_item("second_block_size", second.2)?;
        d.set_item("block_walk_ok", second.0)?;
        if second.0 {
            evidence.append("rar5:second_header")?;
        } else {
            d.set_item("error", second.3)?;
        }
    }
    if header_type == 1
        && d.get_item("header_crc_ok")?.unwrap().extract::<bool>()?
        && (second_offset >= file_size as usize
            || d.get_item("block_walk_ok")?.unwrap().extract::<bool>()?)
    {
        d.set_item("strong_accept", true)?;
    }
    Ok(d.unbind())
}

fn inspect_rar5_block(
    data: &[u8],
    offset: usize,
    file_size: u64,
) -> (bool, u64, u64, &'static str) {
    if offset >= file_size as usize || data.len() < offset + 6 {
        return (false, 0, 0, "rar5_second_header_too_small");
    }
    let Some((header_size, after_size)) = read_vint(data, offset + 4) else {
        return (false, 0, 0, "rar5_second_header_size_vint_missing");
    };
    if after_size.saturating_sub(offset + 4) > 3 {
        return (false, 0, header_size, "rar5_second_header_size_vint_too_long");
    }
    let Some((header_type, after_type)) = read_vint(data, after_size) else {
        return (
            false,
            0,
            header_size,
            "rar5_second_header_type_vint_missing",
        );
    };
    let Some((header_flags, _)) = read_vint(data, after_type) else {
        return (false, header_type, header_size, "rar5_second_header_flags_vint_missing");
    };
    if !matches!(header_type, 1..=5) && header_flags & 0x0004 == 0 {
        return (
            false,
            header_type,
            header_size,
            "rar5_second_header_unknown_type",
        );
    }
    let header_total_size = 4 + (after_size - (offset + 4)) as u64 + header_size;
    if header_size == 0
        || offset as u64 + header_total_size > file_size
        || data.len() < offset + header_total_size as usize
    {
        return (
            false,
            header_type,
            header_size,
            "rar5_second_header_size_out_of_range",
        );
    }
    let stored_crc = u32_le(data, offset);
    let header_data = &data[offset + 4..offset + header_total_size as usize];
    if crc32(header_data) != stored_crc {
        return (
            false,
            header_type,
            header_size,
            "rar5_second_header_crc_mismatch",
        );
    }
    (true, header_type, header_total_size, "")
}
