fn container_empty(py: Python<'_>, error: &str) -> PyResult<Py<PyDict>> {
    let d = dict(py)?;
    d.set_item("plausible", false)?;
    d.set_item("error", error)?;
    d.set_item("format", "")?;
    d.set_item("detected_ext", "")?;
    d.set_item("confidence", "none")?;
    d.set_item("evidence", PyList::empty(py))?;
    Ok(d.unbind())
}

fn container_ok(
    py: Python<'_>,
    format: &str,
    ext: &str,
    evidence_items: &[&str],
) -> PyResult<Py<PyDict>> {
    let d = dict(py)?;
    d.set_item("plausible", true)?;
    d.set_item("error", "")?;
    d.set_item("format", format)?;
    d.set_item("detected_ext", ext)?;
    d.set_item("confidence", "strong")?;
    d.set_item("evidence", PyList::new(py, evidence_items)?)?;
    Ok(d.unbind())
}

fn inspect_cab(py: Python<'_>, header: &[u8], file_size: u64) -> PyResult<Py<PyDict>> {
    if file_size < 36 || header.len() < 36 {
        return container_empty(py, "cab_too_small");
    }
    let cab_size = u32_le(header, 8) as u64;
    let files_offset = u32_le(header, 16) as u64;
    let folder_count = u16_le(header, 26);
    let file_count = u16_le(header, 28);
    if header[25] != 1 || header[24] > 4 {
        return container_empty(py, "cab_version_unsupported");
    }
    if cab_size < 36 || cab_size > file_size {
        return container_empty(py, "cab_size_out_of_range");
    }
    if folder_count == 0 || file_count == 0 {
        return container_empty(py, "cab_empty_folder_or_file_count");
    }
    if files_offset < 36 || files_offset >= cab_size {
        return container_empty(py, "cab_files_offset_out_of_range");
    }
    container_ok(py, "cab", ".cab", &["cab:magic", "cab:header_fields"])
}

fn inspect_arj(py: Python<'_>, header: &[u8], file_size: u64) -> PyResult<Py<PyDict>> {
    if file_size < 10 || header.len() < 10 {
        return container_empty(py, "arj_too_small");
    }
    let header_size = u16_le(header, 2) as usize;
    let header_end = 4 + header_size;
    if header_size < 30 || header_end + 4 > file_size as usize || header_end + 4 > header.len() {
        return container_empty(py, "arj_header_size_out_of_range");
    }
    if u32_le(header, header_end) != crc32(&header[4..header_end]) {
        return container_empty(py, "arj_header_crc_mismatch");
    }
    container_ok(py, "arj", ".arj", &["arj:magic", "arj:header_crc"])
}

fn inspect_cpio(py: Python<'_>, header: &[u8], file_size: u64) -> PyResult<Py<PyDict>> {
    if file_size < 110 || header.len() < 110 {
        return container_empty(py, "cpio_too_small");
    }
    let namesize = parse_hex(&header[94..102]);
    let member_size = parse_hex(&header[54..62]);
    let mode = parse_hex(&header[14..22]);
    if namesize.is_none_or(|v| v == 0 || v > 4096) {
        return container_empty(py, "cpio_invalid_namesize");
    }
    if member_size.is_none() {
        return container_empty(py, "cpio_invalid_filesize");
    }
    if mode.is_none() {
        return container_empty(py, "cpio_invalid_mode");
    }
    if 110 + namesize.unwrap() > file_size {
        return container_empty(py, "cpio_name_out_of_range");
    }
    container_ok(py, "cpio", ".cpio", &["cpio:newc_magic", "cpio:hex_fields"])
}
