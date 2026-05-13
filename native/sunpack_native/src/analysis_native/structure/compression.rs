fn compression_empty(
    py: Python<'_>,
    error: &str,
    format: &str,
    ext: &str,
    magic: bool,
) -> PyResult<Py<PyDict>> {
    let d = dict(py)?;
    d.set_item("plausible", false)?;
    d.set_item("error", error)?;
    d.set_item("magic_matched", magic)?;
    d.set_item("format", format)?;
    d.set_item("detected_ext", ext)?;
    d.set_item("confidence", "none")?;
    let evidence = PyList::empty(py);
    if !format.is_empty() && magic {
        evidence.append(format!("{format}:magic"))?;
    }
    d.set_item("evidence", evidence)?;
    Ok(d.unbind())
}

fn compression_ok(
    py: Python<'_>,
    format: &str,
    ext: &str,
    confidence: &str,
    evidence_items: &[&str],
) -> PyResult<Py<PyDict>> {
    let d = dict(py)?;
    d.set_item("plausible", true)?;
    d.set_item("error", "")?;
    d.set_item("magic_matched", true)?;
    d.set_item("format", format)?;
    d.set_item("detected_ext", ext)?;
    d.set_item("confidence", confidence)?;
    d.set_item("evidence", PyList::new(py, evidence_items)?)?;
    Ok(d.unbind())
}

fn inspect_gzip(py: Python<'_>, header: &[u8], file_size: u64) -> PyResult<Py<PyDict>> {
    if file_size < 18 {
        return compression_empty(py, "gzip_too_small", "gzip", ".gz", true);
    }
    if header.len() < 10 {
        return compression_empty(
            py,
            "short_gzip_header",
            "gzip",
            ".gz",
            header.starts_with(b"\x1f\x8b"),
        );
    }
    if !header.starts_with(b"\x1f\x8b\x08") {
        return compression_empty(py, "gzip_magic_not_found", "", "", false);
    }
    if header[3] & 0xE0 != 0 {
        return compression_empty(py, "gzip_reserved_flags_set", "gzip", ".gz", true);
    }
    compression_ok(
        py,
        "gzip",
        ".gz",
        "medium",
        &["gzip:magic", "gzip:method:deflate", "gzip:flags_valid"],
    )
}

fn inspect_bzip2(py: Python<'_>, header: &[u8], file_size: u64) -> PyResult<Py<PyDict>> {
    if file_size < 14 {
        return compression_empty(py, "bzip2_too_small", "bzip2", ".bz2", true);
    }
    if header.len() < 10 {
        return compression_empty(
            py,
            "short_bzip2_header",
            "bzip2",
            ".bz2",
            header.starts_with(b"BZh"),
        );
    }
    if !header.starts_with(b"BZh") || !b"123456789".contains(&header[3]) {
        return compression_empty(
            py,
            "bzip2_magic_not_found",
            "bzip2",
            ".bz2",
            header.starts_with(b"BZh"),
        );
    }
    if !matches!(
        &header[4..10],
        b"\x31\x41\x59\x26\x53\x59" | b"\x17\x72\x45\x38\x50\x90"
    ) {
        return compression_empty(py, "bzip2_block_marker_not_found", "bzip2", ".bz2", true);
    }
    compression_ok(
        py,
        "bzip2",
        ".bz2",
        "strong",
        &["bzip2:magic", "bzip2:block_marker"],
    )
}

fn inspect_xz(py: Python<'_>, path: &str, header: &[u8], file_size: u64) -> PyResult<Py<PyDict>> {
    if file_size < 24 {
        return compression_empty(py, "xz_too_small", "xz", ".xz", true);
    }
    if header.len() < 12 || !header.starts_with(XZ_MAGIC) {
        return compression_empty(
            py,
            "xz_magic_not_found",
            "xz",
            ".xz",
            header.starts_with(XZ_MAGIC),
        );
    }
    let stream_flags = &header[6..8];
    if u32_le(header, 8) != crc32(stream_flags) {
        return compression_empty(py, "xz_header_crc_mismatch", "xz", ".xz", true);
    }
    let Ok((_, footer)) = read_at(path, file_size - 12, 12) else {
        return compression_empty(py, "os_error", "xz", ".xz", true);
    };
    if footer.len() != 12 || &footer[10..12] != b"YZ" {
        return compression_empty(py, "xz_footer_magic_not_found", "xz", ".xz", true);
    }
    if u32_le(&footer, 0) != crc32(&footer[4..10]) {
        return compression_empty(py, "xz_footer_crc_mismatch", "xz", ".xz", true);
    }
    if &footer[8..10] != stream_flags {
        return compression_empty(py, "xz_stream_flags_mismatch", "xz", ".xz", true);
    }
    compression_ok(
        py,
        "xz",
        ".xz",
        "strong",
        &["xz:magic", "xz:header_crc", "xz:footer_crc"],
    )
}

fn inspect_zstd(py: Python<'_>, header: &[u8], file_size: u64) -> PyResult<Py<PyDict>> {
    if file_size < 6 {
        return compression_empty(py, "zstd_too_small", "zstd", ".zst", true);
    }
    if !header.starts_with(ZSTD_MAGIC) {
        return compression_empty(py, "zstd_magic_not_found", "", "", false);
    }
    if header[4] & 0x08 != 0 {
        return compression_empty(py, "zstd_reserved_bit_set", "zstd", ".zst", true);
    }
    if header[4] & 0x20 == 0 && header.len() < 6 {
        return compression_empty(py, "zstd_window_descriptor_missing", "zstd", ".zst", true);
    }
    compression_ok(
        py,
        "zstd",
        ".zst",
        "medium",
        &["zstd:magic", "zstd:frame_descriptor"],
    )
}
