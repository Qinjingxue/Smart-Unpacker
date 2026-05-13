fn seven_empty<'py>(py: Python<'py>, error: &str) -> PyResult<Bound<'py, PyDict>> {
    let d = dict(py)?;
    d.set_item("plausible", false)?;
    d.set_item("error", error)?;
    d.set_item("magic_matched", false)?;
    d.set_item("format", "")?;
    d.set_item("detected_ext", "")?;
    for key in [
        "version_major",
        "version_minor",
        "next_header_offset",
        "next_header_size",
        "next_header_crc",
        "next_header_nid",
    ] {
        d.set_item(key, 0)?;
    }
    for key in [
        "start_header_crc_ok",
        "next_header_crc_checked",
        "next_header_crc_ok",
        "next_header_nid_valid",
        "next_header_semantic_ok",
        "strong_accept",
    ] {
        d.set_item(key, false)?;
    }
    d.set_item("confidence", "none")?;
    d.set_item("evidence", PyList::empty(py))?;
    Ok(d)
}
