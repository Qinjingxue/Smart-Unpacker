fn entropy_windows_py<'py>(
    py: Python<'py>,
    samples: &[WindowProfile],
    threshold: f64,
    high: bool,
) -> PyResult<Bound<'py, PyList>> {
    let list = PyList::empty(py);
    for sample in samples {
        let selected = if high {
            sample.entropy >= threshold
        } else {
            sample.entropy <= threshold
        };
        if selected {
            let dict = PyDict::new(py);
            dict.set_item("offset", sample.offset)?;
            dict.set_item("end_offset", sample.end_offset)?;
            dict.set_item("entropy", sample.entropy)?;
            list.append(dict)?;
        }
    }
    Ok(list)
}

fn ratio_record_py<'py>(py: Python<'py>, sample: &WindowProfile) -> PyResult<Bound<'py, PyDict>> {
    let dict = PyDict::new(py);
    dict.set_item("printable_ratio", sample.printable_ratio)?;
    dict.set_item("control_ratio", sample.control_ratio)?;
    dict.set_item("high_bit_ratio", sample.high_bit_ratio)?;
    dict.set_item("zero_ratio", sample.zero_ratio)?;
    dict.set_item("ff_ratio", sample.ff_ratio)?;
    dict.set_item("offset", sample.offset)?;
    dict.set_item("end_offset", sample.end_offset)?;
    dict.set_item("distinct_bytes", sample.distinct_bytes)?;
    Ok(dict)
}

fn average_ratio_record_py<'py>(
    py: Python<'py>,
    samples: &[WindowProfile],
) -> PyResult<Bound<'py, PyDict>> {
    let dict = PyDict::new(py);
    if samples.is_empty() {
        return Ok(dict);
    }
    let count = samples.len() as f64;
    dict.set_item(
        "printable_ratio",
        samples.iter().map(|item| item.printable_ratio).sum::<f64>() / count,
    )?;
    dict.set_item(
        "control_ratio",
        samples.iter().map(|item| item.control_ratio).sum::<f64>() / count,
    )?;
    dict.set_item(
        "high_bit_ratio",
        samples.iter().map(|item| item.high_bit_ratio).sum::<f64>() / count,
    )?;
    dict.set_item(
        "zero_ratio",
        samples.iter().map(|item| item.zero_ratio).sum::<f64>() / count,
    )?;
    dict.set_item(
        "ff_ratio",
        samples.iter().map(|item| item.ff_ratio).sum::<f64>() / count,
    )?;
    dict.set_item(
        "avg_distinct_bytes",
        samples
            .iter()
            .map(|item| item.distinct_bytes as f64)
            .sum::<f64>()
            / count,
    )?;
    Ok(dict)
}

fn window_run_profile_py<'py>(
    py: Python<'py>,
    profile: &WindowRunProfile,
) -> PyResult<Bound<'py, PyDict>> {
    let dict = PyDict::new(py);
    dict.set_item(
        "longest_zero_run",
        run_record_py(py, &profile.longest_zero_run)?,
    )?;
    dict.set_item(
        "longest_ff_run",
        run_record_py(py, &profile.longest_ff_run)?,
    )?;
    dict.set_item(
        "longest_repeated_byte_run",
        run_record_py(py, &profile.longest_repeated_byte_run)?,
    )?;
    dict.set_item("tail_run", run_record_py(py, &profile.tail_run)?)?;
    Ok(dict)
}

fn run_record_py<'py>(py: Python<'py>, record: &RunRecord) -> PyResult<Bound<'py, PyDict>> {
    let dict = PyDict::new(py);
    match record.byte {
        Some(byte) => dict.set_item("byte", hex_byte(byte))?,
        None => dict.set_item("byte", py.None())?,
    }
    match record.offset {
        Some(offset) => dict.set_item("offset", offset)?,
        None => dict.set_item("offset", py.None())?,
    }
    dict.set_item("length", record.length)?;
    Ok(dict)
}

fn empty_run() -> RunRecord {
    RunRecord {
        byte: None,
        offset: None,
        length: 0,
    }
}

fn record_run(
    target: &mut RunRecord,
    byte: Option<u8>,
    start: usize,
    length: usize,
    base_offset: u64,
) {
    if byte.is_none() || length <= target.length {
        return;
    }
    target.byte = byte;
    target.offset = Some(base_offset + start as u64);
    target.length = length;
}

fn tail_run(offset: u64, data: &[u8]) -> RunRecord {
    let Some(byte) = data.last().copied() else {
        return empty_run();
    };
    let mut length = 0usize;
    for value in data.iter().rev() {
        if *value != byte {
            break;
        }
        length += 1;
    }
    RunRecord {
        byte: Some(byte),
        offset: Some(offset + data.len().saturating_sub(length) as u64),
        length,
    }
}

fn max_run(left: &RunRecord, right: &RunRecord) -> RunRecord {
    if right.length > left.length {
        right.clone()
    } else {
        left.clone()
    }
}
