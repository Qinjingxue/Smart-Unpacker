fn windows_py<'py>(py: Python<'py>, samples: &[WindowProfile]) -> PyResult<Bound<'py, PyList>> {
    let list = PyList::empty(py);
    for sample in samples {
        let dict = PyDict::new(py);
        dict.set_item("offset", sample.offset)?;
        dict.set_item("end_offset", sample.end_offset)?;
        dict.set_item("size", sample.size)?;
        dict.set_item("entropy", sample.entropy)?;
        dict.set_item("printable_ratio", sample.printable_ratio)?;
        dict.set_item("control_ratio", sample.control_ratio)?;
        dict.set_item("high_bit_ratio", sample.high_bit_ratio)?;
        dict.set_item("zero_ratio", sample.zero_ratio)?;
        dict.set_item("ff_ratio", sample.ff_ratio)?;
        dict.set_item("distinct_bytes", sample.distinct_bytes)?;
        dict.set_item(
            "run_profile",
            window_run_profile_py(py, &sample.run_profile)?,
        )?;
        list.append(dict)?;
    }
    Ok(list)
}

fn entropy_profile_py<'py>(
    py: Python<'py>,
    samples: &[WindowProfile],
    high_threshold: f64,
    low_threshold: f64,
) -> PyResult<Bound<'py, PyDict>> {
    let dict = PyDict::new(py);
    if samples.is_empty() {
        return Ok(dict);
    }
    let head = &samples[0];
    let tail = samples.last().unwrap();
    let min_entropy = samples
        .iter()
        .map(|item| item.entropy)
        .fold(f64::INFINITY, f64::min);
    let max_entropy = samples
        .iter()
        .map(|item| item.entropy)
        .fold(f64::NEG_INFINITY, f64::max);
    let avg_entropy = samples.iter().map(|item| item.entropy).sum::<f64>() / samples.len() as f64;
    let middle_entropy = if samples.len() > 2 {
        Some(
            samples[1..samples.len() - 1]
                .iter()
                .map(|item| item.entropy)
                .sum::<f64>()
                / (samples.len() - 2) as f64,
        )
    } else {
        None
    };
    let overall_class = if avg_entropy >= high_threshold {
        "high_entropy"
    } else if max_entropy <= low_threshold {
        "low_entropy"
    } else if max_entropy - min_entropy >= 1.5 {
        "mixed_entropy"
    } else {
        "medium_entropy"
    };
    dict.set_item("head_entropy", head.entropy)?;
    dict.set_item("middle_entropy", middle_entropy)?;
    dict.set_item("tail_entropy", tail.entropy)?;
    dict.set_item("min_entropy", min_entropy)?;
    dict.set_item("max_entropy", max_entropy)?;
    dict.set_item("avg_entropy", avg_entropy)?;
    dict.set_item("entropy_range", max_entropy - min_entropy)?;
    dict.set_item(
        "head_class",
        entropy_class(head.entropy, high_threshold, low_threshold),
    )?;
    dict.set_item(
        "middle_class",
        middle_entropy
            .map(|value| entropy_class(value, high_threshold, low_threshold))
            .unwrap_or("unknown"),
    )?;
    dict.set_item(
        "tail_class",
        entropy_class(tail.entropy, high_threshold, low_threshold),
    )?;
    dict.set_item("overall_class", overall_class)?;
    dict.set_item("overall_high_entropy", avg_entropy >= high_threshold)?;
    dict.set_item("overall_low_entropy", max_entropy <= low_threshold)?;
    dict.set_item(
        "local_high_entropy",
        samples.iter().any(|item| item.entropy >= high_threshold),
    )?;
    dict.set_item(
        "local_low_entropy",
        samples.iter().any(|item| item.entropy <= low_threshold),
    )?;
    dict.set_item("head_low_entropy", head.entropy <= low_threshold)?;
    dict.set_item("tail_low_entropy", tail.entropy <= low_threshold)?;
    dict.set_item(
        "high_entropy_windows",
        entropy_windows_py(py, samples, high_threshold, true)?,
    )?;
    dict.set_item(
        "low_entropy_windows",
        entropy_windows_py(py, samples, low_threshold, false)?,
    )?;
    Ok(dict)
}

fn byte_class_profile_py<'py>(
    py: Python<'py>,
    samples: &[WindowProfile],
) -> PyResult<Bound<'py, PyDict>> {
    let dict = PyDict::new(py);
    if samples.is_empty() {
        return Ok(dict);
    }
    dict.set_item("head", ratio_record_py(py, &samples[0])?)?;
    dict.set_item(
        "middle",
        if samples.len() > 2 {
            average_ratio_record_py(py, &samples[1..samples.len() - 1])?
        } else {
            PyDict::new(py)
        },
    )?;
    dict.set_item("tail", ratio_record_py(py, samples.last().unwrap())?)?;
    dict.set_item("average", average_ratio_record_py(py, samples)?)?;
    dict.set_item(
        "max_printable_ratio",
        samples
            .iter()
            .map(|item| item.printable_ratio)
            .fold(0.0, f64::max),
    )?;
    dict.set_item(
        "max_zero_ratio",
        samples
            .iter()
            .map(|item| item.zero_ratio)
            .fold(0.0, f64::max),
    )?;
    dict.set_item(
        "max_ff_ratio",
        samples.iter().map(|item| item.ff_ratio).fold(0.0, f64::max),
    )?;
    dict.set_item(
        "max_control_ratio",
        samples
            .iter()
            .map(|item| item.control_ratio)
            .fold(0.0, f64::max),
    )?;
    dict.set_item(
        "max_high_bit_ratio",
        samples
            .iter()
            .map(|item| item.high_bit_ratio)
            .fold(0.0, f64::max),
    )?;
    Ok(dict)
}

fn anomalies_py<'py>(py: Python<'py>, anomalies: &[WindowAnomaly]) -> PyResult<Bound<'py, PyList>> {
    let list = PyList::empty(py);
    for anomaly in anomalies {
        let dict = PyDict::new(py);
        dict.set_item("type", anomaly.anomaly_type)?;
        dict.set_item("offset", anomaly.offset)?;
        if let Some(value) = anomaly.previous_offset {
            dict.set_item("previous_offset", value)?;
        }
        if let Some(value) = anomaly.next_offset {
            dict.set_item("next_offset", value)?;
        }
        if let Some(value) = anomaly.delta {
            dict.set_item("delta", value)?;
        }
        if let Some(value) = anomaly.direction {
            dict.set_item("direction", value)?;
        }
        if let Some(value) = anomaly.dominant_byte {
            dict.set_item("dominant_byte", value)?;
        }
        dict.set_item("confidence", anomaly.confidence)?;
        dict.set_item("approximate", anomaly.approximate)?;
        list.append(dict)?;
    }
    Ok(list)
}

fn run_profile_py<'py>(py: Python<'py>, samples: &[WindowProfile]) -> PyResult<Bound<'py, PyDict>> {
    let dict = PyDict::new(py);
    if samples.is_empty() {
        return Ok(dict);
    }
    let mut longest_zero = empty_run();
    let mut longest_ff = empty_run();
    let mut longest_repeated = empty_run();
    for sample in samples {
        longest_zero = max_run(&longest_zero, &sample.run_profile.longest_zero_run);
        longest_ff = max_run(&longest_ff, &sample.run_profile.longest_ff_run);
        longest_repeated = max_run(
            &longest_repeated,
            &sample.run_profile.longest_repeated_byte_run,
        );
    }
    let tail = &samples.last().unwrap().run_profile.tail_run;
    let tail_padding_likely = tail.length >= 32usize.max(samples.last().unwrap().size / 8)
        && matches!(tail.byte, Some(0) | Some(0xff));
    dict.set_item("longest_zero_run", run_record_py(py, &longest_zero)?)?;
    dict.set_item("longest_ff_run", run_record_py(py, &longest_ff)?)?;
    dict.set_item(
        "longest_repeated_byte_run",
        run_record_py(py, &longest_repeated)?,
    )?;
    dict.set_item("tail_run", run_record_py(py, tail)?)?;
    dict.set_item("tail_padding_likely", tail_padding_likely)?;
    Ok(dict)
}

fn ngram_sketch_py<'py>(
    py: Python<'py>,
    sample_data: &[(u64, Vec<u8>)],
    top_k: usize,
    max_sample_bytes: usize,
) -> PyResult<Bound<'py, PyDict>> {
    let dict = PyDict::new(py);
    if sample_data.is_empty() || max_sample_bytes == 0 {
        dict.set_item("sampled_bytes", 0usize)?;
        dict.set_item("byte_histogram_top", PyList::empty(py))?;
        dict.set_item("bigram_top", PyList::empty(py))?;
        dict.set_item("magic_like_hits", PyList::empty(py))?;
        dict.set_item("magic_like_density_per_mb", 0.0)?;
        return Ok(dict);
    }
    let mut byte_counts = [0usize; 256];
    let mut bigram_counts: HashMap<[u8; 2], usize> = HashMap::new();
    let mut magic_hits = Vec::new();
    let mut scanned = 0usize;
    for (offset, data) in sample_data {
        if scanned >= max_sample_bytes {
            break;
        }
        let read_len = data.len().min(max_sample_bytes - scanned);
        let chunk = &data[..read_len];
        for byte in chunk {
            byte_counts[*byte as usize] += 1;
        }
        for pair in chunk.windows(2) {
            *bigram_counts.entry([pair[0], pair[1]]).or_insert(0) += 1;
        }
        for (name, magic) in MAGIC_PATTERNS {
            for relative in find_all(chunk, magic) {
                magic_hits.push((*name, *offset + relative as u64));
            }
        }
        scanned += read_len;
    }

    let byte_top = PyList::empty(py);
    let mut byte_pairs = byte_counts
        .iter()
        .copied()
        .enumerate()
        .filter(|(_, count)| *count > 0)
        .collect::<Vec<_>>();
    byte_pairs.sort_by(|left, right| right.1.cmp(&left.1).then_with(|| left.0.cmp(&right.0)));
    for (value, count) in byte_pairs.into_iter().take(top_k) {
        let item = PyDict::new(py);
        item.set_item("byte", hex_byte(value as u8))?;
        item.set_item("value", value)?;
        item.set_item("count", count)?;
        item.set_item("ratio", count as f64 / scanned.max(1) as f64)?;
        byte_top.append(item)?;
    }

    let bigram_top = PyList::empty(py);
    let total_bigrams = bigram_counts.values().sum::<usize>();
    let mut bigram_pairs = bigram_counts.into_iter().collect::<Vec<_>>();
    bigram_pairs.sort_by(|left, right| right.1.cmp(&left.1).then_with(|| left.0.cmp(&right.0)));
    for (value, count) in bigram_pairs.into_iter().take(top_k) {
        let item = PyDict::new(py);
        item.set_item("ngram_hex", format!("{:02x}{:02x}", value[0], value[1]))?;
        item.set_item("values", vec![value[0], value[1]])?;
        item.set_item("count", count)?;
        item.set_item("ratio", count as f64 / total_bigrams.max(1) as f64)?;
        bigram_top.append(item)?;
    }

    let magic_list = PyList::empty(py);
    for (name, offset) in magic_hits.iter().take(top_k) {
        let item = PyDict::new(py);
        item.set_item("name", name)?;
        item.set_item("offset", *offset)?;
        magic_list.append(item)?;
    }
    dict.set_item("sampled_bytes", scanned)?;
    dict.set_item("byte_histogram_top", byte_top)?;
    dict.set_item("bigram_top", bigram_top)?;
    dict.set_item("magic_like_hits", magic_list)?;
    dict.set_item(
        "magic_like_density_per_mb",
        if scanned > 0 {
            magic_hits.len() as f64 * 1024.0 * 1024.0 / scanned as f64
        } else {
            0.0
        },
    )?;
    Ok(dict)
}

fn summary_py<'py>(
    py: Python<'py>,
    samples: &[WindowProfile],
    entropy_profile: &Bound<'py, PyDict>,
    byte_class_profile: &Bound<'py, PyDict>,
) -> PyResult<Bound<'py, PyDict>> {
    let dict = PyDict::new(py);
    if samples.is_empty() {
        return Ok(dict);
    }
    let average = byte_class_profile.get_item("average")?.unwrap();
    dict.set_item("min_entropy", entropy_profile.get_item("min_entropy")?)?;
    dict.set_item("max_entropy", entropy_profile.get_item("max_entropy")?)?;
    dict.set_item("avg_entropy", entropy_profile.get_item("avg_entropy")?)?;
    dict.set_item("avg_printable_ratio", average.get_item("printable_ratio")?)?;
    dict.set_item("avg_zero_ratio", average.get_item("zero_ratio")?)?;
    dict.set_item(
        "overall_entropy_class",
        entropy_profile.get_item("overall_class")?,
    )?;
    Ok(dict)
}

fn hints_py<'py>(
    py: Python<'py>,
    samples: &[WindowProfile],
    anomalies: &[WindowAnomaly],
    run_profile: &Bound<'py, PyDict>,
    ngram_sketch: &Bound<'py, PyDict>,
) -> PyResult<Bound<'py, PyList>> {
    let mut hints = Vec::new();
    if samples.is_empty() {
        return Ok(PyList::empty(py));
    }
    let min_entropy = samples
        .iter()
        .map(|item| item.entropy)
        .fold(f64::INFINITY, f64::min);
    let max_entropy = samples
        .iter()
        .map(|item| item.entropy)
        .fold(f64::NEG_INFINITY, f64::max);
    let avg_entropy = samples.iter().map(|item| item.entropy).sum::<f64>() / samples.len() as f64;
    if avg_entropy >= 6.8 {
        hints.push("high_entropy_body");
    }
    if max_entropy - min_entropy >= 1.5
        || anomalies
            .iter()
            .any(|item| item.anomaly_type == "entropy_jump")
    {
        hints.push("entropy_boundary_shift");
    }
    if samples[0].entropy <= 3.5 {
        hints.push("head_low_entropy");
    }
    if samples.last().unwrap().entropy <= 3.5 {
        hints.push("tail_low_entropy");
    }
    if samples.last().unwrap().printable_ratio >= 0.55 {
        hints.push("tail_printable_region");
    }
    if run_profile
        .get_item("tail_padding_likely")?
        .unwrap()
        .extract::<bool>()?
    {
        hints.push("trailing_padding_likely");
    }
    let magic_hits = ngram_sketch.get_item("magic_like_hits")?.unwrap();
    if magic_hits.len()? > 0 {
        hints.push("magic_like_signature_sampled");
    }
    hints.sort_unstable();
    hints.dedup();
    Ok(PyList::new(py, hints)?)
}
