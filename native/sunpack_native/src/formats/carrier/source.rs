fn write_vint(mut value: u64) -> Vec<u8> {
    let mut output = Vec::new();
    loop {
        let mut byte = (value & 0x7f) as u8;
        value >>= 7;
        if value != 0 {
            byte |= 0x80;
        }
        output.push(byte);
        if value == 0 {
            return output;
        }
    }
}

fn read_source_input(
    source_input: &Bound<'_, PyDict>,
    max_bytes: Option<u64>,
) -> Result<Vec<u8>, String> {
    let kind = get_optional_string(source_input, "kind")
        .map_err(|err| err.to_string())?
        .unwrap_or_else(|| "file".to_string());
    match kind.as_str() {
        "bytes" | "memory" => {
            let data_obj = source_input
                .get_item("data")
                .map_err(|err| err.to_string())?
                .ok_or_else(|| "missing bytes repair input data".to_string())?;
            let data = data_obj
                .cast::<PyBytes>()
                .map_err(|err| err.to_string())?
                .as_bytes();
            if max_bytes.is_some_and(|limit| data.len() as u64 > limit) {
                return Err("archive deep repair input exceeds max_input_size_mb".to_string());
            }
            Ok(data.to_vec())
        }
        "file" => {
            let path = get_required_string(source_input, "path").map_err(|err| err.to_string())?;
            read_range_to_vec(&path, 0, None, max_bytes)
        }
        "file_range" => {
            let path = get_required_string(source_input, "path").map_err(|err| err.to_string())?;
            let start = get_optional_u64(source_input, "start")
                .map_err(|err| err.to_string())?
                .unwrap_or(0);
            let end = get_optional_u64(source_input, "end").map_err(|err| err.to_string())?;
            read_range_to_vec(&path, start, end, max_bytes)
        }
        "concat_ranges" => {
            let ranges_obj = source_input
                .get_item("ranges")
                .map_err(|err| err.to_string())?
                .ok_or_else(|| "missing ranges".to_string())?;
            let ranges = ranges_obj.cast::<PyList>().map_err(|err| err.to_string())?;
            let mut output = Vec::new();
            for item in ranges.iter() {
                let dict = item.cast::<PyDict>().map_err(|err| err.to_string())?;
                let path = get_required_string(dict, "path").map_err(|err| err.to_string())?;
                let start = get_optional_u64(dict, "start")
                    .map_err(|err| err.to_string())?
                    .unwrap_or(0);
                let end = get_optional_u64(dict, "end").map_err(|err| err.to_string())?;
                let remaining_limit =
                    max_bytes.map(|limit| limit.saturating_sub(output.len() as u64));
                let chunk = read_range_to_vec(&path, start, end, remaining_limit)?;
                output.extend_from_slice(&chunk);
                if max_bytes.is_some_and(|limit| output.len() as u64 > limit) {
                    return Err("archive deep repair input exceeds max_input_size_mb".to_string());
                }
            }
            Ok(output)
        }
        _ => Err(format!("unsupported repair input kind: {kind}")),
    }
}

fn read_range_to_vec(
    path: &str,
    start: u64,
    end: Option<u64>,
    max_bytes: Option<u64>,
) -> Result<Vec<u8>, String> {
    crate::io::util::read_source_range(
        path,
        start,
        end,
        max_bytes,
        "archive deep repair input exceeds max_input_size_mb",
    )
}
