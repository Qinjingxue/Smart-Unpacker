fn entropy_class(value: f64, high_threshold: f64, low_threshold: f64) -> &'static str {
    if value >= high_threshold {
        "high"
    } else if value <= low_threshold {
        "low"
    } else {
        "medium"
    }
}

fn confidence_from_delta(delta: f64, threshold: f64) -> f64 {
    if threshold <= 0.0 {
        return 0.5;
    }
    (0.45 + (delta - threshold) / (threshold * 2.0).max(0.1)).min(0.95)
}

fn find_all(data: &[u8], needle: &[u8]) -> Vec<usize> {
    if needle.is_empty() || data.len() < needle.len() {
        return Vec::new();
    }
    let mut result = Vec::new();
    let mut start = 0usize;
    while start + needle.len() <= data.len() {
        let Some(index) = data[start..]
            .windows(needle.len())
            .position(|window| window == needle)
        else {
            break;
        };
        let absolute = start + index;
        result.push(absolute);
        start = absolute + 1;
    }
    result
}

fn hex_byte(byte: u8) -> String {
    format!("0x{byte:02x}")
}
