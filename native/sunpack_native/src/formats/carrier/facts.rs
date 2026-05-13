fn confidence_for_candidate(candidate: &ArchiveCandidate) -> f64 {
    match candidate.format {
        TargetFormat::SevenZip if candidate.start_crc_ok && candidate.next_header_crc_ok => 0.92,
        TargetFormat::SevenZip if candidate.start_crc_ok => 0.82,
        TargetFormat::Rar => 0.86,
        TargetFormat::Zip => 0.88,
        _ => 0.7,
    }
}

fn carrier_crop_patch_facts(format: &str, offset: u64, end_offset: u64) -> Vec<String> {
    vec![
        "fixed_field=carrier_prefix_crop".to_string(),
        "after_archive_carrier_crop".to_string(),
        format!("cropped_format={format}"),
        format!("cropped_start={offset}"),
        format!("cropped_end={end_offset}"),
    ]
}

fn carrier_crop_residual_facts(format: &str) -> Vec<&'static str> {
    if format == "zip" {
        vec![
            "central_directory_bad",
            "content_integrity_bad_or_unknown",
            "payload_hash_mismatch",
        ]
    } else {
        Vec::new()
    }
}

fn candidate_crc32(path: &str) -> String {
    match fs::read(path) {
        Ok(bytes) => format!("{:08x}", crc32(&bytes)),
        Err(_) => String::new(),
    }
}

fn find_all(data: &[u8], needle: &[u8]) -> Vec<usize> {
    if needle.is_empty() || data.len() < needle.len() {
        return Vec::new();
    }
    let mut output = Vec::new();
    let mut start = 0usize;
    while start + needle.len() <= data.len() {
        let Some(index) = find_subslice(&data[start..], needle) else {
            break;
        };
        let absolute = start + index;
        output.push(absolute);
        start = absolute + 1;
    }
    output
}

