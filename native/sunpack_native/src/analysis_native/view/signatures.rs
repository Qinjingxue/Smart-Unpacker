fn collect_signature_hits(target: &mut Vec<(&'static str, u64)>, base: u64, data: &[u8]) {
    if data.is_empty() {
        return;
    }
    for (index, byte) in data.iter().enumerate() {
        let candidates = signatures_for_first_byte(*byte);
        if candidates.is_empty() {
            continue;
        }
        for (name, signature) in candidates {
            let end = index + signature.len();
            if end <= data.len() && &data[index..end] == *signature {
                target.push((*name, base + index as u64));
            }
        }
    }
}

fn signatures_for_first_byte(byte: u8) -> &'static [(&'static str, &'static [u8])] {
    match byte {
        b'P' => ANALYSIS_SIGNATURES_P,
        b'R' => ANALYSIS_SIGNATURES_R,
        b'7' => ANALYSIS_SIGNATURES_7,
        0x1f => ANALYSIS_SIGNATURES_GZIP,
        b'B' => ANALYSIS_SIGNATURES_BZIP2,
        0xfd => ANALYSIS_SIGNATURES_XZ,
        b'(' => ANALYSIS_SIGNATURES_ZSTD,
        b'u' => ANALYSIS_SIGNATURES_TAR,
        _ => &[],
    }
}

fn format_for_hit(name: &str) -> &'static str {
    if name.starts_with("zip_") {
        "zip"
    } else if name.starts_with("rar") {
        "rar"
    } else if name == "7z" {
        "7z"
    } else if name == "tar_ustar" {
        "tar"
    } else if name == "gzip" {
        "gzip"
    } else if name == "bzip2" {
        "bzip2"
    } else if name == "xz" {
        "xz"
    } else if name == "zstd" {
        "zstd"
    } else {
        ""
    }
}
