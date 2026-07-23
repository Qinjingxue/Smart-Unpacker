use pyo3::prelude::*;
use std::fs::File;
use std::io::{self, Read, Seek, SeekFrom};

const CHUNK_BYTES: usize = 1024 * 1024;
const QT_IFW_TAIL_WINDOW_BYTES: u64 = 1024 * 1024;
const QT_IFW_MAGIC_COOKIE: u64 = 0xC2630A1C99D668F8;
const QT_IFW_MAGIC_MARKERS: [u64; 4] = [0x12023233, 0x12023234, 0x12023235, 0x12023236];
const PYINSTALLER_COOKIE: &[u8] = b"MEI\x0c\x0b\x0a\x0b\x0e";
const SQUIRREL_AWARE_VERSION_UTF16: &[u8] =
    b"S\0q\0u\0i\0r\0r\0e\0l\0A\0w\0a\0r\0e\0V\0e\0r\0s\0i\0o\0n\0";
const SQUIRREL_SETUP_LOG_UTF16: &[u8] = b"S\0q\0u\0i\0r\0r\0e\0l\0S\0e\0t\0u\0p\0.\0l\0o\0g\0";

const PROFILES: &[(&str, &[&[u8]])] = &[
    (
        "inno_setup",
        &[b"Inno Setup Setup Data (", b"JR.Inno.Setup"],
    ),
    (
        "squirrel_windows",
        &[SQUIRREL_AWARE_VERSION_UTF16, SQUIRREL_SETUP_LOG_UTF16],
    ),
    ("par_packer", &[b"PAR::Packer", b"PAR_TEMP"]),
    ("nuitka_onefile", &[b"NUITKA_ONEFILE_PARENT"]),
];

/// Identify known executable application/installer bundles without exposing file bytes to Python.
#[pyfunction]
pub(crate) fn executable_runtime_bundle_profile(
    py: Python<'_>,
    path: &str,
    scan_limit_bytes: u64,
    executable_image_end: u64,
) -> String {
    let path = path.to_owned();
    py.detach(move || {
        runtime_bundle_profile_native(&path, scan_limit_bytes, executable_image_end)
            .unwrap_or_default()
    })
}

fn runtime_bundle_profile_native(
    path: &str,
    scan_limit_bytes: u64,
    executable_image_end: u64,
) -> io::Result<String> {
    if path.is_empty() || scan_limit_bytes == 0 {
        return Ok(String::new());
    }

    let image_scan_limit = if executable_image_end > 0 {
        scan_limit_bytes.min(executable_image_end)
    } else {
        scan_limit_bytes
    };
    if let Some(profile) = scan_image_profiles(path, image_scan_limit)? {
        return Ok(profile.to_owned());
    }
    if qt_ifw_tail_layout_matches(path)? {
        return Ok("qt_installer_framework".to_owned());
    }
    if tail_contains(path, PYINSTALLER_COOKIE, 256)? {
        return Ok("pyinstaller".to_owned());
    }
    Ok(String::new())
}

fn scan_image_profiles(path: &str, scan_limit_bytes: u64) -> io::Result<Option<&'static str>> {
    let patterns: Vec<&[u8]> = PROFILES
        .iter()
        .flat_map(|(_, required)| required.iter().copied())
        .collect();
    let overlap = patterns
        .iter()
        .map(|pattern| pattern.len())
        .max()
        .unwrap_or(1)
        .saturating_sub(1);
    let mut matched = vec![false; patterns.len()];
    let mut file = File::open(path)?;
    let mut remaining = scan_limit_bytes;
    let mut carry = Vec::with_capacity(overlap);
    let mut chunk = vec![0u8; CHUNK_BYTES];

    while remaining > 0 {
        let requested = usize::try_from(remaining.min(CHUNK_BYTES as u64)).unwrap_or(CHUNK_BYTES);
        let count = file.read(&mut chunk[..requested])?;
        if count == 0 {
            break;
        }
        let mut sample = Vec::with_capacity(carry.len() + count);
        sample.extend_from_slice(&carry);
        sample.extend_from_slice(&chunk[..count]);
        for (index, pattern) in patterns.iter().enumerate() {
            if !matched[index] && find_subslice(&sample, pattern).is_some() {
                matched[index] = true;
            }
        }
        let mut pattern_index = 0usize;
        for (profile, required) in PROFILES {
            let end = pattern_index + required.len();
            if matched[pattern_index..end].iter().all(|value| *value) {
                return Ok(Some(profile));
            }
            pattern_index = end;
        }
        carry.clear();
        carry.extend_from_slice(&sample[sample.len().saturating_sub(overlap)..]);
        remaining -= count as u64;
    }
    Ok(None)
}

fn qt_ifw_tail_layout_matches(path: &str) -> io::Result<bool> {
    let mut file = File::open(path)?;
    let file_size = file.seek(SeekFrom::End(0))?;
    let window_start = file_size.saturating_sub(QT_IFW_TAIL_WINDOW_BYTES);
    file.seek(SeekFrom::Start(window_start))?;
    let mut tail = Vec::new();
    file.read_to_end(&mut tail)?;
    let cookie = QT_IFW_MAGIC_COOKIE.to_le_bytes();
    let mut search_start = 0usize;
    while let Some(relative) = find_subslice(&tail[search_start..], &cookie) {
        let offset = search_start + relative;
        if offset >= 16 {
            let marker = u64::from_le_bytes(tail[offset - 8..offset].try_into().unwrap());
            let binary_content_size =
                u64::from_le_bytes(tail[offset - 16..offset - 8].try_into().unwrap());
            let end_of_binary_content = window_start + offset as u64 + cookie.len() as u64;
            if QT_IFW_MAGIC_MARKERS.contains(&marker)
                && (24..=end_of_binary_content).contains(&binary_content_size)
            {
                return Ok(true);
            }
        }
        search_start = offset + 1;
    }
    Ok(false)
}

fn tail_contains(path: &str, pattern: &[u8], window_bytes: u64) -> io::Result<bool> {
    let mut file = File::open(path)?;
    let size = file.seek(SeekFrom::End(0))?;
    file.seek(SeekFrom::Start(size.saturating_sub(window_bytes)))?;
    let mut tail = Vec::new();
    file.read_to_end(&mut tail)?;
    Ok(find_subslice(&tail, pattern).is_some())
}

fn find_subslice(haystack: &[u8], needle: &[u8]) -> Option<usize> {
    if needle.is_empty() || needle.len() > haystack.len() {
        return None;
    }
    haystack
        .windows(needle.len())
        .position(|window| window == needle)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_support::temp_file;
    use std::fs;

    #[test]
    fn identifies_profile_split_across_chunks() {
        let mut data = vec![b'x'; CHUNK_BYTES - 4];
        data.extend_from_slice(b"PAR::Packer");
        data.extend_from_slice(b"gap PAR_TEMP");
        let path = temp_file("runtime_profile_chunk", &data);
        let profile = runtime_bundle_profile_native(
            path.to_str().unwrap(),
            data.len() as u64,
            data.len() as u64,
        )
        .unwrap();
        assert_eq!(profile, "par_packer");
        let _ = fs::remove_file(path);
    }

    #[test]
    fn ignores_profile_markers_beyond_the_pe_image() {
        let data = b"MZpayload Inno Setup Setup Data ( gap JR.Inno.Setup";
        let path = temp_file("runtime_profile_overlay", data);
        let profile =
            runtime_bundle_profile_native(path.to_str().unwrap(), data.len() as u64, 2).unwrap();
        assert!(profile.is_empty());
        let _ = fs::remove_file(path);
    }

    #[test]
    fn identifies_qt_ifw_tail_layout() {
        let mut data = b"MZ".to_vec();
        data.extend_from_slice(&[0u8; 64]);
        data.extend_from_slice(&64u64.to_le_bytes());
        data.extend_from_slice(&QT_IFW_MAGIC_MARKERS[0].to_le_bytes());
        data.extend_from_slice(&QT_IFW_MAGIC_COOKIE.to_le_bytes());
        let path = temp_file("runtime_profile_qt", &data);
        let profile = runtime_bundle_profile_native(path.to_str().unwrap(), 2, 2).unwrap();
        assert_eq!(profile, "qt_installer_framework");
        let _ = fs::remove_file(path);
    }
}
