const ZIP_LOCAL: &[u8] = b"PK\x03\x04";
const ZIP_EOCD: &[u8] = b"PK\x05\x06";
const RAR4: &[u8] = b"Rar!\x1a\x07\x00";
const RAR5: &[u8] = b"Rar!\x1a\x07\x01\x00";
const SEVEN_ZIP: &[u8] = b"7z\xbc\xaf\x27\x1c";
const GZIP: &[u8] = b"\x1f\x8b\x08";
const BZIP2: &[u8] = b"BZh";
const XZ: &[u8] = b"\xfd7zXZ\x00";
const ZSTD: &[u8] = b"\x28\xb5\x2f\xfd";
const TAR_USTAR: &[u8] = b"ustar";

const MAGIC_PATTERNS: &[(&str, &[u8])] = &[
    ("zip_local", ZIP_LOCAL),
    ("zip_eocd", ZIP_EOCD),
    ("rar4", RAR4),
    ("rar5", RAR5),
    ("7z", SEVEN_ZIP),
    ("gzip", GZIP),
    ("bzip2", BZIP2),
    ("xz", XZ),
    ("zstd", ZSTD),
    ("tar_ustar", TAR_USTAR),
];

pub(crate) struct BinaryProfileConfig {
    pub(crate) window_bytes: usize,
    pub(crate) max_windows: usize,
    pub(crate) max_sample_bytes: usize,
    pub(crate) entropy_high_threshold: f64,
    pub(crate) entropy_low_threshold: f64,
    pub(crate) entropy_jump_threshold: f64,
    pub(crate) ngram_top_k: usize,
    pub(crate) max_ngram_sample_bytes: usize,
}
