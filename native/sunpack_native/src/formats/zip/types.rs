#[derive(Debug, Clone)]
struct DeepZipOptions {
    max_candidates: usize,
    max_entries: usize,
    max_input_bytes: Option<u64>,
    max_output_bytes: Option<u64>,
    max_entry_uncompressed_bytes: Option<u64>,
    max_duration: Option<Duration>,
    verify_candidates: bool,
    allow_unverified_entries: bool,
    password: Option<String>,
}

#[derive(Debug, Clone)]
struct DescriptorDeleteCandidate {
    delete_offset: usize,
    delete_size: usize,
    descriptor_size: usize,
    expected_next_offset: usize,
    actual_next_offset: usize,
    entry_name: Vec<u8>,
    confidence: f64,
}

#[derive(Debug, Clone)]
struct RecoveredEntry {
    name: Vec<u8>,
    extra: Vec<u8>,
    local_header_offset: usize,
    version_needed: u16,
    flags: u16,
    method: u16,
    mod_time: u16,
    mod_date: u16,
    crc32: u32,
    compressed_size: u64,
    uncompressed_size: u64,
    data_start: usize,
    data_end: usize,
    payload_override: Option<Vec<u8>>,
    verified: bool,
    descriptor: bool,
    passthrough: bool,
    boundary_source: BoundarySource,
    experimental_deflate_resync: bool,
}

#[derive(Debug, Default)]
struct ScanResult {
    entries: Vec<RecoveredEntry>,
    warnings: Vec<String>,
    skipped_offsets: Vec<usize>,
    encrypted_entries: usize,
    unsupported_entries: usize,
    descriptor_entries: usize,
    lfh_scanned: usize,
    next_lfh_boundary_entries: usize,
    deflate_consumed_boundary_entries: usize,
    descriptor_signature_entries: usize,
    descriptor_no_signature_entries: usize,
    deflate_resync_partial_entries: usize,
    timed_out: bool,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum BoundarySource {
    HeaderSize,
    NextRecord,
    DeflateConsumed,
    Descriptor,
    DeflateResync,
}

#[derive(Debug)]
struct CandidatePlan {
    name: &'static str,
    indices: Vec<usize>,
    confidence: f64,
    actions: Vec<&'static str>,
    rank_score: i64,
}

#[derive(Debug)]
struct WriteStats {
    entries: usize,
    verified_entries: usize,
    descriptor_entries: usize,
    passthrough_entries: usize,
    size: u64,
}

#[derive(Debug, Clone)]
struct WrittenCandidate {
    name: &'static str,
    policy: &'static str,
    path: String,
    confidence: f64,
    actions: Vec<&'static str>,
    entries: usize,
    verified_entries: usize,
    descriptor_entries: usize,
    passthrough_entries: usize,
    size: u64,
    rank_score: i64,
}

#[derive(Debug)]
struct DeflateInfo {
    consumed: usize,
    uncompressed_size: u64,
    crc32: u32,
}

