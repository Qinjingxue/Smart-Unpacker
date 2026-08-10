#[derive(Clone)]
struct WindowProfile {
    offset: u64,
    end_offset: u64,
    size: usize,
    entropy: f64,
    printable_ratio: f64,
    control_ratio: f64,
    high_bit_ratio: f64,
    zero_ratio: f64,
    ff_ratio: f64,
    distinct_bytes: usize,
    run_profile: WindowRunProfile,
}

#[derive(Clone)]
struct WindowRunProfile {
    longest_zero_run: RunRecord,
    longest_ff_run: RunRecord,
    longest_repeated_byte_run: RunRecord,
    tail_run: RunRecord,
}

#[derive(Clone)]
struct RunRecord {
    byte: Option<u8>,
    offset: Option<u64>,
    length: usize,
}

#[derive(Clone)]
struct WindowAnomaly {
    anomaly_type: &'static str,
    offset: u64,
    previous_offset: Option<u64>,
    next_offset: Option<u64>,
    delta: Option<f64>,
    direction: Option<&'static str>,
    dominant_byte: Option<&'static str>,
    confidence: f64,
    approximate: bool,
}

struct NgramProfile {
    byte_counts: [usize; 256],
    bigram_counts: Vec<usize>,
    magic_hits: Vec<(&'static str, u64)>,
    sampled_bytes: usize,
}

impl NgramProfile {
    fn new() -> Self {
        Self {
            byte_counts: [0; 256],
            bigram_counts: vec![0; 256 * 256],
            magic_hits: Vec::new(),
            sampled_bytes: 0,
        }
    }
}

struct LogicalVolume {
    path: String,
    start: u64,
    end: u64,
}

struct LogicalVolumes {
    volumes: Vec<LogicalVolume>,
    size: u64,
}
