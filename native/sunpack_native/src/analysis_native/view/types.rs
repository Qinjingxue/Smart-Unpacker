#[pyclass]
pub(crate) struct AnalysisBinaryView {
    inner: Mutex<AnalysisBinaryViewInner>,
    read_gate: ReadGate,
}

#[pyclass]
pub(crate) struct AnalysisMultiVolumeView {
    inner: Mutex<AnalysisMultiVolumeViewInner>,
    read_gate: ReadGate,
}

struct AnalysisBinaryViewInner {
    path: String,
    size: u64,
    cache_bytes: usize,
    max_read_bytes: Option<u64>,
    cache: HashMap<(u64, usize), Vec<u8>>,
    order: VecDeque<(u64, usize)>,
    cache_size: usize,
    read_bytes: u64,
    cache_hits: u64,
}

struct AnalysisMultiVolumeViewInner {
    path: String,
    size: u64,
    volumes: Vec<VolumeRange>,
    cache_bytes: usize,
    max_read_bytes: Option<u64>,
    cache: HashMap<(u64, usize), Vec<u8>>,
    order: VecDeque<(u64, usize)>,
    cache_size: usize,
    read_bytes: u64,
    cache_hits: u64,
}

#[derive(Clone)]
struct VolumeRange {
    start: u64,
    end: u64,
    path: String,
}

#[derive(Clone)]
struct VolumeRead {
    path: String,
    start: u64,
    size: usize,
}

struct ReadGate {
    limit: usize,
    active: Mutex<usize>,
    available: Condvar,
}

struct ReadPermit<'a> {
    gate: &'a ReadGate,
}
