struct DirectoryFieldRepair {
    bytes: Vec<u8>,
    patches: Vec<BytePatch>,
    truncate_at: Option<u64>,
    confidence: f64,
    actions: Vec<String>,
    message: String,
}

struct BytePatch {
    offset: u64,
    data: Vec<u8>,
}

#[derive(Clone, Copy)]
struct EocdInfo {
    offset: usize,
    end: usize,
    disk_entries: u16,
    total_entries: u16,
    cd_size: u32,
    cd_offset: u32,
}

#[derive(Clone, Copy)]
struct CdWalk {
    offset: usize,
    end: usize,
    count: usize,
    valid: bool,
}

struct CentralEntry {
    offset: usize,
    flags: u16,
    method: u16,
    crc32: u32,
    compressed_size: u32,
    uncompressed_size: u32,
    name_len: u16,
    extra_len: u16,
    name: Vec<u8>,
    extra: Vec<u8>,
    extra_offset: usize,
    local_header_offset: u32,
}

#[derive(Clone)]
struct LocalHeader {
    offset: usize,
    flags: u16,
    method: u16,
    crc32: u32,
    compressed_size: u32,
    uncompressed_size: u32,
    name: Vec<u8>,
    extra: Vec<u8>,
    extra_offset: usize,
    name_len: u16,
    extra_len: u16,
}

struct Zip64Extra {
    values: Vec<u64>,
    values_offset: usize,
    size_offset: usize,
    stored_size: usize,
}

#[derive(Clone, Copy)]
struct Zip64Eocd {
    offset: usize,
    end: usize,
    cd_size: u64,
    cd_offset: u64,
}

#[derive(Clone, Copy)]
struct Zip64Locator {
    offset: usize,
    end: usize,
    zip64_eocd_offset: u64,
    total_disks: u32,
}

#[derive(Clone, Copy)]
struct DataDescriptorRecord {
    crc32: u32,
}

