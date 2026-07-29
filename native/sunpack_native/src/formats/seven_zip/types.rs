#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum TargetFormat {
    SevenZip,
}

struct ArchiveCandidate {
    format: TargetFormat,
    offset: usize,
    archive_end: usize,
    start_crc_ok: bool,
    next_header_crc_ok: bool,
    warnings: Vec<String>,
}

pub(crate) struct CarrierScanCandidate {
    pub(crate) offset: usize,
    pub(crate) archive_end: usize,
    pub(crate) start_crc_ok: bool,
    pub(crate) next_header_crc_ok: bool,
    pub(crate) warnings: Vec<String>,
}

struct SevenZipHeader {
    archive_end: usize,
    start_header: [u8; 20],
    next_header_start: usize,
    next_header_offset: u64,
    next_header_size: u64,
    next_header_nid: u8,
    stored_start_crc: u32,
    computed_start_crc: u32,
    stored_next_header_crc: u32,
    computed_next_header_crc: u32,
    next_header_nid_valid: bool,
}

struct SevenZipLooseHeaderFacts {
    stored_start_crc: u32,
    computed_start_crc: u32,
    start_crc_ok: bool,
    next_header_offset: u64,
    next_header_size: u64,
    range_valid: bool,
}

#[derive(Clone, Copy)]
struct SevenZipVintSpan {
    start: usize,
    end: usize,
    value: u64,
}

#[derive(Clone, Copy)]
struct SevenZipCrcSpan {
    start: usize,
    value: u32,
}

struct SevenZipPackInfoAst {
    pack_pos: SevenZipVintSpan,
    num_streams: usize,
    sizes: Vec<SevenZipVintSpan>,
    crc_values: Vec<SevenZipCrcSpan>,
    crc_defined_all: bool,
}

struct SevenZipFilesInfoAst {
    num_files: SevenZipVintSpan,
    empty_stream_property: Option<(usize, usize)>,
    empty_file_property: Option<(usize, usize)>,
    anti_property: Option<(usize, usize)>,
}

#[derive(Clone)]
struct SevenZipCoderAst {
    method_id: Vec<u8>,
    properties: Vec<u8>,
    properties_range: Option<(usize, usize)>,
    num_in_streams: u64,
    num_out_streams: u64,
}

#[derive(Clone)]
struct SevenZipFolderAst {
    coders: Vec<SevenZipCoderAst>,
    bind_pairs: Vec<(u64, u64)>,
    packed_streams: Vec<u64>,
    main_output_stream: u64,
    unpack_size: u64,
    unpack_sizes: Vec<SevenZipVintSpan>,
    expected_crc: Option<SevenZipCrcSpan>,
}

struct SevenZipUnpackInfoAst {
    folders: Vec<SevenZipFolderAst>,
}

struct SevenZipSubStreamsInfoAst {
    num_unpack_streams: Vec<usize>,
    unpack_sizes: Vec<SevenZipVintSpan>,
    unpack_size_values: Vec<u64>,
    crc_values: Vec<Option<SevenZipCrcSpan>>,
}

struct SevenZipStreamsInfoAst {
    pack_info: Option<SevenZipPackInfoAst>,
    unpack_info: Option<SevenZipUnpackInfoAst>,
    substreams_info: Option<SevenZipSubStreamsInfoAst>,
    diagnostics: Vec<String>,
}

struct SevenZipHeaderAst {
    header: Vec<u8>,
    pack_info: Option<SevenZipPackInfoAst>,
    unpack_info: Option<SevenZipUnpackInfoAst>,
    substreams_info: Option<SevenZipSubStreamsInfoAst>,
    files_info: Option<SevenZipFilesInfoAst>,
    diagnostics: Vec<String>,
}

#[derive(Clone)]
struct WrittenArchiveCandidate {
    name: String,
    path: String,
    format: String,
    status: String,
    offset: u64,
    end_offset: u64,
    output_bytes: u64,
    confidence: f64,
    actions: Vec<String>,
    warnings: Vec<String>,
}
