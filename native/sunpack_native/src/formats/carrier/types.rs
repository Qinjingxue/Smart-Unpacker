#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum TargetFormat {
    SevenZip,
    Rar,
    Zip,
    Any,
}

impl TargetFormat {
    fn from_name(value: &str) -> Self {
        match value
            .trim()
            .trim_start_matches('.')
            .to_ascii_lowercase()
            .as_str()
        {
            "7z" | "seven_zip" | "sevenzip" => Self::SevenZip,
            "rar" => Self::Rar,
            "zip" => Self::Zip,
            _ => Self::Any,
        }
    }

    fn name(self) -> &'static str {
        match self {
            Self::SevenZip => "7z",
            Self::Rar => "rar",
            Self::Zip => "zip",
            Self::Any => "archive",
        }
    }

    fn ext(self) -> &'static str {
        match self {
            Self::SevenZip => ".7z",
            Self::Rar => ".rar",
            Self::Zip => ".zip",
            Self::Any => ".bin",
        }
    }
}

struct ArchiveCandidate {
    format: TargetFormat,
    offset: usize,
    #[cfg(test)]
    archive_end: usize,
    start_crc_ok: bool,
    next_header_crc_ok: bool,
    warnings: Vec<String>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum RarVersion {
    Rar4,
    Rar5,
}

struct RarWalk {
    version: RarVersion,
    offset: usize,
    last_complete_end: usize,
    end_block_found: bool,
    header_encrypted: bool,
    missing_volume: bool,
    last_block_can_precede_end: bool,
    warnings: Vec<String>,
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

