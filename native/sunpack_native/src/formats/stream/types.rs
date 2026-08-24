#[derive(Clone, Copy, Debug)]
enum StreamFormat {
    Gzip,
    Bzip2,
    Xz,
    Zstd,
}

impl StreamFormat {
    fn from_name(value: &str) -> Option<Self> {
        match value
            .trim()
            .trim_start_matches('.')
            .to_ascii_lowercase()
            .as_str()
        {
            "gzip" | "gz" => Some(Self::Gzip),
            "bzip2" | "bz2" => Some(Self::Bzip2),
            "xz" => Some(Self::Xz),
            "zstd" | "zst" => Some(Self::Zstd),
            _ => None,
        }
    }

    fn name(self) -> &'static str {
        match self {
            Self::Gzip => "gzip",
            Self::Bzip2 => "bzip2",
            Self::Xz => "xz",
            Self::Zstd => "zstd",
        }
    }

    fn ext(self) -> &'static str {
        match self {
            Self::Gzip => ".gz",
            Self::Bzip2 => ".bz2",
            Self::Xz => ".xz",
            Self::Zstd => ".zst",
        }
    }
}

#[derive(Clone, Copy, Debug)]
enum CompressedTarFormat {
    Gzip,
    Bzip2,
    Xz,
    Zstd,
}

impl CompressedTarFormat {
    fn from_name(value: &str) -> Option<Self> {
        match value
            .trim()
            .trim_start_matches('.')
            .to_ascii_lowercase()
            .as_str()
        {
            "tar.gz" | "tgz" | "gzip" | "gz" => Some(Self::Gzip),
            "tar.bz2" | "tbz2" | "tbz" | "bzip2" | "bz2" => Some(Self::Bzip2),
            "tar.xz" | "txz" | "xz" => Some(Self::Xz),
            "tar.zst" | "tar.zstd" | "tzst" | "zstd" | "zst" => Some(Self::Zstd),
            _ => None,
        }
    }

    fn stream(self) -> StreamFormat {
        match self {
            Self::Gzip => StreamFormat::Gzip,
            Self::Bzip2 => StreamFormat::Bzip2,
            Self::Xz => StreamFormat::Xz,
            Self::Zstd => StreamFormat::Zstd,
        }
    }

    fn name(self) -> &'static str {
        match self {
            Self::Gzip => "tar.gz",
            Self::Bzip2 => "tar.bz2",
            Self::Xz => "tar.xz",
            Self::Zstd => "tar.zst",
        }
    }

    fn file_stem(self) -> &'static str {
        match self {
            Self::Gzip => "tar_gzip",
            Self::Bzip2 => "tar_bzip2",
            Self::Xz => "tar_xz",
            Self::Zstd => "tar_zstd",
        }
    }

    fn ext(self) -> &'static str {
        match self {
            Self::Gzip => ".tar.gz",
            Self::Bzip2 => ".tar.bz2",
            Self::Xz => ".tar.xz",
            Self::Zstd => ".tar.zst",
        }
    }
}

struct StreamRepairOptions {
    max_input_bytes: Option<u64>,
    max_output_bytes: Option<u64>,
    max_duration: Option<Duration>,
}

struct RecoveryStats {
    decoded_bytes: u64,
    output_bytes: u64,
    error: Option<String>,
    warnings: Vec<String>,
}

struct DecodedPrefix {
    bytes: Vec<u8>,
    decoded_bytes: u64,
    error: Option<String>,
    timed_out: bool,
    warnings: Vec<String>,
}

struct TarPrefixRepair {
    bytes: Vec<u8>,
    tar_bytes: u64,
    members: u64,
    checksum_fixes: u64,
    truncated_members: u64,
    changed: bool,
    warnings: Vec<String>,
}

enum CandidateEncoder {
    Gzip(GzEncoder<TrackedFile>),
    Bzip2(BzEncoder<TrackedFile>),
    Xz(XzEncoder<TrackedFile>),
    Zstd(ZstdEncoder<'static, TrackedFile>),
}

impl CandidateEncoder {
    fn new(format: StreamFormat, file: TrackedFile) -> io::Result<Self> {
        match format {
            StreamFormat::Gzip => Ok(Self::Gzip(GzEncoder::new(file, GzipCompression::default()))),
            StreamFormat::Bzip2 => Ok(Self::Bzip2(BzEncoder::new(
                file,
                Bzip2Compression::default(),
            ))),
            StreamFormat::Xz => Ok(Self::Xz(XzEncoder::new(file, 6))),
            StreamFormat::Zstd => Ok(Self::Zstd(ZstdEncoder::new(file, 0)?)),
        }
    }

    fn write_all(&mut self, bytes: &[u8]) -> io::Result<()> {
        match self {
            Self::Gzip(encoder) => encoder.write_all(bytes),
            Self::Bzip2(encoder) => encoder.write_all(bytes),
            Self::Xz(encoder) => encoder.write_all(bytes),
            Self::Zstd(encoder) => encoder.write_all(bytes),
        }
    }

    fn finish(self) -> io::Result<TrackedFile> {
        match self {
            Self::Gzip(encoder) => encoder.finish(),
            Self::Bzip2(encoder) => encoder.finish(),
            Self::Xz(encoder) => encoder.finish(),
            Self::Zstd(encoder) => encoder.finish(),
        }
    }
}

