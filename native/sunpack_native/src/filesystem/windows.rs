use super::WatchFileObservation;
use std::collections::HashMap;
use std::ffi::{c_void, OsStr};
use std::io;
use std::os::windows::ffi::OsStrExt;
use std::path::Path;
use std::ptr::{null, null_mut};
use std::sync::{Arc, Mutex, OnceLock};

type Handle = *mut c_void;

const INVALID_HANDLE_VALUE: Handle = -1isize as Handle;
const GENERIC_READ: u32 = 0x8000_0000;
const FILE_READ_ATTRIBUTES: u32 = 0x0000_0080;
const FILE_SHARE_READ: u32 = 0x0000_0001;
const FILE_SHARE_WRITE: u32 = 0x0000_0002;
const FILE_SHARE_DELETE: u32 = 0x0000_0004;
const OPEN_EXISTING: u32 = 3;
const FILE_ATTRIBUTE_NORMAL: u32 = 0x0000_0080;
const FILE_FLAG_BACKUP_SEMANTICS: u32 = 0x0200_0000;
const FSCTL_READ_FILE_USN_DATA: u32 = 0x0009_00eb;
const FSCTL_QUERY_USN_JOURNAL: u32 = 0x0009_00f4;
const FSCTL_READ_USN_JOURNAL: u32 = 0x0009_00bb;
const ALL_USN_REASONS: u32 = 0xffff_ffff;
const USN_REASON_CLOSE: u32 = 0x8000_0000;
const JOURNAL_BUFFER_BYTES: usize = 64 * 1024;
const MAX_JOURNAL_BYTES_PER_OBSERVATION: usize = 1024 * 1024;
// Volume journal reads normally require an elevated token. Cache capability
// failures per volume so one inaccessible volume does not disable all others.
static VOLUME_CONTEXTS: OnceLock<Mutex<HashMap<String, Arc<Mutex<VolumeContext>>>>> =
    OnceLock::new();
const ERROR_SHARING_VIOLATION: i32 = 32;
const ERROR_LOCK_VIOLATION: i32 = 33;
const ERROR_INVALID_HANDLE: i32 = 6;
const ERROR_NOT_READY: i32 = 21;
const ERROR_DEVICE_NOT_CONNECTED: i32 = 1167;

#[derive(Default)]
struct ChangeReasons {
    all: u32,
    without_close: u32,
}

impl ChangeReasons {
    fn observe(&mut self, reason: u32) {
        self.all |= reason;
        // NTFS may defer all accumulated write reasons until the handle-close
        // record. That record is useful evidence, but treating it as a new
        // write interval at the quiet boundary creates a feedback loop.
        if reason & USN_REASON_CLOSE == 0 {
            self.without_close |= reason;
        }
    }
}

#[repr(C)]
struct ReadFileUsnData {
    min_major_version: u16,
    max_major_version: u16,
}

#[repr(C)]
struct ReadUsnJournalData {
    start_usn: i64,
    reason_mask: u32,
    return_only_on_close: u32,
    timeout: u64,
    bytes_to_wait_for: u64,
    usn_journal_id: u64,
}

fn read_usn_journal_request(start_usn: i64, usn_journal_id: u64) -> ReadUsnJournalData {
    ReadUsnJournalData {
        start_usn,
        reason_mask: ALL_USN_REASONS,
        return_only_on_close: 0,
        timeout: 0,
        bytes_to_wait_for: 0,
        usn_journal_id,
    }
}

#[link(name = "Kernel32")]
extern "system" {
    fn CreateFileW(
        file_name: *const u16,
        desired_access: u32,
        share_mode: u32,
        security_attributes: *const c_void,
        creation_disposition: u32,
        flags_and_attributes: u32,
        template_file: Handle,
    ) -> Handle;
    fn DeviceIoControl(
        device: Handle,
        control_code: u32,
        input_buffer: *const c_void,
        input_buffer_size: u32,
        output_buffer: *mut c_void,
        output_buffer_size: u32,
        bytes_returned: *mut u32,
        overlapped: *mut c_void,
    ) -> i32;
    fn CloseHandle(object: Handle) -> i32;
    fn GetVolumePathNameW(file_name: *const u16, volume_path: *mut u16, buffer_length: u32) -> i32;
    fn GetVolumeNameForVolumeMountPointW(
        volume_mount_point: *const u16,
        volume_name: *mut u16,
        buffer_length: u32,
    ) -> i32;
    fn GetVolumeInformationW(
        root_path_name: *const u16,
        volume_name: *mut u16,
        volume_name_size: u32,
        volume_serial_number: *mut u32,
        maximum_component_length: *mut u32,
        file_system_flags: *mut u32,
        file_system_name: *mut u16,
        file_system_name_size: u32,
    ) -> i32;
}

struct OwnedHandle(isize);

impl OwnedHandle {
    fn raw(&self) -> Handle {
        self.0 as Handle
    }
}

impl Drop for OwnedHandle {
    fn drop(&mut self) {
        unsafe {
            CloseHandle(self.raw());
        }
    }
}

struct VolumeContext {
    handle: Option<OwnedHandle>,
    reason_read_unavailable_error: Option<i32>,
}

impl VolumeContext {
    fn new() -> Self {
        Self {
            handle: None,
            reason_read_unavailable_error: None,
        }
    }
}

pub(super) fn filesystem_type(path: &Path) -> io::Result<String> {
    let path = canonical_wide(path)?;
    let mut volume_path = vec![0u16; 32768];
    if unsafe {
        GetVolumePathNameW(
            path.as_ptr(),
            volume_path.as_mut_ptr(),
            volume_path.len() as u32,
        )
    } == 0
    {
        return Err(io::Error::last_os_error());
    }
    let mut filesystem_name = vec![0u16; 64];
    if unsafe {
        GetVolumeInformationW(
            volume_path.as_ptr(),
            null_mut(),
            0,
            null_mut(),
            null_mut(),
            null_mut(),
            filesystem_name.as_mut_ptr(),
            filesystem_name.len() as u32,
        )
    } == 0
    {
        return Err(io::Error::last_os_error());
    }
    Ok(String::from_utf16_lossy(nul_terminated(&filesystem_name)))
}

pub(super) fn watch_file_observation(
    path: &Path,
    since_usn: Option<i64>,
) -> io::Result<WatchFileObservation> {
    let metadata = std::fs::metadata(path)?;
    let handle = open_path(
        path,
        FILE_READ_ATTRIBUTES,
        FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
        metadata.is_dir(),
    )?;
    let mut observation = read_file_usn(handle.raw())?;
    if let Some(previous_usn) = since_usn.filter(|value| *value > 0) {
        if observation.change_usn > previous_usn {
            match read_change_reasons(
                path,
                &observation.file_id,
                previous_usn,
                observation.change_usn,
            ) {
                Ok(reasons) => {
                    observation.change_reasons = reasons.all;
                    observation.change_reasons_without_close = reasons.without_close;
                    observation.change_reasons_known = true;
                }
                Err(error) => {
                    observation.change_reason_error = error.to_string();
                }
            }
        } else if observation.change_usn == previous_usn {
            observation.change_reasons_known = true;
        }
    }
    Ok(observation)
}

pub(super) fn watch_file_is_ready(path: &Path) -> io::Result<bool> {
    let metadata = std::fs::metadata(path)?;
    // Permit antivirus/indexer readers while still conflicting with any
    // handle that requested write access. Requiring share_mode=0 made a
    // completed archive wait several seconds for unrelated readers.
    match open_path(
        path,
        GENERIC_READ,
        FILE_SHARE_READ | FILE_SHARE_DELETE,
        metadata.is_dir(),
    ) {
        Ok(_handle) => Ok(true),
        Err(error)
            if matches!(
                error.raw_os_error(),
                Some(ERROR_SHARING_VIOLATION) | Some(ERROR_LOCK_VIOLATION)
            ) =>
        {
            Ok(false)
        }
        Err(error) => Err(error),
    }
}

fn open_path(
    path: &Path,
    desired_access: u32,
    share_mode: u32,
    is_directory: bool,
) -> io::Result<OwnedHandle> {
    let path = canonical_wide(path)?;
    let flags = if is_directory {
        FILE_FLAG_BACKUP_SEMANTICS
    } else {
        FILE_ATTRIBUTE_NORMAL
    };
    let handle = unsafe {
        CreateFileW(
            path.as_ptr(),
            desired_access,
            share_mode,
            null(),
            OPEN_EXISTING,
            flags,
            null_mut(),
        )
    };
    if handle == INVALID_HANDLE_VALUE {
        return Err(io::Error::last_os_error());
    }
    Ok(OwnedHandle(handle as isize))
}

fn read_file_usn(handle: Handle) -> io::Result<WatchFileObservation> {
    let request = ReadFileUsnData {
        min_major_version: 2,
        max_major_version: 4,
    };
    let mut output = vec![0u8; 4096];
    let mut bytes_returned = 0u32;
    if unsafe {
        DeviceIoControl(
            handle,
            FSCTL_READ_FILE_USN_DATA,
            &request as *const _ as *const c_void,
            std::mem::size_of::<ReadFileUsnData>() as u32,
            output.as_mut_ptr() as *mut c_void,
            output.len() as u32,
            &mut bytes_returned,
            null_mut(),
        )
    } == 0
    {
        return Err(io::Error::last_os_error());
    }
    let bytes = &output[..bytes_returned as usize];
    if bytes.len() < 32 {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "NTFS returned a truncated USN record",
        ));
    }
    let record_length = u32::from_le_bytes(bytes[0..4].try_into().unwrap()) as usize;
    let major_version = u16::from_le_bytes(bytes[4..6].try_into().unwrap());
    if record_length > bytes.len() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "NTFS returned an invalid USN record length",
        ));
    }
    let (file_id_end, usn_offset) = match major_version {
        2 => (16, 24),
        3 | 4 => (24, 40),
        version => {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                format!("unsupported USN record version {version}"),
            ))
        }
    };
    if bytes.len() < usn_offset + 8 {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "NTFS returned a truncated USN identity",
        ));
    }
    let change_usn = i64::from_le_bytes(bytes[usn_offset..usn_offset + 8].try_into().unwrap());
    if change_usn <= 0 {
        return Err(io::Error::new(
            io::ErrorKind::Unsupported,
            "NTFS USN journal is unavailable for this path",
        ));
    }
    let file_id = bytes[8..file_id_end]
        .iter()
        .rev()
        .map(|byte| format!("{byte:02x}"))
        .collect::<String>();
    Ok(WatchFileObservation {
        file_id,
        change_usn,
        change_reasons: 0,
        change_reasons_without_close: 0,
        change_reasons_known: false,
        change_reason_error: String::new(),
    })
}

fn read_change_reasons(
    path: &Path,
    expected_file_id: &str,
    previous_usn: i64,
    current_usn: i64,
) -> io::Result<ChangeReasons> {
    with_volume_context(path, |volume| {
        let journal_id = query_journal_id(volume)?;
        read_change_reasons_from_volume(
            volume,
            journal_id,
            expected_file_id,
            previous_usn,
            current_usn,
        )
    })
}

fn read_change_reasons_from_volume(
    volume: Handle,
    journal_id: u64,
    expected_file_id: &str,
    previous_usn: i64,
    current_usn: i64,
) -> io::Result<ChangeReasons> {
    // StartUsn is a journal byte position and must stay on a record boundary;
    // adding one produces ERROR_INVALID_PARAMETER. The record filter below
    // keeps the interval logically exclusive of previous_usn.
    let mut next_usn = previous_usn;
    let mut scanned_bytes = 0usize;
    let mut reasons = ChangeReasons::default();
    let mut found = false;

    while next_usn <= current_usn {
        let request = read_usn_journal_request(next_usn, journal_id);
        let mut output = vec![0u8; JOURNAL_BUFFER_BYTES];
        let bytes_returned = device_io_control(
            volume,
            FSCTL_READ_USN_JOURNAL,
            &request as *const _ as *const c_void,
            std::mem::size_of::<ReadUsnJournalData>() as u32,
            &mut output,
        )?;
        if bytes_returned < 8 {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "truncated USN journal reply",
            ));
        }
        scanned_bytes = scanned_bytes.saturating_add(bytes_returned);
        if scanned_bytes > MAX_JOURNAL_BYTES_PER_OBSERVATION {
            return Err(io::Error::new(
                io::ErrorKind::Other,
                "USN journal observation exceeded scan budget",
            ));
        }
        let returned_next = i64::from_le_bytes(output[0..8].try_into().unwrap());
        let mut offset = 8usize;
        while offset + 8 <= bytes_returned {
            let record_length =
                u32::from_le_bytes(output[offset..offset + 4].try_into().unwrap()) as usize;
            if record_length < 8 || offset + record_length > bytes_returned {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    "invalid USN journal record",
                ));
            }
            let record = &output[offset..offset + record_length];
            if let Some(reason) =
                record_change_reason(record, expected_file_id, previous_usn, current_usn)?
            {
                found = true;
                reasons.observe(reason);
            }
            offset += record_length;
        }
        if returned_next <= next_usn || returned_next > current_usn {
            break;
        }
        next_usn = returned_next;
    }
    if !found {
        return Err(io::Error::new(
            io::ErrorKind::NotFound,
            "USN journal did not contain the current file record",
        ));
    }
    Ok(reasons)
}

fn record_change_reason(
    record: &[u8],
    expected_file_id: &str,
    previous_usn: i64,
    current_usn: i64,
) -> io::Result<Option<u32>> {
    if record.len() < 8 {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "truncated USN record",
        ));
    }
    let major = u16::from_le_bytes(record[4..6].try_into().unwrap());
    let (file_id_end, usn_offset, reason_offset) = match major {
        2 => (16usize, 24usize, 40usize),
        3 => (24usize, 40usize, 56usize),
        4 => (24usize, 40usize, 48usize),
        _ => return Ok(None),
    };
    if record.len() < reason_offset + 4 {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "truncated USN record",
        ));
    }
    let usn = i64::from_le_bytes(record[usn_offset..usn_offset + 8].try_into().unwrap());
    if usn <= previous_usn
        || usn > current_usn
        || !file_ids_equal(&format_file_id(&record[8..file_id_end]), expected_file_id)
    {
        return Ok(None);
    }
    Ok(Some(u32::from_le_bytes(
        record[reason_offset..reason_offset + 4].try_into().unwrap(),
    )))
}

fn query_journal_id(volume: Handle) -> io::Result<u64> {
    let mut output = vec![0u8; 80];
    let bytes_returned =
        device_io_control(volume, FSCTL_QUERY_USN_JOURNAL, null(), 0, &mut output)?;
    if bytes_returned < 8 {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "truncated USN journal metadata",
        ));
    }
    Ok(u64::from_le_bytes(output[0..8].try_into().unwrap()))
}

pub(super) fn validate_volume_journal(path: &Path) -> io::Result<()> {
    let result = with_volume_context(path, |volume| {
        let mut metadata = vec![0u8; 80];
        let bytes_returned =
            device_io_control(volume, FSCTL_QUERY_USN_JOURNAL, null(), 0, &mut metadata)?;
        if bytes_returned < 24 {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "truncated USN journal metadata",
            ));
        }
        let journal_id = u64::from_le_bytes(metadata[0..8].try_into().unwrap());
        let next_usn = i64::from_le_bytes(metadata[16..24].try_into().unwrap());
        let request = read_usn_journal_request(next_usn, journal_id);
        let mut output = vec![0u8; JOURNAL_BUFFER_BYTES];
        let bytes_returned = device_io_control(
            volume,
            FSCTL_READ_USN_JOURNAL,
            &request as *const _ as *const c_void,
            std::mem::size_of::<ReadUsnJournalData>() as u32,
            &mut output,
        )?;
        if bytes_returned < 8 {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "truncated USN journal reply",
            ));
        }
        Ok(())
    });
    match result {
        // A normal user may read per-file USNs without being allowed to open
        // the volume journal. with_volume_context has already cached that
        // capability failure for this volume, so watch can safely continue
        // with conservative change detection and no repeated volume probes.
        Err(error) if error.raw_os_error() == Some(5) => {
            Ok(())
        }
        other => other,
    }
}

fn device_io_control(
    handle: Handle,
    code: u32,
    input: *const c_void,
    input_size: u32,
    output: &mut [u8],
) -> io::Result<usize> {
    let mut bytes_returned = 0u32;
    if unsafe {
        DeviceIoControl(
            handle,
            code,
            input,
            input_size,
            output.as_mut_ptr() as *mut c_void,
            output.len() as u32,
            &mut bytes_returned,
            null_mut(),
        )
    } == 0
    {
        return Err(io::Error::last_os_error());
    }
    Ok(bytes_returned as usize)
}

fn volume_device(path: &Path) -> io::Result<(String, Vec<u16>)> {
    let path = canonical_wide(path)?;
    let mut mount_point = vec![0u16; 32768];
    if unsafe {
        GetVolumePathNameW(
            path.as_ptr(),
            mount_point.as_mut_ptr(),
            mount_point.len() as u32,
        )
    } == 0
    {
        return Err(io::Error::last_os_error());
    }
    let mut volume_name = vec![0u16; 64];
    if unsafe {
        GetVolumeNameForVolumeMountPointW(
            mount_point.as_ptr(),
            volume_name.as_mut_ptr(),
            volume_name.len() as u32,
        )
    } == 0
    {
        return Err(io::Error::last_os_error());
    }
    // Cache by the stable volume GUID rather than by a drive letter, which can
    // later be assigned to a different removable volume.
    let mut volume = nul_terminated(&volume_name).to_vec();
    if volume.last() == Some(&('\\' as u16)) {
        volume.pop();
    }
    let volume_key = String::from_utf16_lossy(&volume).to_ascii_lowercase();
    volume.push(0);
    Ok((volume_key, volume))
}

fn with_volume_context<T>(
    path: &Path,
    operation: impl FnOnce(Handle) -> io::Result<T>,
) -> io::Result<T> {
    let (volume_key, volume) = volume_device(path)?;
    let contexts = VOLUME_CONTEXTS.get_or_init(|| Mutex::new(HashMap::new()));
    let mut contexts = contexts
        .lock()
        .map_err(|_| io::Error::new(io::ErrorKind::Other, "volume handle cache poisoned"))?;
    let context = Arc::clone(
        contexts
            .entry(volume_key)
            .or_insert_with(|| Arc::new(Mutex::new(VolumeContext::new()))),
    );
    drop(contexts);
    let mut context = context
        .lock()
        .map_err(|_| io::Error::new(io::ErrorKind::Other, "volume context poisoned"))?;
    if let Some(error_code) = context.reason_read_unavailable_error {
        return Err(io::Error::from_raw_os_error(error_code));
    }
    if context.handle.is_none() {
        let handle = unsafe {
            CreateFileW(
                volume.as_ptr(),
                GENERIC_READ,
                FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
                null(),
                OPEN_EXISTING,
                0,
                null_mut(),
            )
        };
        if handle == INVALID_HANDLE_VALUE {
            let error = io::Error::last_os_error();
            if journal_capability_error(&error) {
                context.reason_read_unavailable_error = error.raw_os_error();
            }
            return Err(error);
        }
        context.handle = Some(OwnedHandle(handle as isize));
    }
    let handle = context.handle.as_ref().unwrap().raw();
    let result = operation(handle);
    if let Err(error) = &result {
        if journal_capability_error(error) {
            context.reason_read_unavailable_error = error.raw_os_error();
        } else if stale_volume_handle_error(error) {
            context.handle.take();
        }
    }
    result
}

pub(crate) fn volume_context_count() -> usize {
    VOLUME_CONTEXTS
        .get()
        .and_then(|contexts| contexts.lock().ok().map(|contexts| contexts.len()))
        .unwrap_or(0)
}

pub(crate) fn clear_volume_contexts() -> usize {
    let Some(contexts) = VOLUME_CONTEXTS.get() else {
        return 0;
    };
    let Ok(mut contexts) = contexts.lock() else {
        return 0;
    };
    let removed = contexts.len();
    contexts.clear();
    removed
}

fn journal_capability_error(error: &io::Error) -> bool {
    matches!(error.raw_os_error(), Some(1) | Some(5))
}

fn stale_volume_handle_error(error: &io::Error) -> bool {
    matches!(
        error.raw_os_error(),
        Some(ERROR_INVALID_HANDLE) | Some(ERROR_NOT_READY) | Some(ERROR_DEVICE_NOT_CONNECTED)
    )
}

fn format_file_id(bytes: &[u8]) -> String {
    bytes
        .iter()
        .rev()
        .map(|byte| format!("{byte:02x}"))
        .collect()
}

fn file_ids_equal(left: &str, right: &str) -> bool {
    let left = left.trim_start_matches('0');
    let right = right.trim_start_matches('0');
    left == right
}

fn canonical_wide(path: &Path) -> io::Result<Vec<u16>> {
    let canonical = std::fs::canonicalize(path)?;
    Ok(OsStr::new(&canonical)
        .encode_wide()
        .chain(std::iter::once(0))
        .collect())
}

fn nul_terminated(values: &[u16]) -> &[u16] {
    let length = values
        .iter()
        .position(|value| *value == 0)
        .unwrap_or(values.len());
    &values[..length]
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_v2_data_reason_and_matches_zero_extended_file_id() {
        let mut record = vec![0u8; 60];
        let record_length = record.len() as u32;
        record[0..4].copy_from_slice(&record_length.to_le_bytes());
        record[4..6].copy_from_slice(&2u16.to_le_bytes());
        record[8..16].copy_from_slice(&0x1234u64.to_le_bytes());
        record[24..32].copy_from_slice(&101i64.to_le_bytes());
        record[40..44].copy_from_slice(&0x8000_0001u32.to_le_bytes());

        let reason =
            record_change_reason(&record, "00000000000000000000000000001234", 100, 101).unwrap();

        assert_eq!(reason, Some(0x8000_0001));
    }

    #[test]
    fn parses_v4_reason_from_its_own_layout() {
        let mut record = vec![0u8; 64];
        let record_length = record.len() as u32;
        record[0..4].copy_from_slice(&record_length.to_le_bytes());
        record[4..6].copy_from_slice(&4u16.to_le_bytes());
        record[8..24].copy_from_slice(&0x1234u128.to_le_bytes());
        record[40..48].copy_from_slice(&101i64.to_le_bytes());
        record[48..52].copy_from_slice(&0x8000_0001u32.to_le_bytes());
        record[56..60].copy_from_slice(&7u32.to_le_bytes());

        let reason =
            record_change_reason(&record, "00000000000000000000000000001234", 100, 101).unwrap();

        assert_eq!(reason, Some(0x8000_0001));
    }

    #[test]
    fn journal_request_preserves_the_record_aligned_start_usn() {
        let request = read_usn_journal_request(8_192, 42);

        assert_eq!(request.start_usn, 8_192);
        assert_eq!(request.usn_journal_id, 42);
    }

    #[test]
    fn close_record_does_not_become_a_new_content_interval() {
        let mut reasons = ChangeReasons::default();

        reasons.observe(0x8000_0001);

        assert_eq!(reasons.all, 0x8000_0001);
        assert_eq!(reasons.without_close, 0);
    }

    #[test]
    fn earlier_non_close_data_record_is_preserved_when_close_follows() {
        let mut reasons = ChangeReasons::default();

        reasons.observe(0x0000_0002);
        reasons.observe(0x8000_0002);

        assert_eq!(reasons.all, 0x8000_0002);
        assert_eq!(reasons.without_close, 0x0000_0002);
    }
}
