//! Windows-only overlapped sequential reader used by the embedded scanner.
//!
//! This module deliberately owns a scan-local file handle and completion port.
//! The normal reader, shared handle pool, and request cache remain synchronous
//! and unchanged.  A scan submits a bounded number of reads, hands completed
//! buffers to Rayon workers, and reuses a buffer only after its scan finishes.

use std::collections::HashMap;
use std::ffi::c_void;
use std::io;
use std::os::windows::ffi::OsStrExt;
use std::path::Path;
use std::ptr::null_mut;
use std::sync::{mpsc, Arc, Mutex};

type Handle = *mut c_void;

const INVALID_HANDLE_VALUE: Handle = -1isize as Handle;
const INFINITE: u32 = u32::MAX;
const ERROR_IO_PENDING: u32 = 997;

const GENERIC_READ: u32 = 0x8000_0000;
const FILE_SHARE_READ: u32 = 0x0000_0001;
const FILE_SHARE_WRITE: u32 = 0x0000_0002;
const FILE_SHARE_DELETE: u32 = 0x0000_0004;
const OPEN_EXISTING: u32 = 3;
const FILE_ATTRIBUTE_NORMAL: u32 = 0x0000_0080;
const FILE_FLAG_OVERLAPPED: u32 = 0x4000_0000;
const FILE_FLAG_SEQUENTIAL_SCAN: u32 = 0x0800_0000;

#[repr(C)]
struct Overlapped {
    internal: usize,
    internal_high: usize,
    offset: u32,
    offset_high: u32,
    event: Handle,
}

#[link(name = "kernel32")]
unsafe extern "system" {
    fn CreateFileW(
        file_name: *const u16,
        desired_access: u32,
        share_mode: u32,
        security_attributes: *const c_void,
        creation_disposition: u32,
        flags_and_attributes: u32,
        template_file: Handle,
    ) -> Handle;
    fn CreateIoCompletionPort(
        file_handle: Handle,
        existing_completion_port: Handle,
        completion_key: usize,
        number_of_concurrent_threads: u32,
    ) -> Handle;
    fn ReadFile(
        file: Handle,
        buffer: *mut c_void,
        bytes_to_read: u32,
        bytes_read: *mut u32,
        overlapped: *mut Overlapped,
    ) -> i32;
    fn GetQueuedCompletionStatus(
        completion_port: Handle,
        bytes_transferred: *mut u32,
        completion_key: *mut usize,
        overlapped: *mut *mut Overlapped,
        milliseconds: u32,
    ) -> i32;
    fn CancelIoEx(file: Handle, overlapped: *mut Overlapped) -> i32;
    fn CloseHandle(handle: Handle) -> i32;
    fn GetLastError() -> u32;
}

struct IocpSlot {
    overlapped: Overlapped,
    buffer: Vec<u8>,
    read_start: u64,
    leading_overlap: usize,
    bytes_read: usize,
}

// A slot is moved only after its OVERLAPPED operation has completed.  The
// completion port never accesses it after the owner removes it from pending.
unsafe impl Send for IocpSlot {}

pub(crate) struct IocpScanOutput<T> {
    pub(crate) results: Vec<T>,
    pub(crate) read_bytes: u64,
    pub(crate) read_operations: u64,
}

impl IocpSlot {
    fn new(capacity: usize) -> Self {
        Self {
            overlapped: Overlapped {
                internal: 0,
                internal_high: 0,
                offset: 0,
                offset_high: 0,
                event: null_mut(),
            },
            buffer: vec![0; capacity],
            read_start: 0,
            leading_overlap: 0,
            bytes_read: 0,
        }
    }

    fn key(&mut self) -> usize {
        (&mut self.overlapped as *mut Overlapped).cast::<c_void>() as usize
    }
}

struct IocpHandles {
    file: Handle,
    port: Handle,
}

// Windows kernel handles are process-wide synchronization objects. The
// handle values are shared read-only by the producer and are closed only after
// the Rayon scope has joined and all pending operations have been drained.
unsafe impl Send for IocpHandles {}
unsafe impl Sync for IocpHandles {}

impl Drop for IocpHandles {
    fn drop(&mut self) {
        if !self.file.is_null() && self.file != INVALID_HANDLE_VALUE {
            // The normal path drains all operations before this point.  This
            // best-effort cancellation protects panic/error unwinding paths.
            unsafe {
                let _ = CancelIoEx(self.file, null_mut());
                let _ = CloseHandle(self.file);
            }
        }
        if !self.port.is_null() && self.port != INVALID_HANDLE_VALUE {
            unsafe {
                let _ = CloseHandle(self.port);
            }
        }
    }
}

fn last_error() -> io::Error {
    io::Error::from_raw_os_error(unsafe { GetLastError() } as i32)
}

fn open_handles(path: &Path) -> io::Result<IocpHandles> {
    let mut wide = path.as_os_str().encode_wide().collect::<Vec<_>>();
    wide.push(0);
    let file = unsafe {
        CreateFileW(
            wide.as_ptr(),
            GENERIC_READ,
            FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
            null_mut(),
            OPEN_EXISTING,
            FILE_ATTRIBUTE_NORMAL | FILE_FLAG_OVERLAPPED | FILE_FLAG_SEQUENTIAL_SCAN,
            null_mut(),
        )
    };
    if file == INVALID_HANDLE_VALUE {
        return Err(last_error());
    }

    let port = unsafe { CreateIoCompletionPort(INVALID_HANDLE_VALUE, null_mut(), 0, 0) };
    if port.is_null() || port == INVALID_HANDLE_VALUE {
        let error = last_error();
        unsafe {
            let _ = CloseHandle(file);
        }
        return Err(error);
    }

    let associated = unsafe { CreateIoCompletionPort(file, port, 0, 0) };
    if associated.is_null() || associated == INVALID_HANDLE_VALUE {
        let error = last_error();
        unsafe {
            let _ = CloseHandle(file);
            let _ = CloseHandle(port);
        }
        return Err(error);
    }

    Ok(IocpHandles { file, port })
}

fn configure_slot(
    slot: &mut IocpSlot,
    base: u64,
    file_size: u64,
    chunk_bytes: usize,
    overlap: usize,
) -> io::Result<()> {
    let visible_end = base.saturating_add(chunk_bytes as u64).min(file_size);
    let read_start = base.saturating_sub(overlap as u64);
    let read_len = usize::try_from(visible_end.saturating_sub(read_start))
        .map_err(|_| io::Error::new(io::ErrorKind::InvalidInput, "IOCP read is too large"))?;
    let bytes_to_read = u32::try_from(read_len).map_err(|_| {
        io::Error::new(
            io::ErrorKind::InvalidInput,
            "IOCP read length exceeds ReadFile's DWORD limit",
        )
    })?;

    slot.overlapped = Overlapped {
        internal: 0,
        internal_high: 0,
        offset: read_start as u32,
        offset_high: (read_start >> 32) as u32,
        event: null_mut(),
    };
    slot.buffer.resize(read_len, 0);
    slot.read_start = read_start;
    slot.leading_overlap = (base - read_start) as usize;
    slot.bytes_read = 0;
    // Keep the requested length in the buffer itself; the caller passes it to
    // ReadFile immediately while the slot remains in the pending map.
    debug_assert_eq!(slot.buffer.len(), bytes_to_read as usize);
    Ok(())
}

fn submit_slot(handles: &IocpHandles, slot: &mut IocpSlot) -> io::Result<()> {
    let bytes_to_read = u32::try_from(slot.buffer.len())
        .map_err(|_| io::Error::new(io::ErrorKind::InvalidInput, "IOCP buffer is too large"))?;
    let completed_synchronously = unsafe {
        ReadFile(
            handles.file,
            slot.buffer.as_mut_ptr().cast::<c_void>(),
            bytes_to_read,
            null_mut(),
            &mut slot.overlapped,
        )
    };
    if completed_synchronously != 0 {
        return Ok(());
    }
    let error = unsafe { GetLastError() };
    if error == ERROR_IO_PENDING {
        Ok(())
    } else {
        Err(io::Error::from_raw_os_error(error as i32))
    }
}

fn submit_next_slot(
    handles: &IocpHandles,
    pending: &mut HashMap<usize, Box<IocpSlot>>,
    next_base: &mut u64,
    file_size: u64,
    chunk_bytes: usize,
    overlap: usize,
    mut slot: Box<IocpSlot>,
) -> io::Result<bool> {
    if *next_base >= file_size {
        return Ok(false);
    }
    let base = *next_base;
    let visible_end = base.saturating_add(chunk_bytes as u64).min(file_size);
    *next_base = visible_end;
    configure_slot(&mut slot, base, file_size, chunk_bytes, overlap)?;
    let key = slot.key();
    submit_slot(handles, &mut slot)?;
    pending.insert(key, slot);
    Ok(true)
}

fn cancel_pending(handles: &IocpHandles, pending: &mut HashMap<usize, Box<IocpSlot>>) {
    for slot in pending.values_mut() {
        unsafe {
            let _ = CancelIoEx(handles.file, &mut slot.overlapped);
        }
    }

    while !pending.is_empty() {
        let mut bytes = 0u32;
        let mut key = 0usize;
        let mut overlapped = null_mut();
        let _ = unsafe {
            GetQueuedCompletionStatus(
                handles.port,
                &mut bytes,
                &mut key,
                &mut overlapped,
                INFINITE,
            )
        };
        if !overlapped.is_null() {
            pending.remove(&(overlapped as usize));
        }
    }
}

/// Run a bounded overlapped sequential scan and return the worker results.
///
/// `scan` receives a buffer containing `leading_overlap` bytes before the
/// visible chunk.  It may return results in any order; the caller is expected
/// to sort offsets after this function returns.
pub(crate) fn scan_file<T, F>(
    path: &Path,
    file_size: u64,
    chunk_bytes: usize,
    buffer_count: usize,
    requested_worker_count: usize,
    overlap: usize,
    scan: F,
) -> io::Result<IocpScanOutput<T>>
where
    T: Send,
    F: Fn(&[u8], usize, u64) -> Vec<T> + Send + Sync,
{
    if file_size == 0 {
        return Ok(IocpScanOutput {
            results: Vec::new(),
            read_bytes: 0,
            read_operations: 0,
        });
    }
    let chunk_bytes = chunk_bytes.max(64 * 1024);
    let buffer_count = buffer_count.clamp(2, 64);
    let worker_count = requested_worker_count
        .clamp(1, 8)
        .min(rayon::current_num_threads().clamp(1, 8));
    let mut expected_read_bytes = 0u64;
    let mut expected_read_operations = 0u64;
    let mut expected_base = 0u64;
    while expected_base < file_size {
        let visible_end = expected_base
            .saturating_add(chunk_bytes as u64)
            .min(file_size);
        let read_start = expected_base.saturating_sub(overlap as u64);
        expected_read_bytes =
            expected_read_bytes.saturating_add(visible_end.saturating_sub(read_start));
        expected_read_operations = expected_read_operations.saturating_add(1);
        expected_base = visible_end;
    }
    let handles = open_handles(path)?;
    let scan = &scan;

    let result = rayon::scope(|scope| -> io::Result<IocpScanOutput<T>> {
        let (job_tx, job_rx) = mpsc::sync_channel::<Box<IocpSlot>>(buffer_count);
        let job_rx = Arc::new(Mutex::new(job_rx));
        let (done_tx, done_rx) = mpsc::channel::<(Box<IocpSlot>, Vec<T>)>();

        for _ in 0..worker_count {
            let job_rx = Arc::clone(&job_rx);
            let done_tx = done_tx.clone();
            scope.spawn(move |_| loop {
                let job = {
                    let receiver = job_rx
                        .lock()
                        .expect("IOCP scan job receiver lock is not poisoned");
                    receiver.recv()
                };
                let Ok(job) = job else {
                    break;
                };
                let hits = scan(
                    &job.buffer[..job.bytes_read],
                    job.leading_overlap,
                    job.read_start,
                );
                if done_tx.send((job, hits)).is_err() {
                    break;
                }
            });
        }
        drop(done_tx);

        let mut pending = HashMap::<usize, Box<IocpSlot>>::new();
        let mut next_base = 0u64;
        let mut scan_jobs = 0usize;
        let mut all_results = Vec::new();
        let mut initial_error = None;
        for _ in 0..buffer_count {
            match submit_next_slot(
                &handles,
                &mut pending,
                &mut next_base,
                file_size,
                chunk_bytes,
                overlap,
                Box::new(IocpSlot::new(chunk_bytes + overlap)),
            ) {
                Ok(true) => {}
                Ok(false) => break,
                Err(error) => {
                    initial_error = Some(error);
                    break;
                }
            }
        }
        if let Some(error) = initial_error {
            cancel_pending(&handles, &mut pending);
            drop(job_tx);
            return Err(error);
        }

        let mut fatal_error = None;
        while !pending.is_empty() || scan_jobs > 0 {
            loop {
                match done_rx.try_recv() {
                    Ok((slot, hits)) => {
                        scan_jobs = scan_jobs.saturating_sub(1);
                        all_results.extend(hits);
                        if fatal_error.is_none() {
                            if let Err(error) = submit_next_slot(
                                &handles,
                                &mut pending,
                                &mut next_base,
                                file_size,
                                chunk_bytes,
                                overlap,
                                slot,
                            ) {
                                fatal_error = Some(error);
                                break;
                            }
                        }
                    }
                    Err(mpsc::TryRecvError::Empty) => break,
                    Err(mpsc::TryRecvError::Disconnected) => {
                        fatal_error = Some(io::Error::other("IOCP scanner workers stopped"));
                        break;
                    }
                }
            }
            if fatal_error.is_some() {
                break;
            }

            if pending.is_empty() {
                if scan_jobs == 0 {
                    break;
                }
                let (slot, hits) = match done_rx.recv() {
                    Ok(done) => done,
                    Err(_) => {
                        fatal_error = Some(io::Error::other("IOCP scanner workers stopped"));
                        break;
                    }
                };
                scan_jobs = scan_jobs.saturating_sub(1);
                all_results.extend(hits);
                if let Err(error) = submit_next_slot(
                    &handles,
                    &mut pending,
                    &mut next_base,
                    file_size,
                    chunk_bytes,
                    overlap,
                    slot,
                ) {
                    fatal_error = Some(error);
                    break;
                }
                continue;
            }

            let mut bytes = 0u32;
            let mut completion_key = 0usize;
            let mut overlapped = null_mut();
            let completed = unsafe {
                GetQueuedCompletionStatus(
                    handles.port,
                    &mut bytes,
                    &mut completion_key,
                    &mut overlapped,
                    INFINITE,
                )
            };
            if overlapped.is_null() {
                fatal_error = Some(last_error());
                break;
            }
            let Some(mut slot) = pending.remove(&(overlapped as usize)) else {
                fatal_error = Some(io::Error::other("unknown IOCP completion context"));
                break;
            };
            if completed == 0 {
                let error = unsafe { GetLastError() };
                fatal_error = Some(io::Error::from_raw_os_error(error as i32));
                break;
            }
            slot.bytes_read = (bytes as usize).min(slot.buffer.len());
            if slot.bytes_read > 0 {
                if job_tx.send(slot).is_err() {
                    fatal_error = Some(io::Error::other("IOCP scanner workers stopped"));
                    break;
                }
                scan_jobs += 1;
            }
        }

        if fatal_error.is_some() {
            cancel_pending(&handles, &mut pending);
            drop(job_tx);
            return Err(fatal_error.expect("IOCP fatal error should be present"));
        }

        drop(job_tx);
        Ok(IocpScanOutput {
            results: all_results,
            read_bytes: expected_read_bytes,
            read_operations: expected_read_operations,
        })
    });

    result
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn overlapped_offset_supports_files_above_four_gibabytes() {
        let mut slot = IocpSlot::new(16);
        configure_slot(&mut slot, (4u64 << 30) + 123, (4u64 << 30) + 1024, 512, 7).unwrap();
        assert_eq!(slot.overlapped.offset, 116);
        assert_eq!(slot.overlapped.offset_high, 1);
        assert_eq!(slot.read_start, (4u64 << 30) + 116);
    }
}
