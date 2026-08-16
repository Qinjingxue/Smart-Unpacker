#pragma once

#include "sevenzip_paths.hpp"

#ifdef _WIN32

#include <algorithm>
#include <atomic>
#include <condition_variable>
#include <cstddef>
#include <cstdlib>
#include <cstring>
#include <deque>
#include <memory>
#include <mutex>
#include <string>
#include <thread>
#include <utility>
#include <vector>

namespace sunpack::sevenzip {

class AsyncFileWriter final {
public:
    struct JobState {
        explicit JobState(
            std::size_t budget,
            std::shared_ptr<std::atomic<bool>> external_cancel = nullptr)
            : max_inflight_bytes(budget),
              cancel_token(std::move(external_cancel)) {}

        // All scheduler state is protected by AsyncFileWriter::mutex_.
        HRESULT first_error = S_OK;
        int first_win32_error = 0;
        std::size_t inflight_bytes = 0;
        std::size_t pending_jobs = 0;
        bool cancelled = false;
        const std::size_t max_inflight_bytes;
        std::shared_ptr<std::atomic<bool>> cancel_token;
    };

    using JobStatePtr = std::shared_ptr<JobState>;

    struct Buffer;
    struct FileState;
    using FileStatePtr = std::shared_ptr<FileState>;

    struct WorkItem {
        enum class Kind { Data, Close };

        static WorkItem data(Buffer* value) {
            WorkItem item;
            item.kind = Kind::Data;
            item.buffer = value;
            return item;
        }

        static WorkItem close(FileStatePtr value) {
            WorkItem item;
            item.kind = Kind::Close;
            item.file = std::move(value);
            return item;
        }

        Kind kind = Kind::Data;
        Buffer* buffer = nullptr;
        FileStatePtr file;
    };

    struct FileState {
        FileState(
            JobStatePtr state,
            std::wstring file_path,
            std::wstring archive_path,
            UInt32 archive_index,
            std::size_t trace)
            : job(std::move(state)),
              path(std::move(file_path)),
              item_path(std::move(archive_path)),
              item_index(archive_index),
              trace_index(trace) {}

        JobStatePtr job;
        std::wstring path;
        std::wstring item_path;
        UInt32 item_index = 0;
        std::size_t trace_index = 0;
        std::atomic<UInt64> accepted_bytes{0};
        std::size_t inflight_bytes = 0;
        UInt64 written_bytes = 0;
        UInt32 output_crc32 = 0;
        Int32 operation_result = 0;
        bool operation_result_set = false;
        HRESULT hresult = S_OK;
        int win32_error = 0;
        bool has_output_crc32 = false;
        bool has_mtime_ns = false;
        UInt64 mtime_ns = 0;
        std::vector<unsigned char> magic;
        bool failed = false;
        bool closed = false;
        std::deque<WorkItem> pending;
        bool ready = false;
        bool writing = false;

    private:
        friend class AsyncFileWriter;
        HANDLE handle = INVALID_HANDLE_VALUE;
        bool open_attempted = false;
    };

    struct Buffer {
        Buffer() : data(new unsigned char[kBufferSize]) {}
        std::unique_ptr<unsigned char[]> data;
        FileStatePtr file;
        UInt32 size = 0;
    };

    static constexpr std::size_t kBufferSize = 1U << 20;
    static constexpr std::size_t kBufferCount = 64;
    static constexpr std::size_t kMaxQueuedJobs = 4096;
    static constexpr std::size_t kDefaultWriterCount = 4;
    static constexpr std::size_t kMaxWriterCount = 8;
    static constexpr std::size_t kDefaultJobInFlightBytes = 32U << 20;
    static constexpr std::size_t kDefaultFileInFlightBytes = 8U << 20;

    AsyncFileWriter() : writer_count_(configured_writer_count()) {
        buffers_.reserve(kBufferCount);
        for (std::size_t index = 0; index < kBufferCount; ++index) {
            auto buffer = std::make_unique<Buffer>();
            free_buffers_.push_back(buffer.get());
            buffers_.push_back(std::move(buffer));
        }
        workers_.reserve(writer_count_);
        try {
            for (std::size_t index = 0; index < writer_count_; ++index) {
                workers_.emplace_back([this] { writer_loop(); });
            }
        } catch (...) {
            {
                std::lock_guard<std::mutex> lock(mutex_);
                stopping_ = true;
            }
            work_cv_.notify_all();
            for (auto& worker : workers_) {
                if (worker.joinable()) {
                    worker.join();
                }
            }
            throw;
        }
    }

    ~AsyncFileWriter() { finish(); }

    AsyncFileWriter(const AsyncFileWriter&) = delete;
    AsyncFileWriter& operator=(const AsyncFileWriter&) = delete;

    JobStatePtr make_job(
        std::size_t max_inflight_bytes = 0,
        std::shared_ptr<std::atomic<bool>> cancel_token = nullptr
    ) {
        if (max_inflight_bytes == 0) {
            max_inflight_bytes = kDefaultJobInFlightBytes;
        }
        auto job = std::make_shared<JobState>(max_inflight_bytes, std::move(cancel_token));
        std::lock_guard<std::mutex> lock(mutex_);
        synchronize_cancellation_locked(job);
        active_jobs_.push_back(job);
        return job;
    }

    FileStatePtr make_file(
        const JobStatePtr& job,
        std::wstring path,
        std::wstring item_path,
        UInt32 item_index,
        std::size_t trace_index
    ) {
        return std::make_shared<FileState>(
            job ? job : make_job(),
            std::move(path), std::move(item_path), item_index, trace_index);
    }

    HRESULT write(
        const FileStatePtr& file,
        const void* data,
        UInt32 size,
        UInt32* processed_size
    ) {
        if (processed_size) {
            *processed_size = 0;
        }
        if (!file || (size != 0 && data == nullptr)) {
            return E_POINTER;
        }
        if (size == 0) {
            return S_OK;
        }

        const auto* source = static_cast<const unsigned char*>(data);
        UInt32 consumed = 0;
        const auto job = file->job;
        if (!job) {
            return E_FAIL;
        }
        while (consumed < size) {
            Buffer* buffer = nullptr;
            std::size_t chunk_size = 0;
            {
                std::unique_lock<std::mutex> lock(mutex_);
                producer_cv_.wait(lock, [this, &job, &file] {
                    return terminal_result_locked(job) != S_OK || can_accept_locked(job, file);
                });
                const HRESULT error = terminal_result_locked(job);
                if (error != S_OK) {
                    if (processed_size) {
                        *processed_size = consumed;
                    }
                    return error;
                }
                buffer = free_buffers_.front();
                free_buffers_.pop_front();
                const std::size_t job_available = job->max_inflight_bytes -
                    (std::min)(job->inflight_bytes, job->max_inflight_bytes);
                const std::size_t file_available = kDefaultFileInFlightBytes -
                    (std::min)(file->inflight_bytes, kDefaultFileInFlightBytes);
                chunk_size = (std::min)({
                    static_cast<std::size_t>(size - consumed),
                    kBufferSize,
                    job_available,
                    file_available,
                });
                if (chunk_size == 0) {
                    free_buffers_.push_front(buffer);
                    continue;
                }
                job->inflight_bytes += chunk_size;
                file->inflight_bytes += chunk_size;
            }

            const auto chunk = static_cast<UInt32>(chunk_size);
            std::memcpy(buffer->data.get(), source + consumed, chunk);
            buffer->size = chunk;
            buffer->file = file;

            HRESULT enqueue_result = S_OK;
            {
                std::unique_lock<std::mutex> lock(mutex_);
                const HRESULT error = terminal_result_locked(job);
                if (error != S_OK) {
                    job->inflight_bytes -= chunk;
                    file->inflight_bytes -= chunk;
                    buffer->file.reset();
                    buffer->size = 0;
                    free_buffers_.push_back(buffer);
                    if (processed_size) {
                        *processed_size = consumed;
                    }
                    enqueue_result = error;
                } else {
                    try {
                        enqueue_file_job_locked(file, WorkItem::data(buffer));
                    } catch (...) {
                        job->inflight_bytes -= chunk;
                        file->inflight_bytes -= chunk;
                        buffer->file.reset();
                        buffer->size = 0;
                        free_buffers_.push_back(buffer);
                        set_job_error_locked(job, E_OUTOFMEMORY, ERROR_OUTOFMEMORY);
                        if (processed_size) {
                            *processed_size = consumed;
                        }
                        enqueue_result = E_OUTOFMEMORY;
                    }
                }
                if (enqueue_result == S_OK) {
                    ++queued_jobs_;
                    ++job->pending_jobs;
                }
            }
            if (enqueue_result != S_OK) {
                producer_cv_.notify_all();
                return enqueue_result;
            }
            consumed += chunk;
            file->accepted_bytes.fetch_add(chunk, std::memory_order_relaxed);
            work_cv_.notify_one();
        }

        if (processed_size) {
            *processed_size = consumed;
        }
        return S_OK;
    }

    void close_file(
        const FileStatePtr& file,
        UInt32 output_crc32,
        bool has_output_crc32,
        std::vector<unsigned char> magic
    ) noexcept {
        if (!file) {
            return;
        }
        try {
            std::unique_lock<std::mutex> lock(mutex_);
            synchronize_cancellation_locked(file->job);
            producer_cv_.wait(lock, [this, &file] {
                return terminal_result_locked(file->job) != S_OK || queued_jobs_ < kMaxQueuedJobs;
            });
            const HRESULT error = terminal_result_locked(file->job);
            if (error != S_OK) {
                mark_file_failure_locked(file, error, current_win32_error_locked(file->job));
                return;
            }
            file->output_crc32 = output_crc32;
            file->has_output_crc32 = has_output_crc32;
            file->magic = std::move(magic);
            enqueue_file_job_locked(file, WorkItem::close(file));
            ++queued_jobs_;
            ++file->job->pending_jobs;
            lock.unlock();
            work_cv_.notify_one();
        } catch (...) {
            record_failure(file, E_OUTOFMEMORY, ERROR_OUTOFMEMORY);
        }
    }

    HRESULT finish_job(const JobStatePtr& job) noexcept {
        if (!job) {
            return E_FAIL;
        }
        std::unique_lock<std::mutex> lock(mutex_);
        synchronize_cancellation_locked(job);
        producer_cv_.wait(lock, [&job] {
            return job->pending_jobs == 0;
        });
        const HRESULT result = terminal_result_locked(job);
        unregister_job_locked(job);
        return result;
    }

    void cancel_job(const JobStatePtr& job) noexcept {
        if (!job) {
            return;
        }
        {
            std::lock_guard<std::mutex> lock(mutex_);
            cancel_job_locked(job);
        }
        producer_cv_.notify_all();
    }

    void wake_waiters() noexcept {
        {
            std::lock_guard<std::mutex> lock(mutex_);
            for (auto it = active_jobs_.begin(); it != active_jobs_.end();) {
                if (const auto job = it->lock()) {
                    synchronize_cancellation_locked(job);
                    ++it;
                } else {
                    it = active_jobs_.erase(it);
                }
            }
        }
        producer_cv_.notify_all();
    }

    HRESULT current_error(const JobStatePtr& job) noexcept {
        if (!job) {
            return E_FAIL;
        }
        std::lock_guard<std::mutex> lock(mutex_);
        synchronize_cancellation_locked(job);
        return terminal_result_locked(job);
    }

    int current_win32_error(const JobStatePtr& job) noexcept {
        if (!job) {
            return ERROR_INVALID_STATE;
        }
        std::lock_guard<std::mutex> lock(mutex_);
        synchronize_cancellation_locked(job);
        return current_win32_error_locked(job);
    }

    void finish() noexcept {
        {
            std::lock_guard<std::mutex> lock(mutex_);
            stopping_ = true;
            for (const auto& weak_job : active_jobs_) {
                if (const auto job = weak_job.lock()) {
                    cancel_job_locked(job);
                }
            }
        }
        work_cv_.notify_all();
        producer_cv_.notify_all();
        for (auto& worker : workers_) {
            if (worker.joinable()) {
                worker.join();
            }
        }
    }

private:
    static std::size_t configured_writer_count() noexcept {
        wchar_t text[16]{};
        const DWORD length = GetEnvironmentVariableW(
            L"SUNPACK_ASYNC_WRITER_THREADS", text, static_cast<DWORD>(std::size(text)));
        if (length == 0 || length >= std::size(text)) {
            return kDefaultWriterCount;
        }
        wchar_t* end = nullptr;
        const unsigned long configured = std::wcstoul(text, &end, 10);
        if (end == text || *end != L'\0' || configured == 0) {
            return kDefaultWriterCount;
        }
        return (std::min)(static_cast<std::size_t>(configured), kMaxWriterCount);
    }

    void set_job_error_locked(const JobStatePtr& job, HRESULT hr, int win32_error) noexcept {
        if (job && job->first_error == S_OK) {
            job->first_error = hr;
            job->first_win32_error = win32_error;
        }
    }

    void cancel_job_locked(const JobStatePtr& job) noexcept {
        if (!job) {
            return;
        }
        job->cancelled = true;
        set_job_error_locked(job, E_ABORT, ERROR_OPERATION_ABORTED);
    }

    void synchronize_cancellation_locked(const JobStatePtr& job) noexcept {
        if (job && job->cancel_token && job->cancel_token->load(std::memory_order_acquire)) {
            cancel_job_locked(job);
        }
    }

    HRESULT terminal_result_locked(const JobStatePtr& job) const noexcept {
        if (!job) {
            return E_FAIL;
        }
        if (job->first_error != S_OK) {
            return job->first_error;
        }
        return (job->cancelled || stopping_) ? E_ABORT : S_OK;
    }

    int current_win32_error_locked(const JobStatePtr& job) const noexcept {
        if (!job) {
            return ERROR_INVALID_STATE;
        }
        if (job->first_win32_error != 0) {
            return job->first_win32_error;
        }
        return (job->cancelled || stopping_) ? ERROR_OPERATION_ABORTED : 0;
    }

    bool can_accept_locked(const JobStatePtr& job, const FileStatePtr& file) const noexcept {
        return job && file && !free_buffers_.empty() && queued_jobs_ < kMaxQueuedJobs &&
            job->inflight_bytes < job->max_inflight_bytes &&
            file->inflight_bytes < kDefaultFileInFlightBytes;
    }

    void unregister_job_locked(const JobStatePtr& job) noexcept {
        for (auto it = active_jobs_.begin(); it != active_jobs_.end();) {
            const auto candidate = it->lock();
            if (!candidate || candidate.get() == job.get()) {
                it = active_jobs_.erase(it);
            } else {
                ++it;
            }
        }
    }

    void enqueue_file_job_locked(const FileStatePtr& file, WorkItem item) {
        if (!file) {
            return;
        }
        file->pending.push_back(std::move(item));
        if (!file->ready && !file->writing) {
            try {
                ready_files_.push_back(file);
            } catch (...) {
                file->pending.pop_back();
                throw;
            }
            file->ready = true;
        }
    }

    FileStatePtr select_ready_file_locked() noexcept {
        if (ready_files_.empty()) {
            return nullptr;
        }
        FileStatePtr file = std::move(ready_files_.front());
        ready_files_.pop_front();
        if (file) {
            file->ready = false;
            file->writing = true;
        }
        return file;
    }

    void writer_loop() noexcept {
        for (;;) {
            WorkItem item;
            FileStatePtr file;
            bool capacity_available = false;
            {
                std::unique_lock<std::mutex> lock(mutex_);
                work_cv_.wait(lock, [this] { return stopping_ || !ready_files_.empty(); });
                if (ready_files_.empty()) {
                    if (stopping_) {
                        break;
                    }
                    continue;
                }
                file = select_ready_file_locked();
                if (!file || file->pending.empty()) {
                    if (file) {
                        file->writing = false;
                    }
                    continue;
                }
                item = std::move(file->pending.front());
                file->pending.pop_front();
                --queued_jobs_;
                capacity_available = true;
            }
            if (capacity_available) {
                producer_cv_.notify_all();
            }

            if (item.kind == WorkItem::Kind::Data) {
                process_data(item.buffer);
                release_buffer(item.buffer);
            } else {
                process_close(item.file);
            }

            {
                std::lock_guard<std::mutex> lock(mutex_);
                if (file) {
                    file->writing = false;
                    if (!file->pending.empty() && !file->ready) {
                        ready_files_.push_back(file);
                        file->ready = true;
                    }
                }
            }
            work_cv_.notify_one();
        }
    }

    bool open_file(const FileStatePtr& file) noexcept {
        if (!file || file->failed) {
            return false;
        }
        if (file->handle != INVALID_HANDLE_VALUE) {
            return true;
        }
        if (file->open_attempted) {
            return false;
        }
        file->open_attempted = true;
        file->handle = CreateFileW(
            win32_extended_path(file->path).c_str(),
            GENERIC_WRITE,
            0,
            nullptr,
            CREATE_NEW,
            FILE_ATTRIBUTE_NORMAL | FILE_FLAG_SEQUENTIAL_SCAN,
            nullptr);
        if (file->handle == INVALID_HANDLE_VALUE) {
            const DWORD error = GetLastError();
            record_failure(file, HRESULT_FROM_WIN32(error), static_cast<int>(error));
            return false;
        }
        return true;
    }

    void process_data(Buffer* buffer) noexcept {
        if (!buffer || !buffer->file) {
            return;
        }
        const auto& file = buffer->file;
        const auto job = file->job;
        const HRESULT global_error = current_error(job);
        if (global_error != S_OK) {
            record_failure(file, global_error, current_win32_error(job));
            return;
        }
        if (!open_file(file)) {
            return;
        }

        UInt32 offset = 0;
        while (offset < buffer->size) {
            DWORD written = 0;
            if (!WriteFile(
                    file->handle,
                    buffer->data.get() + offset,
                    buffer->size - offset,
                    &written,
                    nullptr)) {
                const DWORD error = GetLastError();
                record_failure(file, HRESULT_FROM_WIN32(error), static_cast<int>(error));
                return;
            }
            if (written == 0) {
                record_failure(file, HRESULT_FROM_WIN32(ERROR_WRITE_FAULT), ERROR_WRITE_FAULT);
                return;
            }
            offset += written;
            file->written_bytes += written;
        }
    }

    void process_close(const FileStatePtr& file) noexcept {
        if (!file) {
            return;
        }
        const auto job = file->job;
        const HRESULT global_error = current_error(job);
        if (global_error != S_OK) {
            record_failure(file, global_error, current_win32_error(job));
        }
        if (!file->failed && file->handle == INVALID_HANDLE_VALUE) {
            open_file(file);
        }
        if (file->handle != INVALID_HANDLE_VALUE) {
            const HANDLE handle = file->handle;
            file->handle = INVALID_HANDLE_VALUE;
            FILETIME last_write{};
            if (GetFileTime(handle, nullptr, nullptr, &last_write)) {
                ULARGE_INTEGER ticks{};
                ticks.LowPart = last_write.dwLowDateTime;
                ticks.HighPart = last_write.dwHighDateTime;
                constexpr UInt64 unix_epoch_100ns = 116444736000000000ULL;
                if (ticks.QuadPart >= unix_epoch_100ns) {
                    file->mtime_ns = (ticks.QuadPart - unix_epoch_100ns) * 100ULL;
                    file->has_mtime_ns = true;
                }
            }
            if (!CloseHandle(handle)) {
                const DWORD error = GetLastError();
                record_failure(file, HRESULT_FROM_WIN32(error), static_cast<int>(error));
            }
        }
        {
            std::lock_guard<std::mutex> lock(mutex_);
            file->closed = true;
            if (job && job->pending_jobs != 0) {
                --job->pending_jobs;
            }
        }
        producer_cv_.notify_all();
    }

    void release_buffer(Buffer* buffer) noexcept {
        if (!buffer) {
            return;
        }
        const auto file = buffer->file;
        const auto job = file ? file->job : nullptr;
        {
            std::lock_guard<std::mutex> lock(mutex_);
            if (file) {
                file->inflight_bytes -= buffer->size;
            }
            if (job) {
                job->inflight_bytes -= buffer->size;
                if (job->pending_jobs != 0) {
                    --job->pending_jobs;
                }
            }
            buffer->file.reset();
            buffer->size = 0;
            free_buffers_.push_back(buffer);
        }
        producer_cv_.notify_all();
    }

    void record_failure(const FileStatePtr& file, HRESULT hr, int win32_error) noexcept {
        {
            std::lock_guard<std::mutex> lock(mutex_);
            mark_file_failure_locked(file, hr, win32_error);
            if (file && file->job) {
                set_job_error_locked(file->job, hr, win32_error);
            }
        }
        producer_cv_.notify_all();
    }

    static void mark_file_failure_locked(const FileStatePtr& file, HRESULT hr, int win32_error) noexcept {
        if (!file || file->failed) {
            return;
        }
        file->failed = true;
        file->hresult = hr;
        file->win32_error = win32_error;
    }

    std::vector<std::unique_ptr<Buffer>> buffers_;
    std::deque<Buffer*> free_buffers_;
    std::vector<std::thread> workers_;
    std::deque<FileStatePtr> ready_files_;
    std::vector<std::weak_ptr<JobState>> active_jobs_;
    mutable std::mutex mutex_;
    std::condition_variable producer_cv_;
    std::condition_variable work_cv_;
    const std::size_t writer_count_;
    std::size_t queued_jobs_ = 0;
    bool stopping_ = false;
};

}  // namespace sunpack::sevenzip

#endif
