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

        std::atomic<HRESULT> first_error{S_OK};
        std::atomic<int> first_win32_error{0};
        std::atomic<std::size_t> inflight_bytes{0};
        std::atomic<std::size_t> pending_jobs{0};
        std::atomic<bool> cancelled{false};
        const std::size_t max_inflight_bytes;
        std::shared_ptr<std::atomic<bool>> cancel_token;

        bool is_cancelled() const noexcept {
            return cancelled.load(std::memory_order_acquire) ||
                (cancel_token && cancel_token->load(std::memory_order_acquire));
        }
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
        std::atomic<std::size_t> inflight_bytes{0};
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
        return std::make_shared<JobState>(max_inflight_bytes, std::move(cancel_token));
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
                    return job->first_error.load(std::memory_order_acquire) != S_OK ||
                        job->is_cancelled() ||
                        stopping_ ||
                        (!free_buffers_.empty() && queued_jobs_ < kMaxQueuedJobs &&
                         job->inflight_bytes.load(std::memory_order_acquire) < job->max_inflight_bytes &&
                         file->inflight_bytes.load(std::memory_order_acquire) < kDefaultFileInFlightBytes);
                });
                const HRESULT error = job->first_error.load(std::memory_order_acquire);
                if (error != S_OK || job->is_cancelled() || stopping_) {
                    if (processed_size) {
                        *processed_size = consumed;
                    }
                    return error != S_OK ? error : E_ABORT;
                }
                buffer = free_buffers_.front();
                free_buffers_.pop_front();
                const std::size_t job_available = job->max_inflight_bytes -
                    (std::min)(job->inflight_bytes.load(std::memory_order_relaxed), job->max_inflight_bytes);
                const std::size_t file_available = kDefaultFileInFlightBytes -
                    (std::min)(file->inflight_bytes.load(std::memory_order_relaxed), kDefaultFileInFlightBytes);
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
            }

            const auto chunk = static_cast<UInt32>(chunk_size);
            std::memcpy(buffer->data.get(), source + consumed, chunk);
            buffer->size = chunk;
            buffer->file = file;

            {
                std::lock_guard<std::mutex> lock(mutex_);
                const HRESULT error = job->first_error.load(std::memory_order_acquire);
                if (error != S_OK || job->is_cancelled() || stopping_) {
                    buffer->file.reset();
                    buffer->size = 0;
                    free_buffers_.push_back(buffer);
                    producer_cv_.notify_all();
                    if (processed_size) {
                        *processed_size = consumed;
                    }
                    return error != S_OK ? error : E_ABORT;
                }
                enqueue_file_job_locked(file, WorkItem::data(buffer));
                ++queued_jobs_;
                ++job->pending_jobs;
                job->inflight_bytes.fetch_add(chunk, std::memory_order_release);
                file->inflight_bytes.fetch_add(chunk, std::memory_order_release);
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
        file->output_crc32 = output_crc32;
        file->has_output_crc32 = has_output_crc32;
        file->magic = std::move(magic);
        try {
            std::unique_lock<std::mutex> lock(mutex_);
            producer_cv_.wait(lock, [this, &file] {
                return stopping_ || file->job->is_cancelled() || queued_jobs_ < kMaxQueuedJobs;
            });
            if (stopping_ || file->job->is_cancelled()) {
                mark_file_failure(file, E_ABORT, ERROR_OPERATION_ABORTED);
                return;
            }
            enqueue_file_job_locked(file, WorkItem::close(file));
            ++queued_jobs_;
            ++file->job->pending_jobs;
            lock.unlock();
            work_cv_.notify_one();
        } catch (...) {
            record_failure(file, E_OUTOFMEMORY, ERROR_OUTOFMEMORY);
        }
    }

    void finish_job(const JobStatePtr& job) noexcept {
        if (!job) {
            return;
        }
        std::unique_lock<std::mutex> lock(mutex_);
        producer_cv_.wait(lock, [&job] {
            return job->pending_jobs.load(std::memory_order_acquire) == 0;
        });
    }

    void cancel_job(const JobStatePtr& job) noexcept {
        if (!job) {
            return;
        }
        job->cancelled.store(true, std::memory_order_release);
        HRESULT expected = S_OK;
        job->first_error.compare_exchange_strong(
            expected, E_ABORT, std::memory_order_acq_rel, std::memory_order_acquire);
        producer_cv_.notify_all();
    }

    // The worker owns the external cancellation token, while producers only
    // wait on producer_cv_.  Wake all producer/finish waiters after the token
    // changes so a Write() blocked on a full global/job/file budget observes
    // cancellation immediately instead of waiting for the next IO release.
    void wake_waiters() noexcept {
        producer_cv_.notify_all();
    }

    HRESULT current_error(const JobStatePtr& job) const noexcept {
        return job ? job->first_error.load(std::memory_order_acquire) : E_FAIL;
    }

    int current_win32_error(const JobStatePtr& job) const noexcept {
        return job ? job->first_win32_error.load(std::memory_order_acquire) : ERROR_INVALID_STATE;
    }

    void finish() noexcept {
        {
            std::lock_guard<std::mutex> lock(mutex_);
            stopping_ = true;
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

    void enqueue_file_job_locked(const FileStatePtr& file, WorkItem item) noexcept {
        if (!file) {
            return;
        }
        file->pending.push_back(std::move(item));
        if (!file->ready && !file->writing) {
            file->ready = true;
            ready_files_.push_back(file);
        }
    }

    FileStatePtr select_ready_file_locked() noexcept {
        if (ready_files_.empty()) {
            return nullptr;
        }
        std::size_t selected = 0;
        if (last_writer_job_ != nullptr) {
            for (std::size_t index = 0; index < ready_files_.size(); ++index) {
                const auto& candidate = ready_files_[index];
                if (candidate && candidate->job.get() != last_writer_job_) {
                    selected = index;
                    break;
                }
            }
        }
        FileStatePtr file = std::move(ready_files_[selected]);
        ready_files_.erase(ready_files_.begin() + static_cast<std::ptrdiff_t>(selected));
        if (file) {
            file->ready = false;
            file->writing = true;
            last_writer_job_ = file->job.get();
        }
        return file;
    }

    void writer_loop() noexcept {
        for (;;) {
            WorkItem item;
            FileStatePtr file;
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
                        file->ready = true;
                        ready_files_.push_back(file);
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
        if (job && job->is_cancelled() && !file->failed) {
            mark_file_failure(file, E_ABORT, ERROR_OPERATION_ABORTED);
        }
        const HRESULT global_error = job ? job->first_error.load(std::memory_order_acquire) : E_FAIL;
        if (global_error != S_OK && !file->failed) {
            mark_file_failure(file, global_error, job ? job->first_win32_error.load(std::memory_order_acquire) : 0);
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
        if (job && job->is_cancelled() && !file->failed) {
            mark_file_failure(file, E_ABORT, ERROR_OPERATION_ABORTED);
        }
        const HRESULT global_error = job ? job->first_error.load(std::memory_order_acquire) : E_FAIL;
        if (global_error != S_OK && !file->failed) {
            mark_file_failure(file, global_error, job ? job->first_win32_error.load(std::memory_order_acquire) : 0);
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
        file->closed = true;
        if (job) {
            job->pending_jobs.fetch_sub(1, std::memory_order_release);
        }
        producer_cv_.notify_all();
    }

    void release_buffer(Buffer* buffer) noexcept {
        if (!buffer) {
            return;
        }
        const auto file = buffer->file;
        const auto job = file ? file->job : nullptr;
        if (file) {
            file->inflight_bytes.fetch_sub(buffer->size, std::memory_order_release);
        }
        if (job) {
            job->inflight_bytes.fetch_sub(buffer->size, std::memory_order_release);
            job->pending_jobs.fetch_sub(1, std::memory_order_release);
        }
        buffer->file.reset();
        buffer->size = 0;
        {
            std::lock_guard<std::mutex> lock(mutex_);
            free_buffers_.push_back(buffer);
        }
        producer_cv_.notify_all();
    }

    void record_failure(const FileStatePtr& file, HRESULT hr, int win32_error) noexcept {
        mark_file_failure(file, hr, win32_error);
        if (!file || !file->job) {
            return;
        }
        HRESULT expected = S_OK;
        if (file->job->first_error.compare_exchange_strong(
                expected, hr, std::memory_order_acq_rel, std::memory_order_acquire)) {
            file->job->first_win32_error.store(win32_error, std::memory_order_release);
        }
        producer_cv_.notify_all();
    }

    static void mark_file_failure(const FileStatePtr& file, HRESULT hr, int win32_error) noexcept {
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
    mutable std::mutex mutex_;
    std::condition_variable producer_cv_;
    std::condition_variable work_cv_;
    const std::size_t writer_count_;
    JobState* last_writer_job_ = nullptr;
    std::size_t queued_jobs_ = 0;
    bool stopping_ = false;
};

}  // namespace sunpack::sevenzip

#endif
