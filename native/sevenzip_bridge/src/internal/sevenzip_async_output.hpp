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
    struct FileState {
        FileState(
            std::wstring file_path,
            std::wstring archive_path,
            UInt32 archive_index,
            std::size_t trace,
            std::size_t writer_lane)
            : path(std::move(file_path)),
              item_path(std::move(archive_path)),
              item_index(archive_index),
              trace_index(trace),
              lane(writer_lane) {}

        std::wstring path;
        std::wstring item_path;
        UInt32 item_index = 0;
        std::size_t trace_index = 0;
        std::size_t lane = 0;
        std::atomic<UInt64> accepted_bytes{0};
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

    private:
        friend class AsyncFileWriter;
        HANDLE handle = INVALID_HANDLE_VALUE;
        bool open_attempted = false;
    };

    using FileStatePtr = std::shared_ptr<FileState>;

    static constexpr std::size_t kBufferSize = 1U << 20;
    static constexpr std::size_t kBufferCount = 64;
    static constexpr std::size_t kMaxQueuedJobs = 4096;
    static constexpr std::size_t kDefaultWriterCount = 4;
    static constexpr std::size_t kMaxWriterCount = 8;

    AsyncFileWriter() : writer_count_(configured_writer_count()) {
        buffers_.reserve(kBufferCount);
        for (std::size_t index = 0; index < kBufferCount; ++index) {
            auto buffer = std::make_unique<Buffer>();
            free_buffers_.push_back(buffer.get());
            buffers_.push_back(std::move(buffer));
        }
        lanes_.reserve(writer_count_);
        workers_.reserve(writer_count_);
        for (std::size_t lane = 0; lane < writer_count_; ++lane) {
            lanes_.push_back(std::make_unique<WriterLane>());
        }
        try {
            for (std::size_t lane = 0; lane < writer_count_; ++lane) {
                workers_.emplace_back([this, lane] { writer_loop(lane); });
            }
        } catch (...) {
            {
                std::lock_guard<std::mutex> lock(mutex_);
                stopping_ = true;
            }
            for (const auto& lane : lanes_) {
                lane->cv.notify_all();
            }
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

    FileStatePtr make_file(
        std::wstring path,
        std::wstring item_path,
        UInt32 item_index,
        std::size_t trace_index
    ) {
        // One archive item always stays on one FIFO lane. This permits file
        // creation/write/close work for different items to overlap without
        // allowing a Close job to overtake that file's Data jobs.
        const std::size_t lane = next_lane_++ % writer_count_;
        return std::make_shared<FileState>(
            std::move(path), std::move(item_path), item_index, trace_index, lane);
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
        while (consumed < size) {
            Buffer* buffer = nullptr;
            {
                std::unique_lock<std::mutex> lock(mutex_);
                producer_cv_.wait(lock, [this] {
                    return first_error_.load(std::memory_order_acquire) != S_OK ||
                        stopping_ ||
                        (!free_buffers_.empty() && queued_jobs_ < kMaxQueuedJobs);
                });
                const HRESULT error = first_error_.load(std::memory_order_acquire);
                if (error != S_OK || stopping_) {
                    if (processed_size) {
                        *processed_size = consumed;
                    }
                    return error != S_OK ? error : E_ABORT;
                }
                buffer = free_buffers_.front();
                free_buffers_.pop_front();
            }

            const UInt32 chunk_size = static_cast<UInt32>(
                (std::min)(static_cast<std::size_t>(size - consumed), kBufferSize));
            std::memcpy(buffer->data.get(), source + consumed, chunk_size);
            buffer->size = chunk_size;
            buffer->file = file;

            {
                std::lock_guard<std::mutex> lock(mutex_);
                const HRESULT error = first_error_.load(std::memory_order_acquire);
                if (error != S_OK || stopping_) {
                    buffer->file.reset();
                    buffer->size = 0;
                    free_buffers_.push_back(buffer);
                    producer_cv_.notify_all();
                    if (processed_size) {
                        *processed_size = consumed;
                    }
                    return error != S_OK ? error : E_ABORT;
                }
                lanes_[file->lane]->jobs.push_back(Job::data(buffer));
                ++queued_jobs_;
            }
            consumed += chunk_size;
            file->accepted_bytes.fetch_add(chunk_size, std::memory_order_relaxed);
            lanes_[file->lane]->cv.notify_one();
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
            producer_cv_.wait(lock, [this] {
                return stopping_ || queued_jobs_ < kMaxQueuedJobs;
            });
            if (stopping_) {
                mark_file_failure(file, E_ABORT, ERROR_OPERATION_ABORTED);
                return;
            }
            lanes_[file->lane]->jobs.push_back(Job::close(file));
            ++queued_jobs_;
            lock.unlock();
            lanes_[file->lane]->cv.notify_one();
        } catch (...) {
            record_failure(file, E_OUTOFMEMORY, ERROR_OUTOFMEMORY);
        }
    }

    HRESULT current_error() const noexcept {
        return first_error_.load(std::memory_order_acquire);
    }

    int current_win32_error() const noexcept {
        return first_win32_error_.load(std::memory_order_acquire);
    }

    void finish() noexcept {
        {
            std::lock_guard<std::mutex> lock(mutex_);
            stopping_ = true;
        }
        for (const auto& lane : lanes_) {
            lane->cv.notify_all();
        }
        producer_cv_.notify_all();
        for (auto& worker : workers_) {
            if (worker.joinable()) {
                worker.join();
            }
        }
    }

private:
    struct Buffer {
        Buffer() : data(new unsigned char[kBufferSize]) {}
        std::unique_ptr<unsigned char[]> data;
        FileStatePtr file;
        UInt32 size = 0;
    };

    enum class JobKind { Data, Close };

    struct Job {
        static Job data(Buffer* value) {
            Job job;
            job.kind = JobKind::Data;
            job.buffer = value;
            return job;
        }

        static Job close(FileStatePtr value) {
            Job job;
            job.kind = JobKind::Close;
            job.file = std::move(value);
            return job;
        }

        JobKind kind = JobKind::Data;
        Buffer* buffer = nullptr;
        FileStatePtr file;
    };

    struct WriterLane {
        std::deque<Job> jobs;
        std::condition_variable cv;
    };

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

    void writer_loop(std::size_t lane_index) noexcept {
        WriterLane& lane = *lanes_[lane_index];
        for (;;) {
            Job job;
            {
                std::unique_lock<std::mutex> lock(mutex_);
                lane.cv.wait(lock, [this, &lane] { return stopping_ || !lane.jobs.empty(); });
                if (lane.jobs.empty()) {
                    if (stopping_) {
                        break;
                    }
                    continue;
                }
                job = std::move(lane.jobs.front());
                lane.jobs.pop_front();
                --queued_jobs_;
                producer_cv_.notify_all();
            }

            if (job.kind == JobKind::Data) {
                process_data(job.buffer);
                release_buffer(job.buffer);
            } else {
                process_close(job.file);
            }
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
        const HRESULT global_error = first_error_.load(std::memory_order_acquire);
        if (global_error != S_OK && !file->failed) {
            mark_file_failure(file, global_error, first_win32_error_.load(std::memory_order_acquire));
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
        const HRESULT global_error = first_error_.load(std::memory_order_acquire);
        if (global_error != S_OK && !file->failed) {
            mark_file_failure(file, global_error, first_win32_error_.load(std::memory_order_acquire));
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
    }

    void release_buffer(Buffer* buffer) noexcept {
        if (!buffer) {
            return;
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
        HRESULT expected = S_OK;
        if (first_error_.compare_exchange_strong(
                expected, hr, std::memory_order_acq_rel, std::memory_order_acquire)) {
            first_win32_error_.store(win32_error, std::memory_order_release);
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
    std::vector<std::unique_ptr<WriterLane>> lanes_;
    std::vector<std::thread> workers_;
    mutable std::mutex mutex_;
    std::condition_variable producer_cv_;
    std::atomic<HRESULT> first_error_{S_OK};
    std::atomic<int> first_win32_error_{0};
    const std::size_t writer_count_;
    std::size_t next_lane_ = 0;
    std::size_t queued_jobs_ = 0;
    bool stopping_ = false;
};

}  // namespace sunpack::sevenzip

#endif
