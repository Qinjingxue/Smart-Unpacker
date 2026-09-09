#pragma once
#include "sevenzip_paths.hpp"
#ifdef _WIN32
#include <algorithm>
#include <atomic>
#include <chrono>
#include <functional>
#include <filesystem>
#include <cwctype>
#include <limits>
#include <memory>
#include <mutex>
#include <string>
#include <unordered_map>

namespace sunpack::sevenzip {
struct DiskSpacePolicy {
    uint64_t reserve_bytes = 256ULL << 20;
    uint64_t quantum_bytes = 64ULL << 20;
    uint64_t sample_ms = 500;
};
struct DiskSpaceSample { uint64_t free_bytes = 0; DWORD error = 0; };
struct DiskSpaceVolume {
    std::wstring root;
    uint64_t cluster = 4096;
    std::mutex mutex;
    std::mutex sample_mutex;
    uint64_t balance = 0;
    std::atomic<uint64_t> pending{0};
    std::atomic<uint64_t> completed{0};
    std::chrono::steady_clock::time_point sampled{};
    uint64_t queries = 0, grants = 0, rejections = 0;
    DWORD query_error = 0;
    std::function<DiskSpaceSample()> provider;

    void refresh(uint64_t interval, bool force = false) {
        // Only this per-volume sampler lock is held across the OS query.
        std::lock_guard<std::mutex> sample_lock(sample_mutex);
        const auto now = std::chrono::steady_clock::now();
        {
            std::lock_guard<std::mutex> lock(mutex);
            auto age = std::chrono::duration_cast<std::chrono::milliseconds>(now - sampled).count();
            if (queries && age < static_cast<long long>(force ? 10 : interval)) return;
        }
        const auto before = completed.load();
        DiskSpaceSample sample;
        if (provider) sample = provider();
        else {
            ULARGE_INTEGER available{};
            if (GetDiskFreeSpaceExW(root.c_str(), &available, nullptr, nullptr)) sample.free_bytes = available.QuadPart;
            else sample.error = GetLastError();
        }
        std::lock_guard<std::mutex> lock(mutex);
        // Writes completing during sampling may still be included in free_bytes.
        // Charge them conservatively until the next sample.
        const auto in_flight = pending.load();
        const auto raced = completed.load() - before;
        const auto debt = in_flight > UINT64_MAX - raced ? UINT64_MAX : in_flight + raced;
        balance = sample.free_bytes > debt ? sample.free_bytes - debt : 0;
        query_error = sample.error;
        sampled = now;
        ++queries;
    }
    bool grant(uint64_t minimum, uint64_t desired, const DiskSpacePolicy& policy,
               uint64_t& granted, DWORD& error, uint64_t& available) {
        refresh(policy.sample_ms);
        for (int pass = 0; pass < 2; ++pass) {
            {
                std::lock_guard<std::mutex> lock(mutex);
                available = balance > policy.reserve_bytes ? balance - policy.reserve_bytes : 0;
                error = query_error;
                if (!error && available >= minimum) {
                    granted = (std::min)(desired, available);
                    balance -= granted;
                    pending.fetch_add(granted);
                    ++grants;
                    return true;
                }
            }
            if (pass == 0) refresh(policy.sample_ms, true);
        }
        std::lock_guard<std::mutex> lock(mutex);
        ++rejections;
        if (!error) error = ERROR_DISK_FULL;
        return false;
    }
    void unused(uint64_t bytes) {
        std::lock_guard<std::mutex> lock(mutex);
        pending.fetch_sub(bytes);
        balance = balance > UINT64_MAX - bytes ? UINT64_MAX : balance + bytes;
    }
    void written(uint64_t bytes) {
        // completed precedes pending: racing samples can overcharge, never undercharge.
        completed.fetch_add(bytes);
        pending.fetch_sub(bytes);
    }
};

inline std::shared_ptr<DiskSpaceVolume> disk_space_volume(const std::wstring& path, DWORD& error) {
    auto current = std::filesystem::path(win32_extended_path(path));
    std::error_code ec;
    while (!std::filesystem::exists(current, ec) && current.has_parent_path() && current.parent_path() != current) {
        current = current.parent_path();
        ec.clear();
    }
    // Resolve junctions and aliases through the actual existing directory handle.
    HANDLE handle = CreateFileW(current.c_str(), 0, FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
                                nullptr, OPEN_EXISTING, FILE_FLAG_BACKUP_SEMANTICS, nullptr);
    if (handle == INVALID_HANDLE_VALUE) { error = GetLastError(); return {}; }
    std::wstring resolved(32768, L'\0');
    DWORD length = GetFinalPathNameByHandleW(handle, resolved.data(), static_cast<DWORD>(resolved.size()), FILE_NAME_NORMALIZED);
    CloseHandle(handle);
    if (!length || length >= resolved.size()) { error = length ? ERROR_FILENAME_EXCED_RANGE : GetLastError(); return {}; }
    resolved.resize(length);
    std::wstring root(32768, L'\0');
    if (!GetVolumePathNameW(resolved.c_str(), root.data(), static_cast<DWORD>(root.size()))) { error = GetLastError(); return {}; }
    root.resize(wcslen(root.c_str()));
    wchar_t guid[128]{};
    std::wstring key = GetVolumeNameForVolumeMountPointW(root.c_str(), guid, 128) ? guid : root;
    std::transform(key.begin(), key.end(), key.begin(), towlower);
    static std::mutex registry_mutex;
    static std::unordered_map<std::wstring, std::shared_ptr<DiskSpaceVolume>> registry;
    std::lock_guard<std::mutex> lock(registry_mutex);
    if (auto existing = registry[key]) return existing;
    auto volume = std::make_shared<DiskSpaceVolume>();
    volume->root = root;
    DWORD sectors{}, bytes{}, free_clusters{}, clusters{};
    if (GetDiskFreeSpaceW(root.c_str(), &sectors, &bytes, &free_clusters, &clusters))
        volume->cluster = static_cast<uint64_t>(sectors) * bytes;
    registry[key] = volume;
    return volume;
}

class DiskSpaceLease {
public:
    DiskSpaceLease(std::wstring path, DiskSpacePolicy policy = {}) : policy_(policy) {
        volume_ = disk_space_volume(path, error_);
    }
    DiskSpaceLease(std::shared_ptr<DiskSpaceVolume> volume, DiskSpacePolicy policy) : volume_(std::move(volume)), policy_(policy) {}
    ~DiskSpaceLease() { if (volume_) volume_->unused(credit_ + charged_ - written_); }
    bool consume(uint64_t bytes, uint64_t remaining_hint = 0) {
        std::lock_guard<std::mutex> lock(mutex_);
        if (error_) return false;
        if (!bytes) return true;
        if (bytes > credit_) {
            uint64_t grant = 0;
            const auto need = bytes - credit_;
            const auto desired = (std::max)(need, (std::min)(policy_.quantum_bytes, remaining_hint ? remaining_hint : policy_.quantum_bytes));
            if (!volume_->grant(need, desired, policy_, grant, error_, available_)) { requested_ = need; return false; }
            credit_ += grant;
        }
        credit_ -= bytes;
        charged_ += bytes;
        return true;
    }
    void written(uint64_t bytes) {
        written_.fetch_add(bytes);
        volume_->written(bytes);
    }
    bool check_total(uint64_t total) {
        if (!volume_) return false;
        volume_->refresh(policy_.sample_ms);
        std::lock_guard<std::mutex> lock(volume_->mutex);
        available_ = volume_->balance > policy_.reserve_bytes ? volume_->balance - policy_.reserve_bytes : 0;
        if (volume_->query_error) error_ = volume_->query_error;
        else if (total > available_) error_ = ERROR_DISK_FULL;
        if (error_) {
            requested_ = total;
            ++volume_->rejections;
        }
        return !error_;
    }
    uint64_t rounded(uint64_t bytes) const {
        const auto unit = volume_ ? volume_->cluster : 4096;
        return bytes > UINT64_MAX - unit + 1 ? UINT64_MAX : (bytes + unit - 1) / unit * unit;
    }
    DWORD error() const { return error_; }
    uint64_t available() const { return available_; }
    uint64_t requested() const { return requested_; }
    std::wstring root() const { return volume_ ? volume_->root : L""; }
    std::shared_ptr<DiskSpaceVolume> volume() const { return volume_; }
private:
    DiskSpacePolicy policy_;
    std::shared_ptr<DiskSpaceVolume> volume_;
    std::mutex mutex_;
    uint64_t credit_ = 0, charged_ = 0;
    std::atomic<uint64_t> written_{0};
    DWORD error_ = 0;
    uint64_t available_ = 0, requested_ = 0;
};
inline thread_local DiskSpacePolicy current_disk_space_policy;
} // namespace sunpack::sevenzip
#endif
