#pragma once



#include "sevenzip_paths.hpp"

#include "sevenzip_sdk.hpp"



#ifdef _WIN32

#include <algorithm>

#include <filesystem>

#include <string>

#include <utility>

#include <vector>

#endif



namespace sunpack::sevenzip {



#ifdef _WIN32



class FileInStream final : public IInStream {

public:

    explicit FileInStream(const std::wstring& path, ExtractInputTrace* trace = nullptr, std::wstring mode = L"file")

        : path_(path),

          trace_(trace),

          handle_(CreateFileW(win32_extended_path(path).c_str(), GENERIC_READ, FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,

                              nullptr, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, nullptr)) {

        if (trace_) {

            trace_->mode = std::move(mode);

            trace_->last_source_path = path_;

            LARGE_INTEGER size{};

            if (handle_ != INVALID_HANDLE_VALUE && GetFileSizeEx(handle_, &size)) {

                trace_->virtual_size = static_cast<UInt64>(size.QuadPart);

            } else if (handle_ == INVALID_HANDLE_VALUE) {

                const DWORD error = GetLastError();

                trace_->read_error = true;

                trace_->last_hresult = HRESULT_FROM_WIN32(error);

                trace_->last_win32_error = static_cast<int>(error);

            }

        }

    }

    ~FileInStream() {

        if (handle_ != INVALID_HANDLE_VALUE) {

            CloseHandle(handle_);

        }

    }

    bool is_open() const { return handle_ != INVALID_HANDLE_VALUE; }



    HRESULT STDMETHODCALLTYPE QueryInterface(REFIID iid, void** object) override {

        if (!object) {

            return E_POINTER;

        }

        *object = nullptr;

        if (IsEqualGUID(iid, IID_IUnknown) || IsEqualGUID(iid, IID_ISequentialInStream) || IsEqualGUID(iid, IID_IInStream)) {

            *object = static_cast<IInStream*>(this);

            AddRef();

            return S_OK;

        }

        return E_NOINTERFACE;

    }

    ULONG STDMETHODCALLTYPE AddRef() override { return InterlockedIncrement(&refs_); }

    ULONG STDMETHODCALLTYPE Release() override {

        const ULONG refs = InterlockedDecrement(&refs_);

        if (refs == 0) {

            delete this;

        }

        return refs;

    }

    HRESULT STDMETHODCALLTYPE Read(void* data, UInt32 size, UInt32* processedSize) override {

        if (processedSize) {

            *processedSize = 0;

        }

        if (trace_) {

            trace_->last_read_virtual_offset = position_;

            trace_->last_read_source_offset = position_;

            trace_->last_read_requested = size;

            trace_->last_read_returned = 0;

            trace_->last_source_path = path_;

            trace_->last_range_index = 0;

        }

        DWORD read = 0;

        if (!ReadFile(handle_, data, size, &read, nullptr)) {

            const DWORD error = GetLastError();

            const HRESULT hr = HRESULT_FROM_WIN32(error);

            if (trace_) {

                trace_->read_error = true;

                trace_->last_hresult = hr;

                trace_->last_win32_error = static_cast<int>(error);

            }

            return hr;

        }

        position_ += read;

        if (trace_) {

            trace_->position = position_;

            trace_->max_position_seen = std::max<UInt64>(trace_->max_position_seen, position_);

            trace_->total_bytes_returned += read;

            trace_->last_read_returned = read;

            trace_->last_hresult = S_OK;

            trace_->last_win32_error = 0;

        }

        if (processedSize) {

            *processedSize = read;

        }

        return S_OK;

    }

    HRESULT STDMETHODCALLTYPE Seek(Int64 offset, UInt32 seekOrigin, UInt64* newPosition) override {

        LARGE_INTEGER distance{};

        distance.QuadPart = offset;

        LARGE_INTEGER new_pos{};

        if (!SetFilePointerEx(handle_, distance, &new_pos, seekOrigin)) {

            const DWORD error = GetLastError();

            const HRESULT hr = HRESULT_FROM_WIN32(error);

            if (trace_) {

                trace_->last_seek_offset = offset;

                trace_->last_seek_origin = seekOrigin;

                trace_->last_hresult = hr;

                trace_->last_win32_error = static_cast<int>(error);

            }

            return hr;

        }

        position_ = static_cast<UInt64>(new_pos.QuadPart);

        if (trace_) {

            trace_->position = position_;

            trace_->max_position_seen = std::max<UInt64>(trace_->max_position_seen, position_);

            trace_->last_seek_offset = offset;

            trace_->last_seek_origin = seekOrigin;

            trace_->last_seek_new_position = position_;

            trace_->last_hresult = S_OK;

            trace_->last_win32_error = 0;

        }

        if (newPosition) {

            *newPosition = position_;

        }

        return S_OK;

    }



private:

    LONG refs_ = 1;

    std::wstring path_;

    ExtractInputTrace* trace_ = nullptr;

    HANDLE handle_ = INVALID_HANDLE_VALUE;

    UInt64 position_ = 0;

};



class MultiFileInStream final : public IInStream {

public:

    explicit MultiFileInStream(std::vector<std::wstring> paths, ExtractInputTrace* trace = nullptr)

        : paths_(std::move(paths)), trace_(trace) {

        UInt64 total = 0;

        for (const auto& path : paths_) {

            try {

                const UInt64 size = static_cast<UInt64>(std::filesystem::file_size(path));

                sizes_.push_back(size);

                offsets_.push_back(total);

                total += size;

            } catch (...) {

                valid_ = false;

                sizes_.push_back(0);

                offsets_.push_back(total);

            }

        }

        total_size_ = total;

        valid_ = valid_ && !paths_.empty();

        if (trace_) {

            trace_->mode = L"multi_file";

            trace_->virtual_size = total_size_;

        }

    }



    bool is_open() const { return valid_; }



    HRESULT STDMETHODCALLTYPE QueryInterface(REFIID iid, void** object) override {

        if (!object) {

            return E_POINTER;

        }

        *object = nullptr;

        if (IsEqualGUID(iid, IID_IUnknown) || IsEqualGUID(iid, IID_ISequentialInStream) || IsEqualGUID(iid, IID_IInStream)) {

            *object = static_cast<IInStream*>(this);

            AddRef();

            return S_OK;

        }

        return E_NOINTERFACE;

    }

    ULONG STDMETHODCALLTYPE AddRef() override { return InterlockedIncrement(&refs_); }

    ULONG STDMETHODCALLTYPE Release() override {

        const ULONG refs = InterlockedDecrement(&refs_);

        if (refs == 0) {

            delete this;

        }

        return refs;

    }

    HRESULT STDMETHODCALLTYPE Read(void* data, UInt32 size, UInt32* processedSize) override {

        if (processedSize) {

            *processedSize = 0;

        }

        if (!valid_ || !data) {

            return E_FAIL;

        }



        auto* out = static_cast<unsigned char*>(data);

        UInt32 total_read = 0;

        while (total_read < size && position_ < total_size_) {

            std::size_t index = find_part_index(position_);

            if (index >= paths_.size()) {

                break;

            }

            const UInt64 part_offset = position_ - offsets_[index];

            const UInt64 remaining_in_part = sizes_[index] - part_offset;

            const UInt32 want = static_cast<UInt32>(std::min<UInt64>(size - total_read, remaining_in_part));

            if (want == 0) {

                break;

            }

            if (trace_) {

                trace_->last_read_virtual_offset = position_;

                trace_->last_read_source_offset = part_offset;

                trace_->last_read_requested = want;

                trace_->last_read_returned = 0;

                trace_->last_source_path = paths_[index];

                trace_->last_range_index = static_cast<UInt32>(index);

            }



            HANDLE handle = CreateFileW(win32_extended_path(paths_[index]).c_str(), GENERIC_READ, FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,

                                        nullptr, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, nullptr);

            if (handle == INVALID_HANDLE_VALUE) {

                const DWORD error = GetLastError();

                const HRESULT hr = HRESULT_FROM_WIN32(error);

                if (trace_) {

                    trace_->read_error = true;

                    trace_->last_hresult = hr;

                    trace_->last_win32_error = static_cast<int>(error);

                }

                return hr;

            }

            LARGE_INTEGER distance{};

            distance.QuadPart = static_cast<LONGLONG>(part_offset);

            if (!SetFilePointerEx(handle, distance, nullptr, FILE_BEGIN)) {

                const DWORD error = GetLastError();

                CloseHandle(handle);

                const HRESULT hr = HRESULT_FROM_WIN32(error);

                if (trace_) {

                    trace_->read_error = true;

                    trace_->last_hresult = hr;

                    trace_->last_win32_error = static_cast<int>(error);

                }

                return hr;

            }

            DWORD read = 0;

            const BOOL ok = ReadFile(handle, out + total_read, want, &read, nullptr);

            const DWORD error = GetLastError();

            CloseHandle(handle);

            if (!ok) {

                const HRESULT hr = HRESULT_FROM_WIN32(error);

                if (trace_) {

                    trace_->read_error = true;

                    trace_->last_hresult = hr;

                    trace_->last_win32_error = static_cast<int>(error);

                }

                return hr;

            }

            if (read == 0) {

                break;

            }

            total_read += read;

            position_ += read;

            if (trace_) {

                trace_->position = position_;

                trace_->max_position_seen = std::max<UInt64>(trace_->max_position_seen, position_);

                trace_->total_bytes_returned += read;

                trace_->last_read_returned = read;

                trace_->last_hresult = S_OK;

                trace_->last_win32_error = 0;

            }

        }

        if (processedSize) {

            *processedSize = total_read;

        }

        return S_OK;

    }

    HRESULT STDMETHODCALLTYPE Seek(Int64 offset, UInt32 seekOrigin, UInt64* newPosition) override {

        Int64 base = 0;

        if (seekOrigin == FILE_CURRENT) {

            base = static_cast<Int64>(position_);

        } else if (seekOrigin == FILE_END) {

            base = static_cast<Int64>(total_size_);

        }

        const Int64 next = base + offset;

        if (next < 0) {

            return E_INVALIDARG;

        }

        position_ = static_cast<UInt64>(next);

        if (trace_) {

            trace_->position = position_;

            trace_->max_position_seen = std::max<UInt64>(trace_->max_position_seen, position_);

            trace_->last_seek_offset = offset;

            trace_->last_seek_origin = seekOrigin;

            trace_->last_seek_new_position = position_;

            trace_->last_hresult = S_OK;

            trace_->last_win32_error = 0;

        }

        if (newPosition) {

            *newPosition = position_;

        }

        return S_OK;

    }



private:

    std::size_t find_part_index(UInt64 position) const {

        for (std::size_t index = 0; index < paths_.size(); ++index) {

            if (position >= offsets_[index] && position < offsets_[index] + sizes_[index]) {

                return index;

            }

        }

        return paths_.size();

    }



    LONG refs_ = 1;

    std::vector<std::wstring> paths_;

    std::vector<UInt64> sizes_;

    std::vector<UInt64> offsets_;

    UInt64 total_size_ = 0;

    UInt64 position_ = 0;

    ExtractInputTrace* trace_ = nullptr;

    bool valid_ = true;

};



struct NormalizedInputRange {

    std::wstring path;

    UInt64 start = 0;

    UInt64 length = 0;

    UInt64 virtual_offset = 0;

};

struct PatchedInputSegment {

    enum class Kind { FileRange, Bytes };

    Kind kind = Kind::FileRange;

    std::wstring path;

    UInt64 source_start = 0;

    UInt64 length = 0;

    UInt64 virtual_offset = 0;

    std::vector<unsigned char> data;

};



class MultiRangeInStream final : public IInStream {

public:

    explicit MultiRangeInStream(const std::vector<ExtractInputRange>& ranges, ExtractInputTrace* trace = nullptr)

        : trace_(trace) {

        UInt64 virtual_offset = 0;

        for (const auto& input : ranges) {

            if (input.path.empty()) {

                valid_ = false;

                continue;

            }

            UInt64 file_size = 0;

            try {

                file_size = static_cast<UInt64>(std::filesystem::file_size(input.path));

            } catch (...) {

                valid_ = false;

                continue;

            }

            const UInt64 start = std::min<UInt64>(input.start, file_size);

            const UInt64 end = input.has_end ? std::min<UInt64>(input.end, file_size) : file_size;

            if (end < start) {

                valid_ = false;

                continue;

            }

            const UInt64 length = end - start;

            if (length == 0) {

                continue;

            }

            ranges_.push_back(NormalizedInputRange{input.path, start, length, virtual_offset});

            virtual_offset += length;

        }

        total_size_ = virtual_offset;

        valid_ = valid_ && !ranges_.empty();

        if (trace_) {

            trace_->mode = ranges_.size() == 1 ? L"file_range" : L"concat_ranges";

            trace_->virtual_size = total_size_;

        }

    }



    bool is_open() const { return valid_; }



    HRESULT STDMETHODCALLTYPE QueryInterface(REFIID iid, void** object) override {

        if (!object) {

            return E_POINTER;

        }

        *object = nullptr;

        if (IsEqualGUID(iid, IID_IUnknown) || IsEqualGUID(iid, IID_ISequentialInStream) || IsEqualGUID(iid, IID_IInStream)) {

            *object = static_cast<IInStream*>(this);

            AddRef();

            return S_OK;

        }

        return E_NOINTERFACE;

    }

    ULONG STDMETHODCALLTYPE AddRef() override { return InterlockedIncrement(&refs_); }

    ULONG STDMETHODCALLTYPE Release() override {

        const ULONG refs = InterlockedDecrement(&refs_);

        if (refs == 0) {

            delete this;

        }

        return refs;

    }

    HRESULT STDMETHODCALLTYPE Read(void* data, UInt32 size, UInt32* processedSize) override {

        if (processedSize) {

            *processedSize = 0;

        }

        if (!valid_ || !data) {

            return E_FAIL;

        }

        auto* out = static_cast<unsigned char*>(data);

        UInt32 total_read = 0;

        while (total_read < size && position_ < total_size_) {

            const auto* range = find_range(position_);

            if (!range) {

                break;

            }

            const UInt64 offset_in_range = position_ - range->virtual_offset;

            const UInt64 remaining = range->length - offset_in_range;

            const UInt32 want = static_cast<UInt32>(std::min<UInt64>(size - total_read, remaining));

            if (trace_) {

                trace_->last_read_virtual_offset = position_;

                trace_->last_read_source_offset = range->start + offset_in_range;

                trace_->last_read_requested = want;

                trace_->last_read_returned = 0;

                trace_->last_source_path = range->path;

                trace_->last_range_index = range_index(position_);

            }

            HANDLE handle = CreateFileW(win32_extended_path(range->path).c_str(), GENERIC_READ, FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,

                                        nullptr, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, nullptr);

            if (handle == INVALID_HANDLE_VALUE) {

                const DWORD error = GetLastError();

                const HRESULT hr = HRESULT_FROM_WIN32(error);

                if (trace_) {

                    trace_->read_error = true;

                    trace_->last_hresult = hr;

                    trace_->last_win32_error = static_cast<int>(error);

                }

                return hr;

            }

            LARGE_INTEGER distance{};

            distance.QuadPart = static_cast<LONGLONG>(range->start + offset_in_range);

            if (!SetFilePointerEx(handle, distance, nullptr, FILE_BEGIN)) {

                const DWORD error = GetLastError();

                CloseHandle(handle);

                const HRESULT hr = HRESULT_FROM_WIN32(error);

                if (trace_) {

                    trace_->read_error = true;

                    trace_->last_hresult = hr;

                    trace_->last_win32_error = static_cast<int>(error);

                }

                return hr;

            }

            DWORD read = 0;

            const BOOL ok = ReadFile(handle, out + total_read, want, &read, nullptr);

            const DWORD error = GetLastError();

            CloseHandle(handle);

            if (!ok) {

                const HRESULT hr = HRESULT_FROM_WIN32(error);

                if (trace_) {

                    trace_->read_error = true;

                    trace_->last_hresult = hr;

                    trace_->last_win32_error = static_cast<int>(error);

                }

                return hr;

            }

            if (read == 0) {

                break;

            }

            total_read += read;

            position_ += read;

            if (trace_) {

                trace_->position = position_;

                trace_->max_position_seen = std::max<UInt64>(trace_->max_position_seen, position_);

                trace_->total_bytes_returned += read;

                trace_->last_read_returned = read;

                trace_->last_hresult = S_OK;

                trace_->last_win32_error = 0;

            }

        }

        if (processedSize) {

            *processedSize = total_read;

        }

        return S_OK;

    }

    HRESULT STDMETHODCALLTYPE Seek(Int64 offset, UInt32 seekOrigin, UInt64* newPosition) override {

        Int64 base = 0;

        if (seekOrigin == FILE_CURRENT) {

            base = static_cast<Int64>(position_);

        } else if (seekOrigin == FILE_END) {

            base = static_cast<Int64>(total_size_);

        }

        const Int64 next = base + offset;

        if (next < 0) {

            return E_INVALIDARG;

        }

        position_ = static_cast<UInt64>(next);

        if (trace_) {

            trace_->position = position_;

            trace_->max_position_seen = std::max<UInt64>(trace_->max_position_seen, position_);

            trace_->last_seek_offset = offset;

            trace_->last_seek_origin = seekOrigin;

            trace_->last_seek_new_position = position_;

            trace_->last_hresult = S_OK;

            trace_->last_win32_error = 0;

        }

        if (newPosition) {

            *newPosition = position_;

        }

        return S_OK;

    }



private:

    const NormalizedInputRange* find_range(UInt64 position) const {

        for (const auto& range : ranges_) {

            if (position >= range.virtual_offset && position < range.virtual_offset + range.length) {

                return &range;

            }

        }

        return nullptr;

    }

    UInt32 range_index(UInt64 position) const {

        for (std::size_t index = 0; index < ranges_.size(); ++index) {

            const auto& range = ranges_[index];

            if (position >= range.virtual_offset && position < range.virtual_offset + range.length) {

                return static_cast<UInt32>(index);

            }

        }

        return 0;

    }



    LONG refs_ = 1;

    std::vector<NormalizedInputRange> ranges_;

    UInt64 total_size_ = 0;

    UInt64 position_ = 0;

    ExtractInputTrace* trace_ = nullptr;

    bool valid_ = true;

};


class PatchedInStream final : public IInStream {

public:

    PatchedInStream(
        const std::vector<ExtractInputRange>& ranges,
        const std::vector<ExtractPatchOperation>& patches,
        ExtractInputTrace* trace = nullptr
    ) : trace_(trace) {
        UInt64 virtual_offset = 0;
        for (const auto& input : ranges) {
            if (input.path.empty()) {
                valid_ = false;
                continue;
            }
            UInt64 file_size = 0;
            try {
                file_size = static_cast<UInt64>(std::filesystem::file_size(input.path));
            } catch (...) {
                valid_ = false;
                continue;
            }
            const UInt64 start = std::min<UInt64>(input.start, file_size);
            const UInt64 end = input.has_end ? std::min<UInt64>(input.end, file_size) : file_size;
            if (end < start) {
                valid_ = false;
                continue;
            }
            const UInt64 length = end - start;
            if (length == 0) {
                continue;
            }
            PatchedInputSegment segment;
            segment.kind = PatchedInputSegment::Kind::FileRange;
            segment.path = input.path;
            segment.source_start = start;
            segment.length = length;
            segment.virtual_offset = virtual_offset;
            segments_.push_back(std::move(segment));
            virtual_offset += length;
        }
        valid_ = valid_ && !segments_.empty();
        if (valid_) {
            for (const auto& patch : patches) {
                if (!apply_patch(patch)) {
                    valid_ = false;
                    break;
                }
            }
        }
        reindex_segments();
        if (trace_) {
            trace_->mode = L"virtual_patch";
            trace_->virtual_size = total_size_;
        }
    }

    bool is_open() const { return valid_; }

    HRESULT STDMETHODCALLTYPE QueryInterface(REFIID iid, void** object) override {
        if (!object) {
            return E_POINTER;
        }
        *object = nullptr;
        if (IsEqualGUID(iid, IID_IUnknown) || IsEqualGUID(iid, IID_ISequentialInStream) || IsEqualGUID(iid, IID_IInStream)) {
            *object = static_cast<IInStream*>(this);
            AddRef();
            return S_OK;
        }
        return E_NOINTERFACE;
    }

    ULONG STDMETHODCALLTYPE AddRef() override { return InterlockedIncrement(&refs_); }

    ULONG STDMETHODCALLTYPE Release() override {
        const ULONG refs = InterlockedDecrement(&refs_);
        if (refs == 0) {
            delete this;
        }
        return refs;
    }

    HRESULT STDMETHODCALLTYPE Read(void* data, UInt32 size, UInt32* processedSize) override {
        if (processedSize) {
            *processedSize = 0;
        }
        if (!valid_ || !data) {
            return E_FAIL;
        }
        auto* out = static_cast<unsigned char*>(data);
        UInt32 total_read = 0;
        while (total_read < size && position_ < total_size_) {
            const auto* segment = find_segment(position_);
            if (!segment) {
                break;
            }
            const UInt64 offset_in_segment = position_ - segment->virtual_offset;
            const UInt64 remaining = segment->length - offset_in_segment;
            const UInt32 want = static_cast<UInt32>(std::min<UInt64>(size - total_read, remaining));
            UInt32 read = 0;
            HRESULT hr = S_OK;
            if (segment->kind == PatchedInputSegment::Kind::Bytes) {
                std::copy_n(segment->data.data() + offset_in_segment, want, out + total_read);
                read = want;
            } else {
                hr = read_file_segment(*segment, offset_in_segment, want, out + total_read, &read);
                if (hr != S_OK) {
                    return hr;
                }
            }
            if (read == 0) {
                break;
            }
            total_read += read;
            position_ += read;
            if (trace_) {
                trace_->position = position_;
                trace_->max_position_seen = std::max<UInt64>(trace_->max_position_seen, position_);
                trace_->total_bytes_returned += read;
                trace_->last_read_returned = read;
                trace_->last_hresult = S_OK;
                trace_->last_win32_error = 0;
            }
        }
        if (processedSize) {
            *processedSize = total_read;
        }
        return S_OK;
    }

    HRESULT STDMETHODCALLTYPE Seek(Int64 offset, UInt32 seekOrigin, UInt64* newPosition) override {
        Int64 base = 0;
        if (seekOrigin == FILE_CURRENT) {
            base = static_cast<Int64>(position_);
        } else if (seekOrigin == FILE_END) {
            base = static_cast<Int64>(total_size_);
        }
        const Int64 next = base + offset;
        if (next < 0) {
            return E_INVALIDARG;
        }
        position_ = static_cast<UInt64>(next);
        if (trace_) {
            trace_->position = position_;
            trace_->max_position_seen = std::max<UInt64>(trace_->max_position_seen, position_);
            trace_->last_seek_offset = offset;
            trace_->last_seek_origin = seekOrigin;
            trace_->last_seek_new_position = position_;
            trace_->last_hresult = S_OK;
            trace_->last_win32_error = 0;
        }
        if (newPosition) {
            *newPosition = position_;
        }
        return S_OK;
    }

private:

    bool apply_patch(const ExtractPatchOperation& patch) {
        if (!patch.target.empty() && patch.target != L"logical") {
            return false;
        }
        if (patch.op == L"replace_range") {
            const UInt64 size = patch.has_size ? patch.size : static_cast<UInt64>(patch.data.size());
            if (size != patch.data.size() || patch.offset + size > total_length()) {
                return false;
            }
            auto before = slice_segments(0, patch.offset);
            auto after = slice_segments(patch.offset + size, total_length());
            PatchedInputSegment replacement;
            replacement.kind = PatchedInputSegment::Kind::Bytes;
            replacement.length = static_cast<UInt64>(patch.data.size());
            replacement.data = patch.data;
            segments_ = std::move(before);
            segments_.push_back(std::move(replacement));
            segments_.insert(segments_.end(), after.begin(), after.end());
            reindex_segments();
            return true;
        }
        if (patch.op == L"truncate") {
            segments_ = slice_segments(0, patch.offset);
            reindex_segments();
            return true;
        }
        if (patch.op == L"append") {
            if (!patch.data.empty()) {
                PatchedInputSegment segment;
                segment.kind = PatchedInputSegment::Kind::Bytes;
                segment.length = static_cast<UInt64>(patch.data.size());
                segment.data = patch.data;
                segments_.push_back(std::move(segment));
                reindex_segments();
            }
            return true;
        }
        if (patch.op == L"insert") {
            if (patch.offset > total_length()) {
                return false;
            }
            auto before = slice_segments(0, patch.offset);
            auto after = slice_segments(patch.offset, total_length());
            segments_ = std::move(before);
            if (!patch.data.empty()) {
                PatchedInputSegment segment;
                segment.kind = PatchedInputSegment::Kind::Bytes;
                segment.length = static_cast<UInt64>(patch.data.size());
                segment.data = patch.data;
                segments_.push_back(std::move(segment));
            }
            segments_.insert(segments_.end(), after.begin(), after.end());
            reindex_segments();
            return true;
        }
        if (patch.op == L"delete") {
            if (!patch.has_size || patch.offset + patch.size > total_length()) {
                return false;
            }
            auto before = slice_segments(0, patch.offset);
            auto after = slice_segments(patch.offset + patch.size, total_length());
            segments_ = std::move(before);
            segments_.insert(segments_.end(), after.begin(), after.end());
            reindex_segments();
            return true;
        }
        return false;
    }

    std::vector<PatchedInputSegment> slice_segments(UInt64 start, UInt64 end) const {
        std::vector<PatchedInputSegment> out;
        for (const auto& segment : segments_) {
            const UInt64 segment_start = segment.virtual_offset;
            const UInt64 segment_end = segment.virtual_offset + segment.length;
            if (segment_end <= start) {
                continue;
            }
            if (segment_start >= end) {
                break;
            }
            const UInt64 take_start = std::max<UInt64>(start, segment_start) - segment_start;
            const UInt64 take_end = std::min<UInt64>(end, segment_end) - segment_start;
            if (take_end <= take_start) {
                continue;
            }
            PatchedInputSegment copy = segment;
            copy.virtual_offset = 0;
            copy.length = take_end - take_start;
            if (copy.kind == PatchedInputSegment::Kind::Bytes) {
                copy.data.assign(segment.data.begin() + take_start, segment.data.begin() + take_end);
            } else {
                copy.source_start = segment.source_start + take_start;
            }
            out.push_back(std::move(copy));
        }
        return out;
    }

    void reindex_segments() {
        UInt64 offset = 0;
        for (auto& segment : segments_) {
            segment.virtual_offset = offset;
            offset += segment.length;
        }
        total_size_ = offset;
    }

    UInt64 total_length() const {
        UInt64 length = 0;
        for (const auto& segment : segments_) {
            length += segment.length;
        }
        return length;
    }

    const PatchedInputSegment* find_segment(UInt64 position) const {
        for (const auto& segment : segments_) {
            if (position >= segment.virtual_offset && position < segment.virtual_offset + segment.length) {
                return &segment;
            }
        }
        return nullptr;
    }

    HRESULT read_file_segment(const PatchedInputSegment& segment, UInt64 offset_in_segment, UInt32 want, unsigned char* out, UInt32* read_out) {
        if (read_out) {
            *read_out = 0;
        }
        if (trace_) {
            trace_->last_read_virtual_offset = position_;
            trace_->last_read_source_offset = segment.source_start + offset_in_segment;
            trace_->last_read_requested = want;
            trace_->last_read_returned = 0;
            trace_->last_source_path = segment.path;
        }
        HANDLE handle = CreateFileW(win32_extended_path(segment.path).c_str(), GENERIC_READ, FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
                                    nullptr, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, nullptr);
        if (handle == INVALID_HANDLE_VALUE) {
            const DWORD error = GetLastError();
            const HRESULT hr = HRESULT_FROM_WIN32(error);
            if (trace_) {
                trace_->read_error = true;
                trace_->last_hresult = hr;
                trace_->last_win32_error = static_cast<int>(error);
            }
            return hr;
        }
        LARGE_INTEGER distance{};
        distance.QuadPart = static_cast<LONGLONG>(segment.source_start + offset_in_segment);
        if (!SetFilePointerEx(handle, distance, nullptr, FILE_BEGIN)) {
            const DWORD error = GetLastError();
            CloseHandle(handle);
            const HRESULT hr = HRESULT_FROM_WIN32(error);
            if (trace_) {
                trace_->read_error = true;
                trace_->last_hresult = hr;
                trace_->last_win32_error = static_cast<int>(error);
            }
            return hr;
        }
        DWORD read = 0;
        const BOOL ok = ReadFile(handle, out, want, &read, nullptr);
        const DWORD error = GetLastError();
        CloseHandle(handle);
        if (!ok) {
            const HRESULT hr = HRESULT_FROM_WIN32(error);
            if (trace_) {
                trace_->read_error = true;
                trace_->last_hresult = hr;
                trace_->last_win32_error = static_cast<int>(error);
            }
            return hr;
        }
        if (read_out) {
            *read_out = read;
        }
        return S_OK;
    }

    LONG refs_ = 1;

    std::vector<PatchedInputSegment> segments_;

    UInt64 total_size_ = 0;

    UInt64 position_ = 0;

    ExtractInputTrace* trace_ = nullptr;

    bool valid_ = true;

};





ComPtr<IInStream> open_archive_stream(

    const std::wstring& archive_path,

    const std::vector<std::wstring>& part_paths,

    bool& opened,

    ExtractInputTrace* trace = nullptr

);



std::wstring callback_archive_path(const std::wstring& archive_path, const std::vector<std::wstring>& part_paths);



#endif



}  // namespace sunpack::sevenzip
