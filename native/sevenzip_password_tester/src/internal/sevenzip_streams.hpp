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



namespace smart_unpacker::sevenzip {



#ifdef _WIN32



class FileInStream final : public IInStream {

public:

    explicit FileInStream(const std::wstring& path)

        : handle_(CreateFileW(win32_extended_path(path).c_str(), GENERIC_READ, FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,

                              nullptr, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, nullptr)) {}

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

        DWORD read = 0;

        if (!ReadFile(handle_, data, size, &read, nullptr)) {

            return HRESULT_FROM_WIN32(GetLastError());

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

            return HRESULT_FROM_WIN32(GetLastError());

        }

        if (newPosition) {

            *newPosition = static_cast<UInt64>(new_pos.QuadPart);

        }

        return S_OK;

    }



private:

    LONG refs_ = 1;

    HANDLE handle_ = INVALID_HANDLE_VALUE;

};



class MultiFileInStream final : public IInStream {

public:

    explicit MultiFileInStream(std::vector<std::wstring> paths) : paths_(std::move(paths)) {

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



            HANDLE handle = CreateFileW(win32_extended_path(paths_[index]).c_str(), GENERIC_READ, FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,

                                        nullptr, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, nullptr);

            if (handle == INVALID_HANDLE_VALUE) {

                return HRESULT_FROM_WIN32(GetLastError());

            }

            LARGE_INTEGER distance{};

            distance.QuadPart = static_cast<LONGLONG>(part_offset);

            if (!SetFilePointerEx(handle, distance, nullptr, FILE_BEGIN)) {

                const DWORD error = GetLastError();

                CloseHandle(handle);

                return HRESULT_FROM_WIN32(error);

            }

            DWORD read = 0;

            const BOOL ok = ReadFile(handle, out + total_read, want, &read, nullptr);

            const DWORD error = GetLastError();

            CloseHandle(handle);

            if (!ok) {

                return HRESULT_FROM_WIN32(error);

            }

            if (read == 0) {

                break;

            }

            total_read += read;

            position_ += read;

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

    bool valid_ = true;

};



struct NormalizedInputRange {

    std::wstring path;

    UInt64 start = 0;

    UInt64 length = 0;

    UInt64 virtual_offset = 0;

};



class MultiRangeInStream final : public IInStream {

public:

    explicit MultiRangeInStream(const std::vector<ExtractInputRange>& ranges) {

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

            HANDLE handle = CreateFileW(win32_extended_path(range->path).c_str(), GENERIC_READ, FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,

                                        nullptr, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, nullptr);

            if (handle == INVALID_HANDLE_VALUE) {

                return HRESULT_FROM_WIN32(GetLastError());

            }

            LARGE_INTEGER distance{};

            distance.QuadPart = static_cast<LONGLONG>(range->start + offset_in_range);

            if (!SetFilePointerEx(handle, distance, nullptr, FILE_BEGIN)) {

                const DWORD error = GetLastError();

                CloseHandle(handle);

                return HRESULT_FROM_WIN32(error);

            }

            DWORD read = 0;

            const BOOL ok = ReadFile(handle, out + total_read, want, &read, nullptr);

            const DWORD error = GetLastError();

            CloseHandle(handle);

            if (!ok) {

                return HRESULT_FROM_WIN32(error);

            }

            if (read == 0) {

                break;

            }

            total_read += read;

            position_ += read;

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



    LONG refs_ = 1;

    std::vector<NormalizedInputRange> ranges_;

    UInt64 total_size_ = 0;

    UInt64 position_ = 0;

    bool valid_ = true;

};





ComPtr<IInStream> open_archive_stream(

    const std::wstring& archive_path,

    const std::vector<std::wstring>& part_paths,

    bool& opened

);



std::wstring callback_archive_path(const std::wstring& archive_path, const std::vector<std::wstring>& part_paths);



#endif



}  // namespace smart_unpacker::sevenzip

