#include "sevenzip_password_tester/password_tester.hpp"
#include "archive_operations.hpp"

#ifdef _WIN32
#include <objbase.h>
#include <oleauto.h>
#include <windows.h>
#endif

#include <algorithm>
#include <cstdint>
#include <cwchar>
#include <cwctype>
#include <filesystem>
#include <fstream>
#include <map>
#include <memory>
#include <mutex>
#include <optional>
#include <string>
#include <vector>

namespace smart_unpacker::sevenzip {

#ifdef _WIN32

using UInt32 = std::uint32_t;
using UInt64 = std::uint64_t;
using UInt16 = std::uint16_t;
using Int32 = std::int32_t;
using Int64 = std::int64_t;

constexpr Int32 kAllItems = -1;
constexpr Int32 kTestMode = 1;
constexpr Int32 kExtractMode = 0;

constexpr Int32 kOpOk = 0;
constexpr Int32 kOpUnsupportedMethod = 1;
constexpr Int32 kOpDataError = 2;
constexpr Int32 kOpCrcError = 3;
constexpr Int32 kOpUnavailable = 4;
constexpr Int32 kOpUnexpectedEnd = 5;
constexpr Int32 kOpDataAfterEnd = 6;
constexpr Int32 kOpIsNotArc = 7;
constexpr Int32 kOpHeadersError = 8;
constexpr Int32 kOpWrongPassword = 9;

constexpr UInt32 kpidPath = 3;
constexpr UInt32 kpidName = 4;
constexpr UInt32 kpidIsDir = 6;
constexpr UInt32 kpidSize = 7;
constexpr UInt32 kpidPackSize = 8;
constexpr UInt32 kpidSolid = 13;
constexpr UInt32 kpidEncrypted = 15;
constexpr UInt32 kpidDictionarySize = 18;
constexpr UInt32 kpidCRC = 19;
constexpr UInt32 kpidMethod = 22;

bool prop_bool(const PROPVARIANT& value);
UInt64 prop_u64(const PROPVARIANT& value);
std::wstring prop_text(const PROPVARIANT& value);
void clear_prop(PROPVARIANT& value);
std::wstring archive_type_for_path(const std::wstring& path);

const GUID IID_ISequentialInStream = {
    0x23170F69, 0x40C1, 0x278A, {0x00, 0x00, 0x00, 0x03, 0x00, 0x01, 0x00, 0x00}};
const GUID IID_ISequentialOutStream = {
    0x23170F69, 0x40C1, 0x278A, {0x00, 0x00, 0x00, 0x03, 0x00, 0x02, 0x00, 0x00}};
const GUID IID_IInStream = {
    0x23170F69, 0x40C1, 0x278A, {0x00, 0x00, 0x00, 0x03, 0x00, 0x03, 0x00, 0x00}};
const GUID IID_IProgress = {
    0x23170F69, 0x40C1, 0x278A, {0x00, 0x00, 0x00, 0x00, 0x00, 0x05, 0x00, 0x00}};
const GUID IID_ICryptoGetTextPassword = {
    0x23170F69, 0x40C1, 0x278A, {0x00, 0x00, 0x00, 0x05, 0x00, 0x10, 0x00, 0x00}};
const GUID IID_IArchiveOpenCallback = {
    0x23170F69, 0x40C1, 0x278A, {0x00, 0x00, 0x00, 0x06, 0x00, 0x10, 0x00, 0x00}};
const GUID IID_IArchiveExtractCallback = {
    0x23170F69, 0x40C1, 0x278A, {0x00, 0x00, 0x00, 0x06, 0x00, 0x20, 0x00, 0x00}};
const GUID IID_IArchiveOpenVolumeCallback = {
    0x23170F69, 0x40C1, 0x278A, {0x00, 0x00, 0x00, 0x06, 0x00, 0x30, 0x00, 0x00}};
const GUID IID_IInArchive = {
    0x23170F69, 0x40C1, 0x278A, {0x00, 0x00, 0x00, 0x06, 0x00, 0x60, 0x00, 0x00}};

GUID format_guid(unsigned char format_id) {
    return {0x23170F69, 0x40C1, 0x278A, {0x10, 0x00, 0x00, 0x01, 0x10, format_id, 0x00, 0x00}};
}

std::wstring win32_extended_path(const std::wstring& path) {
    if (path.empty()) {
        return path;
    }
    if (path.rfind(LR"(\\?\)", 0) == 0 || path.rfind(LR"(\\.\)", 0) == 0) {
        return path;
    }
    if (path.rfind(LR"(\\)", 0) == 0) {
        return LR"(\\?\UNC\)" + path.substr(2);
    }
    if (path.size() >= 3 && path[1] == L':' && (path[2] == L'\\' || path[2] == L'/')) {
        return LR"(\\?\)" + path;
    }
    return path;
}

struct ISequentialInStream : public IUnknown {
    virtual HRESULT STDMETHODCALLTYPE Read(void* data, UInt32 size, UInt32* processedSize) = 0;
};

struct IInStream : public ISequentialInStream {
    virtual HRESULT STDMETHODCALLTYPE Seek(Int64 offset, UInt32 seekOrigin, UInt64* newPosition) = 0;
};

struct IProgress : public IUnknown {
    virtual HRESULT STDMETHODCALLTYPE SetTotal(UInt64 total) = 0;
    virtual HRESULT STDMETHODCALLTYPE SetCompleted(const UInt64* completeValue) = 0;
};

struct IArchiveOpenCallback : public IUnknown {
    virtual HRESULT STDMETHODCALLTYPE SetTotal(const UInt64* files, const UInt64* bytes) = 0;
    virtual HRESULT STDMETHODCALLTYPE SetCompleted(const UInt64* files, const UInt64* bytes) = 0;
};

struct IArchiveOpenVolumeCallback : public IUnknown {
    virtual HRESULT STDMETHODCALLTYPE GetProperty(UInt32 propID, PROPVARIANT* value) = 0;
    virtual HRESULT STDMETHODCALLTYPE GetStream(const wchar_t* name, IInStream** inStream) = 0;
};

struct ISequentialOutStream : public IUnknown {
    virtual HRESULT STDMETHODCALLTYPE Write(const void* data, UInt32 size, UInt32* processedSize) = 0;
};

struct IArchiveExtractCallback : public IProgress {
    virtual HRESULT STDMETHODCALLTYPE GetStream(UInt32 index, ISequentialOutStream** outStream, Int32 askExtractMode) = 0;
    virtual HRESULT STDMETHODCALLTYPE PrepareOperation(Int32 askExtractMode) = 0;
    virtual HRESULT STDMETHODCALLTYPE SetOperationResult(Int32 opRes) = 0;
};

struct ICryptoGetTextPassword : public IUnknown {
    virtual HRESULT STDMETHODCALLTYPE CryptoGetTextPassword(BSTR* password) = 0;
};

struct IInArchive : public IUnknown {
    virtual HRESULT STDMETHODCALLTYPE Open(IInStream* stream, const UInt64* maxCheckStartPosition, IArchiveOpenCallback* openCallback) = 0;
    virtual HRESULT STDMETHODCALLTYPE Close() = 0;
    virtual HRESULT STDMETHODCALLTYPE GetNumberOfItems(UInt32* numItems) = 0;
    virtual HRESULT STDMETHODCALLTYPE GetProperty(UInt32 index, UInt32 propID, PROPVARIANT* value) = 0;
    virtual HRESULT STDMETHODCALLTYPE Extract(const UInt32* indices, UInt32 numItems, Int32 testMode, IArchiveExtractCallback* extractCallback) = 0;
    virtual HRESULT STDMETHODCALLTYPE GetArchiveProperty(UInt32 propID, PROPVARIANT* value) = 0;
    virtual HRESULT STDMETHODCALLTYPE GetNumberOfProperties(UInt32* numProps) = 0;
    virtual HRESULT STDMETHODCALLTYPE GetPropertyInfo(UInt32 index, BSTR* name, UInt32* propID, VARTYPE* varType) = 0;
    virtual HRESULT STDMETHODCALLTYPE GetNumberOfArchiveProperties(UInt32* numProps) = 0;
    virtual HRESULT STDMETHODCALLTYPE GetArchivePropertyInfo(UInt32 index, BSTR* name, UInt32* propID, VARTYPE* varType) = 0;
};

bool get_item_property(IInArchive* archive, UInt32 index, UInt32 prop_id, PROPVARIANT& value);

using CreateObjectFunc = HRESULT(WINAPI*)(const GUID* clsid, const GUID* iid, void** outObject);

class ComModule {
public:
    explicit ComModule(const std::wstring& path) : module_(LoadLibraryW(path.c_str())) {}
    ~ComModule() {
        if (module_) {
            FreeLibrary(module_);
        }
    }
    HMODULE get() const { return module_; }
    CreateObjectFunc create_object() const {
        if (!module_) {
            return nullptr;
        }
        return reinterpret_cast<CreateObjectFunc>(GetProcAddress(module_, "CreateObject"));
    }

private:
    HMODULE module_ = nullptr;
};

template <typename T>
class ComPtr {
public:
    ComPtr() = default;
    explicit ComPtr(T* ptr) : ptr_(ptr) {}
    ~ComPtr() { reset(); }
    ComPtr(const ComPtr&) = delete;
    ComPtr& operator=(const ComPtr&) = delete;
    T* get() const { return ptr_; }
    T** out() {
        reset();
        return &ptr_;
    }
    T* operator->() const { return ptr_; }
    explicit operator bool() const { return ptr_ != nullptr; }
    void reset() {
        if (ptr_) {
            ptr_->Release();
            ptr_ = nullptr;
        }
    }

private:
    T* ptr_ = nullptr;
};

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

CreateObjectFunc cached_create_object(const std::wstring& seven_zip_dll_path) {
    static std::mutex mutex;
    static std::wstring cached_path;
    static std::unique_ptr<ComModule> cached_module;

    std::lock_guard<std::mutex> lock(mutex);
    if (!cached_module || cached_path != seven_zip_dll_path) {
        cached_module = std::make_unique<ComModule>(seven_zip_dll_path);
        cached_path = seven_zip_dll_path;
    }
    return cached_module ? cached_module->create_object() : nullptr;
}

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

std::wstring lower_text(std::wstring value) {
    std::transform(value.begin(), value.end(), value.begin(), [](wchar_t ch) { return static_cast<wchar_t>(::towlower(ch)); });
    return value;
}

std::wstring filename_lower(const std::wstring& path) {
    return lower_text(std::filesystem::path(path).filename().wstring());
}

bool ends_with(const std::wstring& value, const std::wstring& suffix) {
    return value.size() >= suffix.size() && value.compare(value.size() - suffix.size(), suffix.size(), suffix) == 0;
}

bool is_sfx_path(const std::wstring& path) {
    std::wstring ext = std::filesystem::path(path).extension().wstring();
    ext = lower_text(std::move(ext));
    return ext == L".exe" || ext == L".dll";
}

std::optional<int> parse_volume_number(const std::wstring& path) {
    const std::wstring name = filename_lower(path);
    if (name.size() >= 4 && name[name.size() - 4] == L'.') {
        const wchar_t a = name[name.size() - 3];
        const wchar_t b = name[name.size() - 2];
        const wchar_t c = name[name.size() - 1];
        if (iswdigit(a) && iswdigit(b) && iswdigit(c)) {
            return ((a - L'0') * 100) + ((b - L'0') * 10) + (c - L'0');
        }
    }

    const std::wstring marker = L".part";
    const std::size_t part_pos = name.rfind(marker);
    if (part_pos != std::wstring::npos && (ends_with(name, L".rar") || ends_with(name, L".exe"))) {
        const std::size_t start = part_pos + marker.size();
        const std::size_t end = name.size() - 4;
        if (start < end) {
            int number = 0;
            for (std::size_t index = start; index < end; ++index) {
                if (!iswdigit(name[index])) {
                    return std::nullopt;
                }
                number = (number * 10) + (name[index] - L'0');
            }
            return number;
        }
    }

    if (name.size() >= 4 && name[name.size() - 4] == L'.' && name[name.size() - 3] == L'r') {
        const wchar_t a = name[name.size() - 2];
        const wchar_t b = name[name.size() - 1];
        if (iswdigit(a) && iswdigit(b)) {
            return ((a - L'0') * 10) + (b - L'0') + 2;
        }
    }
    if (ends_with(name, L".rar")) {
        return 1;
    }

    return std::nullopt;
}

std::vector<std::wstring> unique_existing_paths(const std::wstring& archive_path, const std::vector<std::wstring>& part_paths) {
    std::vector<std::wstring> input = part_paths.empty() ? std::vector<std::wstring>{archive_path} : part_paths;
    if (std::find(input.begin(), input.end(), archive_path) == input.end()) {
        input.push_back(archive_path);
    }

    std::vector<std::wstring> result;
    std::vector<std::wstring> seen;
    for (const auto& path : input) {
        if (path.empty()) {
            continue;
        }
        const std::wstring key = lower_text(std::filesystem::path(path).wstring());
        if (std::find(seen.begin(), seen.end(), key) != seen.end()) {
            continue;
        }
        seen.push_back(key);
        result.push_back(path);
    }
    return result;
}

std::vector<std::wstring> sorted_data_volume_paths(const std::vector<std::wstring>& paths) {
    std::vector<std::wstring> volumes;
    for (const auto& path : paths) {
        const auto volume_number = parse_volume_number(path);
        if (volume_number.has_value()) {
            volumes.push_back(path);
        }
    }
    std::sort(volumes.begin(), volumes.end(), [](const std::wstring& left, const std::wstring& right) {
        const int left_number = parse_volume_number(left).value_or(0);
        const int right_number = parse_volume_number(right).value_or(0);
        if (left_number != right_number) {
            return left_number < right_number;
        }
        return lower_text(left) < lower_text(right);
    });
    return volumes;
}

ComPtr<IInStream> open_archive_stream(
    const std::wstring& archive_path,
    const std::vector<std::wstring>& part_paths,
    bool& opened
) {
    opened = false;
    if (is_sfx_path(archive_path)) {
        std::vector<std::wstring> volumes = sorted_data_volume_paths(unique_existing_paths(archive_path, part_paths));
        if (!volumes.empty() && is_sfx_path(volumes.front())) {
            auto* stream = new FileInStream(volumes.front());
            opened = stream->is_open();
            return ComPtr<IInStream>(stream);
        }
        if (volumes.size() > 1) {
            auto* stream = new MultiFileInStream(std::move(volumes));
            opened = stream->is_open();
            return ComPtr<IInStream>(stream);
        }
        if (volumes.size() == 1) {
            auto* stream = new FileInStream(volumes.front());
            opened = stream->is_open();
            return ComPtr<IInStream>(stream);
        }
        auto* stream = new FileInStream(archive_path);
        opened = stream->is_open();
        return ComPtr<IInStream>(stream);
    }

    std::vector<std::wstring> paths = sorted_data_volume_paths(unique_existing_paths(archive_path, part_paths));
    if (paths.empty()) {
        paths = std::vector<std::wstring>{archive_path};
    }
    if (paths.size() > 1) {
        auto* stream = new MultiFileInStream(std::move(paths));
        opened = stream->is_open();
        return ComPtr<IInStream>(stream);
    }

    auto* stream = new FileInStream(archive_path);
    opened = stream->is_open();
    return ComPtr<IInStream>(stream);
}

std::wstring callback_archive_path(const std::wstring& archive_path, const std::vector<std::wstring>& part_paths) {
    if (is_sfx_path(archive_path)) {
        const auto volumes = sorted_data_volume_paths(unique_existing_paths(archive_path, part_paths));
        if (!volumes.empty() && is_sfx_path(volumes.front())) {
            return volumes.front();
        }
    }
    return archive_path;
}

class OpenCallback final : public IArchiveOpenCallback, public IArchiveOpenVolumeCallback, public ICryptoGetTextPassword {
public:
    explicit OpenCallback(std::wstring password, std::wstring archive_path = L"", std::vector<std::wstring> part_paths = {})
        : password_(std::move(password)),
          archive_path_(std::move(archive_path)),
          part_paths_(std::move(part_paths)) {
        for (const auto& path : part_paths_) {
            const std::wstring name = lower_path(std::filesystem::path(path).filename().wstring());
            if (!name.empty()) {
                volume_paths_[name] = path;
            }
            volume_paths_[lower_path(std::filesystem::path(path).wstring())] = path;
        }
        if (!archive_path_.empty()) {
            const std::wstring name = lower_path(std::filesystem::path(archive_path_).filename().wstring());
            if (!name.empty()) {
                volume_paths_[name] = archive_path_;
            }
            volume_paths_[lower_path(std::filesystem::path(archive_path_).wstring())] = archive_path_;
        }
    }

    HRESULT STDMETHODCALLTYPE QueryInterface(REFIID iid, void** object) override {
        if (!object) {
            return E_POINTER;
        }
        *object = nullptr;
        if (IsEqualGUID(iid, IID_IUnknown) || IsEqualGUID(iid, IID_IArchiveOpenCallback)) {
            *object = static_cast<IArchiveOpenCallback*>(this);
        } else if (IsEqualGUID(iid, IID_IArchiveOpenVolumeCallback)) {
            *object = static_cast<IArchiveOpenVolumeCallback*>(this);
        } else if (IsEqualGUID(iid, IID_ICryptoGetTextPassword)) {
            *object = static_cast<ICryptoGetTextPassword*>(this);
        } else {
            return E_NOINTERFACE;
        }
        AddRef();
        return S_OK;
    }
    ULONG STDMETHODCALLTYPE AddRef() override { return InterlockedIncrement(&refs_); }
    ULONG STDMETHODCALLTYPE Release() override {
        const ULONG refs = InterlockedDecrement(&refs_);
        if (refs == 0) {
            delete this;
        }
        return refs;
    }
    HRESULT STDMETHODCALLTYPE SetTotal(const UInt64*, const UInt64*) override { return S_OK; }
    HRESULT STDMETHODCALLTYPE SetCompleted(const UInt64*, const UInt64*) override { return S_OK; }
    HRESULT STDMETHODCALLTYPE GetProperty(UInt32 propID, PROPVARIANT* value) override {
        if (!value) {
            return E_POINTER;
        }
        value->vt = VT_EMPTY;
        if (propID == kpidName && !archive_path_.empty()) {
            value->vt = VT_BSTR;
            value->bstrVal = SysAllocString(archive_path_.c_str());
            return value->bstrVal ? S_OK : E_OUTOFMEMORY;
        }
        return S_OK;
    }
    HRESULT STDMETHODCALLTYPE GetStream(const wchar_t* name, IInStream** inStream) override {
        if (!inStream) {
            return E_POINTER;
        }
        *inStream = nullptr;
        if (!name) {
            return E_FAIL;
        }

        std::wstring requested = lower_path(std::filesystem::path(name).filename().wstring());
        auto found = volume_paths_.find(requested);
        if (found == volume_paths_.end()) {
            requested = lower_path(std::wstring(name));
            found = volume_paths_.find(requested);
        }
        if (found == volume_paths_.end()) {
            return E_FAIL;
        }

        auto* stream = new FileInStream(found->second);
        if (!stream->is_open()) {
            stream->Release();
            return E_FAIL;
        }
        *inStream = stream;
        return S_OK;
    }
    HRESULT STDMETHODCALLTYPE CryptoGetTextPassword(BSTR* password) override {
        if (!password) {
            return E_POINTER;
        }
        *password = SysAllocString(password_.c_str());
        return *password ? S_OK : E_OUTOFMEMORY;
    }

private:
    static std::wstring lower_path(std::wstring value) {
        std::transform(value.begin(), value.end(), value.begin(), [](wchar_t ch) { return static_cast<wchar_t>(::towlower(ch)); });
        return value;
    }

    LONG refs_ = 1;
    std::wstring password_;
    std::wstring archive_path_;
    std::vector<std::wstring> part_paths_;
    std::map<std::wstring, std::wstring> volume_paths_;
};

class ExtractCallback final : public IArchiveExtractCallback, public ICryptoGetTextPassword {
public:
    explicit ExtractCallback(std::wstring password) : password_(std::move(password)) {}
    Int32 operation_result() const { return operation_result_; }

    HRESULT STDMETHODCALLTYPE QueryInterface(REFIID iid, void** object) override {
        if (!object) {
            return E_POINTER;
        }
        *object = nullptr;
        if (IsEqualGUID(iid, IID_IUnknown) || IsEqualGUID(iid, IID_IProgress) || IsEqualGUID(iid, IID_IArchiveExtractCallback)) {
            *object = static_cast<IArchiveExtractCallback*>(this);
        } else if (IsEqualGUID(iid, IID_ICryptoGetTextPassword)) {
            *object = static_cast<ICryptoGetTextPassword*>(this);
        } else {
            return E_NOINTERFACE;
        }
        AddRef();
        return S_OK;
    }
    ULONG STDMETHODCALLTYPE AddRef() override { return InterlockedIncrement(&refs_); }
    ULONG STDMETHODCALLTYPE Release() override {
        const ULONG refs = InterlockedDecrement(&refs_);
        if (refs == 0) {
            delete this;
        }
        return refs;
    }
    HRESULT STDMETHODCALLTYPE SetTotal(UInt64) override { return S_OK; }
    HRESULT STDMETHODCALLTYPE SetCompleted(const UInt64*) override { return S_OK; }
    HRESULT STDMETHODCALLTYPE GetStream(UInt32, ISequentialOutStream** outStream, Int32) override {
        if (!outStream) {
            return E_POINTER;
        }
        *outStream = nullptr;
        return S_OK;
    }
    HRESULT STDMETHODCALLTYPE PrepareOperation(Int32) override { return S_OK; }
    HRESULT STDMETHODCALLTYPE SetOperationResult(Int32 opRes) override {
        operation_result_ = opRes;
        return S_OK;
    }
    HRESULT STDMETHODCALLTYPE CryptoGetTextPassword(BSTR* password) override {
        if (!password) {
            return E_POINTER;
        }
        *password = SysAllocString(password_.c_str());
        return *password ? S_OK : E_OUTOFMEMORY;
    }

private:
    LONG refs_ = 1;
    std::wstring password_;
    Int32 operation_result_ = kOpOk;
};

class FileOutStream final : public ISequentialOutStream {
public:
    explicit FileOutStream(const std::wstring& path)
        : handle_(CreateFileW(win32_extended_path(path).c_str(), GENERIC_WRITE, 0, nullptr, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, nullptr)) {}
    ~FileOutStream() {
        if (handle_ != INVALID_HANDLE_VALUE) {
            CloseHandle(handle_);
        }
    }
    bool is_open() const { return handle_ != INVALID_HANDLE_VALUE; }
    UInt64 bytes_written() const { return bytes_written_; }

    HRESULT STDMETHODCALLTYPE QueryInterface(REFIID iid, void** object) override {
        if (!object) {
            return E_POINTER;
        }
        *object = nullptr;
        if (IsEqualGUID(iid, IID_IUnknown) || IsEqualGUID(iid, IID_ISequentialOutStream)) {
            *object = static_cast<IUnknown*>(this);
        } else {
            return E_NOINTERFACE;
        }
        AddRef();
        return S_OK;
    }
    ULONG STDMETHODCALLTYPE AddRef() override { return InterlockedIncrement(&refs_); }
    ULONG STDMETHODCALLTYPE Release() override {
        const ULONG refs = InterlockedDecrement(&refs_);
        if (refs == 0) {
            delete this;
        }
        return refs;
    }
    HRESULT STDMETHODCALLTYPE Write(const void* data, UInt32 size, UInt32* processedSize) override {
        if (processedSize) {
            *processedSize = 0;
        }
        if (handle_ == INVALID_HANDLE_VALUE) {
            return E_FAIL;
        }
        DWORD written = 0;
        if (!WriteFile(handle_, data, size, &written, nullptr)) {
            return HRESULT_FROM_WIN32(GetLastError());
        }
        bytes_written_ += written;
        if (processedSize) {
            *processedSize = written;
        }
        return S_OK;
    }

private:
    LONG refs_ = 1;
    HANDLE handle_ = INVALID_HANDLE_VALUE;
    UInt64 bytes_written_ = 0;
};

std::optional<std::filesystem::path> safe_relative_item_path(const std::wstring& raw_name) {
    if (raw_name.empty()) {
        return std::nullopt;
    }
    std::filesystem::path candidate(raw_name);
    if (candidate.is_absolute() || candidate.has_root_name() || candidate.has_root_directory()) {
        return std::nullopt;
    }
    std::filesystem::path normalized;
    for (const auto& part : candidate) {
        const auto text = part.wstring();
        if (text.empty() || text == L"." || text == L"/" || text == L"\\") {
            continue;
        }
        if (text == L"..") {
            return std::nullopt;
        }
        normalized /= part;
    }
    if (normalized.empty()) {
        return std::nullopt;
    }
    return normalized;
}

class ExtractToDiskCallback final : public IArchiveExtractCallback, public ICryptoGetTextPassword {
public:
    ExtractToDiskCallback(
        IInArchive* archive,
        std::wstring password,
        std::wstring output_dir,
        ExtractProgressCallback progress
    ) : archive_(archive),
        password_(std::move(password)),
        output_dir_(std::move(output_dir)),
        progress_(std::move(progress)) {}

    Int32 operation_result() const { return operation_result_; }
    UInt32 files_written() const { return files_written_; }
    UInt32 dirs_written() const { return dirs_written_; }
    UInt64 bytes_written() const { return bytes_written_; }
    UInt64 completed_bytes() const { return completed_bytes_; }
    const std::wstring& failed_item() const { return failed_item_; }
    bool output_error() const { return output_error_; }

    HRESULT STDMETHODCALLTYPE QueryInterface(REFIID iid, void** object) override {
        if (!object) {
            return E_POINTER;
        }
        *object = nullptr;
        if (IsEqualGUID(iid, IID_IUnknown) || IsEqualGUID(iid, IID_IProgress) || IsEqualGUID(iid, IID_IArchiveExtractCallback)) {
            *object = static_cast<IArchiveExtractCallback*>(this);
        } else if (IsEqualGUID(iid, IID_ICryptoGetTextPassword)) {
            *object = static_cast<ICryptoGetTextPassword*>(this);
        } else {
            return E_NOINTERFACE;
        }
        AddRef();
        return S_OK;
    }
    ULONG STDMETHODCALLTYPE AddRef() override { return InterlockedIncrement(&refs_); }
    ULONG STDMETHODCALLTYPE Release() override {
        const ULONG refs = InterlockedDecrement(&refs_);
        if (refs == 0) {
            delete this;
        }
        return refs;
    }
    HRESULT STDMETHODCALLTYPE SetTotal(UInt64 total) override {
        total_bytes_ = total;
        emit("total", 0, L"");
        return S_OK;
    }
    HRESULT STDMETHODCALLTYPE SetCompleted(const UInt64* completeValue) override {
        if (completeValue) {
            completed_bytes_ = *completeValue;
            emit("progress", current_index_, current_item_);
        }
        return S_OK;
    }
    HRESULT STDMETHODCALLTYPE GetStream(UInt32 index, ISequentialOutStream** outStream, Int32 askExtractMode) override {
        if (!outStream) {
            return E_POINTER;
        }
        *outStream = nullptr;
        current_index_ = index;
        current_item_.clear();
        if (askExtractMode != kExtractMode) {
            return S_OK;
        }

        PROPVARIANT value{};
        bool is_dir = false;
        if (get_item_property(archive_, index, kpidIsDir, value)) {
            is_dir = prop_bool(value);
        }
        clear_prop(value);

        std::wstring name;
        if (get_item_property(archive_, index, kpidPath, value)) {
            name = prop_text(value);
        }
        clear_prop(value);
        if (name.empty() && get_item_property(archive_, index, kpidName, value)) {
            name = prop_text(value);
        }
        clear_prop(value);
        if (name.empty()) {
            name = L"#" + std::to_wstring(index);
        }
        current_item_ = name;

        const auto safe_path = safe_relative_item_path(name);
        if (!safe_path.has_value()) {
            failed_item_ = name;
            output_error_ = true;
            return E_INVALIDARG;
        }
        const auto target = std::filesystem::path(win32_extended_path(output_dir_)) / safe_path.value();
        emit("item_start", index, name);
        try {
            if (is_dir) {
                std::filesystem::create_directories(target);
                dirs_written_ += 1;
                return S_OK;
            }
            std::filesystem::create_directories(target.parent_path());
        } catch (...) {
            failed_item_ = name;
            output_error_ = true;
            return E_FAIL;
        }

        auto* stream = new FileOutStream(target.wstring());
        if (!stream->is_open()) {
            stream->Release();
            failed_item_ = name;
            output_error_ = true;
            return E_FAIL;
        }
        *outStream = stream;
        return S_OK;
    }
    HRESULT STDMETHODCALLTYPE PrepareOperation(Int32) override { return S_OK; }
    HRESULT STDMETHODCALLTYPE SetOperationResult(Int32 opRes) override {
        if (opRes != kOpOk || operation_result_ == kOpOk) {
            operation_result_ = opRes;
        }
        if (opRes == kOpOk && !current_item_.empty()) {
            files_written_ += 1;
        } else if (opRes != kOpOk && failed_item_.empty()) {
            failed_item_ = current_item_;
        }
        emit(opRes == kOpOk ? "item_done" : "item_failed", current_index_, current_item_);
        return S_OK;
    }
    HRESULT STDMETHODCALLTYPE CryptoGetTextPassword(BSTR* password) override {
        if (!password) {
            return E_POINTER;
        }
        *password = SysAllocString(password_.c_str());
        return *password ? S_OK : E_OUTOFMEMORY;
    }

private:
    void emit(const std::string& event, UInt32 item_index, const std::wstring& item_path) {
        if (!progress_) {
            return;
        }
        ExtractProgressEvent progress;
        progress.event = event;
        progress.completed_bytes = completed_bytes_;
        progress.total_bytes = total_bytes_;
        progress.item_index = item_index;
        progress.item_path = item_path;
        progress_(progress);
    }

    LONG refs_ = 1;
    IInArchive* archive_ = nullptr;
    std::wstring password_;
    std::wstring output_dir_;
    ExtractProgressCallback progress_;
    UInt64 completed_bytes_ = 0;
    UInt64 total_bytes_ = 0;
    UInt64 bytes_written_ = 0;
    UInt32 current_index_ = 0;
    UInt32 files_written_ = 0;
    UInt32 dirs_written_ = 0;
    std::wstring current_item_;
    std::wstring failed_item_;
    Int32 operation_result_ = kOpOk;
    bool output_error_ = false;
};

std::wstring lower_extension(const std::wstring& path) {
    std::wstring ext = std::filesystem::path(path).extension().wstring();
    std::transform(ext.begin(), ext.end(), ext.begin(), [](wchar_t ch) { return static_cast<wchar_t>(::towlower(ch)); });
    return ext;
}

std::wstring split_volume_family(const std::vector<std::wstring>& part_paths) {
    for (const auto& path : sorted_data_volume_paths(part_paths)) {
        const std::wstring name = filename_lower(path);
        if (name.find(L".zip.") != std::wstring::npos) {
            return L"zip";
        }
        if (name.find(L".7z.") != std::wstring::npos) {
            return L"7z";
        }
        if (name.find(L".rar.") != std::wstring::npos || name.find(L".part") != std::wstring::npos || ends_with(name, L".r00")) {
            return L"rar";
        }
    }
    return L"";
}

std::vector<unsigned char> format_ids_for_signature(const std::wstring& archive_path, bool scan_prefix = false) {
    HANDLE handle = CreateFileW(win32_extended_path(archive_path).c_str(), GENERIC_READ, FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
                                nullptr, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, nullptr);
    if (handle == INVALID_HANDLE_VALUE) {
        return {};
    }

    const DWORD bytes_to_read = scan_prefix ? 1024 * 1024 : 8;
    std::vector<unsigned char> buffer(bytes_to_read);
    DWORD read = 0;
    const BOOL ok = ReadFile(handle, buffer.data(), bytes_to_read, &read, nullptr);
    CloseHandle(handle);
    if (!ok || read == 0) {
        return {};
    }
    buffer.resize(read);

    const unsigned char rar4[] = {'R', 'a', 'r', '!', 0x1A, 0x07, 0x00};
    const unsigned char rar5[] = {'R', 'a', 'r', '!', 0x1A, 0x07, 0x01, 0x00};
    const unsigned char seven_zip[] = {'7', 'z', 0xBC, 0xAF, 0x27, 0x1C};
    const unsigned char zip[] = {'P', 'K', 0x03, 0x04};
    const unsigned char gzip[] = {0x1F, 0x8B};
    const unsigned char bzip2[] = {'B', 'Z', 'h'};
    const unsigned char xz[] = {0xFD, '7', 'z', 'X', 'Z', 0x00};
    const unsigned char zstd[] = {0x28, 0xB5, 0x2F, 0xFD};

    const std::size_t search_limit = scan_prefix ? buffer.size() : 1;
    for (std::size_t offset = 0; offset < search_limit; ++offset) {
        const std::size_t remaining = buffer.size() - offset;
        const unsigned char* cursor = buffer.data() + offset;
        if (remaining >= sizeof(rar5) && std::equal(std::begin(rar5), std::end(rar5), cursor)) {
            return {0xCC};
        }
        if (remaining >= sizeof(rar4) && std::equal(std::begin(rar4), std::end(rar4), cursor)) {
            return {0x03};
        }
        if (remaining >= sizeof(seven_zip) && std::equal(std::begin(seven_zip), std::end(seven_zip), cursor)) {
            return {0x07};
        }
        if (remaining >= sizeof(zip) && std::equal(std::begin(zip), std::end(zip), cursor)) {
            return {0x01};
        }
        if (remaining >= sizeof(xz) && std::equal(std::begin(xz), std::end(xz), cursor)) {
            return {0x0C};
        }
        if (remaining >= sizeof(zstd) && std::equal(std::begin(zstd), std::end(zstd), cursor)) {
            return {0x0E};
        }
        if (remaining >= sizeof(bzip2) && std::equal(std::begin(bzip2), std::end(bzip2), cursor)) {
            return {0x02};
        }
        if (remaining >= sizeof(gzip) && std::equal(std::begin(gzip), std::end(gzip), cursor)) {
            return {0x0F};
        }
    }
    return {};
}

std::vector<unsigned char> rar_format_ids_for_paths(
    const std::wstring& archive_path,
    const std::vector<std::wstring>& part_paths,
    bool scan_prefix = false
) {
    std::vector<std::wstring> candidates = unique_existing_paths(archive_path, part_paths);
    std::vector<std::wstring> volumes = sorted_data_volume_paths(candidates);
    candidates.insert(candidates.end(), volumes.begin(), volumes.end());
    for (const auto& path : candidates) {
        const auto ids = format_ids_for_signature(path, scan_prefix || is_sfx_path(path));
        if (ids == std::vector<unsigned char>{0xCC} || ids == std::vector<unsigned char>{0x03}) {
            return ids;
        }
    }
    return {0xCC, 0x03};
}

std::vector<GUID> candidate_formats(const std::wstring& archive_path, const std::vector<std::wstring>& part_paths = {}) {
    const std::wstring ext = lower_extension(archive_path);
    std::wstring name = std::filesystem::path(archive_path).filename().wstring();
    std::transform(name.begin(), name.end(), name.begin(), [](wchar_t ch) { return static_cast<wchar_t>(::towlower(ch)); });
    const std::wstring split_family = split_volume_family(part_paths);
    std::vector<unsigned char> ids;
    if (is_sfx_path(archive_path) && split_family == L"zip") {
        ids = {0x01};
    } else if (is_sfx_path(archive_path) && split_family == L"7z") {
        ids = {0x07};
    } else if (is_sfx_path(archive_path) && split_family == L"rar") {
        ids = rar_format_ids_for_paths(archive_path, part_paths, true);
    } else if (ext == L".zip" || ext == L".jar" || ext == L".docx" || ext == L".xlsx" || ext == L".apk") {
        ids = {0x01};
    } else if (name.size() >= 8 && name.compare(name.size() - 8, 8, L".zip.001") == 0) {
        ids = {0x01, 0x07};
    } else if (name.size() >= 7 && name.compare(name.size() - 7, 7, L".7z.001") == 0) {
        ids = {0x07, 0x01};
    } else if (ext == L".7z") {
        ids = {0x07};
    } else if (ext == L".tar") {
        ids = {0xEE};
    } else if (ext == L".gz" || ext == L".tgz") {
        ids = {0xEF, 0xEE};
    } else if (ext == L".bz2" || ext == L".tbz2" || ext == L".tbz") {
        ids = {0x02, 0xEE};
    } else if (ext == L".xz" || ext == L".txz") {
        ids = {0x0C, 0xEE};
    } else if (ext == L".zst" || ext == L".tzst") {
        ids = {0x0E, 0xEE};
    } else if (ext == L".001") {
        ids = format_ids_for_signature(archive_path);
        if (ids.empty()) {
            ids = {0x07};
        }
    } else if (ext == L".rar" || ext == L".r00") {
        ids = rar_format_ids_for_paths(archive_path, part_paths);
    } else {
        ids = format_ids_for_signature(archive_path, is_sfx_path(archive_path));
        if (ids.empty()) {
            ids = {0x07, 0x01, 0x03, 0xCC, 0xEE, 0xEF, 0x02, 0x0C, 0x0E};
        }
    }

    std::vector<GUID> formats;
    for (const unsigned char id : ids) {
        formats.push_back(format_guid(id));
    }
    return formats;
}

std::vector<GUID> candidate_formats_for_hint(const std::wstring& format_hint, const std::wstring& archive_path, const std::vector<std::wstring>& part_paths = {}) {
    std::wstring hint = lower_text(format_hint);
    if (!hint.empty() && hint.front() == L'.') {
        hint.erase(hint.begin());
    }
    std::vector<unsigned char> ids;
    if (hint == L"zip") {
        ids = {0x01};
    } else if (hint == L"7z" || hint == L"sevenzip" || hint == L"seven_zip") {
        ids = {0x07};
    } else if (hint == L"rar" || hint == L"rar4") {
        ids = {0x03, 0xCC};
    } else if (hint == L"rar5") {
        ids = {0xCC, 0x03};
    } else if (hint == L"tar") {
        ids = {0xEE};
    } else if (hint == L"gz" || hint == L"gzip" || hint == L"tar.gz" || hint == L"tgz") {
        ids = {0xEF, 0xEE};
    } else if (hint == L"bz2" || hint == L"bzip2" || hint == L"tar.bz2" || hint == L"tbz2" || hint == L"tbz") {
        ids = {0x02, 0xEE};
    } else if (hint == L"xz" || hint == L"tar.xz" || hint == L"txz") {
        ids = {0x0C, 0xEE};
    } else if (hint == L"zst" || hint == L"zstd" || hint == L"tar.zst" || hint == L"tzst") {
        ids = {0x0E, 0xEE};
    }
    if (ids.empty()) {
        return candidate_formats(archive_path, part_paths);
    }
    std::vector<GUID> formats;
    for (const unsigned char id : ids) {
        formats.push_back(format_guid(id));
    }
    return formats;
}

bool looks_wrong_password(HRESULT hr, Int32 op_res) {
    return op_res == kOpWrongPassword || op_res == kOpDataError || op_res == kOpCrcError || hr == S_FALSE;
}

bool looks_damaged(Int32 op_res) {
    return op_res == kOpUnexpectedEnd || op_res == kOpHeadersError || op_res == kOpIsNotArc || op_res == kOpUnavailable;
}

bool looks_damaged_health_result(const std::wstring& password, Int32 op_res) {
    return looks_damaged(op_res) || (password.empty() && (op_res == kOpDataError || op_res == kOpCrcError));
}

bool looks_missing_volume(const std::wstring& archive_path, Int32 op_res) {
    if (op_res != kOpUnexpectedEnd && op_res != kOpUnavailable && op_res != kOpHeadersError) {
        return false;
    }
    const std::wstring lower = filename_lower(archive_path);
    return lower.find(L".001") != std::wstring::npos ||
        lower.find(L".part") != std::wstring::npos ||
        lower.find(L".r00") != std::wstring::npos ||
        lower.find(L".r01") != std::wstring::npos;
}

UInt64 file_size_or_zero(const std::wstring& path);

bool has_numbered_split_head(const std::vector<std::wstring>& part_paths) {
    for (const auto& path : sorted_data_volume_paths(part_paths)) {
        std::wstring name = filename_lower(path);
        if (name.size() >= 4 && name.compare(name.size() - 4, 4, L".001") == 0) {
            return true;
        }
        if (name.find(L".part") != std::wstring::npos && parse_volume_number(path).value_or(0) == 1) {
            return true;
        }
    }
    return false;
}

bool likely_missing_split_tail(const std::vector<std::wstring>& part_paths) {
    const auto volumes = sorted_data_volume_paths(part_paths);
    if (volumes.empty() || !has_numbered_split_head(volumes)) {
        return false;
    }
    if (volumes.size() == 1) {
        return true;
    }
    std::size_t reference_index = 0;
    if (is_sfx_path(volumes.front()) && volumes.size() > 1) {
        reference_index = 1;
    }
    const UInt64 first_size = file_size_or_zero(volumes[reference_index]);
    const UInt64 last_size = file_size_or_zero(volumes.back());
    if (volumes.size() <= reference_index + 1) {
        return true;
    }
    return first_size > 0 && last_size >= first_size;
}

bool has_split_volume_gap(const std::vector<std::wstring>& part_paths) {
    const auto volumes = sorted_data_volume_paths(part_paths);
    if (volumes.size() < 2) {
        return false;
    }
    int expected = parse_volume_number(volumes.front()).value_or(0);
    for (const auto& path : volumes) {
        const int current = parse_volume_number(path).value_or(expected);
        if (current != expected) {
            return true;
        }
        expected += 1;
    }
    return false;
}

bool has_split_volume_evidence(const std::wstring& archive_path, const std::vector<std::wstring>& part_paths) {
    const auto volumes = sorted_data_volume_paths(unique_existing_paths(archive_path, part_paths));
    if (volumes.size() > 1) {
        return true;
    }
    return looks_missing_volume(archive_path, kOpHeadersError);
}

std::wstring archive_type_for_path(const std::wstring& path) {
    const std::wstring ext = lower_extension(path);
    if (ext == L".zip" || ext == L".jar" || ext == L".docx" || ext == L".xlsx" || ext == L".apk") {
        return L"zip";
    }
    if (ext == L".7z" || ext == L".001") {
        return L"7z";
    }
    if (ext == L".rar" || ext == L".r00") {
        return L"rar";
    }
    if (ext == L".exe" || ext == L".dll") {
        return L"pe";
    }
    if (ext == L".tar") {
        return L"tar";
    }
    if (ext == L".gz" || ext == L".tgz") {
        return L"gzip";
    }
    if (ext == L".bz2" || ext == L".tbz" || ext == L".tbz2") {
        return L"bzip2";
    }
    if (ext == L".xz" || ext == L".txz") {
        return L"xz";
    }
    return L"";
}

UInt64 file_size_or_zero(const std::wstring& path) {
    try {
        return static_cast<UInt64>(std::filesystem::file_size(path));
    } catch (...) {
        return 0;
    }
}

UInt64 archive_input_size(const std::wstring& archive_path, const std::vector<std::wstring>& part_paths) {
    const auto paths = part_paths.empty() ? std::vector<std::wstring>{archive_path} : part_paths;
    UInt64 total = 0;
    for (const auto& path : paths) {
        total += file_size_or_zero(path);
    }
    return total;
}

bool prop_bool(const PROPVARIANT& value) {
    if (value.vt == VT_BOOL) {
        return value.boolVal != VARIANT_FALSE;
    }
    if (value.vt == VT_UI1) {
        return value.bVal != 0;
    }
    if (value.vt == VT_I4) {
        return value.lVal != 0;
    }
    if (value.vt == VT_UI4) {
        return value.ulVal != 0;
    }
    return false;
}

UInt64 prop_u64(const PROPVARIANT& value) {
    switch (value.vt) {
    case VT_UI8:
        return value.uhVal.QuadPart;
    case VT_I8:
        return static_cast<UInt64>(value.hVal.QuadPart);
    case VT_UI4:
        return value.ulVal;
    case VT_I4:
        return static_cast<UInt64>(value.lVal);
    case VT_UI2:
        return value.uiVal;
    case VT_I2:
        return static_cast<UInt64>(value.iVal);
    case VT_UI1:
        return value.bVal;
    default:
        return 0;
    }
}

UInt32 prop_u32(const PROPVARIANT& value) {
    return static_cast<UInt32>(prop_u64(value) & 0xFFFFFFFFu);
}

std::wstring prop_text(const PROPVARIANT& value) {
    if (value.vt == VT_BSTR && value.bstrVal) {
        return std::wstring(value.bstrVal, SysStringLen(value.bstrVal));
    }
    return L"";
}

void clear_prop(PROPVARIANT& value) {
    if (value.vt == VT_BSTR && value.bstrVal) {
        SysFreeString(value.bstrVal);
    }
    value.vt = VT_EMPTY;
}

bool get_archive_property_bool(IInArchive* archive, UInt32 prop_id) {
    PROPVARIANT value{};
    value.vt = VT_EMPTY;
    if (archive->GetArchiveProperty(prop_id, &value) != S_OK) {
        return false;
    }
    const bool result = prop_bool(value);
    clear_prop(value);
    return result;
}

bool get_item_property(IInArchive* archive, UInt32 index, UInt32 prop_id, PROPVARIANT& value) {
    value = PROPVARIANT{};
    value.vt = VT_EMPTY;
    return archive->GetProperty(index, prop_id, &value) == S_OK && value.vt != VT_EMPTY;
}

bool archive_has_encrypted_items(IInArchive* archive) {
    UInt32 num_items = 0;
    if (!archive || archive->GetNumberOfItems(&num_items) != S_OK) {
        return false;
    }
    for (UInt32 index = 0; index < num_items; ++index) {
        PROPVARIANT value{};
        if (get_item_property(archive, index, kpidEncrypted, value)) {
            const bool encrypted = prop_bool(value);
            clear_prop(value);
            if (encrypted) {
                return true;
            }
        } else {
            clear_prop(value);
        }
    }
    return false;
}

bool fill_resource_analysis_from_open_archive(IInArchive* archive, ResourceAnalysisResult& result) {
    result.is_archive = true;
    result.solid = get_archive_property_bool(archive, kpidSolid);
    UInt32 num_items = 0;
    if (archive->GetNumberOfItems(&num_items) != S_OK) {
        result.status = PasswordTestStatus::Error;
        result.message = "archive item list could not be read";
        return false;
    }

    std::map<std::wstring, UInt64> method_sizes;
    for (UInt32 index = 0; index < num_items; ++index) {
        PROPVARIANT value{};
        const bool is_dir = get_item_property(archive, index, kpidIsDir, value) ? prop_bool(value) : false;
        clear_prop(value);

        UInt64 unpacked_size = 0;
        if (get_item_property(archive, index, kpidSize, value)) {
            unpacked_size = prop_u64(value);
        }
        clear_prop(value);

        UInt64 packed_size = 0;
        if (get_item_property(archive, index, kpidPackSize, value)) {
            packed_size = prop_u64(value);
        }
        clear_prop(value);

        UInt64 dictionary_size = 0;
        if (get_item_property(archive, index, kpidDictionarySize, value)) {
            dictionary_size = prop_u64(value);
        }
        clear_prop(value);

        bool encrypted = false;
        if (get_item_property(archive, index, kpidEncrypted, value)) {
            encrypted = prop_bool(value);
        }
        clear_prop(value);
        result.encrypted = result.encrypted || encrypted;

        std::wstring method;
        if (get_item_property(archive, index, kpidMethod, value)) {
            method = prop_text(value);
        }
        clear_prop(value);

        result.item_count += 1;
        if (is_dir) {
            result.dir_count += 1;
            continue;
        }
        result.file_count += 1;
        result.total_unpacked_size += unpacked_size;
        result.total_packed_size += packed_size;
        result.largest_item_size = std::max(result.largest_item_size, unpacked_size);
        result.largest_dictionary_size = std::max(result.largest_dictionary_size, dictionary_size);
        if (!method.empty()) {
            method_sizes[method] += unpacked_size ? unpacked_size : 1;
        }
    }

    if (result.total_packed_size == 0) {
        result.total_packed_size = result.archive_size;
    }
    UInt64 best_size = 0;
    for (const auto& item : method_sizes) {
        if (item.second > best_size) {
            best_size = item.second;
            result.dominant_method = item.first;
        }
    }
    result.status = PasswordTestStatus::Ok;
    result.message = "archive resources analyzed";
    return true;
}

HealthProbeResult check_archive_health_internal(
    CreateObjectFunc create_object,
    const std::wstring& archive_path,
    const std::wstring& password,
    const std::vector<std::wstring>& part_paths
) {
    HealthProbeResult result;
    result.backend_available = true;
    bool any_format_created = false;
    HRESULT last_hr = E_FAIL;
    Int32 last_op_res = kOpOk;

    for (const GUID& format : candidate_formats(archive_path, part_paths)) {
        ComPtr<IInArchive> archive;
        HRESULT hr = create_object(&format, &IID_IInArchive, reinterpret_cast<void**>(archive.out()));
        if (hr != S_OK || !archive) {
            last_hr = hr;
            continue;
        }
        any_format_created = true;

        bool stream_opened = false;
        ComPtr<IInStream> stream = open_archive_stream(archive_path, part_paths, stream_opened);
        if (!stream_opened) {
            if (is_sfx_path(archive_path) && !sorted_data_volume_paths(part_paths).empty()) {
                result.status = PasswordTestStatus::Damaged;
                result.is_archive = true;
                result.missing_volume = true;
                result.message = "split self-extracting archive stub is missing";
                return result;
            }
            result.status = PasswordTestStatus::Error;
            result.message = "archive file could not be opened";
            return result;
        }

        ComPtr<IArchiveOpenCallback> open_callback(new OpenCallback(password, callback_archive_path(archive_path, part_paths), part_paths));
        hr = archive->Open(stream.get(), nullptr, open_callback.get());
        if (hr != S_OK) {
            last_hr = hr;
            continue;
        }

        const bool opened_as_encrypted = archive_has_encrypted_items(archive.get());
        archive->Close();

        result.is_archive = true;
        result.operation_result = kOpOk;
        if (has_split_volume_gap(part_paths) || likely_missing_split_tail(part_paths)) {
            result.status = PasswordTestStatus::Damaged;
            result.missing_volume = true;
            result.message = "split archive is missing one or more volumes";
            return result;
        }
        if (opened_as_encrypted && password.empty()) {
            result.status = PasswordTestStatus::WrongPassword;
            result.encrypted = true;
            result.wrong_password = true;
            result.message = "archive is encrypted or password is wrong";
            return result;
        }
        result.encrypted = opened_as_encrypted;
        result.status = PasswordTestStatus::Ok;
        result.message = "archive health probe opened archive";
        return result;
    }

    result.operation_result = last_op_res;
    if (!any_format_created) {
        result.status = PasswordTestStatus::Unsupported;
        result.message = "7z.dll did not create a supported archive handler";
    } else if (has_split_volume_gap(part_paths) || likely_missing_split_tail(part_paths) ||
        (has_split_volume_evidence(archive_path, part_paths) && looks_missing_volume(archive_path, last_op_res))) {
        result.status = PasswordTestStatus::Damaged;
        result.is_archive = true;
        result.missing_volume = true;
        result.message = "split archive is missing one or more volumes";
    } else if (looks_damaged_health_result(password, last_op_res)) {
        result.status = PasswordTestStatus::Damaged;
        result.is_archive = true;
        result.damaged = true;
        result.message = "archive appears damaged";
    } else if (looks_wrong_password(last_hr, last_op_res)) {
        result.status = PasswordTestStatus::WrongPassword;
        result.is_archive = true;
        result.encrypted = true;
        result.wrong_password = true;
        result.message = "archive is encrypted or password is wrong";
    } else {
        result.status = PasswordTestStatus::Unsupported;
        result.message = "archive could not be opened by supported handlers";
    }
    return result;
}

ResourceAnalysisResult analyze_archive_resources_internal(
    CreateObjectFunc create_object,
    const std::wstring& archive_path,
    const std::wstring& password,
    const std::vector<std::wstring>& part_paths
) {
    ResourceAnalysisResult result;
    result.archive_size = archive_input_size(archive_path, part_paths);
    bool any_format_created = false;
    HRESULT last_hr = E_FAIL;

    for (const GUID& format : candidate_formats(archive_path, part_paths)) {
        ComPtr<IInArchive> archive;
        HRESULT hr = create_object(&format, &IID_IInArchive, reinterpret_cast<void**>(archive.out()));
        if (hr != S_OK || !archive) {
            last_hr = hr;
            continue;
        }
        any_format_created = true;

        bool stream_opened = false;
        ComPtr<IInStream> stream = open_archive_stream(archive_path, part_paths, stream_opened);
        if (!stream_opened) {
            result.status = PasswordTestStatus::Error;
            result.message = "archive file could not be opened";
            return result;
        }

        ComPtr<IArchiveOpenCallback> open_callback(new OpenCallback(password, callback_archive_path(archive_path, part_paths), part_paths));
        hr = archive->Open(stream.get(), nullptr, open_callback.get());
        if (hr != S_OK) {
            last_hr = hr;
            continue;
        }

        const bool ok = fill_resource_analysis_from_open_archive(archive.get(), result);
        archive->Close();
        if (!ok) {
            return result;
        }
        return result;
    }

    if (!any_format_created) {
        result.status = PasswordTestStatus::Unsupported;
        result.message = "7z.dll did not create a supported archive handler";
    } else if (looks_wrong_password(last_hr, kOpOk)) {
        result.status = PasswordTestStatus::WrongPassword;
        result.encrypted = true;
        result.message = "archive is encrypted or password is wrong";
    } else {
        result.status = PasswordTestStatus::Unsupported;
        result.message = "archive could not be opened by supported handlers";
    }
    return result;
}

CrcManifestResult read_archive_crc_manifest_internal(
    CreateObjectFunc create_object,
    const std::wstring& archive_path,
    const std::wstring& password,
    const std::vector<std::wstring>& part_paths,
    UInt32 max_items
) {
    CrcManifestResult result;
    bool any_format_created = false;
    HRESULT last_hr = E_FAIL;
    Int32 last_op_res = kOpOk;

    for (const GUID& format : candidate_formats(archive_path, part_paths)) {
        ComPtr<IInArchive> archive;
        HRESULT hr = create_object(&format, &IID_IInArchive, reinterpret_cast<void**>(archive.out()));
        if (hr != S_OK || !archive) {
            last_hr = hr;
            continue;
        }
        any_format_created = true;

        bool stream_opened = false;
        ComPtr<IInStream> stream = open_archive_stream(archive_path, part_paths, stream_opened);
        if (!stream_opened) {
            result.status = PasswordTestStatus::Error;
            result.message = "archive file could not be opened";
            return result;
        }

        ComPtr<IArchiveOpenCallback> open_callback(new OpenCallback(password, callback_archive_path(archive_path, part_paths), part_paths));
        hr = archive->Open(stream.get(), nullptr, open_callback.get());
        if (hr != S_OK) {
            last_hr = hr;
            continue;
        }

        result.is_archive = true;
        UInt32 num_items = 0;
        if (archive->GetNumberOfItems(&num_items) != S_OK) {
            archive->Close();
            result.status = PasswordTestStatus::Error;
            result.message = "archive item list could not be read";
            return result;
        }
        result.item_count = num_items;

        const UInt32 limit = max_items == 0 ? num_items : std::min(max_items, num_items);
        for (UInt32 index = 0; index < limit; ++index) {
            PROPVARIANT value{};
            const bool is_dir = get_item_property(archive.get(), index, kpidIsDir, value) ? prop_bool(value) : false;
            clear_prop(value);

            bool encrypted = false;
            if (get_item_property(archive.get(), index, kpidEncrypted, value)) {
                encrypted = prop_bool(value);
            }
            clear_prop(value);
            result.encrypted = result.encrypted || encrypted;

            if (is_dir) {
                continue;
            }

            CrcManifestItem item;
            if (get_item_property(archive.get(), index, kpidName, value)) {
                item.path = prop_text(value);
            }
            clear_prop(value);
            if (item.path.empty()) {
                item.path = L"#" + std::to_wstring(index);
            }

            if (get_item_property(archive.get(), index, kpidSize, value)) {
                item.size = prop_u64(value);
            }
            clear_prop(value);

            if (get_item_property(archive.get(), index, kpidCRC, value)) {
                item.crc32 = prop_u32(value);
                item.has_crc = true;
            }
            clear_prop(value);

            result.file_count += 1;
            result.files.push_back(std::move(item));
        }

        auto* raw_extract_callback = new ExtractCallback(password);
        ComPtr<IArchiveExtractCallback> extract_callback(raw_extract_callback);
        hr = archive->Extract(nullptr, static_cast<UInt32>(kAllItems), kTestMode, extract_callback.get());
        last_hr = hr;
        last_op_res = raw_extract_callback->operation_result();
        archive->Close();

        if (hr == S_OK && last_op_res == kOpOk) {
            result.status = PasswordTestStatus::Ok;
            result.message = "archive CRC manifest read";
            return result;
        }
        result.checksum_error = last_op_res == kOpCrcError;
        if (looks_wrong_password(hr, last_op_res)) {
            result.status = PasswordTestStatus::WrongPassword;
            result.encrypted = true;
            result.message = "archive is encrypted or password is wrong";
            return result;
        }
        if (looks_damaged(last_op_res) || result.checksum_error) {
            result.status = PasswordTestStatus::Damaged;
            result.damaged = true;
            result.message = result.checksum_error ? "archive checksum error" : "archive appears damaged";
            return result;
        }
    }

    if (!any_format_created) {
        result.status = PasswordTestStatus::Unsupported;
        result.message = "7z.dll did not create a supported archive handler";
    } else if (looks_wrong_password(last_hr, last_op_res)) {
        result.status = PasswordTestStatus::WrongPassword;
        result.encrypted = true;
        result.message = "archive is encrypted or password is wrong";
    } else if (looks_damaged(last_op_res)) {
        result.status = PasswordTestStatus::Damaged;
        result.damaged = true;
        result.message = "archive appears damaged";
    } else {
        result.status = PasswordTestStatus::Unsupported;
        result.message = "archive could not be opened by supported handlers";
    }
    return result;
}

UInt16 le16_at(const std::vector<unsigned char>& data, std::size_t offset) {
    if (offset + 2 > data.size()) {
        return 0;
    }
    return static_cast<UInt16>(data[offset] | (data[offset + 1] << 8));
}

UInt32 le32_at(const std::vector<unsigned char>& data, std::size_t offset) {
    if (offset + 4 > data.size()) {
        return 0;
    }
    return static_cast<UInt32>(data[offset] | (data[offset + 1] << 8) | (data[offset + 2] << 16) | (data[offset + 3] << 24));
}

UInt32 crc32_bytes(const unsigned char* bytes, std::size_t size) {
    UInt32 crc = 0xFFFF'FFFFu;
    for (std::size_t i = 0; i < size; ++i) {
        crc ^= bytes[i];
        for (int bit = 0; bit < 8; ++bit) {
            const UInt32 mask = (crc & 1u) ? 0xEDB8'8320u : 0u;
            crc = (crc >> 1) ^ mask;
        }
    }
    return ~crc;
}

bool read_file_bytes(const std::wstring& path, std::vector<unsigned char>& data) {
    try {
        const auto size = std::filesystem::file_size(path);
        data.resize(static_cast<std::size_t>(size));
    } catch (...) {
        return false;
    }
    HANDLE handle = CreateFileW(win32_extended_path(path).c_str(), GENERIC_READ, FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
                                nullptr, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, nullptr);
    if (handle == INVALID_HANDLE_VALUE) {
        return false;
    }
    DWORD read = 0;
    const BOOL ok = data.empty() || ReadFile(handle, data.data(), static_cast<DWORD>(data.size()), &read, nullptr);
    CloseHandle(handle);
    return ok && read == data.size();
}

bool strict_zip_stored_entries_ok(const std::wstring& path) {
    std::vector<unsigned char> data;
    if (!read_file_bytes(path, data) || data.size() < 22) {
        return false;
    }
    const std::size_t min_eocd = data.size() > 65557 ? data.size() - 65557 : 0;
    std::size_t eocd = std::string::npos;
    for (std::size_t pos = data.size() - 22 + 1; pos-- > min_eocd;) {
        if (pos + 4 <= data.size() && le32_at(data, pos) == 0x06054b50u) {
            eocd = pos;
            break;
        }
        if (pos == 0) {
            break;
        }
    }
    if (eocd == std::string::npos || eocd + 22 > data.size()) {
        return false;
    }
    const UInt16 entries = le16_at(data, eocd + 10);
    const UInt16 comment_len = le16_at(data, eocd + 20);
    const UInt32 cd_size = le32_at(data, eocd + 12);
    const UInt32 cd_offset = le32_at(data, eocd + 16);
    if (entries == 0 || eocd + 22u + comment_len != data.size() || cd_offset > data.size() || static_cast<UInt64>(cd_offset) + cd_size > data.size()) {
        return false;
    }
    auto extra_ok = [&](std::size_t offset, std::size_t size) {
        const std::size_t end = offset + size;
        if (end > data.size()) {
            return false;
        }
        std::size_t cursor = offset;
        while (cursor < end) {
            if (cursor + 4 > end) {
                return false;
            }
            const UInt16 header_id = le16_at(data, cursor);
            const UInt16 data_size = le16_at(data, cursor + 2);
            if (header_id == 0 && data_size == 0) {
                return false;
            }
            cursor += 4u + data_size;
        }
        return cursor == end;
    };
    std::size_t cursor = cd_offset;
    for (UInt16 index = 0; index < entries; ++index) {
        if (cursor + 46 > data.size() || le32_at(data, cursor) != 0x02014b50u) {
            return false;
        }
        const UInt16 method = le16_at(data, cursor + 10);
        const UInt32 expected_crc = le32_at(data, cursor + 16);
        const UInt32 compressed_size = le32_at(data, cursor + 20);
        const UInt32 local_offset = le32_at(data, cursor + 42);
        const UInt16 name_len = le16_at(data, cursor + 28);
        const UInt16 extra_len = le16_at(data, cursor + 30);
        const UInt16 comment_len = le16_at(data, cursor + 32);
        if (!extra_ok(cursor + 46u + name_len, extra_len)) {
            return false;
        }
        const std::size_t cd_name_offset = cursor + 46u;
        cursor += 46u + name_len + extra_len + comment_len;
        if (cursor > data.size() || local_offset + 30u > data.size() || le32_at(data, local_offset) != 0x04034b50u) {
            return false;
        }
        const UInt16 local_name_len = le16_at(data, local_offset + 26);
        const UInt16 local_extra_len = le16_at(data, local_offset + 28);
        const std::size_t local_name_offset = local_offset + 30u;
        if (local_name_len != name_len || local_name_offset + local_name_len > data.size() ||
            !std::equal(data.begin() + cd_name_offset, data.begin() + cd_name_offset + name_len, data.begin() + local_name_offset)) {
            return false;
        }
        if (!extra_ok(local_offset + 30u + local_name_len, local_extra_len)) {
            return false;
        }
        const UInt64 payload_offset = static_cast<UInt64>(local_offset) + 30u + local_name_len + local_extra_len;
        if (payload_offset + compressed_size > data.size()) {
            return false;
        }
        if (method == 0 && crc32_bytes(data.data() + payload_offset, compressed_size) != expected_crc) {
            return false;
        }
    }
    return cursor == static_cast<std::size_t>(cd_offset) + cd_size;
}

bool strict_seven_zip_headers_ok(const std::wstring& path) {
    std::vector<unsigned char> data;
    if (!read_file_bytes(path, data) || data.size() < 32) {
        return false;
    }
    const unsigned char signature[] = {'7', 'z', 0xBC, 0xAF, 0x27, 0x1C};
    if (!std::equal(std::begin(signature), std::end(signature), data.begin())) {
        return false;
    }
    const UInt32 stored_start_crc = le32_at(data, 8);
    if (crc32_bytes(data.data() + 12, 20) != stored_start_crc) {
        return false;
    }
    const UInt64 next_offset =
        static_cast<UInt64>(le32_at(data, 12)) |
        (static_cast<UInt64>(le32_at(data, 16)) << 32);
    const UInt64 next_size =
        static_cast<UInt64>(le32_at(data, 20)) |
        (static_cast<UInt64>(le32_at(data, 24)) << 32);
    const UInt32 next_crc = le32_at(data, 28);
    const UInt64 next_start = 32u + next_offset;
    if (next_start > data.size() || next_size > data.size() || next_start + next_size > data.size()) {
        return false;
    }
    if (next_size == 0) {
        return true;
    }
    return crc32_bytes(data.data() + next_start, static_cast<std::size_t>(next_size)) == next_crc;
}

ExtractArchiveResult extract_archive_internal(
    CreateObjectFunc create_object,
    const std::wstring& archive_path,
    const std::wstring& password,
    const std::vector<std::wstring>& part_paths,
    const std::vector<ExtractInputRange>& input_ranges,
    const std::wstring& format_hint,
    const std::wstring& output_dir,
    ExtractProgressCallback progress
) {
    ExtractArchiveResult result;
    result.backend_available = true;
    bool any_format_created = false;
    bool any_opened = false;
    HRESULT last_hr = E_FAIL;
    Int32 last_op_res = kOpOk;

    try {
        std::filesystem::create_directories(std::filesystem::path(win32_extended_path(output_dir)));
    } catch (...) {
        result.status = PasswordTestStatus::Error;
        result.message = "output directory could not be created";
        return result;
    }

    const auto formats = candidate_formats_for_hint(format_hint, archive_path, part_paths);
    for (const GUID& format : formats) {
        ComPtr<IInArchive> archive;
        HRESULT hr = create_object(&format, &IID_IInArchive, reinterpret_cast<void**>(archive.out()));
        if (hr != S_OK || !archive) {
            last_hr = hr;
            continue;
        }
        any_format_created = true;

        bool stream_opened = false;
        ComPtr<IInStream> stream = [&]() {
            if (!input_ranges.empty()) {
                auto* range_stream = new MultiRangeInStream(input_ranges);
                stream_opened = range_stream->is_open();
                return ComPtr<IInStream>(range_stream);
            }
            return open_archive_stream(archive_path, part_paths, stream_opened);
        }();
        if (!stream_opened) {
            result.status = PasswordTestStatus::Error;
            result.message = "archive file could not be opened";
            return result;
        }

        ComPtr<IArchiveOpenCallback> open_callback(new OpenCallback(password, callback_archive_path(archive_path, part_paths), part_paths));
        hr = archive->Open(stream.get(), nullptr, open_callback.get());
        if (hr != S_OK) {
            last_hr = hr;
            continue;
        }
        any_opened = true;

        UInt32 num_items = 0;
        if (archive->GetNumberOfItems(&num_items) == S_OK) {
            result.item_count = num_items;
        }

        result.archive_type = !format_hint.empty() ? format_hint : archive_type_for_path(archive_path);
        auto* raw_extract_callback = new ExtractToDiskCallback(archive.get(), password, output_dir, std::move(progress));
        ComPtr<IArchiveExtractCallback> extract_callback(raw_extract_callback);
        hr = archive->Extract(nullptr, static_cast<UInt32>(kAllItems), 0, extract_callback.get());
        last_hr = hr;
        last_op_res = raw_extract_callback->operation_result();
        result.operation_result = last_op_res;
        result.files_written = raw_extract_callback->files_written();
        result.dirs_written = raw_extract_callback->dirs_written();
        result.bytes_written = raw_extract_callback->completed_bytes();
        result.failed_item = raw_extract_callback->failed_item();
        archive->Close();

        if (hr == S_OK && last_op_res == kOpOk) {
            if (!result.failed_item.empty()) {
                result.status = PasswordTestStatus::Damaged;
                result.command_ok = false;
                result.damaged = true;
                result.checksum_error = true;
                result.message = "archive item failed during extraction";
                return result;
            }
            if (password.empty() && input_ranges.empty() && lower_extension(archive_path) == L".zip" && !strict_zip_stored_entries_ok(archive_path)) {
                result.status = PasswordTestStatus::Damaged;
                result.command_ok = false;
                result.damaged = true;
                result.checksum_error = true;
                result.message = "zip structure or stored-entry checksum error";
                return result;
            }
            result.status = PasswordTestStatus::Ok;
            result.command_ok = true;
            result.message = "archive extracted";
            return result;
        }
        if (raw_extract_callback->output_error()) {
            result.status = PasswordTestStatus::Error;
            result.message = "archive item could not be written safely";
            return result;
        }
        if (looks_wrong_password(hr, last_op_res)) {
            if (password.empty() && (last_op_res == kOpDataError || last_op_res == kOpCrcError || last_op_res == kOpHeadersError || last_op_res == kOpUnexpectedEnd)) {
                result.status = PasswordTestStatus::Damaged;
                result.damaged = true;
                result.checksum_error = last_op_res == kOpCrcError;
                result.message = result.checksum_error ? "archive checksum error" : "archive appears damaged";
                return result;
            }
            result.status = PasswordTestStatus::WrongPassword;
            result.encrypted = true;
            result.wrong_password = true;
            result.checksum_error = last_op_res == kOpCrcError;
            result.message = "archive is encrypted or password is wrong";
            return result;
        }
        if (looks_missing_volume(archive_path, last_op_res)) {
            result.status = PasswordTestStatus::Damaged;
            result.damaged = true;
            result.missing_volume = true;
            result.message = "archive split volume appears incomplete";
            return result;
        }
        if (looks_damaged(last_op_res)) {
            result.status = PasswordTestStatus::Damaged;
            result.damaged = true;
            result.message = "archive appears damaged";
            return result;
        }
        result.status = PasswordTestStatus::Unsupported;
        result.unsupported_method = last_op_res == kOpUnsupportedMethod;
        result.message = result.unsupported_method ? "archive uses an unsupported method" : "archive could not be extracted";
    }

    if (!any_format_created) {
        result.status = PasswordTestStatus::Unsupported;
        result.message = "7z.dll did not create a supported archive handler";
    } else if (!any_opened) {
        if (password.empty() && input_ranges.empty() && lower_extension(archive_path) == L".7z" && !strict_seven_zip_headers_ok(archive_path)) {
            result.status = PasswordTestStatus::Damaged;
            result.damaged = true;
            result.message = "7z structure or header checksum error";
            return result;
        }
        if (password.empty() && (last_op_res == kOpDataError || last_op_res == kOpCrcError || last_op_res == kOpHeadersError || last_op_res == kOpUnexpectedEnd)) {
            result.status = PasswordTestStatus::Damaged;
            result.damaged = true;
            result.checksum_error = last_op_res == kOpCrcError;
            result.message = result.checksum_error ? "archive checksum error" : "archive appears damaged";
            return result;
        }
        result.status = looks_wrong_password(last_hr, last_op_res) ? PasswordTestStatus::WrongPassword : PasswordTestStatus::Unsupported;
        result.wrong_password = result.status == PasswordTestStatus::WrongPassword;
        result.encrypted = result.wrong_password;
        result.message = result.wrong_password ? "archive is encrypted or password is wrong" : "archive could not be opened by supported handlers";
    }
    return result;
}

PasswordTestResult test_one_password(
    CreateObjectFunc create_object,
    const std::wstring& archive_path,
    const std::wstring& password,
    const std::vector<std::wstring>& part_paths,
    const std::vector<GUID>& formats,
    const std::vector<ExtractInputRange>& input_ranges = {}
);

PasswordTestResult test_one_password(
    CreateObjectFunc create_object,
    const std::wstring& archive_path,
    const std::wstring& password,
    const std::vector<std::wstring>& part_paths
) {
    return test_one_password(
        create_object,
        archive_path,
        password,
        part_paths,
        candidate_formats(archive_path, part_paths),
        {});
}

PasswordTestResult test_one_password(
    CreateObjectFunc create_object,
    const std::wstring& archive_path,
    const std::wstring& password,
    const std::vector<std::wstring>& part_paths,
    const std::vector<GUID>& formats,
    const std::vector<ExtractInputRange>& input_ranges
) {
    PasswordTestResult result;
    result.backend_available = true;

    bool any_format_created = false;
    bool any_opened = false;
    HRESULT last_hr = E_FAIL;
    Int32 last_op_res = kOpOk;

    for (const GUID& format : formats) {
        ComPtr<IInArchive> archive;
        HRESULT hr = create_object(&format, &IID_IInArchive, reinterpret_cast<void**>(archive.out()));
        if (hr != S_OK || !archive) {
            last_hr = hr;
            continue;
        }
        any_format_created = true;

        bool stream_opened = false;
        ComPtr<IInStream> stream = [&]() {
            if (!input_ranges.empty()) {
                auto* range_stream = new MultiRangeInStream(input_ranges);
                stream_opened = range_stream->is_open();
                return ComPtr<IInStream>(range_stream);
            }
            return open_archive_stream(archive_path, part_paths, stream_opened);
        }();
        if (!stream_opened) {
            result.status = PasswordTestStatus::Error;
            result.message = "archive file could not be opened";
            return result;
        }

        ComPtr<IArchiveOpenCallback> open_callback(new OpenCallback(password, callback_archive_path(archive_path, part_paths), part_paths));
        hr = archive->Open(stream.get(), nullptr, open_callback.get());
        if (hr != S_OK) {
            last_hr = hr;
            continue;
        }
        any_opened = true;

        auto* raw_extract_callback = new ExtractCallback(password);
        ComPtr<IArchiveExtractCallback> extract_callback(raw_extract_callback);
        hr = archive->Extract(nullptr, static_cast<UInt32>(kAllItems), kTestMode, extract_callback.get());
        last_hr = hr;
        last_op_res = raw_extract_callback->operation_result();
        archive->Close();

        if (hr == S_OK && last_op_res == kOpOk) {
            result.status = PasswordTestStatus::Ok;
            result.message = "password accepted";
            return result;
        }

        if (looks_wrong_password(hr, last_op_res)) {
            result.status = PasswordTestStatus::WrongPassword;
            result.message = "wrong password";
            return result;
        }

        if (looks_damaged(last_op_res)) {
            result.status = PasswordTestStatus::Damaged;
            result.message = "archive appears damaged";
            return result;
        }
    }

    if (!any_format_created) {
        result.status = PasswordTestStatus::Unsupported;
        result.message = "7z.dll did not create a supported archive handler";
    } else if (!any_opened) {
        result.status = PasswordTestStatus::Unsupported;
        result.message = "archive could not be opened by supported handlers";
    } else if (looks_damaged(last_op_res)) {
        result.status = PasswordTestStatus::Damaged;
        result.message = "archive appears damaged";
    } else if (looks_wrong_password(last_hr, last_op_res)) {
        result.status = PasswordTestStatus::WrongPassword;
        result.message = "wrong password";
    } else {
        result.status = PasswordTestStatus::Error;
        result.message = "archive test failed";
    }
    return result;
}

PasswordTestResult test_one_password_reuse_stream(
    CreateObjectFunc create_object,
    const std::wstring& archive_path,
    const std::wstring& password,
    const std::vector<std::wstring>& part_paths,
    const std::vector<GUID>& formats,
    IInStream* stream
) {
    PasswordTestResult result;
    result.backend_available = true;

    bool any_format_created = false;
    bool any_opened = false;
    HRESULT last_hr = E_FAIL;
    Int32 last_op_res = kOpOk;

    UInt64 pos = 0;
    stream->Seek(0, 0, &pos);

    for (const GUID& format : formats) {
        ComPtr<IInArchive> archive;
        HRESULT hr = create_object(&format, &IID_IInArchive, reinterpret_cast<void**>(archive.out()));
        if (hr != S_OK || !archive) {
            last_hr = hr;
            continue;
        }
        any_format_created = true;

        ComPtr<IArchiveOpenCallback> open_callback(new OpenCallback(password, callback_archive_path(archive_path, part_paths), part_paths));
        hr = archive->Open(stream, nullptr, open_callback.get());
        if (hr != S_OK) {
            last_hr = hr;
            continue;
        }
        any_opened = true;

        auto* raw_extract_callback = new ExtractCallback(password);
        ComPtr<IArchiveExtractCallback> extract_callback(raw_extract_callback);
        hr = archive->Extract(nullptr, static_cast<UInt32>(kAllItems), kTestMode, extract_callback.get());
        last_hr = hr;
        last_op_res = raw_extract_callback->operation_result();
        archive->Close();

        if (hr == S_OK && last_op_res == kOpOk) {
            result.status = PasswordTestStatus::Ok;
            result.message = "password accepted";
            return result;
        }

        if (looks_wrong_password(hr, last_op_res)) {
            result.status = PasswordTestStatus::WrongPassword;
            result.message = "wrong password";
            return result;
        }

        if (looks_damaged(last_op_res)) {
            result.status = PasswordTestStatus::Damaged;
            result.message = "archive appears damaged";
            return result;
        }
    }

    if (!any_format_created) {
        result.status = PasswordTestStatus::Unsupported;
        result.message = "7z.dll did not create a supported archive handler";
    } else if (!any_opened) {
        result.status = PasswordTestStatus::Unsupported;
        result.message = "archive could not be opened by supported handlers";
    } else if (looks_damaged(last_op_res)) {
        result.status = PasswordTestStatus::Damaged;
        result.message = "archive appears damaged";
    } else if (looks_wrong_password(last_hr, last_op_res)) {
        result.status = PasswordTestStatus::WrongPassword;
        result.message = "wrong password";
    } else {
        result.status = PasswordTestStatus::Error;
        result.message = "archive test failed";
    }
    return result;
}

#endif

bool is_backend_available(const std::wstring& seven_zip_dll_path) {
#ifdef _WIN32
    ComModule module(seven_zip_dll_path);
    return module.get() != nullptr && module.create_object() != nullptr;
#else
    (void)seven_zip_dll_path;
    return false;
#endif
}

ExtractArchiveResult extract_archive_with_parts(
    const std::wstring& seven_zip_dll_path,
    const std::wstring& archive_path,
    const std::vector<std::wstring>& part_paths,
    const std::wstring& format_hint,
    const std::wstring& password,
    const std::wstring& output_dir,
    ExtractProgressCallback progress
) {
#ifdef _WIN32
    ComModule module(seven_zip_dll_path);
    auto create_object = module.create_object();
    if (!create_object) {
        ExtractArchiveResult result;
        result.status = PasswordTestStatus::BackendUnavailable;
        result.message = "7z.dll could not be loaded";
        return result;
    }
    const std::vector<std::wstring> effective_part_paths =
        part_paths.empty() ? std::vector<std::wstring>{archive_path} : part_paths;
    return extract_archive_internal(
        create_object,
        archive_path,
        password,
        effective_part_paths,
        {},
        format_hint,
        output_dir,
        std::move(progress));
#else
    (void)seven_zip_dll_path;
    (void)archive_path;
    (void)part_paths;
    (void)format_hint;
    (void)password;
    (void)output_dir;
    (void)progress;
    ExtractArchiveResult result;
    result.status = PasswordTestStatus::BackendUnavailable;
    result.message = "native archive extraction is only implemented on Windows";
    return result;
#endif
}

ExtractArchiveResult extract_archive_with_ranges(
    const std::wstring& seven_zip_dll_path,
    const std::wstring& archive_path,
    const std::vector<ExtractInputRange>& ranges,
    const std::wstring& format_hint,
    const std::wstring& password,
    const std::wstring& output_dir,
    ExtractProgressCallback progress
) {
#ifdef _WIN32
    ComModule module(seven_zip_dll_path);
    auto create_object = module.create_object();
    if (!create_object) {
        ExtractArchiveResult result;
        result.status = PasswordTestStatus::BackendUnavailable;
        result.message = "7z.dll could not be loaded";
        return result;
    }
    return extract_archive_internal(
        create_object,
        archive_path,
        password,
        {},
        ranges,
        format_hint,
        output_dir,
        std::move(progress));
#else
    (void)seven_zip_dll_path;
    (void)archive_path;
    (void)ranges;
    (void)format_hint;
    (void)password;
    (void)output_dir;
    (void)progress;
    ExtractArchiveResult result;
    result.status = PasswordTestStatus::BackendUnavailable;
    result.message = "native archive range extraction is only implemented on Windows";
    return result;
#endif
}

HealthProbeResult check_archive_health_with_parts(
    const std::wstring& seven_zip_dll_path,
    const std::wstring& archive_path,
    const std::vector<std::wstring>& part_paths,
    const std::wstring& password
) {
#ifdef _WIN32
    ComModule module(seven_zip_dll_path);
    auto create_object = module.create_object();
    if (!create_object) {
        HealthProbeResult result;
        result.status = PasswordTestStatus::BackendUnavailable;
        result.message = "7z.dll could not be loaded";
        return result;
    }
    return check_archive_health_internal(create_object, archive_path, password, part_paths);
#else
    (void)seven_zip_dll_path;
    (void)archive_path;
    (void)part_paths;
    (void)password;
    HealthProbeResult result;
    result.status = PasswordTestStatus::BackendUnavailable;
    result.message = "native archive health checking is only implemented on Windows";
    return result;
#endif
}

ResourceAnalysisResult analyze_archive_resources_with_parts(
    const std::wstring& seven_zip_dll_path,
    const std::wstring& archive_path,
    const std::vector<std::wstring>& part_paths,
    const std::wstring& password
) {
#ifdef _WIN32
    ComModule module(seven_zip_dll_path);
    auto create_object = module.create_object();
    if (!create_object) {
        ResourceAnalysisResult result;
        result.status = PasswordTestStatus::BackendUnavailable;
        result.message = "7z.dll could not be loaded";
        return result;
    }
    return analyze_archive_resources_internal(create_object, archive_path, password, part_paths);
#else
    (void)seven_zip_dll_path;
    (void)archive_path;
    (void)part_paths;
    (void)password;
    ResourceAnalysisResult result;
    result.status = PasswordTestStatus::BackendUnavailable;
    result.message = "native archive resource analysis is only implemented on Windows";
    return result;
#endif
}

CrcManifestResult read_archive_crc_manifest_with_parts(
    const std::wstring& seven_zip_dll_path,
    const std::wstring& archive_path,
    const std::vector<std::wstring>& part_paths,
    const std::wstring& password,
    UInt32 max_items
) {
#ifdef _WIN32
    ComModule module(seven_zip_dll_path);
    if (!module.get()) {
        CrcManifestResult result;
        result.status = PasswordTestStatus::BackendUnavailable;
        result.message = "7z.dll could not be loaded";
        return result;
    }
    const auto create_object = module.create_object();
    if (!create_object) {
        CrcManifestResult result;
        result.status = PasswordTestStatus::BackendUnavailable;
        result.message = "7z.dll CreateObject export was not found";
        return result;
    }
    return read_archive_crc_manifest_internal(create_object, archive_path, password, part_paths, max_items);
#else
    (void)seven_zip_dll_path;
    (void)archive_path;
    (void)part_paths;
    (void)password;
    (void)max_items;
    CrcManifestResult result;
    result.status = PasswordTestStatus::BackendUnavailable;
    result.message = "native archive CRC manifest is only implemented on Windows";
    return result;
#endif
}

PasswordTestResult test_password_with_parts(
    const std::wstring& seven_zip_dll_path,
    const std::wstring& archive_path,
    const std::vector<std::wstring>& part_paths,
    const std::wstring& password
);

PasswordTestResult test_passwords_with_parts(
    const std::wstring& seven_zip_dll_path,
    const std::wstring& archive_path,
    const std::vector<std::wstring>& part_paths,
    const wchar_t* const* passwords,
    int password_count
);

PasswordTestResult test_password(
    const std::wstring& seven_zip_dll_path,
    const std::wstring& archive_path,
    const std::wstring& password
) {
    return test_password_with_parts(seven_zip_dll_path, archive_path, {archive_path}, password);
}

PasswordTestResult test_password_with_parts(
    const std::wstring& seven_zip_dll_path,
    const std::wstring& archive_path,
    const std::vector<std::wstring>& part_paths,
    const std::wstring& password
) {
#ifdef _WIN32
    CreateObjectFunc create_object = cached_create_object(seven_zip_dll_path);
    if (!create_object) {
        PasswordTestResult result;
        result.status = PasswordTestStatus::BackendUnavailable;
        result.message = "7z.dll could not be loaded";
        return result;
    }

    PasswordTestResult result = test_one_password(create_object, archive_path, password, part_paths.empty() ? std::vector<std::wstring>{archive_path} : part_paths);
    result.attempts = 1;
    result.matched_index = result.status == PasswordTestStatus::Ok ? 0 : -1;
    return result;
#else
    (void)seven_zip_dll_path;
    (void)archive_path;
    (void)password;
    PasswordTestResult result;
    result.status = PasswordTestStatus::BackendUnavailable;
    result.message = "native password testing is only implemented on Windows";
    return result;
#endif
}

PasswordTestResult test_passwords(
    const std::wstring& seven_zip_dll_path,
    const std::wstring& archive_path,
    const wchar_t* const* passwords,
    int password_count
) {
    return test_passwords_with_parts(seven_zip_dll_path, archive_path, {archive_path}, passwords, password_count);
}

PasswordTestResult test_passwords_with_parts(
    const std::wstring& seven_zip_dll_path,
    const std::wstring& archive_path,
    const std::vector<std::wstring>& part_paths,
    const wchar_t* const* passwords,
    int password_count
) {
#ifdef _WIN32
    CreateObjectFunc create_object = cached_create_object(seven_zip_dll_path);
    if (!create_object) {
        PasswordTestResult result;
        result.status = PasswordTestStatus::BackendUnavailable;
        result.message = "7z.dll could not be loaded";
        return result;
    }

    PasswordTestResult last;
    last.backend_available = true;
    if (password_count <= 0) {
        const wchar_t* empty = L"";
        passwords = &empty;
        password_count = 1;
    }
    const std::wstring ext = lower_extension(archive_path);
    const bool retry_unsupported_as_password =
        ext == L".7z" ||
        ext == L".001" ||
        ext == L".rar" ||
        ext == L".r00" ||
        ext == L".jpg" ||
        ext == L".jpeg" ||
        ext == L".png" ||
        ext == L".gif" ||
        ext == L".pdf" ||
        ext == L".webp" ||
        is_sfx_path(archive_path);
    const std::vector<std::wstring> effective_part_paths =
        part_paths.empty() ? std::vector<std::wstring>{archive_path} : part_paths;
    const std::vector<GUID> formats = candidate_formats(archive_path, effective_part_paths);

    bool stream_opened = false;
    ComPtr<IInStream> stream = open_archive_stream(archive_path, effective_part_paths, stream_opened);
    if (!stream_opened) {
        PasswordTestResult result;
        result.status = PasswordTestStatus::Error;
        result.message = "archive file could not be opened";
        return result;
    }

    for (int i = 0; i < password_count; ++i) {
        const wchar_t* raw_password = passwords[i] ? passwords[i] : L"";
        PasswordTestResult current = test_one_password_reuse_stream(
            create_object,
            archive_path,
            raw_password,
            effective_part_paths,
            formats,
            stream.get());
        current.attempts = i + 1;
        last = current;
        if (current.status == PasswordTestStatus::Ok) {
            current.matched_index = i;
            return current;
        }
        if (current.status == PasswordTestStatus::BackendUnavailable ||
            current.status == PasswordTestStatus::Damaged ||
            current.status == PasswordTestStatus::Error) {
            current.matched_index = -1;
            return current;
        }
        if (current.status == PasswordTestStatus::Unsupported && !retry_unsupported_as_password) {
            current.matched_index = -1;
            return current;
        }
    }

    last.status = PasswordTestStatus::WrongPassword;
    last.matched_index = -1;
    last.attempts = password_count;
    last.message = "wrong password";
    return last;
#else
    (void)seven_zip_dll_path;
    (void)archive_path;
    (void)passwords;
    (void)password_count;
    PasswordTestResult result;
    result.status = PasswordTestStatus::BackendUnavailable;
    result.message = "native password testing is only implemented on Windows";
    return result;
#endif
}

PasswordTestResult test_passwords_with_ranges(
    const std::wstring& seven_zip_dll_path,
    const std::wstring& archive_path,
    const std::vector<ExtractInputRange>& ranges,
    const std::wstring& format_hint,
    const wchar_t* const* passwords,
    int password_count
) {
#ifdef _WIN32
    CreateObjectFunc create_object = cached_create_object(seven_zip_dll_path);
    if (!create_object) {
        PasswordTestResult result;
        result.status = PasswordTestStatus::BackendUnavailable;
        result.message = "7z.dll could not be loaded";
        return result;
    }

    PasswordTestResult last;
    last.backend_available = true;
    if (password_count <= 0) {
        const wchar_t* empty = L"";
        passwords = &empty;
        password_count = 1;
    }

    const std::vector<std::wstring> part_paths{archive_path};
    const std::vector<GUID> formats = candidate_formats_for_hint(format_hint, archive_path, part_paths);
    for (int i = 0; i < password_count; ++i) {
        const wchar_t* raw_password = passwords[i] ? passwords[i] : L"";
        PasswordTestResult current = test_one_password(
            create_object,
            archive_path,
            raw_password,
            part_paths,
            formats,
            ranges);
        current.attempts = i + 1;
        last = current;
        if (current.status == PasswordTestStatus::Ok) {
            current.matched_index = i;
            return current;
        }
        if (current.status == PasswordTestStatus::BackendUnavailable ||
            current.status == PasswordTestStatus::Damaged ||
            current.status == PasswordTestStatus::Error) {
            current.matched_index = -1;
            return current;
        }
    }

    last.status = PasswordTestStatus::WrongPassword;
    last.matched_index = -1;
    last.attempts = password_count;
    last.message = "wrong password";
    return last;
#else
    (void)seven_zip_dll_path;
    (void)archive_path;
    (void)ranges;
    (void)format_hint;
    (void)passwords;
    (void)password_count;
    PasswordTestResult result;
    result.status = PasswordTestStatus::BackendUnavailable;
    result.message = "native password testing is only implemented on Windows";
    return result;
#endif
}

const char* status_name(PasswordTestStatus status) {
    switch (status) {
    case PasswordTestStatus::Ok:
        return "ok";
    case PasswordTestStatus::WrongPassword:
        return "wrong_password";
    case PasswordTestStatus::Damaged:
        return "damaged";
    case PasswordTestStatus::Unsupported:
        return "unsupported";
    case PasswordTestStatus::BackendUnavailable:
        return "backend_unavailable";
    case PasswordTestStatus::Error:
        return "error";
    }
    return "unknown";
}

}  // namespace smart_unpacker::sevenzip

