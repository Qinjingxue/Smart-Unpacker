#pragma once



#include "sevenzip_properties.hpp"

#include "sevenzip_streams.hpp"



#ifdef _WIN32

#include <algorithm>

#include <cstddef>

#include <filesystem>

#include <map>

#include <optional>

#include <string>

#include <utility>

#include <vector>

#endif



namespace packrelic::sevenzip {



#ifdef _WIN32



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

    explicit FileOutStream(const std::wstring& path, ExtractOutputTrace* trace = nullptr, std::size_t item_trace_index = 0)

        : trace_(trace),
          item_trace_index_(item_trace_index),

          handle_(CreateFileW(win32_extended_path(path).c_str(), GENERIC_WRITE, 0, nullptr, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, nullptr)) {

        if (trace_ && handle_ == INVALID_HANDLE_VALUE) {

            const DWORD error = GetLastError();

            trace_->last_hresult = HRESULT_FROM_WIN32(error);

            trace_->last_win32_error = static_cast<int>(error);

            mark_item_failure(trace_->last_hresult, trace_->last_win32_error);

        }

    }

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

            if (trace_) {

                trace_->last_hresult = E_FAIL;

            }

            return E_FAIL;

        }

        DWORD written = 0;

        if (!WriteFile(handle_, data, size, &written, nullptr)) {

            const DWORD error = GetLastError();

            const HRESULT hr = HRESULT_FROM_WIN32(error);

            if (trace_) {

                trace_->last_hresult = hr;

                trace_->last_win32_error = static_cast<int>(error);

                trace_->last_write_size = 0;

                mark_item_failure(hr, static_cast<int>(error));

            }

            return hr;

        }

        bytes_written_ += written;

        if (trace_) {

            trace_->total_bytes_written += written;

            trace_->current_item_bytes_written += written;

            trace_->last_write_size = written;

            trace_->last_hresult = S_OK;

            trace_->last_win32_error = 0;

            if (item_trace_index_ < trace_->items.size()) {

                trace_->items[item_trace_index_].bytes_written += written;

                trace_->items[item_trace_index_].hresult = S_OK;

                trace_->items[item_trace_index_].win32_error = 0;

            }

        }

        if (processedSize) {

            *processedSize = written;

        }

        return S_OK;

    }



private:

    void mark_item_failure(HRESULT hr, int win32_error) {

        if (!trace_ || item_trace_index_ >= trace_->items.size()) {

            return;

        }

        auto& item = trace_->items[item_trace_index_];

        item.failed = true;

        item.hresult = static_cast<int>(hr);

        item.win32_error = win32_error;

    }

    LONG refs_ = 1;

    ExtractOutputTrace* trace_ = nullptr;

    std::size_t item_trace_index_ = 0;

    HANDLE handle_ = INVALID_HANDLE_VALUE;

    UInt64 bytes_written_ = 0;

};



class TraceOutStream final : public ISequentialOutStream {

public:

    explicit TraceOutStream(ExtractOutputTrace* trace = nullptr, std::size_t item_trace_index = 0)

        : trace_(trace), item_trace_index_(item_trace_index) {}

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

    HRESULT STDMETHODCALLTYPE Write(const void*, UInt32 size, UInt32* processedSize) override {

        bytes_written_ += size;

        if (trace_) {

            trace_->total_bytes_written += size;

            trace_->current_item_bytes_written += size;

            trace_->last_write_size = size;

            trace_->last_hresult = S_OK;

            trace_->last_win32_error = 0;

            if (item_trace_index_ < trace_->items.size()) {

                trace_->items[item_trace_index_].bytes_written += size;

                trace_->items[item_trace_index_].hresult = S_OK;

                trace_->items[item_trace_index_].win32_error = 0;

            }

        }

        if (processedSize) {

            *processedSize = size;

        }

        return S_OK;

    }



private:

    LONG refs_ = 1;

    ExtractOutputTrace* trace_ = nullptr;

    std::size_t item_trace_index_ = 0;

    UInt64 bytes_written_ = 0;

};



inline std::optional<std::filesystem::path> safe_relative_item_path(const std::wstring& raw_name) {

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

        ExtractProgressCallback progress,

        bool dry_run = false,

        ExtractOutputTrace* output_trace = nullptr

    ) : archive_(archive),

        password_(std::move(password)),

        output_dir_(std::move(output_dir)),

        progress_(std::move(progress)),

        dry_run_(dry_run),

        output_trace_(output_trace) {}



    Int32 operation_result() const { return operation_result_; }

    UInt32 files_written() const { return files_written_; }

    UInt32 dirs_written() const { return dirs_written_; }

    UInt64 bytes_written() const { return bytes_written_; }

    UInt64 completed_bytes() const { return completed_bytes_; }

    const std::wstring& failed_item() const { return failed_item_; }

    UInt32 failed_item_index() const { return failed_item_index_; }

    UInt64 failed_item_bytes_written() const { return failed_item_bytes_written_; }

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

        current_item_bytes_written_ = 0;

        current_item_is_dir_ = false;

        current_trace_active_ = false;

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

        current_item_is_dir_ = is_dir;

        if (output_trace_) {

            output_trace_->current_item_index = index;

            output_trace_->current_item_path = name;

            output_trace_->current_item_bytes_written = 0;

            begin_item_trace(index, name, is_dir);

        }



        const auto safe_path = safe_relative_item_path(name);

        if (!safe_path.has_value()) {

            failed_item_ = name;

            failed_item_index_ = index;

            failed_item_bytes_written_ = 0;

            output_error_ = true;

            mark_current_item_failure(E_INVALIDARG, 0);

            return E_INVALIDARG;

        }

        emit("item_start", index, name);

        try {

            if (is_dir) {

                if (!dry_run_) {

                    const auto target = std::filesystem::path(win32_extended_path(output_dir_)) / safe_path.value();

                    std::filesystem::create_directories(target);

                }

                dirs_written_ += 1;

                return S_OK;

            }

            if (!dry_run_) {

                const auto target = std::filesystem::path(win32_extended_path(output_dir_)) / safe_path.value();

                std::filesystem::create_directories(target.parent_path());

            }

        } catch (...) {

            failed_item_ = name;

            failed_item_index_ = index;

            failed_item_bytes_written_ = current_item_bytes_written_;

            output_error_ = true;

            mark_current_item_failure(E_FAIL, 0);

            return E_FAIL;

        }

        if (dry_run_) {

            *outStream = new TraceOutStream(output_trace_, current_trace_index_);

            return S_OK;

        }

        const auto target = std::filesystem::path(win32_extended_path(output_dir_)) / safe_path.value();



        auto* stream = new FileOutStream(target.wstring(), output_trace_, current_trace_index_);

        if (!stream->is_open()) {

            stream->Release();

            failed_item_ = name;

            failed_item_index_ = index;

            failed_item_bytes_written_ = current_item_bytes_written_;

            output_error_ = true;

            mark_current_item_failure(output_trace_ ? static_cast<HRESULT>(output_trace_->last_hresult) : E_FAIL,
                                      output_trace_ ? output_trace_->last_win32_error : 0);

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

        if (opRes == kOpOk && !current_item_.empty() && !current_item_is_dir_) {

            files_written_ += 1;

        } else if (opRes != kOpOk && failed_item_.empty()) {

            failed_item_ = current_item_;

            failed_item_index_ = current_index_;

        }

        current_item_bytes_written_ = output_trace_ ? output_trace_->current_item_bytes_written : current_item_bytes_written_;

        finish_current_item_trace(opRes);

        if (opRes != kOpOk) {

            failed_item_bytes_written_ = current_item_bytes_written_;

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

    void begin_item_trace(UInt32 index, const std::wstring& item_path, bool is_dir) {

        if (!output_trace_) {

            return;

        }

        ExtractOutputItemTrace item;

        item.index = index;

        item.path = item_path;

        item.is_dir = is_dir;

        item.operation_result = kOpOk;

        output_trace_->items.push_back(std::move(item));

        current_trace_index_ = output_trace_->items.size() - 1;

        current_trace_active_ = true;

    }

    void finish_current_item_trace(Int32 opRes) {

        if (!output_trace_ || !current_trace_active_ || current_trace_index_ >= output_trace_->items.size()) {

            return;

        }

        auto& item = output_trace_->items[current_trace_index_];

        item.bytes_written = output_trace_->current_item_bytes_written;

        item.operation_result = opRes;

        item.done = opRes == kOpOk && !item.failed;

        item.failed = item.failed || opRes != kOpOk;

        item.hresult = output_trace_->last_hresult;

        item.win32_error = output_trace_->last_win32_error;

    }

    void mark_current_item_failure(HRESULT hr, int win32_error) {

        if (!output_trace_ || !current_trace_active_ || current_trace_index_ >= output_trace_->items.size()) {

            return;

        }

        auto& item = output_trace_->items[current_trace_index_];

        item.bytes_written = output_trace_->current_item_bytes_written;

        item.hresult = static_cast<int>(hr);

        item.win32_error = win32_error;

        item.failed = true;

        output_trace_->last_hresult = static_cast<int>(hr);

        output_trace_->last_win32_error = win32_error;

    }

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

    bool dry_run_ = false;

    ExtractOutputTrace* output_trace_ = nullptr;

    UInt64 completed_bytes_ = 0;

    UInt64 total_bytes_ = 0;

    UInt64 bytes_written_ = 0;

    UInt64 current_item_bytes_written_ = 0;

    UInt64 failed_item_bytes_written_ = 0;

    UInt32 current_index_ = 0;

    UInt32 failed_item_index_ = 0;

    UInt32 files_written_ = 0;

    UInt32 dirs_written_ = 0;

    std::size_t current_trace_index_ = 0;

    std::wstring current_item_;

    std::wstring failed_item_;

    Int32 operation_result_ = kOpOk;

    bool current_item_is_dir_ = false;

    bool current_trace_active_ = false;

    bool output_error_ = false;

};



#endif



}  // namespace packrelic::sevenzip
