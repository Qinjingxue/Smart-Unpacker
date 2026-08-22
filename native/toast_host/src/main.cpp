#include <windows.h>
#include <shellapi.h>
#include <shlobj.h>
#include <propkey.h>
#include <propvarutil.h>
#include <NotificationActivationCallback.h>

#include <winrt/base.h>
#include <winrt/Windows.Data.Xml.Dom.h>
#include <winrt/Windows.Foundation.Collections.h>
#include <winrt/Windows.UI.Notifications.h>

#include <algorithm>
#include <array>
#include <atomic>
#include <cstdio>
#include <cstdint>
#include <cstring>
#include <cwchar>
#include <filesystem>
#include <functional>
#include <limits>
#include <memory>
#include <optional>
#include <stdexcept>
#include <string>
#include <string_view>
#include <utility>
#include <vector>

namespace {

using winrt::Windows::Data::Xml::Dom::XmlDocument;
using winrt::Windows::UI::Notifications::NotificationData;
using winrt::Windows::UI::Notifications::NotificationUpdateResult;
using winrt::Windows::UI::Notifications::ToastDismissalReason;
using winrt::Windows::UI::Notifications::ToastDismissedEventArgs;
using winrt::Windows::UI::Notifications::ToastNotification;
using winrt::Windows::UI::Notifications::ToastNotificationManager;

constexpr wchar_t kAppId[] = L"SunPack.Watch.Toast";
constexpr wchar_t kProgressToastTag[] = L"watch-progress";
constexpr wchar_t kFinalToastTag[] = L"watch-final";
constexpr wchar_t kToastGroup[] = L"SunPack";
constexpr wchar_t kClsidText[] = L"{C5A6B4E9-3184-44E2-9F15-6A71804F7A36}";
constexpr CLSID kToastActivatorClsid = {
    0xc5a6b4e9, 0x3184, 0x44e2, {0x9f, 0x15, 0x6a, 0x71, 0x80, 0x4f, 0x7a, 0x36}
};

constexpr std::uint32_t kProtocolMagic = 0x4E545053;
constexpr std::uint16_t kProtocolVersion = 1;
constexpr std::size_t kHeaderBytes = 20;
constexpr std::uint32_t kMaximumFrameBytes = 64 * 1024;

class WinrtApartmentScope {
public:
    WinrtApartmentScope() {
        winrt::init_apartment(winrt::apartment_type::multi_threaded);
    }

    ~WinrtApartmentScope() {
        winrt::clear_factory_cache();
        winrt::uninit_apartment();
    }

    WinrtApartmentScope(const WinrtApartmentScope&) = delete;
    WinrtApartmentScope& operator=(const WinrtApartmentScope&) = delete;
};

enum class MessageType : std::uint16_t {
    hello = 1,
    snapshot = 2,
    clear = 3,
    ping = 4,
    shutdown = 5,
};

enum class SnapshotKind : std::uint8_t {
    progress = 1,
    success = 2,
    failure = 3,
    mixed = 4,
};

enum class ProgressMode : std::uint8_t {
    none = 0,
    determinate = 1,
    indeterminate = 2,
};

enum class ActionKind : std::uint8_t {
    open_directory = 1,
    open_log = 2,
};

struct Action {
    ActionKind kind{};
    std::wstring label;
    std::wstring target;
};

struct Snapshot {
    SnapshotKind kind{};
    ProgressMode progress_mode{};
    double progress_value{};
    std::uint32_t ttl_ms{};
    std::wstring batch_id;
    std::wstring title;
    std::wstring body;
    std::wstring progress_title;
    std::wstring progress_status;
    std::wstring progress_value_text;
    std::vector<Action> actions;
};

struct Frame {
    MessageType type{};
    std::uint64_t sequence{};
    std::vector<std::uint8_t> payload;
};

std::atomic<HANDLE> g_activation_event{nullptr};

std::wstring executable_path() {
    std::wstring buffer(32768, L'\0');
    const DWORD length = GetModuleFileNameW(nullptr, buffer.data(), static_cast<DWORD>(buffer.size()));
    if (length == 0 || length >= buffer.size()) {
        winrt::throw_last_error();
    }
    buffer.resize(length);
    return buffer;
}

std::wstring quote_argument(std::wstring_view value) {
    std::wstring result = L"\"";
    std::size_t backslashes = 0;
    for (const wchar_t ch : value) {
        if (ch == L'\\') {
            ++backslashes;
            continue;
        }
        if (ch == L'\"') {
            result.append(backslashes * 2 + 1, L'\\');
            result.push_back(L'\"');
            backslashes = 0;
            continue;
        }
        result.append(backslashes, L'\\');
        backslashes = 0;
        result.push_back(ch);
    }
    result.append(backslashes * 2, L'\\');
    result.push_back(L'\"');
    return result;
}

bool is_ordinary_integrity() {
    HANDLE token = nullptr;
    if (!OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &token)) {
        return false;
    }
    DWORD bytes = 0;
    GetTokenInformation(token, TokenIntegrityLevel, nullptr, 0, &bytes);
    std::vector<std::uint8_t> buffer(bytes);
    const BOOL ok = bytes != 0 && GetTokenInformation(
        token,
        TokenIntegrityLevel,
        buffer.data(),
        bytes,
        &bytes
    );
    CloseHandle(token);
    if (!ok) {
        return false;
    }
    const auto label = reinterpret_cast<const TOKEN_MANDATORY_LABEL*>(buffer.data());
    const auto sid = label->Label.Sid;
    const DWORD count = *GetSidSubAuthorityCount(sid);
    const DWORD rid = *GetSidSubAuthority(sid, count - 1);
    return rid < SECURITY_MANDATORY_HIGH_RID;
}

std::wstring programs_shortcut_path(bool create_directory = true) {
    PWSTR raw = nullptr;
    winrt::check_hresult(SHGetKnownFolderPath(FOLDERID_Programs, KF_FLAG_CREATE, nullptr, &raw));
    std::unique_ptr<wchar_t, decltype(&CoTaskMemFree)> owner(raw, CoTaskMemFree);
    const std::filesystem::path directory = std::filesystem::path(raw) / L"SunPack";
    if (create_directory) {
        std::filesystem::create_directories(directory);
    }
    return (directory / L"SunPack Toast Host.lnk").wstring();
}

void set_registry_string(HKEY root, const std::wstring& subkey, const std::wstring& value) {
    HKEY key = nullptr;
    const LSTATUS created = RegCreateKeyExW(
        root,
        subkey.c_str(),
        0,
        nullptr,
        REG_OPTION_NON_VOLATILE,
        KEY_SET_VALUE,
        nullptr,
        &key,
        nullptr
    );
    if (created != ERROR_SUCCESS) {
        winrt::check_hresult(HRESULT_FROM_WIN32(created));
    }
    const LSTATUS written = RegSetValueExW(
        key,
        nullptr,
        0,
        REG_SZ,
        reinterpret_cast<const BYTE*>(value.c_str()),
        static_cast<DWORD>((value.size() + 1) * sizeof(wchar_t))
    );
    RegCloseKey(key);
    if (written != ERROR_SUCCESS) {
        winrt::check_hresult(HRESULT_FROM_WIN32(written));
    }
}

void register_toast_identity() {
    const std::wstring executable = executable_path();
    const std::wstring registry_path = std::wstring(L"Software\\Classes\\CLSID\\") + kClsidText + L"\\LocalServer32";
    set_registry_string(HKEY_CURRENT_USER, registry_path, quote_argument(executable) + L" -ToastActivated");

    winrt::com_ptr<IShellLinkW> link;
    winrt::check_hresult(CoCreateInstance(
        CLSID_ShellLink,
        nullptr,
        CLSCTX_INPROC_SERVER,
        IID_PPV_ARGS(link.put())
    ));
    winrt::check_hresult(link->SetPath(executable.c_str()));
    winrt::check_hresult(link->SetArguments(L"--toast-shortcut"));
    winrt::check_hresult(link->SetDescription(L"SunPack Watch notifications"));

    const auto store = link.as<IPropertyStore>();
    PROPVARIANT app_id{};
    winrt::check_hresult(InitPropVariantFromString(kAppId, &app_id));
    winrt::check_hresult(store->SetValue(PKEY_AppUserModel_ID, app_id));
    PropVariantClear(&app_id);
    PROPVARIANT activator{};
    winrt::check_hresult(InitPropVariantFromCLSID(kToastActivatorClsid, &activator));
    winrt::check_hresult(store->SetValue(PKEY_AppUserModel_ToastActivatorCLSID, activator));
    PropVariantClear(&activator);
    winrt::check_hresult(store->Commit());
    const auto persist = link.as<IPersistFile>();
    winrt::check_hresult(persist->Save(programs_shortcut_path().c_str(), TRUE));
}

bool toast_identity_registered() noexcept {
    try {
        const std::wstring registry_path = std::wstring(L"Software\\Classes\\CLSID\\") + kClsidText + L"\\LocalServer32";
        DWORD bytes = 0;
        if (RegGetValueW(
            HKEY_CURRENT_USER,
            registry_path.c_str(),
            nullptr,
            RRF_RT_REG_SZ,
            nullptr,
            nullptr,
            &bytes
        ) != ERROR_SUCCESS || bytes < sizeof(wchar_t)) {
            return false;
        }
        std::wstring value(bytes / sizeof(wchar_t), L'\0');
        if (RegGetValueW(
            HKEY_CURRENT_USER,
            registry_path.c_str(),
            nullptr,
            RRF_RT_REG_SZ,
            nullptr,
            value.data(),
            &bytes
        ) != ERROR_SUCCESS) {
            return false;
        }
        value.resize(std::wcslen(value.c_str()));
        const std::wstring expected = quote_argument(executable_path()) + L" -ToastActivated";
        return value == expected && std::filesystem::is_regular_file(programs_shortcut_path(false));
    } catch (...) {
        return false;
    }
}

void unregister_toast_identity() noexcept {
    const std::wstring registry_path = std::wstring(L"Software\\Classes\\CLSID\\") + kClsidText;
    RegDeleteTreeW(HKEY_CURRENT_USER, registry_path.c_str());
    try {
        std::filesystem::remove(programs_shortcut_path(false));
    } catch (...) {
    }
}

std::wstring xml_escape(std::wstring_view text) {
    std::wstring result;
    result.reserve(text.size());
    for (const wchar_t ch : text) {
        switch (ch) {
        case L'&': result += L"&amp;"; break;
        case L'<': result += L"&lt;"; break;
        case L'>': result += L"&gt;"; break;
        case L'\"': result += L"&quot;"; break;
        case L'\'': result += L"&apos;"; break;
        default:
            if (ch >= 0x20 || ch == L'\t' || ch == L'\n' || ch == L'\r') {
                result.push_back(ch);
            }
        }
    }
    return result;
}

std::wstring utf8_to_utf16(const std::uint8_t* data, std::size_t size) {
    if (size == 0) {
        return {};
    }
    if (size > static_cast<std::size_t>(std::numeric_limits<int>::max())) {
        throw std::runtime_error("UTF-8 field is too large");
    }
    const int required = MultiByteToWideChar(
        CP_UTF8,
        MB_ERR_INVALID_CHARS,
        reinterpret_cast<const char*>(data),
        static_cast<int>(size),
        nullptr,
        0
    );
    if (required <= 0) {
        winrt::throw_last_error();
    }
    std::wstring result(static_cast<std::size_t>(required), L'\0');
    if (MultiByteToWideChar(
        CP_UTF8,
        MB_ERR_INVALID_CHARS,
        reinterpret_cast<const char*>(data),
        static_cast<int>(size),
        result.data(),
        required
    ) != required) {
        winrt::throw_last_error();
    }
    return result;
}

std::string utf16_to_utf8(std::wstring_view value) {
    if (value.empty()) {
        return {};
    }
    const int required = WideCharToMultiByte(
        CP_UTF8,
        WC_ERR_INVALID_CHARS,
        value.data(),
        static_cast<int>(value.size()),
        nullptr,
        0,
        nullptr,
        nullptr
    );
    if (required <= 0) {
        winrt::throw_last_error();
    }
    std::string result(static_cast<std::size_t>(required), '\0');
    if (WideCharToMultiByte(
        CP_UTF8,
        WC_ERR_INVALID_CHARS,
        value.data(),
        static_cast<int>(value.size()),
        result.data(),
        required,
        nullptr,
        nullptr
    ) != required) {
        winrt::throw_last_error();
    }
    return result;
}

std::string_view dismissal_reason_name(ToastDismissalReason reason) noexcept {
    switch (reason) {
    case ToastDismissalReason::TimedOut:
        return "TimedOut";
    case ToastDismissalReason::UserCanceled:
        return "UserCanceled";
    case ToastDismissalReason::ApplicationHidden:
        return "ApplicationHidden";
    default:
        return "Unknown";
    }
}

void append_dismissal_event(
    const std::wstring& log_path,
    std::string_view kind,
    ToastDismissalReason reason
) noexcept {
    if (log_path.empty()) return;
    HANDLE file = CreateFileW(
        log_path.c_str(),
        FILE_APPEND_DATA,
        FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
        nullptr,
        OPEN_ALWAYS,
        FILE_ATTRIBUTE_NORMAL,
        nullptr
    );
    if (file == INVALID_HANDLE_VALUE) return;
    LARGE_INTEGER size{};
    if (GetFileSizeEx(file, &size) && size.QuadPart > 1024 * 1024) {
        CloseHandle(file);
        file = CreateFileW(
            log_path.c_str(),
            GENERIC_WRITE,
            FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
            nullptr,
            CREATE_ALWAYS,
            FILE_ATTRIBUTE_NORMAL,
            nullptr
        );
        if (file == INVALID_HANDLE_VALUE) return;
    }
    SYSTEMTIME now{};
    GetSystemTime(&now);
    char timestamp[32]{};
    const int timestamp_length = std::snprintf(
        timestamp,
        sizeof(timestamp),
        "%04u-%02u-%02uT%02u:%02u:%02u.%03uZ",
        now.wYear,
        now.wMonth,
        now.wDay,
        now.wHour,
        now.wMinute,
        now.wSecond,
        now.wMilliseconds
    );
    std::string line = "{\"time\":\"";
    if (timestamp_length > 0) {
        line.append(timestamp, static_cast<std::size_t>(timestamp_length));
    }
    line += "\",\"event\":\"toast_dismissed\",\"kind\":\"";
    line += kind;
    line += "\",\"reason\":\"";
    line += dismissal_reason_name(reason);
    line += "\"}\r\n";
    DWORD written = 0;
    WriteFile(file, line.data(), static_cast<DWORD>(line.size()), &written, nullptr);
    CloseHandle(file);
}

std::wstring hex_encode(std::wstring_view value) {
    constexpr wchar_t digits[] = L"0123456789ABCDEF";
    const std::string utf8 = utf16_to_utf8(value);
    std::wstring result;
    result.reserve(utf8.size() * 2);
    for (const unsigned char byte : utf8) {
        result.push_back(digits[byte >> 4]);
        result.push_back(digits[byte & 0x0f]);
    }
    return result;
}

std::optional<std::wstring> hex_decode(std::wstring_view value) {
    if (value.empty() || value.size() % 2 != 0 || value.size() > 65534) {
        return std::nullopt;
    }
    auto digit = [](wchar_t ch) -> int {
        if (ch >= L'0' && ch <= L'9') return ch - L'0';
        if (ch >= L'a' && ch <= L'f') return ch - L'a' + 10;
        if (ch >= L'A' && ch <= L'F') return ch - L'A' + 10;
        return -1;
    };
    std::vector<std::uint8_t> bytes(value.size() / 2);
    for (std::size_t index = 0; index < bytes.size(); ++index) {
        const int high = digit(value[index * 2]);
        const int low = digit(value[index * 2 + 1]);
        if (high < 0 || low < 0) {
            return std::nullopt;
        }
        bytes[index] = static_cast<std::uint8_t>((high << 4) | low);
    }
    try {
        return utf8_to_utf16(bytes.data(), bytes.size());
    } catch (...) {
        return std::nullopt;
    }
}

bool absolute_existing_target(const std::wstring& path, bool directory) {
    if (path.empty() || !std::filesystem::path(path).is_absolute()) {
        return false;
    }
    const DWORD attributes = GetFileAttributesW(path.c_str());
    if (attributes == INVALID_FILE_ATTRIBUTES) {
        return false;
    }
    return directory
        ? (attributes & FILE_ATTRIBUTE_DIRECTORY) != 0
        : (attributes & FILE_ATTRIBUTE_DIRECTORY) == 0;
}

void activate_action(std::wstring_view arguments) noexcept {
    try {
        const std::size_t separator = arguments.find(L'|');
        if (separator == std::wstring_view::npos) {
            return;
        }
        const std::wstring_view kind = arguments.substr(0, separator);
        const auto decoded = hex_decode(arguments.substr(separator + 1));
        if (!decoded) {
            return;
        }
        bool directory = false;
        if (kind == L"dir") {
            directory = true;
        } else if (kind == L"log") {
            const std::filesystem::path path(*decoded);
            if (path.extension() != L".txt") {
                return;
            }
        } else {
            return;
        }
        if (!absolute_existing_target(*decoded, directory)) {
            return;
        }
        ShellExecuteW(nullptr, L"open", decoded->c_str(), nullptr, nullptr, SW_SHOWNORMAL);
    } catch (...) {
    }
}

class ActivationCallback final : public INotificationActivationCallback {
public:
    HRESULT STDMETHODCALLTYPE QueryInterface(REFIID iid, void** object) noexcept override {
        if (object == nullptr) return E_POINTER;
        *object = nullptr;
        if (iid == IID_IUnknown || iid == __uuidof(INotificationActivationCallback)) {
            *object = static_cast<INotificationActivationCallback*>(this);
            AddRef();
            return S_OK;
        }
        return E_NOINTERFACE;
    }

    ULONG STDMETHODCALLTYPE AddRef() noexcept override {
        return ++references_;
    }

    ULONG STDMETHODCALLTYPE Release() noexcept override {
        const ULONG value = --references_;
        if (value == 0) delete this;
        return value;
    }

    HRESULT STDMETHODCALLTYPE Activate(
        LPCWSTR app_user_model_id,
        LPCWSTR invoked_args,
        const NOTIFICATION_USER_INPUT_DATA*,
        ULONG
    ) noexcept override {
        if (app_user_model_id != nullptr && std::wstring_view(app_user_model_id) == kAppId) {
            activate_action(invoked_args == nullptr ? std::wstring_view{} : std::wstring_view(invoked_args));
        }
        if (const HANDLE event = g_activation_event.load()) {
            SetEvent(event);
        }
        return S_OK;
    }

private:
    std::atomic<ULONG> references_{1};
};

class ActivationFactory final : public IClassFactory {
public:
    HRESULT STDMETHODCALLTYPE QueryInterface(REFIID iid, void** object) noexcept override {
        if (object == nullptr) return E_POINTER;
        *object = nullptr;
        if (iid == IID_IUnknown || iid == IID_IClassFactory) {
            *object = static_cast<IClassFactory*>(this);
            AddRef();
            return S_OK;
        }
        return E_NOINTERFACE;
    }

    ULONG STDMETHODCALLTYPE AddRef() noexcept override { return ++references_; }
    ULONG STDMETHODCALLTYPE Release() noexcept override {
        const ULONG value = --references_;
        if (value == 0) delete this;
        return value;
    }

    HRESULT STDMETHODCALLTYPE CreateInstance(IUnknown* outer, REFIID iid, void** object) noexcept override {
        if (outer != nullptr) return CLASS_E_NOAGGREGATION;
        auto* callback = new (std::nothrow) ActivationCallback();
        if (callback == nullptr) return E_OUTOFMEMORY;
        const HRESULT result = callback->QueryInterface(iid, object);
        callback->Release();
        return result;
    }

    HRESULT STDMETHODCALLTYPE LockServer(BOOL) noexcept override { return S_OK; }

private:
    std::atomic<ULONG> references_{1};
};

int run_activation_server() {
    if (!is_ordinary_integrity()) {
        return ERROR_ELEVATION_REQUIRED;
    }
    winrt::init_apartment(winrt::apartment_type::multi_threaded);
    HANDLE event = CreateEventW(nullptr, TRUE, FALSE, nullptr);
    if (event == nullptr) {
        winrt::throw_last_error();
    }
    g_activation_event.store(event);
    auto* factory = new ActivationFactory();
    DWORD cookie = 0;
    const HRESULT registered = CoRegisterClassObject(
        kToastActivatorClsid,
        factory,
        CLSCTX_LOCAL_SERVER,
        REGCLS_MULTIPLEUSE,
        &cookie
    );
    factory->Release();
    if (FAILED(registered)) {
        CloseHandle(event);
        winrt::check_hresult(registered);
    }
    CoResumeClassObjects();
    WaitForSingleObject(event, 30'000);
    CoRevokeClassObject(cookie);
    g_activation_event.store(nullptr);
    CloseHandle(event);
    return 0;
}

template <typename T>
T read_little_endian(const std::uint8_t* data) {
    T value{};
    std::memcpy(&value, data, sizeof(T));
    return value;
}

class PayloadReader {
public:
    explicit PayloadReader(const std::vector<std::uint8_t>& payload) : payload_(payload) {}

    std::uint8_t byte() {
        require(1);
        return payload_[offset_++];
    }

    std::uint32_t uint32() {
        require(4);
        const auto value = read_little_endian<std::uint32_t>(payload_.data() + offset_);
        offset_ += 4;
        return value;
    }

    double floating() {
        require(8);
        const auto value = read_little_endian<double>(payload_.data() + offset_);
        offset_ += 8;
        return value;
    }

    std::wstring string() {
        const std::uint32_t length = uint32();
        require(length);
        std::wstring result = utf8_to_utf16(payload_.data() + offset_, length);
        offset_ += length;
        return result;
    }

    bool finished() const noexcept { return offset_ == payload_.size(); }

private:
    void require(std::size_t count) const {
        if (count > payload_.size() - offset_) {
            throw std::runtime_error("truncated Toast IPC payload");
        }
    }

    const std::vector<std::uint8_t>& payload_;
    std::size_t offset_{};
};

Snapshot parse_snapshot(const std::vector<std::uint8_t>& payload) {
    PayloadReader reader(payload);
    Snapshot result;
    result.kind = static_cast<SnapshotKind>(reader.byte());
    result.progress_mode = static_cast<ProgressMode>(reader.byte());
    const std::uint8_t action_count = reader.byte();
    if (reader.byte() != 0 || action_count > 2) {
        throw std::runtime_error("invalid Toast snapshot header");
    }
    result.progress_value = std::clamp(reader.floating(), 0.0, 1.0);
    result.ttl_ms = reader.uint32();
    result.batch_id = reader.string();
    result.title = reader.string();
    result.body = reader.string();
    result.progress_title = reader.string();
    result.progress_status = reader.string();
    result.progress_value_text = reader.string();
    if (result.progress_mode < ProgressMode::none || result.progress_mode > ProgressMode::indeterminate) {
        throw std::runtime_error("invalid Toast progress mode");
    }
    for (std::uint8_t index = 0; index < action_count; ++index) {
        Action action;
        action.kind = static_cast<ActionKind>(reader.byte());
        action.label = reader.string();
        action.target = reader.string();
        if (action.kind != ActionKind::open_directory && action.kind != ActionKind::open_log) {
            throw std::runtime_error("invalid Toast action kind");
        }
        result.actions.push_back(std::move(action));
    }
    if (!reader.finished()) {
        throw std::runtime_error("trailing Toast IPC snapshot data");
    }
    if (result.kind < SnapshotKind::progress || result.kind > SnapshotKind::mixed) {
        throw std::runtime_error("invalid Toast snapshot kind");
    }
    return result;
}

enum class ReadResult { complete, disconnected, parent_exited };

ReadResult read_exact(HANDLE pipe, HANDLE parent, HANDLE expiry_timer, void* destination, DWORD size, const std::function<void()>& expire) {
    auto* output = static_cast<std::uint8_t*>(destination);
    DWORD offset = 0;
    while (offset < size) {
        HANDLE event = CreateEventW(nullptr, TRUE, FALSE, nullptr);
        if (event == nullptr) winrt::throw_last_error();
        OVERLAPPED operation{};
        operation.hEvent = event;
        DWORD transferred = 0;
        BOOL started = ReadFile(pipe, output + offset, size - offset, &transferred, &operation);
        if (!started) {
            const DWORD error = GetLastError();
            if (error == ERROR_BROKEN_PIPE || error == ERROR_PIPE_NOT_CONNECTED) {
                CloseHandle(event);
                return ReadResult::disconnected;
            }
            if (error != ERROR_IO_PENDING) {
                CloseHandle(event);
                winrt::throw_last_error();
            }
            std::array<HANDLE, 3> handles{event, parent, expiry_timer};
            const DWORD count = parent == nullptr ? 2 : 3;
            if (parent == nullptr) {
                handles[1] = expiry_timer;
            }
            while (true) {
                const DWORD wait = WaitForMultipleObjects(count, handles.data(), FALSE, INFINITE);
                if (wait == WAIT_OBJECT_0) {
                    if (!GetOverlappedResult(pipe, &operation, &transferred, FALSE)) {
                        const DWORD result_error = GetLastError();
                        CloseHandle(event);
                        if (result_error == ERROR_BROKEN_PIPE || result_error == ERROR_PIPE_NOT_CONNECTED) {
                            return ReadResult::disconnected;
                        }
                        winrt::throw_last_error();
                    }
                    break;
                }
                const DWORD parent_index = parent == nullptr ? 0xffffffff : WAIT_OBJECT_0 + 1;
                const DWORD expiry_index = parent == nullptr ? WAIT_OBJECT_0 + 1 : WAIT_OBJECT_0 + 2;
                if (wait == parent_index) {
                    CancelIoEx(pipe, &operation);
                    GetOverlappedResult(pipe, &operation, &transferred, TRUE);
                    CloseHandle(event);
                    return ReadResult::parent_exited;
                }
                if (wait == expiry_index) {
                    expire();
                    continue;
                }
                CancelIoEx(pipe, &operation);
                CloseHandle(event);
                winrt::throw_last_error();
            }
        }
        CloseHandle(event);
        if (transferred == 0) {
            return ReadResult::disconnected;
        }
        offset += transferred;
    }
    return ReadResult::complete;
}

std::optional<Frame> read_frame(HANDLE pipe, HANDLE parent, HANDLE expiry_timer, const std::function<void()>& expire) {
    std::array<std::uint8_t, kHeaderBytes> header{};
    if (read_exact(pipe, parent, expiry_timer, header.data(), static_cast<DWORD>(header.size()), expire) != ReadResult::complete) {
        return std::nullopt;
    }
    if (read_little_endian<std::uint32_t>(header.data()) != kProtocolMagic
        || read_little_endian<std::uint16_t>(header.data() + 4) != kProtocolVersion) {
        throw std::runtime_error("invalid Toast IPC protocol header");
    }
    const std::uint32_t payload_size = read_little_endian<std::uint32_t>(header.data() + 8);
    if (payload_size > kMaximumFrameBytes - kHeaderBytes) {
        throw std::runtime_error("oversized Toast IPC frame");
    }
    Frame result;
    result.type = static_cast<MessageType>(read_little_endian<std::uint16_t>(header.data() + 6));
    result.sequence = read_little_endian<std::uint64_t>(header.data() + 12);
    result.payload.resize(payload_size);
    if (payload_size != 0 && read_exact(pipe, parent, expiry_timer, result.payload.data(), payload_size, expire) != ReadResult::complete) {
        return std::nullopt;
    }
    return result;
}

std::wstring action_arguments(const Action& action) {
    return std::wstring(action.kind == ActionKind::open_directory ? L"dir|" : L"log|") + hex_encode(action.target);
}

class ToastPresenter {
public:
    ToastPresenter(HANDLE expiry_timer, std::wstring diagnostic_log_path)
        : notifier_(ToastNotificationManager::CreateToastNotifier(kAppId)),
          expiry_timer_(expiry_timer),
          diagnostic_log_path_(std::move(diagnostic_log_path)) {}

    ~ToastPresenter() {
        clear();
    }

    void show(const Snapshot& snapshot, std::uint64_t sequence) {
        cancel_expiry();
        if (snapshot.kind == SnapshotKind::progress) {
            show_progress(snapshot, sequence);
        } else {
            show_final(snapshot);
        }
        if (snapshot.ttl_ms > 0) {
            LARGE_INTEGER due{};
            due.QuadPart = -static_cast<LONGLONG>(snapshot.ttl_ms) * 10'000;
            if (!SetWaitableTimer(expiry_timer_, &due, 0, nullptr, nullptr, FALSE)) {
                winrt::throw_last_error();
            }
        }
    }

    void clear() noexcept {
        cancel_expiry();
        remove(kProgressToastTag);
        remove(kFinalToastTag);
        progress_shown_ = false;
    }

private:
    void remove(std::wstring_view tag) noexcept {
        try {
            ToastNotificationManager::History().Remove(tag, kToastGroup, kAppId);
        } catch (...) {
        }
    }

    void observe_dismissal(const ToastNotification& toast, std::string_view kind) {
        if (diagnostic_log_path_.empty()) return;
        const auto log_path = diagnostic_log_path_;
        const std::string kind_name(kind);
        toast.Dismissed([log_path, kind_name](
            const ToastNotification&,
            const ToastDismissedEventArgs& args
        ) noexcept {
            append_dismissal_event(log_path, kind_name, args.Reason());
        });
    }

    void show_progress(const Snapshot& snapshot, std::uint64_t sequence) {
        NotificationData data;
        const auto values = data.Values();
        values.Insert(L"title", snapshot.title);
        values.Insert(L"body", snapshot.body);
        values.Insert(L"progressTitle", snapshot.progress_title);
        values.Insert(L"progressStatus", snapshot.progress_status);
        values.Insert(L"progressValueString", snapshot.progress_value_text);
        if (snapshot.progress_mode == ProgressMode::indeterminate) {
            values.Insert(L"progressValue", L"indeterminate");
        } else {
            values.Insert(L"progressValue", winrt::to_hstring(snapshot.progress_value));
        }
        data.SequenceNumber(static_cast<std::uint32_t>(sequence & 0xffffffff));
        if (progress_shown_) {
            const auto updated = notifier_.Update(data, kProgressToastTag, kToastGroup);
            if (updated == NotificationUpdateResult::Succeeded) {
                return;
            }
        }
        remove(kFinalToastTag);
        XmlDocument document;
        document.LoadXml(
            LR"(<toast duration="long" launch="noop"><visual><binding template="ToastGeneric"><text>{title}</text><text>{body}</text><progress title="{progressTitle}" value="{progressValue}" valueStringOverride="{progressValueString}" status="{progressStatus}"/></binding></visual></toast>)"
        );
        ToastNotification toast(document);
        toast.Tag(kProgressToastTag);
        toast.Group(kToastGroup);
        toast.Data(data);
        observe_dismissal(toast, "progress");
        notifier_.Show(toast);
        progress_shown_ = true;
    }

    void show_final(const Snapshot& snapshot) {
        remove(kProgressToastTag);
        progress_shown_ = false;
        std::wstring xml = L"<toast duration=\"long\" launch=\"noop\"><visual><binding template=\"ToastGeneric\"><text>";
        xml += xml_escape(snapshot.title);
        xml += L"</text>";
        if (!snapshot.body.empty()) {
            xml += L"<text>" + xml_escape(snapshot.body) + L"</text>";
        }
        xml += L"</binding></visual>";
        if (!snapshot.actions.empty()) {
            xml += L"<actions>";
            for (const auto& action : snapshot.actions) {
                xml += L"<action activationType=\"background\" content=\"";
                xml += xml_escape(action.label);
                xml += L"\" arguments=\"";
                xml += xml_escape(action_arguments(action));
                xml += L"\"/>";
            }
            xml += L"</actions>";
        }
        xml += L"</toast>";
        XmlDocument document;
        document.LoadXml(xml);
        ToastNotification toast(document);
        toast.Tag(kFinalToastTag);
        toast.Group(kToastGroup);
        observe_dismissal(toast, "final");
        notifier_.Show(toast);
    }

    void cancel_expiry() noexcept {
        if (expiry_timer_ != nullptr) CancelWaitableTimer(expiry_timer_);
    }

    winrt::Windows::UI::Notifications::ToastNotifier notifier_{nullptr};
    HANDLE expiry_timer_{};
    std::wstring diagnostic_log_path_;
    bool progress_shown_{};
};

std::optional<std::wstring> argument_value(int argc, wchar_t** argv, std::wstring_view name) {
    for (int index = 1; index + 1 < argc; ++index) {
        if (std::wstring_view(argv[index]) == name) {
            return std::wstring(argv[index + 1]);
        }
    }
    return std::nullopt;
}

bool has_argument(int argc, wchar_t** argv, std::wstring_view name) {
    for (int index = 1; index < argc; ++index) {
        if (std::wstring_view(argv[index]) == name) return true;
    }
    return false;
}

DWORD parse_process_id(const std::optional<std::wstring>& value) {
    if (!value || value->empty()) return 0;
    wchar_t* end = nullptr;
    const unsigned long parsed = std::wcstoul(value->c_str(), &end, 10);
    return end != value->c_str() && *end == L'\0' ? static_cast<DWORD>(parsed) : 0;
}

HANDLE connect_server_pipe(const std::wstring& name, HANDLE parent) {
    if (!name.starts_with(L"\\\\.\\pipe\\SunPackToast-")) {
        throw std::runtime_error("invalid Toast pipe name");
    }
    HANDLE pipe = CreateNamedPipeW(
        name.c_str(),
        PIPE_ACCESS_INBOUND | FILE_FLAG_OVERLAPPED,
        PIPE_TYPE_BYTE | PIPE_READMODE_BYTE | PIPE_WAIT | PIPE_REJECT_REMOTE_CLIENTS,
        1,
        kMaximumFrameBytes,
        kMaximumFrameBytes,
        5'000,
        nullptr
    );
    if (pipe == INVALID_HANDLE_VALUE) winrt::throw_last_error();
    HANDLE event = CreateEventW(nullptr, TRUE, FALSE, nullptr);
    if (event == nullptr) {
        CloseHandle(pipe);
        winrt::throw_last_error();
    }
    OVERLAPPED operation{};
    operation.hEvent = event;
    const BOOL connected = ConnectNamedPipe(pipe, &operation);
    bool overlapped_pending = false;
    if (!connected) {
        const DWORD error = GetLastError();
        if (error == ERROR_PIPE_CONNECTED) {
            SetEvent(event);
        } else if (error != ERROR_IO_PENDING) {
            CloseHandle(event);
            CloseHandle(pipe);
            winrt::throw_last_error();
        } else {
            overlapped_pending = true;
        }
    } else {
        SetEvent(event);
    }
    std::array<HANDLE, 2> waits{event, parent};
    const DWORD result = WaitForMultipleObjects(parent == nullptr ? 1 : 2, waits.data(), FALSE, INFINITE);
    if (result == WAIT_OBJECT_0 + 1) {
        CancelIoEx(pipe, &operation);
        CloseHandle(event);
        CloseHandle(pipe);
        return INVALID_HANDLE_VALUE;
    }
    DWORD transferred = 0;
    if (overlapped_pending && !GetOverlappedResult(pipe, &operation, &transferred, FALSE)) {
        const DWORD error = GetLastError();
        CloseHandle(event);
        CloseHandle(pipe);
        SetLastError(error);
        winrt::throw_last_error();
    }
    CloseHandle(event);
    return pipe;
}

int run_host(
    const std::wstring& pipe_name,
    const std::wstring& session,
    DWORD parent_pid,
    const std::wstring& diagnostic_log_path
) {
    if (!is_ordinary_integrity()) {
        return ERROR_ELEVATION_REQUIRED;
    }
    WinrtApartmentScope apartment;
    if (!toast_identity_registered()) {
        register_toast_identity();
    }
    winrt::check_hresult(SetCurrentProcessExplicitAppUserModelID(kAppId));
    HANDLE parent = parent_pid == 0 ? nullptr : OpenProcess(SYNCHRONIZE, FALSE, parent_pid);
    HANDLE pipe = connect_server_pipe(pipe_name, parent);
    if (pipe == INVALID_HANDLE_VALUE) {
        if (parent != nullptr) CloseHandle(parent);
        return 0;
    }
    HANDLE expiry_timer = CreateWaitableTimerW(nullptr, FALSE, nullptr);
    if (expiry_timer == nullptr) {
        DisconnectNamedPipe(pipe);
        CloseHandle(pipe);
        if (parent != nullptr) CloseHandle(parent);
        winrt::throw_last_error();
    }
    std::unique_ptr<ToastPresenter> presenter;
    const auto release_presenter = [&] {
        if (presenter) presenter->clear();
        presenter.reset();
    };
    const auto expire = [&] { release_presenter(); };
    std::uint64_t last_sequence = 0;
    bool authenticated = false;
    int result = 0;
    try {
        while (true) {
            auto frame = read_frame(pipe, parent, expiry_timer, expire);
            if (!frame) break;
            if (frame->sequence <= last_sequence) {
                throw std::runtime_error("non-monotonic Toast IPC sequence");
            }
            last_sequence = frame->sequence;
            if (!authenticated) {
                if (frame->type != MessageType::hello) {
                    throw std::runtime_error("Toast IPC session was not authenticated");
                }
                PayloadReader reader(frame->payload);
                if (reader.string() != session || !reader.finished()) {
                    throw std::runtime_error("Toast IPC session token mismatch");
                }
                authenticated = true;
                continue;
            }
            switch (frame->type) {
            case MessageType::snapshot:
                if (!presenter) {
                    presenter = std::make_unique<ToastPresenter>(expiry_timer, diagnostic_log_path);
                }
                presenter->show(parse_snapshot(frame->payload), frame->sequence);
                break;
            case MessageType::clear:
                if (!frame->payload.empty()) throw std::runtime_error("invalid clear frame");
                release_presenter();
                break;
            case MessageType::ping:
                if (!frame->payload.empty()) throw std::runtime_error("invalid ping frame");
                break;
            case MessageType::shutdown:
                if (!frame->payload.empty()) throw std::runtime_error("invalid shutdown frame");
                release_presenter();
                CloseHandle(expiry_timer);
                DisconnectNamedPipe(pipe);
                CloseHandle(pipe);
                if (parent != nullptr) CloseHandle(parent);
                return 0;
            default:
                throw std::runtime_error("unknown Toast IPC message type");
            }
        }
    } catch (...) {
        result = ERROR_INVALID_DATA;
    }
    release_presenter();
    CloseHandle(expiry_timer);
    DisconnectNamedPipe(pipe);
    CloseHandle(pipe);
    if (parent != nullptr) CloseHandle(parent);
    return result;
}

int self_test() {
    const std::wstring original = L"C:\\测试\\failed & log.txt";
    const auto decoded = hex_decode(hex_encode(original));
    if (!decoded || *decoded != original) return 1;
    if (xml_escape(L"<&\"'>") != L"&lt;&amp;&quot;&apos;&gt;") return 2;
    {
        WinrtApartmentScope apartment;
        XmlDocument first;
        first.LoadXml(L"<root><value>first</value></root>");
        XmlDocument second;
        second.LoadXml(L"<root><value>second</value></root>");
    }
    return 0;
}

} // namespace

int WINAPI wWinMain(HINSTANCE, HINSTANCE, PWSTR, int) {
    int argc = 0;
    wchar_t** argv = CommandLineToArgvW(GetCommandLineW(), &argc);
    if (argv == nullptr) return static_cast<int>(GetLastError());
    const auto release_argv = std::unique_ptr<wchar_t*, decltype(&LocalFree)>(argv, LocalFree);
    try {
        if (has_argument(argc, argv, L"--self-test")) {
            return self_test();
        }
        if (has_argument(argc, argv, L"--register-toast")) {
            winrt::init_apartment(winrt::apartment_type::multi_threaded);
            register_toast_identity();
            return 0;
        }
        if (has_argument(argc, argv, L"--unregister-toast")) {
            unregister_toast_identity();
            return 0;
        }
        if (has_argument(argc, argv, L"-ToastActivated")) {
            return run_activation_server();
        }
        const auto pipe = argument_value(argc, argv, L"--pipe");
        const auto session = argument_value(argc, argv, L"--session");
        const auto diagnostic_log = argument_value(argc, argv, L"--diagnostic-log");
        const DWORD parent_pid = parse_process_id(argument_value(argc, argv, L"--parent-pid"));
        if (!pipe || !session || session->size() < 16 || parent_pid == 0) {
            return ERROR_INVALID_PARAMETER;
        }
        return run_host(*pipe, *session, parent_pid, diagnostic_log.value_or(L""));
    } catch (const winrt::hresult_error& error) {
        return static_cast<int>(error.code().value & 0x7fffffff);
    } catch (...) {
        return ERROR_INVALID_DATA;
    }
}
