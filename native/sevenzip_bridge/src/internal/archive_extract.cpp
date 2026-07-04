#include "sevenzip_bridge/bridge.hpp"



#include "archive_operations.hpp"

#include "strict_archive_validation.hpp"

#include "sevenzip_callbacks.hpp"

#include "sevenzip_formats.hpp"

#include "sevenzip_paths.hpp"

#include "sevenzip_status.hpp"

#include "sevenzip_streams.hpp"



#ifdef _WIN32

#include <utility>

#endif



namespace sunpack::sevenzip {



#ifdef _WIN32

namespace {

std::wstring format_name_for_guid(const GUID& format) {

    const unsigned char id = format.Data4[5];

    switch (id) {

    case 0x01:

        return L"zip";

    case 0x02:

        return L"bzip2";

    case 0x03:

        return L"rar4";

    case 0x07:

        return L"7z";

    case 0x0C:

        return L"xz";

    case 0x0E:

        return L"zstd";

    case 0x0F:

    case 0xEF:

        return L"gzip";

    case 0xCC:

        return L"rar5";

    case 0xEE:

        return L"tar";

    }

    return L"unknown";

}

void set_failure(ExtractArchiveResult& result, const std::string& stage, const std::string& kind, HRESULT hr = S_OK) {

    if (result.failure_stage.empty()) {

        result.failure_stage = stage;

    }

    if (result.failure_kind.empty()) {

        result.failure_kind = kind;

    }

    if (hr != S_OK || result.hresult == 0) {

        result.hresult = static_cast<int>(hr);

    }

}

void set_missing_volume_failure(
    ExtractArchiveResult& result,
    const std::string& stage,
    const std::string& evidence,
    const std::wstring& requested_name = L"",
    HRESULT hr = S_OK
) {
    result.status = PasswordTestStatus::Damaged;
    result.damaged = true;
    result.missing_volume = true;
    result.missing_volume_suspected = false;
    result.missing_volume_evidence = evidence;
    result.missing_volume_name = requested_name;
    set_failure(result, stage, "missing_volume", hr);
    result.message = requested_name.empty()
        ? "archive split volume appears incomplete"
        : "archive handler requested a missing split volume";
}

std::string kind_for_operation_result(Int32 op_res) {

    if (op_res == kOpWrongPassword) {

        return "encrypted_or_wrong_password";

    }

    if (op_res == kOpCrcError) {

        return "checksum_error";

    }

    if (op_res == kOpUnsupportedMethod) {

        return "unsupported_method";

    }

    if (op_res == kOpUnexpectedEnd || op_res == kOpHeadersError || op_res == kOpIsNotArc || op_res == kOpDataError) {

        return "corrupted_data";

    }

    return "unknown";

}

}  // namespace



ExtractArchiveResult extract_archive_internal(

    CreateObjectFunc create_object,

    const std::wstring& archive_path,

    const std::wstring& password,

    const std::vector<std::wstring>& part_paths,

    const std::vector<ExtractInputRange>& input_ranges,

    const std::vector<ExtractPatchOperation>& input_patches,

    const std::wstring& format_hint,

    const std::wstring& output_dir,

    const std::wstring& codepage,

    const std::vector<std::wstring>& decoded_names,

    ExtractProgressCallback progress,

    bool dry_run = false

) {

    ExtractArchiveResult result;

    result.backend_available = true;
    result.requested_codepage = codepage;

    if (has_split_volume_gap(part_paths)) {
        set_missing_volume_failure(result, "input_preflight", "standard_sequence_gap");
        return result;
    }

    if (seven_zip_parts_prove_missing_tail(part_paths)) {
        set_missing_volume_failure(result, "input_preflight", "seven_zip_start_header_length");
        return result;
    }

    if (likely_missing_split_tail(part_paths)) {
        result.missing_volume_suspected = true;
        result.missing_volume_evidence = "tail_size_heuristic";
    }

    bool any_format_created = false;

    bool any_opened = false;

    HRESULT last_hr = E_FAIL;

    Int32 last_op_res = kOpOk;



    if (!dry_run) {

        try {

            std::filesystem::create_directories(std::filesystem::path(win32_extended_path(output_dir)));

        } catch (...) {

            result.status = PasswordTestStatus::Error;

            set_failure(result, "output_prepare", "output_filesystem");

            result.message = "output directory could not be created";

            return result;

        }

    }



    const auto formats = candidate_formats_for_hint(format_hint, archive_path, part_paths);

    for (const GUID& format : formats) {

        ExtractHandlerAttempt attempt;

        attempt.format = format_name_for_guid(format);

        ComPtr<IInArchive> archive;

        HRESULT hr = create_object(&format, &IID_IInArchive, reinterpret_cast<void**>(archive.out()));

        attempt.create_hresult = static_cast<int>(hr);

        if (hr != S_OK || !archive) {

            last_hr = hr;

            result.handler_attempts.push_back(attempt);

            continue;

        }

        attempt.created = true;

        any_format_created = true;



        bool stream_opened = false;

        ComPtr<IInStream> stream = [&]() {

            if (!input_patches.empty()) {

                std::vector<ExtractInputRange> patch_ranges = input_ranges;

                if (patch_ranges.empty()) {

                    const std::vector<std::wstring> effective_parts = part_paths.empty() ? std::vector<std::wstring>{archive_path} : part_paths;

                    for (const auto& path : effective_parts) {

                        ExtractInputRange range;

                        range.path = path;

                        range.start = 0;

                        range.has_end = false;

                        patch_ranges.push_back(std::move(range));

                    }

                }

                auto* patched_stream = new PatchedInStream(patch_ranges, input_patches, &result.input_trace);

                stream_opened = patched_stream->is_open();

                return ComPtr<IInStream>(patched_stream);

            }

            if (!input_ranges.empty()) {

                auto* range_stream = new MultiRangeInStream(input_ranges, &result.input_trace);

                stream_opened = range_stream->is_open();

                return ComPtr<IInStream>(range_stream);

            }

            return open_archive_stream(archive_path, part_paths, stream_opened, &result.input_trace);

        }();

        if (!stream_opened) {

            result.status = PasswordTestStatus::Error;

            set_failure(result, "input_open", "input_stream", static_cast<HRESULT>(result.input_trace.last_hresult));

            result.message = "archive file could not be opened";

            result.handler_attempts.push_back(attempt);

            return result;

        }



        auto* raw_open_callback = new OpenCallback(password, callback_archive_path(archive_path, part_paths), part_paths);
        ComPtr<IArchiveOpenCallback> open_callback(raw_open_callback);

        hr = archive->Open(stream.get(), nullptr, open_callback.get());

        if (raw_open_callback->missing_volume_requested()) {
            set_missing_volume_failure(
                result,
                "archive_open",
                "open_volume_callback_not_found",
                raw_open_callback->missing_volume_name(),
                hr
            );
            result.handler_attempts.push_back(attempt);
            return result;
        }

        attempt.open_hresult = static_cast<int>(hr);

        if (hr != S_OK) {

            last_hr = hr;

            result.handler_attempts.push_back(attempt);

            continue;

        }

        attempt.opened = true;

        result.handler_attempts.push_back(attempt);

        any_opened = true;



        UInt32 num_items = 0;

        if (archive->GetNumberOfItems(&num_items) == S_OK) {

            result.item_count = num_items;

            result.output_trace.items.reserve(num_items);

        }

        if (!codepage.empty()) {
            if (decoded_names.size() != num_items) {
                archive->Close();
                result.status = PasswordTestStatus::Error;
                set_failure(result, "filename_encoding", "decoded_name_count_mismatch");
                result.message = "decoded ZIP filename count does not match archive item count";
                return result;
            }
            result.applied_codepage = codepage;
            result.filename_decoder = L"sunpack_zip_raw_names";
        }



        result.archive_type = !format_hint.empty() ? format_hint : archive_type_for_path(archive_path);

        auto* raw_extract_callback = new ExtractToDiskCallback(
            archive.get(),
            password,
            output_dir,
            decoded_names,
            std::move(progress),
            dry_run,
            &result.output_trace,
            num_items);

        ComPtr<IArchiveExtractCallback> extract_callback(raw_extract_callback);

        hr = archive->Extract(nullptr, static_cast<UInt32>(kAllItems), 0, extract_callback.get());

        last_hr = hr;

        last_op_res = raw_extract_callback->operation_result();

        result.operation_result = last_op_res;

        result.files_written = raw_extract_callback->files_written();

        result.dirs_written = raw_extract_callback->dirs_written();

        result.output_inventory_complete = raw_extract_callback->output_root_initially_empty();

        result.bytes_written = result.output_trace.total_bytes_written;

        result.failed_item = raw_extract_callback->failed_item();

        result.failed_item_index = raw_extract_callback->failed_item_index();

        result.failed_item_bytes_written = raw_extract_callback->failed_item_bytes_written();

        result.hresult = static_cast<int>(hr);

        archive->Close();



        if (hr == S_OK && last_op_res == kOpOk) {

            if (!result.failed_item.empty()) {

                result.status = PasswordTestStatus::Damaged;

                result.command_ok = false;

                result.damaged = true;

                result.checksum_error = true;

                set_failure(result, "item_extract", "checksum_error", hr);

                result.message = "archive item failed during extraction";

                return result;

            }

            result.status = PasswordTestStatus::Ok;

            result.command_ok = true;

            result.missing_volume_suspected = false;
            if (result.missing_volume_evidence == "tail_size_heuristic") {
                result.missing_volume_evidence.clear();
            }

            result.message = dry_run ? "archive dry-run completed" : "archive extracted";

            return result;

        }

        if (raw_extract_callback->output_error()) {

            result.status = PasswordTestStatus::Error;

            set_failure(result, "output_write", "output_filesystem", static_cast<HRESULT>(result.output_trace.last_hresult));

            result.message = "archive item could not be written safely";

            return result;

        }

        if (looks_wrong_password(hr, last_op_res)) {

            if (password.empty() && (last_op_res == kOpDataError || last_op_res == kOpCrcError || last_op_res == kOpHeadersError || last_op_res == kOpUnexpectedEnd)) {

                result.status = PasswordTestStatus::Damaged;

                result.damaged = true;

                result.checksum_error = last_op_res == kOpCrcError;

                set_failure(result, "item_extract", kind_for_operation_result(last_op_res), hr);

                result.message = result.checksum_error ? "archive checksum error" : "archive appears damaged";

                return result;

            }

            if (!password.empty() && (last_op_res == kOpDataError || last_op_res == kOpCrcError) &&
                (result.files_written > 0 || result.failed_item_bytes_written > 0)) {

                result.status = PasswordTestStatus::Damaged;

                result.damaged = true;

                result.checksum_error = last_op_res == kOpCrcError;

                set_failure(result, "item_extract", kind_for_operation_result(last_op_res), hr);

                result.message = result.checksum_error ? "archive checksum error" : "archive appears damaged";

                return result;

            }

            result.status = PasswordTestStatus::WrongPassword;

            result.encrypted = true;

            result.wrong_password = true;

            result.checksum_error = last_op_res == kOpCrcError;

            set_failure(result, "item_extract", "encrypted_or_wrong_password", hr);

            result.message = "archive is encrypted or password is wrong";

            return result;

        }

        if (looks_damaged(last_op_res)) {

            result.status = PasswordTestStatus::Damaged;

            result.damaged = true;

            set_failure(result, "item_extract", kind_for_operation_result(last_op_res), hr);

            result.message = "archive appears damaged";

            return result;

        }

        result.status = PasswordTestStatus::Unsupported;

        result.unsupported_method = last_op_res == kOpUnsupportedMethod;

        set_failure(result, "item_extract", result.unsupported_method ? "unsupported_method" : "unknown", hr);

        result.message = result.unsupported_method ? "archive uses an unsupported method" : "archive could not be extracted";

    }



    if (!any_format_created) {

        result.status = PasswordTestStatus::Unsupported;

        set_failure(result, "handler_create", "unsupported", last_hr);

        result.message = "7z.dll did not create a supported archive handler";

    } else if (!any_opened) {

        if (password.empty() && (last_op_res == kOpDataError || last_op_res == kOpCrcError || last_op_res == kOpHeadersError || last_op_res == kOpUnexpectedEnd)) {

            result.status = PasswordTestStatus::Damaged;

            result.damaged = true;

            result.checksum_error = last_op_res == kOpCrcError;

            set_failure(result, "archive_open", kind_for_operation_result(last_op_res), last_hr);

            result.message = result.checksum_error ? "archive checksum error" : "archive appears damaged";

            return result;

        }

        result.status = looks_wrong_password(last_hr, last_op_res) ? PasswordTestStatus::WrongPassword : PasswordTestStatus::Unsupported;

        result.wrong_password = result.status == PasswordTestStatus::WrongPassword;

        result.encrypted = result.wrong_password;

        set_failure(result, "archive_open", result.wrong_password ? "encrypted_or_wrong_password" : "structure_recognition", last_hr);

        result.message = result.wrong_password ? "archive is encrypted or password is wrong" : "archive could not be opened by supported handlers";

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

    const std::wstring& codepage,

    const std::vector<std::wstring>& decoded_names,

    ExtractProgressCallback progress,

    bool dry_run

) {

#ifdef _WIN32

    ComModule module(seven_zip_dll_path);

    auto create_object = module.create_object();

    if (!create_object) {

        ExtractArchiveResult result;

        result.status = PasswordTestStatus::BackendUnavailable;

        set_failure(result, "backend_load", "backend_unavailable");

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

        {},

        format_hint,

        output_dir,

        codepage,

        decoded_names,

        std::move(progress),

        dry_run);

#else

    (void)seven_zip_dll_path;

    (void)archive_path;

    (void)part_paths;

    (void)format_hint;

    (void)password;

    (void)output_dir;

    (void)codepage;

    (void)decoded_names;

    (void)progress;

    (void)dry_run;

    ExtractArchiveResult result;

    result.status = PasswordTestStatus::BackendUnavailable;

    result.failure_stage = "backend_load";

    result.failure_kind = "backend_unavailable";

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

    const std::wstring& codepage,

    const std::vector<std::wstring>& decoded_names,

    ExtractProgressCallback progress,

    bool dry_run

) {

#ifdef _WIN32

    ComModule module(seven_zip_dll_path);

    auto create_object = module.create_object();

    if (!create_object) {

        ExtractArchiveResult result;

        result.status = PasswordTestStatus::BackendUnavailable;

        set_failure(result, "backend_load", "backend_unavailable");

        result.message = "7z.dll could not be loaded";

        return result;

    }

    return extract_archive_internal(

        create_object,

        archive_path,

        password,

        {},

        ranges,

        {},

        format_hint,

        output_dir,

        codepage,

        decoded_names,

        std::move(progress),

        dry_run);

#else

    (void)seven_zip_dll_path;

    (void)archive_path;

    (void)ranges;

    (void)format_hint;

    (void)password;

    (void)output_dir;

    (void)codepage;

    (void)decoded_names;

    (void)progress;

    (void)dry_run;

    ExtractArchiveResult result;

    result.status = PasswordTestStatus::BackendUnavailable;

    result.failure_stage = "backend_load";

    result.failure_kind = "backend_unavailable";

    result.message = "native archive range extraction is only implemented on Windows";

    return result;

#endif

}



ExtractArchiveResult extract_archive_with_patches(

    const std::wstring& seven_zip_dll_path,

    const std::wstring& archive_path,

    const std::vector<std::wstring>& part_paths,

    const std::vector<ExtractInputRange>& ranges,

    const std::vector<ExtractPatchOperation>& patches,

    const std::wstring& format_hint,

    const std::wstring& password,

    const std::wstring& output_dir,

    const std::wstring& codepage,

    const std::vector<std::wstring>& decoded_names,

    ExtractProgressCallback progress,

    bool dry_run

) {

#ifdef _WIN32

    ComModule module(seven_zip_dll_path);

    auto create_object = module.create_object();

    if (!create_object) {

        ExtractArchiveResult result;

        result.status = PasswordTestStatus::BackendUnavailable;

        set_failure(result, "backend_load", "backend_unavailable");

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

        ranges,

        patches,

        format_hint,

        output_dir,

        codepage,

        decoded_names,

        std::move(progress),

        dry_run);

#else

    (void)seven_zip_dll_path;

    (void)archive_path;

    (void)part_paths;

    (void)ranges;

    (void)patches;

    (void)format_hint;

    (void)password;

    (void)output_dir;

    (void)codepage;

    (void)decoded_names;

    (void)progress;

    (void)dry_run;

    ExtractArchiveResult result;

    result.status = PasswordTestStatus::BackendUnavailable;

    result.failure_stage = "backend_load";

    result.failure_kind = "backend_unavailable";

    result.message = "native archive patched extraction is only implemented on Windows";

    return result;

#endif

}





}  // namespace sunpack::sevenzip