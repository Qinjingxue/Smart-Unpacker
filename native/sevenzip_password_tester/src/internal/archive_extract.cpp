#include "sevenzip_password_tester/password_tester.hpp"



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



namespace smart_unpacker::sevenzip {



#ifdef _WIN32



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





}  // namespace smart_unpacker::sevenzip

