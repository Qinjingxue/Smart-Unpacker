#include "archive_operations.hpp"

#include "sevenzip_callbacks.hpp"
#include "sevenzip_formats.hpp"
#include "sevenzip_paths.hpp"
#include "sevenzip_properties.hpp"
#include "sevenzip_status.hpp"
#include "sevenzip_streams.hpp"

namespace packrelic::sevenzip {


#ifdef _WIN32

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

#endif

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


}  // namespace packrelic::sevenzip
