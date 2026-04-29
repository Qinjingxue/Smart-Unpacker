#include "sevenzip_password_tester/password_tester.hpp"



#include "archive_open_plan.hpp"

#include "sevenzip_callbacks.hpp"

#include "sevenzip_formats.hpp"

#include "sevenzip_paths.hpp"

#include "sevenzip_status.hpp"

#include "sevenzip_streams.hpp"



namespace packrelic::sevenzip {



#ifdef _WIN32



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

    PasswordTestResult fallback;

    fallback.backend_available = true;

    bool has_fallback = false;



    const auto plans = password_test_open_plans(archive_path, part_paths, formats, input_ranges);

    for (const auto& plan : plans) {

        PasswordTestResult result;

        result.backend_available = true;

        apply_plan_metadata(result, plan);



        bool any_format_created = false;

        bool any_opened = false;

        HRESULT last_hr = E_FAIL;

        Int32 last_op_res = kOpOk;



        for (const GUID& format : plan.formats) {

            ComPtr<IInArchive> archive;

            HRESULT hr = create_object(&format, &IID_IInArchive, reinterpret_cast<void**>(archive.out()));

            if (hr != S_OK || !archive) {

                last_hr = hr;

                continue;

            }

            any_format_created = true;



            bool stream_opened = false;

            ComPtr<IInStream> stream = open_stream_for_plan(plan, archive_path, part_paths, stream_opened);

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

        } else if (!any_opened && plan.uses_ranges() && plan.archive_type == L"7z") {

            result.status = PasswordTestStatus::WrongPassword;

            result.message = "wrong password";

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



        fallback = result;

        has_fallback = true;

        if (plan.uses_ranges() && result.status != PasswordTestStatus::Unsupported) {

            return result;

        }

    }



    if (has_fallback) {

        return fallback;

    }

    PasswordTestResult result;

    result.backend_available = true;

    result.status = PasswordTestStatus::Unsupported;

    result.message = "archive could not be opened by supported handlers";

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



    for (int i = 0; i < password_count; ++i) {

        const wchar_t* raw_password = passwords[i] ? passwords[i] : L"";

        PasswordTestResult current = test_one_password(

            create_object,

            archive_path,

            raw_password,

            effective_part_paths,

            formats);

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





}  // namespace packrelic::sevenzip

