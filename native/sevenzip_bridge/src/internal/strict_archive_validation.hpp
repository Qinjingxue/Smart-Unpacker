#pragma once



#include "sevenzip_sdk.hpp"



namespace sunpack::sevenzip {



#ifdef _WIN32



bool strict_zip_stored_entries_ok(const std::wstring& path);

bool strict_seven_zip_headers_ok(const std::wstring& path);



#endif



}  // namespace sunpack::sevenzip

