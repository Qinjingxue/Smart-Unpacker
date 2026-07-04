#pragma once

#include "sevenzip_bridge/bridge.hpp"
#include "sevenzip_sdk.hpp"



namespace sunpack::sevenzip {



#ifdef _WIN32



bool strict_seven_zip_headers_ok(const std::wstring& path);

bool seven_zip_parts_prove_missing_tail(const std::vector<std::wstring>& part_paths);



#endif



}  // namespace sunpack::sevenzip
