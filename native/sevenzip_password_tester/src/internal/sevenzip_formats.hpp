#pragma once



#include "sevenzip_sdk.hpp"



#ifdef _WIN32

#include <vector>

#endif



namespace smart_unpacker::sevenzip {



#ifdef _WIN32



std::vector<GUID> candidate_formats(const std::wstring& archive_path, const std::vector<std::wstring>& part_paths = {});

std::vector<GUID> candidate_formats_for_hint(const std::wstring& format_hint, const std::wstring& archive_path, const std::vector<std::wstring>& part_paths = {});



#endif



}  // namespace smart_unpacker::sevenzip

