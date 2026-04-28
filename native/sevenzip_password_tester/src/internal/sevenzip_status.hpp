#pragma once



#include "sevenzip_sdk.hpp"



namespace smart_unpacker::sevenzip {



#ifdef _WIN32



bool looks_wrong_password(HRESULT hr, Int32 op_res);

bool looks_damaged(Int32 op_res);

bool looks_damaged_health_result(const std::wstring& password, Int32 op_res);



#endif



}  // namespace smart_unpacker::sevenzip

