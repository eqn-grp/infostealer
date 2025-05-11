#pragma once
#include "main.h"
#include "kull_m_dpapi.h"

BOOL dpapi_unprotect_blob(PKULL_M_DPAPI_BLOB blob, LPCVOID masterkey, DWORD masterkeyLen, PVOID* dataOut, DWORD* dataOutLen);
wchar_t* string_getrandomGUID();
