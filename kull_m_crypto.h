/*	Benjamin DELPY `gentilkiwi`
	http://blog.gentilkiwi.com
	benjamin@gentilkiwi.com
	Licence : http://creativecommons.org/licenses/by/3.0/fr/
*/
#pragma once
#include "main.h"
#include "dpapi.h"

#define PVK_FILE_VERSION_0				0
#define PVK_MAGIC						0xb0b5f11e // bob's file
#define PVK_NO_ENCRYPT					0

typedef struct _PVK_FILE_HDR {
	DWORD	dwMagic;
	DWORD	dwVersion;
	DWORD	dwKeySpec;
	DWORD	dwEncryptType;
	DWORD	cbEncryptData;
	DWORD	cbPvk;
} PVK_FILE_HDR, * PPVK_FILE_HDR;

BOOL kull_m_crypto_hash(ALG_ID algid, LPCVOID data, DWORD dataLen, LPVOID hash, DWORD hashWanted);
BOOL kull_m_crypto_hkey(HCRYPTPROV hProv, DWORD calgid, LPCVOID key, DWORD keyLen, DWORD flags, HCRYPTKEY *hKey, HCRYPTPROV *hSessionProv);
BOOL kull_m_crypto_hmac(DWORD calgid, LPCVOID key, DWORD keyLen, LPCVOID message, DWORD messageLen, LPVOID hash, DWORD hashWanted);
BOOL kull_m_crypto_DeriveKeyRaw(ALG_ID hashId, LPVOID hash, DWORD hashLen, LPVOID key, DWORD keyLen);
BOOL kull_m_crypto_close_hprov_delete_container(HCRYPTPROV hProv);
BOOL kull_m_crypto_hkey_session(ALG_ID calgid, LPCVOID key, DWORD keyLen, DWORD flags, HCRYPTKEY *hSessionKey, HCRYPTPROV *hSessionProv);

void kuhl_m_crypto_exportRawKeyToFile(LPCVOID data, DWORD size, BOOL isCNG, DWORD dwKeySpec, DWORD dwProviderType, const wchar_t* store, const DWORD index, const wchar_t* name, BOOL wantExport, BOOL wantInfos);
