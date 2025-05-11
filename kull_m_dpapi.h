/*	Benjamin DELPY `gentilkiwi`
	http://blog.gentilkiwi.com
	benjamin@gentilkiwi.com
	Licence : http://creativecommons.org/licenses/by/3.0/fr/
*/
#pragma once
#include "main.h"
#include "kull_m_crypto.h"
#include "kuhl_m_dpapi_oe.h"

#pragma pack(push, 4) 
typedef struct _KULL_M_DPAPI_MASTERKEY {
	DWORD	dwVersion;
	BYTE	salt[16];
	DWORD	rounds;
	ALG_ID	algHash;
	ALG_ID	algCrypt;
	PBYTE	pbKey;
	DWORD	__dwKeyLen;
} KULL_M_DPAPI_MASTERKEY, * PKULL_M_DPAPI_MASTERKEY;

typedef struct _KULL_M_DPAPI_MASTERKEY_CREDHIST {
	DWORD	dwVersion;
	GUID	guid;
} KULL_M_DPAPI_MASTERKEY_CREDHIST, * PKULL_M_DPAPI_MASTERKEY_CREDHIST;

typedef struct _KULL_M_DPAPI_MASTERKEY_DOMAINKEY {
	DWORD	dwVersion;
	DWORD	dwSecretLen;
	DWORD	dwAccesscheckLen;
	GUID	guidMasterKey;
	BYTE*	pbSecret;
	BYTE*	pbAccesscheck;
} KULL_M_DPAPI_MASTERKEY_DOMAINKEY, * PKULL_M_DPAPI_MASTERKEY_DOMAINKEY;

typedef struct _KULL_M_DPAPI_MASTERKEYS {
	DWORD	dwVersion;
	DWORD	unk0;
	DWORD	unk1;
	WCHAR	szGuid[36];
	DWORD	unk2;
	DWORD	unk3;
	DWORD	dwFlags;
	DWORD64	dwMasterKeyLen;
	DWORD64 dwBackupKeyLen;
	DWORD64 dwCredHistLen;
	DWORD64	dwDomainKeyLen;
	PKULL_M_DPAPI_MASTERKEY	MasterKey;
	PKULL_M_DPAPI_MASTERKEY	BackupKey;
	PKULL_M_DPAPI_MASTERKEY_CREDHIST	CredHist;
	PKULL_M_DPAPI_MASTERKEY_DOMAINKEY	DomainKey;
} KULL_M_DPAPI_MASTERKEYS, * PKULL_M_DPAPI_MASTERKEYS;

typedef struct _KULL_M_DPAPI_DOMAIN_RSA_MASTER_KEY {
	DWORD  cbMasterKey;
	DWORD  cbSuppKey;
	BYTE   buffer[ANYSIZE_ARRAY];
} KULL_M_DPAPI_DOMAIN_RSA_MASTER_KEY, * PKULL_M_DPAPI_DOMAIN_RSA_MASTER_KEY;

typedef struct _KULL_M_DPAPI_DOMAIN_ACCESS_CHECK {
	DWORD  dwVersion;
	DWORD  dataLen;
	BYTE   data[ANYSIZE_ARRAY];
	// sid
	// SHA1 (or SHA512)
} KULL_M_DPAPI_DOMAIN_ACCESS_CHECK, * PKULL_M_DPAPI_DOMAIN_ACCESS_CHECK;
#pragma pack(pop) 


void kull_m_dpapi_ptr_replace(PVOID ptr, DWORD64 size);
PKULL_M_DPAPI_BLOB kull_m_dpapi_blob_create(PVOID data/*, DWORD size*/);
void kull_m_dpapi_blob_delete(PKULL_M_DPAPI_BLOB blob);

BOOL kull_m_dpapi_hmac_sha1_incorrect(LPCVOID key, DWORD keyLen, LPCVOID salt, DWORD saltLen, LPCVOID entropy, DWORD entropyLen, LPCVOID data, DWORD dataLen, LPVOID outKey);
BOOL kull_m_dpapi_sessionkey(LPCVOID masterkey, DWORD masterkeyLen, LPCVOID salt, DWORD saltLen, LPCVOID entropy, DWORD entropyLen, LPCVOID data, DWORD dataLen, ALG_ID hashAlg, LPVOID outKey, DWORD outKeyLen);
