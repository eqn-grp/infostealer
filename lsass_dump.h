#pragma once
#include "main.h"
#include "globals_sekurlsa.h"
#include "kuhl_m_sekurlsa_nt6.h"
#include "kull_m_process.h"
#include "kuhl_m_dpapi_oe.h"
#include "kull_m_crypto.h"

//globals
#define KULL_M_WIN_BUILD_2K3	3790
#define KULL_M_WIN_BUILD_XP		2600
#define KULL_M_WIN_BUILD_7		7600
#define KULL_M_WIN_BUILD_8		9200
#define KULL_M_WIN_MIN_BUILD_8		8000
#define KULL_M_WIN_BUILD_10_1507	10240
#define KULL_M_WIN_BUILD_10_1607	14393
#define KULL_M_WIN_BUILD_10_1703	15063
#define KULL_M_WIN_BUILD_10_1803	17134
#define KULL_M_WIN_BUILD_10_1809	17763
#define KULL_M_WIN_BUILD_10_1903	18362
#define KULL_M_WIN_BUILD_2022		20348

#define SECRET_QUERY_VALUE	0x00000002L

typedef struct _KIWI_BACKUP_KEY {
	DWORD version;
	DWORD keyLen;
	DWORD certLen;
	BYTE data[ANYSIZE_ARRAY];
} KIWI_BACKUP_KEY, * PKIWI_BACKUP_KEY;

//sekurlsa utils
typedef struct _KIWI_MSV1_0_PRIMARY_CREDENTIALS {
	struct _KIWI_MSV1_0_PRIMARY_CREDENTIALS* next;
	ANSI_STRING Primary;
	LSA_UNICODE_STRING Credentials;
} KIWI_MSV1_0_PRIMARY_CREDENTIALS, * PKIWI_MSV1_0_PRIMARY_CREDENTIALS;

typedef struct _KIWI_MSV1_0_CREDENTIALS {
	struct _KIWI_MSV1_0_CREDENTIALS* next;
	DWORD AuthenticationPackageId;
	PKIWI_MSV1_0_PRIMARY_CREDENTIALS PrimaryCredentials;
} KIWI_MSV1_0_CREDENTIALS, * PKIWI_MSV1_0_CREDENTIALS;

typedef struct _KIWI_MSV1_0_LIST_61 {
	struct _KIWI_MSV1_0_LIST_6* Flink;
	struct _KIWI_MSV1_0_LIST_6* Blink;
	PVOID unk0;
	ULONG unk1;
	PVOID unk2;
	ULONG unk3;
	ULONG unk4;
	ULONG unk5;
	HANDLE hSemaphore6;
	PVOID unk7;
	HANDLE hSemaphore8;
	PVOID unk9;
	PVOID unk10;
	ULONG unk11;
	ULONG unk12;
	PVOID unk13;
	LUID LocallyUniqueIdentifier;
	LUID SecondaryLocallyUniqueIdentifier;
	LSA_UNICODE_STRING UserName;
	LSA_UNICODE_STRING Domaine;
	PVOID unk14;
	PVOID unk15;
	PSID  pSid;
	ULONG LogonType;
	ULONG Session;
	LARGE_INTEGER LogonTime; // autoalign x86
	LSA_UNICODE_STRING LogonServer;
	PKIWI_MSV1_0_CREDENTIALS Credentials;
	PVOID unk19;
	PVOID unk20;
	PVOID unk21;
	ULONG unk22;
	PVOID CredentialManager;
} KIWI_MSV1_0_LIST_61, * PKIWI_MSV1_0_LIST_61;

typedef struct _KIWI_MSV1_0_LIST_63 {
	struct _KIWI_MSV1_0_LIST_63* Flink;	//off_2C5718
	struct _KIWI_MSV1_0_LIST_63* Blink; //off_277380
	PVOID unk0; // unk_2C0AC8
	ULONG unk1; // 0FFFFFFFFh
	PVOID unk2; // 0
	ULONG unk3; // 0
	ULONG unk4; // 0
	ULONG unk5; // 0A0007D0h
	HANDLE hSemaphore6; // 0F9Ch
	PVOID unk7; // 0
	HANDLE hSemaphore8; // 0FB8h
	PVOID unk9; // 0
	PVOID unk10; // 0
	ULONG unk11; // 0
	ULONG unk12; // 0 
	PVOID unk13; // unk_2C0A28
	LUID LocallyUniqueIdentifier;
	LUID SecondaryLocallyUniqueIdentifier;
	BYTE waza[12]; /// to do (maybe align)
	LSA_UNICODE_STRING UserName;
	LSA_UNICODE_STRING Domaine;
	PVOID unk14;
	PVOID unk15;
	LSA_UNICODE_STRING Type;
	PSID  pSid;
	ULONG LogonType;
	PVOID unk18;
	ULONG Session;
	LARGE_INTEGER LogonTime; // autoalign x86
	LSA_UNICODE_STRING LogonServer;
	PKIWI_MSV1_0_CREDENTIALS Credentials;
	PVOID unk19;
	PVOID unk20;
	PVOID unk21;
	ULONG unk22;
	ULONG unk23;
	ULONG unk24;
	ULONG unk25;
	ULONG unk26;
	PVOID unk27;
	PVOID unk28;
	PVOID unk29;
	PVOID CredentialManager;
} KIWI_MSV1_0_LIST_63, * PKIWI_MSV1_0_LIST_63;

typedef struct _KUHL_M_SEKURLSA_ENUM_HELPER {
	SIZE_T tailleStruct;
	ULONG offsetToLuid;
	ULONG offsetToLogonType;
	ULONG offsetToSession;
	ULONG offsetToUsername;
	ULONG offsetToDomain;
	ULONG offsetToCredentials;
	ULONG offsetToPSid;
	ULONG offsetToCredentialManager;
	ULONG offsetToLogonTime;
	ULONG offsetToLogonServer;
} KUHL_M_SEKURLSA_ENUM_HELPER, * PKUHL_M_SEKURLSA_ENUM_HELPER;

DWORD MIMIKATZ_NT_MAJOR_VERSION, MIMIKATZ_NT_MINOR_VERSION, MIMIKATZ_NT_BUILD_NUMBER;
typedef BOOL(CALLBACK* PKULL_M_MODULE_ENUM_CALLBACK) (PKULL_M_PROCESS_VERY_BASIC_MODULE_INFORMATION pModuleInformation, PVOID pvArg);

//sekurlsa_enum_callback_dpapi
typedef BOOL(CALLBACK* PKUHL_M_SEKURLSA_ENUM) (IN PKIWI_BASIC_SECURITY_LOGON_SESSION_DATA pData, IN OPTIONAL LPVOID pOptionalData);
typedef void (CALLBACK* PKUHL_M_SEKURLSA_ENUM_LOGONDATA) (IN PKIWI_BASIC_SECURITY_LOGON_SESSION_DATA pData);

#define SecEqualLuid(L1, L2)    \
            ( ( ((PLUID)L1)->LowPart == ((PLUID)L2)->LowPart ) && \
              ( ((PLUID)L1)->HighPart == ((PLUID)L2)->HighPart ) ) \

typedef struct _KIWI_MASTERKEY_CACHE_ENTRY {
	struct _KIWI_MATERKEY_CACHE_ENTRY* Flink;
	struct _KIWI_MATERKEY_CACHE_ENTRY* Blink;
	LUID LogonId;
	GUID KeyUid;
	FILETIME insertTime;
	ULONG keySize;
	BYTE  key[ANYSIZE_ARRAY];
} KIWI_MASTERKEY_CACHE_ENTRY, * PKIWI_MASTERKEY_CACHE_ENTRY;


//patch
typedef struct _KULL_M_PATCH_PATTERN {
	DWORD Length;
	BYTE* Pattern;
} KULL_M_PATCH_PATTERN, * PKULL_M_PATCH_PATTERN;

typedef struct _KULL_M_PATCH_OFFSETS {
	LONG off0;
	LONG off1;
	LONG off2;
	LONG off3;
	LONG off4;
	LONG off5;
	LONG off6;
	LONG off7;
	LONG off8;
	LONG off9;
} KULL_M_PATCH_OFFSETS, * PKULL_M_PATCH_OFFSETS;

typedef struct _KULL_M_PATCH_GENERIC {
	DWORD MinBuildNumber;
	KULL_M_PATCH_PATTERN Search;
	KULL_M_PATCH_PATTERN Patch;
	KULL_M_PATCH_OFFSETS Offsets;
} KULL_M_PATCH_GENERIC, * PKULL_M_PATCH_GENERIC;

//process

typedef BOOL(CALLBACK* PKULL_M_PROCESS_ENUM_CALLBACK) (PSYSTEM_PROCESS_INFORMATION pSystemProcessInformation, PVOID pvArg);

//exports
BOOL memory_open(IN KULL_M_MEMORY_TYPE Type, IN HANDLE hAny, OUT PKULL_M_MEMORY_HANDLE* hMemory);
PKULL_M_MEMORY_HANDLE memory_close(IN PKULL_M_MEMORY_HANDLE hMemory);
BOOL kull_m_memory_copy(OUT PKULL_M_MEMORY_ADDRESS Destination, IN PKULL_M_MEMORY_ADDRESS Source, IN SIZE_T Length);
PKULL_M_PATCH_GENERIC kull_m_patch_getGenericFromBuild(PKULL_M_PATCH_GENERIC generics, SIZE_T cbGenerics, DWORD BuildNumber);
BOOL kull_m_memory_search(IN PKULL_M_MEMORY_ADDRESS Pattern, IN SIZE_T Length, IN PKULL_M_MEMORY_SEARCH Search, IN BOOL bufferMeFirst);

//ntdll export
NTSTATUS NTAPI LsaOpenSecret(__in LSA_HANDLE PolicyHandle, __in PLSA_UNICODE_STRING SecretName, __in ACCESS_MASK DesiredAccess, __out PLSA_HANDLE SecretHandle);
NTSTATUS NTAPI LsaQuerySecret(__in LSA_HANDLE SecretHandle, __out_opt OPTIONAL PLSA_UNICODE_STRING* CurrentValue, __out_opt PLARGE_INTEGER CurrentValueSetTime, __out_opt PLSA_UNICODE_STRING* OldValue, __out_opt PLARGE_INTEGER OldValueSetTime);
VOID WINAPI RtlInitUnicodeString(OUT PUNICODE_STRING DestinationString, IN PCWSTR SourceString);
BOOLEAN WINAPI RtlEqualUnicodeString (IN PCUNICODE_STRING String1, IN PCUNICODE_STRING String2, IN BOOLEAN CaseInSensitive);
VOID WINAPI RtlGetNtVersionNumbers (LPDWORD pMajor, LPDWORD pMinor, LPDWORD pBuild);
