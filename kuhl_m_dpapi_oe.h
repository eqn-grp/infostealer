/*	Benjamin DELPY `gentilkiwi`
	https://blog.gentilkiwi.com
	benjamin@gentilkiwi.com
	Licence : https://creativecommons.org/licenses/by/4.0/
*/
#pragma once
#include "main.h"

typedef struct _KUHL_M_DPAPI_DOMAINKEY_ENTRY {
	GUID guid;
	BOOL isNewKey;
	DWORD keyLen;
	BYTE* key;
} KUHL_M_DPAPI_DOMAINKEY_ENTRY, * PKUHL_M_DPAPI_DOMAINKEY_ENTRY;


typedef struct _KUHL_M_DPAPI_OE_DOMAINKEY_ENTRY {
	LIST_ENTRY navigator;
	KUHL_M_DPAPI_DOMAINKEY_ENTRY data;
} KUHL_M_DPAPI_OE_DOMAINKEY_ENTRY, *PKUHL_M_DPAPI_OE_DOMAINKEY_ENTRY;

LIST_ENTRY gDPAPI_Domainkeys;

PKUHL_M_DPAPI_OE_DOMAINKEY_ENTRY kuhl_m_dpapi_oe_domainkey_get(LPCGUID guid);
BOOL kuhl_m_dpapi_oe_domainkey_add(LPCGUID guid, LPCVOID key, DWORD keyLen, BOOL isNewKey);
