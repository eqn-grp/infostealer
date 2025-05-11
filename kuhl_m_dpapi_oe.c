/*	Benjamin DELPY `gentilkiwi`
	https://blog.gentilkiwi.com
	benjamin@gentilkiwi.com
	Licence : https://creativecommons.org/licenses/by/4.0/
*/
#include "kuhl_m_dpapi_oe.h"

LIST_ENTRY gDPAPI_Domainkeys = {&gDPAPI_Domainkeys, &gDPAPI_Domainkeys};
// to do CREDHIST_encrypted
// to do Masterkey_encrypted



PKUHL_M_DPAPI_OE_DOMAINKEY_ENTRY kuhl_m_dpapi_oe_domainkey_get(LPCGUID guid)
{
	PKUHL_M_DPAPI_OE_DOMAINKEY_ENTRY entry;
	for(entry = (PKUHL_M_DPAPI_OE_DOMAINKEY_ENTRY) gDPAPI_Domainkeys.Flink; entry != (PKUHL_M_DPAPI_OE_DOMAINKEY_ENTRY) &gDPAPI_Domainkeys; entry = (PKUHL_M_DPAPI_OE_DOMAINKEY_ENTRY) entry->navigator.Flink)
		if(RtlEqualGuid(guid, &entry->data.guid))
			return entry;
	return NULL;
}

BOOL kuhl_m_dpapi_oe_domainkey_add(LPCGUID guid, LPCVOID key, DWORD keyLen, BOOL isNewKey)
{
	BOOL status = FALSE;
	PKUHL_M_DPAPI_OE_DOMAINKEY_ENTRY entry;
	if(guid && key && keyLen)
	{
		if(!kuhl_m_dpapi_oe_domainkey_get(guid))
		{
			if(entry = (PKUHL_M_DPAPI_OE_DOMAINKEY_ENTRY) LocalAlloc(LPTR, sizeof(KUHL_M_DPAPI_OE_DOMAINKEY_ENTRY)))
			{
				RtlCopyMemory(&entry->data.guid, guid, sizeof(GUID));
				entry->data.isNewKey = isNewKey;
				if(entry->data.key = (BYTE *) LocalAlloc(LPTR, keyLen))
				{
					RtlCopyMemory(entry->data.key, key, keyLen);
					entry->data.keyLen = keyLen;
					status = TRUE;
				}
				entry->navigator.Blink = gDPAPI_Domainkeys.Blink;
				entry->navigator.Flink = &gDPAPI_Domainkeys;
				((PKUHL_M_DPAPI_OE_DOMAINKEY_ENTRY) gDPAPI_Domainkeys.Blink)->navigator.Flink = (PLIST_ENTRY) entry;
				gDPAPI_Domainkeys.Blink= (PLIST_ENTRY) entry;
			}
		}
	}
	return status;
}










