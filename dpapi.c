 #include "dpapi.h"

wchar_t* string_getrandomGUID() {

	UNICODE_STRING uString;
	GUID guid;
	HCRYPTPROV hTmpCryptProv;
	wchar_t* buffer = NULL;

	if (CryptAcquireContext(&hTmpCryptProv, NULL, NULL, PROV_RSA_FULL, CRYPT_VERIFYCONTEXT)) {
		if (CryptGenRandom(hTmpCryptProv, sizeof(GUID), (BYTE*)&guid)) {
			if (NT_SUCCESS(RtlStringFromGUID(&guid, &uString))) {
				buffer = (wchar_t*)my_heapalloc(uString.MaximumLength);

				if (buffer) {
					my_memcpy(buffer, uString.Buffer, uString.MaximumLength);
				}
				myRtlFreeUnicodeString(&uString);
			}
		}
		CryptReleaseContext(hTmpCryptProv, 0);
	}
	return buffer;
}

BOOL dpapi_unprotect_blob(PKULL_M_DPAPI_BLOB blob, LPCVOID masterkey, DWORD masterkeyLen, PVOID* dataOut, DWORD* dataOutLen) {

	BOOL status = FALSE;
	PVOID hmac, key;
	HCRYPTPROV hSessionProv;
	HCRYPTKEY hSessionKey;
	DWORD hashLen = blob->dwAlgHashLen / 8, cryptLen = blob->dwAlgCryptLen / 8;
	
	if (hmac = LocalAlloc(LPTR, hashLen))
	{
		if (kull_m_dpapi_sessionkey(masterkey, masterkeyLen, blob->pbSalt, blob->dwSaltLen, NULL, 0, NULL, 0, blob->algHash, hmac, hashLen))
		{
			if (key = LocalAlloc(LPTR, cryptLen))
			{
				if (kull_m_crypto_DeriveKeyRaw(blob->algHash, hmac, hashLen, key, cryptLen))
				{
					if (kull_m_crypto_hkey_session(blob->algCrypt, key, cryptLen, 0, &hSessionKey, &hSessionProv))
					{	
						if (*dataOut = LocalAlloc(LPTR, blob->dwDataLen))
						{
							RtlCopyMemory(*dataOut, blob->pbData, blob->dwDataLen);
							*dataOutLen = blob->dwDataLen;
							status = CryptDecrypt(hSessionKey, 0, TRUE, 0, (LPBYTE)*dataOut, dataOutLen);
							//if (!status){LocalFree(*dataOut);}
						}
						CryptDestroyKey(hSessionKey);
						kull_m_crypto_close_hprov_delete_container(hSessionProv);
					}
				}
				LocalFree(key);
			}
		}
		LocalFree(hmac);
	}

	return status;
}

int dpapi_unprotect(void* data, BYTE* masterkey, DWORD masterkey_len) {

	int status = 0;
	//PVOID dataOut;
	PKULL_M_DPAPI_BLOB blob;

	blob = kull_m_dpapi_blob_create(data);

	if (blob) {
		if (masterkey && masterkey_len) {
			status = dpapi_unprotect_blob(blob, masterkey, masterkey_len, (PVOID*)&Output.pbData, &Output.cbData);
		}
		kull_m_dpapi_blob_delete(blob);
	}
	return status;
}