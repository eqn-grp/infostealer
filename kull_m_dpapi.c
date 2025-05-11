/*	Benjamin DELPY `gentilkiwi`
	http://blog.gentilkiwi.com
	benjamin@gentilkiwi.com
	Licence : http://creativecommons.org/licenses/by/3.0/fr/
*/
#include "kull_m_dpapi.h"

void kull_m_dpapi_ptr_replace(PVOID ptr, DWORD64 size)
{
	PVOID tempPtr = NULL;
	if(size)
		if(tempPtr = LocalAlloc(LPTR, (SIZE_T) size))
			RtlCopyMemory(tempPtr, *(PVOID *) ptr, (size_t) size);
	*(PVOID *) ptr = tempPtr;
}

PKULL_M_DPAPI_BLOB kull_m_dpapi_blob_create(PVOID data/*, DWORD size*/)
{
	PKULL_M_DPAPI_BLOB blob = NULL;
	if(blob = (PKULL_M_DPAPI_BLOB) LocalAlloc(LPTR, sizeof(KULL_M_DPAPI_BLOB)))
	{
		RtlCopyMemory(blob, data, FIELD_OFFSET(KULL_M_DPAPI_BLOB, szDescription));
		blob->szDescription = (PWSTR) ((PBYTE) data + FIELD_OFFSET(KULL_M_DPAPI_BLOB, szDescription));
		RtlCopyMemory(&blob->algCrypt, (PBYTE) blob->szDescription + blob->dwDescriptionLen, blob->dwDescriptionLen + FIELD_OFFSET(KULL_M_DPAPI_BLOB, pbSalt) - FIELD_OFFSET(KULL_M_DPAPI_BLOB, algCrypt));
		blob->pbSalt = (PBYTE) blob->szDescription + blob->dwDescriptionLen + FIELD_OFFSET(KULL_M_DPAPI_BLOB, pbSalt) - FIELD_OFFSET(KULL_M_DPAPI_BLOB, algCrypt);
		blob->dwHmacKeyLen = *(PDWORD) ((PBYTE) blob->pbSalt + blob->dwSaltLen);
		blob->pbHmackKey = (PBYTE) blob->pbSalt + blob->dwSaltLen + FIELD_OFFSET(KULL_M_DPAPI_BLOB, pbHmackKey) - FIELD_OFFSET(KULL_M_DPAPI_BLOB, dwHmacKeyLen);
		RtlCopyMemory(&blob->algHash, (PBYTE) blob->pbHmackKey + blob->dwHmacKeyLen, blob->dwHmacKeyLen + FIELD_OFFSET(KULL_M_DPAPI_BLOB, pbHmack2Key) - FIELD_OFFSET(KULL_M_DPAPI_BLOB, algHash));
		blob->pbHmack2Key = (PBYTE) blob->pbHmackKey + blob->dwHmacKeyLen + FIELD_OFFSET(KULL_M_DPAPI_BLOB, pbHmack2Key) - FIELD_OFFSET(KULL_M_DPAPI_BLOB, algHash);
		blob->dwDataLen = *(PDWORD) ((PBYTE) blob->pbHmack2Key + blob->dwHmac2KeyLen);
		blob->pbData = (PBYTE) blob->pbHmack2Key + blob->dwHmac2KeyLen + FIELD_OFFSET(KULL_M_DPAPI_BLOB, pbData) - FIELD_OFFSET(KULL_M_DPAPI_BLOB, dwDataLen);
		blob->dwSignLen = *(PDWORD) ((PBYTE) blob->pbData + blob->dwDataLen);
		blob->pbSign = (PBYTE) blob->pbData + blob->dwDataLen + FIELD_OFFSET(KULL_M_DPAPI_BLOB, pbSign) - FIELD_OFFSET(KULL_M_DPAPI_BLOB, dwSignLen);
		
		kull_m_dpapi_ptr_replace(&blob->szDescription, blob->dwDescriptionLen);
		kull_m_dpapi_ptr_replace(&blob->pbSalt, blob->dwSaltLen);
		kull_m_dpapi_ptr_replace(&blob->pbHmackKey, blob->dwHmacKeyLen);
		kull_m_dpapi_ptr_replace(&blob->pbHmack2Key, blob->dwHmac2KeyLen);
		kull_m_dpapi_ptr_replace(&blob->pbData, blob->dwDataLen);
		kull_m_dpapi_ptr_replace(&blob->pbSign, blob->dwSignLen);
	}
	return blob;
}

void kull_m_dpapi_blob_delete(PKULL_M_DPAPI_BLOB blob)
{
	if(blob)
	{
		if(blob->szDescription)
			LocalFree(blob->szDescription);
		if(blob->pbSalt)
			LocalFree(blob->pbSalt);
		if(blob->pbHmackKey)
			LocalFree(blob->pbHmackKey);
		if(blob->pbHmack2Key)
			LocalFree(blob->pbHmack2Key);
		if(blob->pbData)
			LocalFree(blob->pbData);
		if(blob->pbSign)
			LocalFree(blob->pbSign);
		LocalFree(blob);
	}
}


BOOL kull_m_dpapi_hmac_sha1_incorrect(LPCVOID key, DWORD keyLen, LPCVOID salt, DWORD saltLen, LPCVOID entropy, DWORD entropyLen, LPCVOID data, DWORD dataLen, LPVOID outKey)
{
	BOOL status = FALSE;
	BYTE ipad[64], opad[64], hash[SHA_DIGEST_LENGTH], *bufferI, *bufferO;
	DWORD i;

	RtlFillMemory(ipad, sizeof(ipad), '6');
	RtlFillMemory(opad, sizeof(opad), '\\');
	for(i = 0; i < keyLen; i++)
	{
		ipad[i] ^= ((PBYTE) key)[i];
		opad[i] ^= ((PBYTE) key)[i];
	}
	if(bufferI = (PBYTE) LocalAlloc(LPTR, sizeof(ipad) + saltLen))
	{
		RtlCopyMemory(bufferI, ipad, sizeof(ipad));
		RtlCopyMemory(bufferI + sizeof(ipad), salt, saltLen);
		if(kull_m_crypto_hash(CALG_SHA1, bufferI, sizeof(ipad) + saltLen, hash, SHA_DIGEST_LENGTH))
		{
			if(bufferO = (PBYTE) LocalAlloc(LPTR, sizeof(opad) + SHA_DIGEST_LENGTH + entropyLen + dataLen))
			{
				RtlCopyMemory(bufferO, opad, sizeof(opad));
				RtlCopyMemory(bufferO + sizeof(opad), hash, SHA_DIGEST_LENGTH);
				if(entropy && entropyLen)
					RtlCopyMemory(bufferO + sizeof(opad) + SHA_DIGEST_LENGTH, entropy, entropyLen);
				if(data && dataLen)
					RtlCopyMemory(bufferO + sizeof(opad) + SHA_DIGEST_LENGTH + entropyLen, data, dataLen);
				
				status = kull_m_crypto_hash(CALG_SHA1, bufferO, sizeof(opad) + SHA_DIGEST_LENGTH + entropyLen + dataLen, outKey, SHA_DIGEST_LENGTH);
				LocalFree(bufferO);
			}
		}
		LocalFree(bufferI);
	}
	return status;
}

BOOL kull_m_dpapi_sessionkey(LPCVOID masterkey, DWORD masterkeyLen, LPCVOID salt, DWORD saltLen, LPCVOID entropy, DWORD entropyLen, LPCVOID data, DWORD dataLen, ALG_ID hashAlg, LPVOID outKey, DWORD outKeyLen)
{
	BOOL status = FALSE;
	LPCVOID pKey = NULL;
	BYTE dgstMasterKey[SHA_DIGEST_LENGTH];
	PBYTE tmp;
	if(masterkeyLen == SHA_DIGEST_LENGTH)
		pKey = masterkey;
	else if(kull_m_crypto_hash(CALG_SHA1, masterkey, masterkeyLen, dgstMasterKey, SHA_DIGEST_LENGTH))
		pKey = dgstMasterKey;
	
	if(pKey)
	{
		if((hashAlg == CALG_SHA1) && (entropy || data))
			status = kull_m_dpapi_hmac_sha1_incorrect(masterkey, masterkeyLen, salt, saltLen, entropy, entropyLen, data, dataLen, outKey);
		else if(tmp = (PBYTE) LocalAlloc(LPTR, saltLen + entropyLen + dataLen))
		{
			RtlCopyMemory(tmp, salt, saltLen);
			if(entropy && entropyLen)
				RtlCopyMemory(tmp + saltLen, entropy, entropyLen);
			if(data && dataLen)
				RtlCopyMemory(tmp + saltLen + entropyLen, data, dataLen);
			status = kull_m_crypto_hmac(hashAlg, pKey, SHA_DIGEST_LENGTH, tmp, saltLen + entropyLen + dataLen, outKey, outKeyLen);
			LocalFree(tmp);
		}
	}
	return status;
}


//dpapi decrypt masterkey
void kuhl_m_dpapi_display_MasterkeyInfosAndFree(PVOID data, DWORD dataLen)
{
	wprintf(L"  key : ");
	string_wprintf_hex(data, dataLen, 0);
	wprintf(L"\n");

	LocalFree(data);
}

BOOL kull_m_dpapi_unprotect_domainkey_with_key(PKULL_M_DPAPI_MASTERKEY_DOMAINKEY domainkey, LPCVOID key, DWORD keyLen, PVOID* output, DWORD* outputLen, PSID* sid)
{
	BOOL status = FALSE;
	HCRYPTPROV hProv, hSessionProv;
	HCRYPTKEY hKey, hSessionKey;
	PKULL_M_DPAPI_DOMAIN_RSA_MASTER_KEY rsa_buffer;
	PKULL_M_DPAPI_DOMAIN_ACCESS_CHECK des_buffer;
	BYTE digest[SHA_DIGEST_LENGTH];
	DWORD cbOutput;
	PSID pSid;

	if (CryptAcquireContext(&hProv, NULL, NULL, PROV_RSA_AES, CRYPT_VERIFYCONTEXT))
	{
		if (CryptImportKey(hProv, (PBYTE)key, keyLen, 0, 0, &hKey))
		{
			cbOutput = domainkey->dwSecretLen;
			if (rsa_buffer = (PKULL_M_DPAPI_DOMAIN_RSA_MASTER_KEY) LocalAlloc(LPTR, cbOutput))
			{
				RtlCopyMemory(rsa_buffer, domainkey->pbSecret, cbOutput);
				if (CryptDecrypt(hKey, 0, TRUE, 0, (PBYTE)rsa_buffer, &cbOutput))
				{
					if (kull_m_crypto_hkey(hProv, CALG_3DES, rsa_buffer->buffer + rsa_buffer->cbMasterKey, 192 / 8, 0, &hSessionKey, &hSessionProv))
					{
						if (CryptSetKeyParam(hSessionKey, KP_IV, rsa_buffer->buffer + rsa_buffer->cbMasterKey + 192 / 8, 0))
						{
							cbOutput = domainkey->dwAccesscheckLen;
							if (des_buffer = (PKULL_M_DPAPI_DOMAIN_ACCESS_CHECK) LocalAlloc(LPTR, cbOutput))
							{
								RtlCopyMemory(des_buffer, domainkey->pbAccesscheck, cbOutput);
								if (CryptDecrypt(hSessionKey, 0, FALSE, 0, (PBYTE)des_buffer, &cbOutput))
								{
									pSid = (PSID)(des_buffer->data + des_buffer->dataLen);
									if (kull_m_crypto_hash(CALG_SHA1, des_buffer, cbOutput - SHA_DIGEST_LENGTH, digest, SHA_DIGEST_LENGTH))
									{
										if (RtlEqualMemory((PBYTE)des_buffer + cbOutput - SHA_DIGEST_LENGTH, digest, SHA_DIGEST_LENGTH))
										{
											*outputLen = rsa_buffer->cbMasterKey;
											if (*output = LocalAlloc(LPTR, *outputLen))
											{
												RtlCopyMemory(*output, rsa_buffer->buffer, *outputLen);
												status = TRUE;
												*sid = NULL;
												if (sid)
												{
													status = FALSE;
													cbOutput = GetLengthSid(pSid);
													if (*sid = (PSID)LocalAlloc(LPTR, cbOutput))
														status = CopySid(cbOutput, *sid, pSid);
												}

												if (!status)
												{
													if (*output)
														*output = LocalFree(*output);
													if (*sid)
														*sid = LocalFree(*sid);
													*outputLen = 0;
												}
											}
										}
									}
								}

								LocalFree(des_buffer);
							}
						}

						CryptDestroyKey(hSessionKey);
						kull_m_crypto_close_hprov_delete_container(hSessionProv);
					}
				}
				LocalFree(rsa_buffer);
			}
			CryptDestroyKey(hKey);
		}
		CryptReleaseContext(hProv, 0);
	}
	return status;
}

PKULL_M_DPAPI_MASTERKEY_DOMAINKEY kull_m_dpapi_masterkeys_domainkey_create(LPCVOID data, DWORD64 size)
{
	PKULL_M_DPAPI_MASTERKEY_DOMAINKEY domainkey = NULL;
	if (data && (domainkey = (PKULL_M_DPAPI_MASTERKEY_DOMAINKEY)LocalAlloc(LPTR, sizeof(KULL_M_DPAPI_MASTERKEY_DOMAINKEY))))
	{
		RtlCopyMemory(domainkey, data, FIELD_OFFSET(KULL_M_DPAPI_MASTERKEY_DOMAINKEY, pbSecret));
		domainkey->pbSecret = (PBYTE)data + FIELD_OFFSET(KULL_M_DPAPI_MASTERKEY_DOMAINKEY, pbSecret);
		domainkey->pbAccesscheck = (PBYTE)data + FIELD_OFFSET(KULL_M_DPAPI_MASTERKEY_DOMAINKEY, pbSecret) + domainkey->dwSecretLen;
		kull_m_dpapi_ptr_replace(&domainkey->pbSecret, domainkey->dwSecretLen);
		kull_m_dpapi_ptr_replace(&domainkey->pbAccesscheck, domainkey->dwAccesscheckLen);
	}
	return domainkey;
}

PKULL_M_DPAPI_MASTERKEYS kull_m_dpapi_masterkeys_create(LPCVOID data/*, DWORD size*/)
{
	PKULL_M_DPAPI_MASTERKEYS masterkeys = NULL;
	if (data && (masterkeys = (PKULL_M_DPAPI_MASTERKEYS)LocalAlloc(LPTR, sizeof(KULL_M_DPAPI_MASTERKEYS))))
	{
		RtlCopyMemory(masterkeys, data, FIELD_OFFSET(KULL_M_DPAPI_MASTERKEYS, MasterKey));
		if (masterkeys->dwDomainKeyLen)
			masterkeys->DomainKey = kull_m_dpapi_masterkeys_domainkey_create((PBYTE)data + FIELD_OFFSET(KULL_M_DPAPI_MASTERKEYS, MasterKey) + masterkeys->dwMasterKeyLen + masterkeys->dwBackupKeyLen + masterkeys->dwCredHistLen, masterkeys->dwDomainKeyLen);
	}
	return masterkeys;
}

BOOL kull_m_file_readGeneric(LPCSTR fileName, PBYTE* data, PDWORD length, DWORD flags)
{
	BOOL reussite = FALSE;
	DWORD dwBytesReaded;
	LARGE_INTEGER filesize;
	HANDLE hFile = NULL;

	if ((hFile = CreateFileA(fileName, GENERIC_READ, FILE_SHARE_READ | FILE_SHARE_WRITE, NULL, OPEN_EXISTING, flags, NULL)) && hFile != INVALID_HANDLE_VALUE)
	{
		if (GetFileSizeEx(hFile, &filesize) && !filesize.HighPart)
		{
			*length = filesize.LowPart;
			if (*data = (PBYTE)LocalAlloc(LPTR, *length))
			{
				if (!(reussite = ReadFile(hFile, *data, *length, &dwBytesReaded, NULL) && (*length == dwBytesReaded)))
					LocalFree(*data);
			}
		}
		CloseHandle(hFile);
	}
	return reussite;
}

char* kuhl_m_dpapi_masterkey(const char* szIn, DWORD* output_len)
{
	PKULL_M_DPAPI_MASTERKEYS masterkeys;
	PBYTE buffer, pHash = NULL, pSystem = NULL;
	PVOID output = NULL, derivedKey;
	PPVK_FILE_HDR pvkBuffer;
	DWORD szBuffer, szPvkBuffer, cbHash = 0, cbSystem = 0, cbSystemOffset = 0, cbOutput = 0;
	//PPOLICY_DNS_DOMAIN_INFO pPolicyDnsDomainInfo = NULL;
	//LPCWSTR szSid = NULL, szPassword = NULL, szHash = NULL, szSystem = NULL, szDomain = NULL, szDc = NULL;
	//LPWSTR convertedSid = NULL, szTmpDc = NULL;
	PSID pSid;
	//UNICODE_STRING uGuid;
	//GUID guid;
	//BOOL isProtected = FALSE, statusGuid = FALSE;

	if (szIn) {
		if (kull_m_file_readGeneric(szIn, &buffer, &szBuffer, 0)) {
			if (masterkeys = kull_m_dpapi_masterkeys_create(buffer)) {
				if (masterkeys->DomainKey && masterkeys->dwDomainKeyLen) {
						//printf("\n");
						//if (kull_m_file_readGeneric(szDomainpvk, (PBYTE*)&pvkBuffer, &szPvkBuffer, 0)) {
						if (pvkBuffer = (PPVK_FILE_HDR) domain_pvk_buf) {
							szPvkBuffer = domain_pvk_size;
							if (kull_m_dpapi_unprotect_domainkey_with_key(masterkeys->DomainKey, (PBYTE)pvkBuffer + sizeof(PVK_FILE_HDR), pvkBuffer->cbPvk, &output, &cbOutput, &pSid)) {
								*output_len = cbOutput;
								//kuhl_m_dpapi_oe_domainkey_add(&masterkeys->DomainKey->guidMasterKey, (PBYTE)pvkBuffer + sizeof(PVK_FILE_HDR), pvkBuffer->cbPvk, TRUE);
								//kuhl_m_dpapi_display_MasterkeyInfosAndFree( output, cbOutput);
							}
							//LocalFree(pvkBuffer);
						}
				}

				if (pHash)
					LocalFree(pHash);
				if (pSystem)
					LocalFree(pSystem);
				if (masterkeys) {
					if (masterkeys->DomainKey) {
						if (masterkeys->DomainKey->pbSecret)
							LocalFree(masterkeys->DomainKey->pbSecret);
						if (masterkeys->DomainKey->pbAccesscheck)
							LocalFree(masterkeys->DomainKey->pbAccesscheck);

						LocalFree(masterkeys->DomainKey);
					}
					LocalFree(masterkeys);
				}
			}
			LocalFree(buffer);
		}
	}

	return (char*) output;
}