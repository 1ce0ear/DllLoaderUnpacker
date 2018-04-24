#include <windows.h>
#include <stdbool.h>
#include <assert.h>
#include <io.h>
#include <stdio.h>
#include "../Logger/Include/logger.h"
#include "Include/DllInjector.h"
#include "Include/TLS.h"

static DWORD GetTLSCallbacksNum(ULONG *TLSCallback) {
	DWORD i = 0;
	while (1) {
		if (TLSCallback[i]) {
			WriteLog(__FILEW__, __LINE__, L"TLSCallback = %p", TLSCallback[i]);
			i++;
		}
		else {
			break;
		}
	}

	return i;
}

static ULONG GetRawFromVA(IMAGE_SECTION_HEADER *ImageSectionHeaderStart,
	int NumSections, ULONG VA, ULONG VABase) {
	WriteLog(__FILEW__, __LINE__, L"ImageSectionHeaderStart = %p, "
		L"NumSection = %d", ImageSectionHeaderStart, NumSections);

	ULONG RVA = VA - VABase;
	IMAGE_SECTION_HEADER *CurrImageSectionHeader = ImageSectionHeaderStart;
	IMAGE_SECTION_HEADER *NextImageSectionHeader = CurrImageSectionHeader + 1;
	ULONG Raw;
	int i;

	for (i = 0; i < NumSections - 1; i++) {
		if (CurrImageSectionHeader->VirtualAddress <= RVA &&
			NextImageSectionHeader->VirtualAddress > RVA) {
			WriteLog(__FILEW__, __LINE__, L"In section %d", i);
			break;
		}

		CurrImageSectionHeader++;
		NextImageSectionHeader++;
	}

	Raw = CurrImageSectionHeader->PointerToRawData
		+ RVA - CurrImageSectionHeader->VirtualAddress;

	WriteLog(__FILEW__, __LINE__, L"Raw = %d", Raw);
	return Raw;
}

static BOOLEAN DumpPatchedTLSExe(char *FileName, __int64 FileSize,
	char *BaseAddr) {
	HANDLE hFile = CreateFileA(FileName, GENERIC_READ | GENERIC_WRITE,
		FILE_SHARE_WRITE, NULL, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
	if (hFile == INVALID_HANDLE_VALUE) {
		WriteLog(__FILEW__, __LINE__, L"Fail to call CreateFile");
		return FALSE;
	}

	DWORD BytesWritten;
	if (!WriteFile(hFile, BaseAddr, FileSize, &BytesWritten, NULL) ||
		BytesWritten != FileSize) {
		CloseHandle(hFile);
		WriteLog(__FILEW__, __LINE__, L"Fail to call WriteFile");
		return FALSE;
	}

	CloseHandle(hFile);

	return TRUE;
}

static BOOLEAN WriteConfigForDll(struct InjectorCommunication_s *Comm) {
	HANDLE hFile;
	DWORD dwBytesWritten;

	hFile = CreateFileA(DLL_CONFIG, FILE_ALL_ACCESS, 0,
		NULL, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, 0);

	if (hFile == INVALID_HANDLE_VALUE) {
		WriteLog(__FILEW__, __LINE__, L"Fail to call CreateFile.");
		return false;
	}

	/* Write dwNumTLSCallbacks first. */
	if (!WriteFile(hFile, &Comm->dwNumTLSCallbacks, sizeof(DWORD),
		&dwBytesWritten, NULL) || dwBytesWritten != sizeof(DWORD)) {
		CloseHandle(hFile);
		return false;
	}

	/* Write TLSCallback addresses. */
	if (!WriteFile(hFile, Comm->TLSCallbacks,
		sizeof(DWORD) * Comm->dwNumTLSCallbacks, &dwBytesWritten, NULL) ||
		dwBytesWritten != sizeof(DWORD) * Comm->dwNumTLSCallbacks) {
		CloseHandle(hFile);
		return false;
	}

	CloseHandle(hFile);

	return true;
}

BOOLEAN CheckTLS(char *PEFileName, struct InjectorCommunication_s *Comm) {
	HANDLE hFile;
	HANDLE hFileMapping;
	LPVOID lpFileBase;
	PIMAGE_DOS_HEADER dosHeader;
	BOOLEAN bIsTLSExist = false;

	hFile = CreateFileA(PEFileName, FILE_READ_ACCESS | FILE_WRITE_ACCESS, 0,
		NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, 0);

	if (hFile == INVALID_HANDLE_VALUE) {
		WriteLog(__FILEW__, __LINE__, L"Fail to call CreateFile.");
		return bIsTLSExist;
	}

	LARGE_INTEGER FileSize;
	/* Get file size. */
	if (!GetFileSizeEx(hFile, &FileSize)) {
		CloseHandle(hFile);
		return bIsTLSExist;
	}

	hFileMapping = CreateFileMappingA(hFile, NULL, PAGE_READWRITE, 0, 0, NULL);
	if (hFileMapping == 0) {
		CloseHandle(hFile);
		WriteLog(__FILEW__, __LINE__, L"Fail to call CreateFileMapping."
			L" Error = %d", GetLastError());
		return bIsTLSExist;
	}

	lpFileBase = MapViewOfFile(hFileMapping, FILE_MAP_ALL_ACCESS, 0, 0, 0);
	if (lpFileBase == 0) {
		CloseHandle(hFileMapping);
		CloseHandle(hFile);
		WriteLog(__FILEW__, __LINE__, L"Fail to call MapViewOfFile.");
		return bIsTLSExist;
	}

	IMAGE_DOS_HEADER *DOSHeader = (PIMAGE_DOS_HEADER)lpFileBase;
	IMAGE_NT_HEADERS *NTHEADER = (IMAGE_NT_HEADERS *)((char *)lpFileBase +
		DOSHeader->e_lfanew);
	IMAGE_FILE_HEADER *FileHeader = (IMAGE_FILE_HEADER *)((char *)NTHEADER +
		offsetof(IMAGE_NT_HEADERS, FileHeader));

	/* Get TLS Data Directory. */
	IMAGE_OPTIONAL_HEADER *OptionalHeader = (IMAGE_OPTIONAL_HEADER *)((char *)
		NTHEADER + sizeof(IMAGE_FILE_HEADER) +
		offsetof(IMAGE_NT_HEADERS, FileHeader));

	IMAGE_DATA_DIRECTORY *DataDirectory = (IMAGE_DATA_DIRECTORY *)((char *)
		OptionalHeader + sizeof(IMAGE_OPTIONAL_HEADER) -
		sizeof(IMAGE_DATA_DIRECTORY) * IMAGE_NUMBEROF_DIRECTORY_ENTRIES);

	IMAGE_DATA_DIRECTORY *TLSDataDirectory =
		&DataDirectory[IMAGE_DIRECTORY_ENTRY_TLS];

	if (TLSDataDirectory->VirtualAddress == 0) {
		WriteLog(__FILEW__, __LINE__, L"No TLS Callback.");
		goto Cleanup;
	}

	/* Get IMAGE_TLS_DIRECTORY32. */
	IMAGE_TLS_DIRECTORY32 *ImageTLSDirectory = (IMAGE_TLS_DIRECTORY32 *)(
		(char *)lpFileBase + TLSDataDirectory->VirtualAddress);

	WriteLog(__FILEW__, __LINE__, L"Attempt to get #TLS");

	/* Translate VA to Raw. */
	IMAGE_SECTION_HEADER *ImageSectionHeaderStart = (IMAGE_SECTION_HEADER *)(
		(char *)OptionalHeader + sizeof(IMAGE_OPTIONAL_HEADER));
	IMAGE_TLS_DIRECTORY *TLSDirectoryRaw = (IMAGE_TLS_DIRECTORY *)GetRawFromVA(
		ImageSectionHeaderStart,
		FileHeader->NumberOfSections, (ULONG)ImageTLSDirectory,
		(ULONG)lpFileBase);
	
	TLSDirectoryRaw = (char *)TLSDirectoryRaw + (ULONG)lpFileBase;

	ULONG *TLSCallback = (ULONG *)GetRawFromVA(
		ImageSectionHeaderStart,
		FileHeader->NumberOfSections,
		TLSDirectoryRaw->AddressOfCallBacks + (ULONG)lpFileBase -
		OptionalHeader->ImageBase,
		(ULONG)lpFileBase);
	
	TLSCallback = (char *)TLSCallback + (ULONG)lpFileBase;

	WriteLog(__FILEW__, __LINE__, L"TLSDirectoryRaw->AddressOfCallBacks = %p",
		TLSDirectoryRaw->AddressOfCallBacks);

	/* Get the number of TLS Callback. */
	Comm->dwNumTLSCallbacks = GetTLSCallbacksNum(TLSCallback);

	DWORD NumCallBacks = Comm->dwNumTLSCallbacks;

	/* Address of array of callback function pointers. */
	WriteLog(__FILEW__, __LINE__, L"There are %d TLS Callbacks.",
		NumCallBacks);

	Comm->TLSCallbacks = malloc(NumCallBacks * sizeof(void *));

	if (!Comm->TLSCallbacks) {
		WriteLog(__FILEW__, __LINE__, L"Malloc failed!");
		goto Cleanup;
	}

	/* Save callback address to struct. */
	for (int i = 0; i < NumCallBacks; i++) {
		Comm->TLSCallbacks[i] = TLSCallback[i];
	};

	/* Clear up DataDirectory. */
	TLSDataDirectory->VirtualAddress = TLSDataDirectory->Size = 0;

	/* Write TLS Callbacks to file. */
	if (!WriteConfigForDll(Comm)) {
		WriteLog(__FILEW__, __LINE__, L"Fail to write config for dll.");
		goto Cleanup;
	}

	/* Dump new PE File. */
	if (DumpPatchedTLSExe(TLS_PATCHED_EXE_NAME, FileSize.QuadPart,
		lpFileBase)) {
		bIsTLSExist = TRUE;
	}

Cleanup:
	UnmapViewOfFile(lpFileBase);
	CloseHandle(hFileMapping);
	CloseHandle(hFile);
	if (Comm->TLSCallbacks) {
		free(Comm->TLSCallbacks);
	}

	return bIsTLSExist;
}