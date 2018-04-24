#include <windows.h>
#include <stdio.h>
#include <process.h>
#include <tlhelp32.h> 
#include "../Logger/Include/logger.h"
#include "Include/ApiHook.h"
#include "Include/Forensics.h"
#include <wincrypt.h>
#include <excpt.h>

/*F+F+++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++
Function: CheckModuleRange.

Summary:  Check if address belongs to any module. For dll loader, the base
		  address of the new image should not belong to any modules.

Returns:  bool.
-----------------------------------------------------------------F-F*/
static bool CheckModuleRange(ULONG addr) {
	HANDLE hModuleSnap = INVALID_HANDLE_VALUE;
	MODULEENTRY32 me32;
	ULONG ExeBaseAddr = GetModuleHandle(NULL);

	if (addr == ExeBaseAddr) {
		return FALSE;
	}

	/* Take a snapshot of all modules in the specified process. */
	hModuleSnap = CreateToolhelp32Snapshot(TH32CS_SNAPMODULE,
		GetCurrentProcessId());
	if (hModuleSnap == INVALID_HANDLE_VALUE) {
		WriteLog(__FILEW__, __LINE__, L"CreateToolhelp32Snapshot failed.");
		return TRUE;
	}

	/* Set the size of the structure before using it. */
	me32.dwSize = sizeof(MODULEENTRY32);

	/* Retrieve information about the first module and exit if unsuccessful. */
	if (!Module32First(hModuleSnap, &me32)) {
		CloseHandle(hModuleSnap);
		WriteLog(__FILEW__, __LINE__, L"Module32First failed.");
		return TRUE;
	}

	do {
		if (me32.modBaseAddr == ExeBaseAddr) {
			continue;
		}

		if (addr >= me32.modBaseAddr &&
			addr <= me32.modBaseAddr + me32.modBaseSize) {
			return FALSE;
		}
	} while (Module32Next(hModuleSnap, &me32));

	/* Do not forget to clean up the snapshot object. */
	CloseHandle(hModuleSnap);
	return TRUE;
}

/*F+F+++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++
Function: ProbeForReadMem.

Summary:  Check address validity.

Returns:  bool.
-----------------------------------------------------------------F-F*/
static bool ProbeForReadMem(HANDLE hProcess, unsigned char *uAddr,
	DWORD dwSize) {
	DWORD BytesRead;

	/* TODO: Consider a better way to check memory validity in user mode. */
	char *Buffer = malloc(dwSize);
	
	if (!Buffer) {
		return FALSE;
	}

	if (!ReadProcessMemory(hProcess, uAddr, Buffer, dwSize, &BytesRead) ||
		BytesRead != dwSize) {
		free(Buffer);
		return FALSE;
	}

	free(Buffer);
	return TRUE;
}

/*F+F+++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++
Function: PrintPECharacteristic.

Summary:  Print PE Characteristic for log.

Returns:  void.
-----------------------------------------------------------------F-F*/
static void PrintPECharacteristic(WORD Character) {
	if (Character & IMAGE_FILE_RELOCS_STRIPPED) {
		WriteLog(__FILEW__, __LINE__, L"PE Type: IMAGE_FILE_RELOCS_STRIPPED");
	}

	if (Character & IMAGE_FILE_EXECUTABLE_IMAGE) {
		WriteLog(__FILEW__, __LINE__, L"PE Type: IMAGE_FILE_EXECUTABLE_IMAGE");
	}

	if (Character & IMAGE_FILE_32BIT_MACHINE) {
		WriteLog(__FILEW__, __LINE__, L"PE Type: IMAGE_FILE_32BIT_MACHINE");
	}

	if (Character & IMAGE_FILE_DEBUG_STRIPPED) {
		WriteLog(__FILEW__, __LINE__, L"PE Type: IMAGE_FILE_DEBUG_STRIPPED");
	}

	if (Character & IMAGE_FILE_SYSTEM) {
		WriteLog(__FILEW__, __LINE__, L"PE Type: IMAGE_FILE_SYSTEM");
	}

	if (Character & IMAGE_FILE_DLL) {
		WriteLog(__FILEW__, __LINE__, L"PE Type: IMAGE_FILE_DLL");
	}
}

/*F+F+++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++
Function: CheckDuplicateDump.

Summary:  Check whether we have dump the same image before by hash value.

Returns:  bool.
-----------------------------------------------------------------F-F*/
static bool CheckDuplicateDump(BYTE *hash) {
	bool bIsFound = false;

	struct DumpHashList *CurrentDumpHashList = DumpHashListHeader.next;

	while (CurrentDumpHashList) {
		if (!memcmp(hash, CurrentDumpHashList, 256)) {
			bIsFound = TRUE;
			break;
		}
		CurrentDumpHashList = CurrentDumpHashList->next;
	}

	if (!bIsFound) {
		/* Insert to front. */
		struct DumpHashList *NewDumpHashList = malloc(
			sizeof(struct DumpHashList));
		if (!NewDumpHashList) {
			WriteLog(__FILEW__, __LINE__, L"PE Dump: malloc failed.");
			return FALSE;
		}
		memcpy(NewDumpHashList->hash, hash, 256);

		NewDumpHashList->next = DumpHashListHeader.next;
		DumpHashListHeader.next = NewDumpHashList;
	}

	return bIsFound;
}

/*F+F+++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++
Function: DumpRawFile.

Summary:  Dump raw file by base address and size of image.

Returns:  void.
-----------------------------------------------------------------F-F*/
static HANDLE DumpRawFile(HANDLE hProcess, unsigned char *uAddr,
	DWORD SizeOfImage, char *DumpName) {

	BYTE *Buffer = malloc(SizeOfImage);
	BYTE DumpHash[256];
	DWORD BytesRead;

	if (!Buffer) {
		WriteLog(__FILEW__, __LINE__, L"PE Dump: malloc failed.");
		return INVALID_HANDLE_VALUE;
	}

	/* Get PE image. */
	if (!ReadProcessMemory(hProcess, uAddr, Buffer, SizeOfImage, &BytesRead) ||
		BytesRead != SizeOfImage) {
		WriteLog(__FILEW__, __LINE__, L"PE Dump: ReadProcessMemory failed.");
	}

	WriteLog(__FILEW__, __LINE__, L"PE Dump: PE image is read.");
	AcquireSha256Hash(Buffer, DumpHash);
	WriteLog(__FILEW__, __LINE__, L"PE Dump: Get Dump hash.");

	/* Check duplicate dump. */
	if (CheckDuplicateDump(DumpHash)) {
		WriteLog(__FILEW__, __LINE__, L"PE Dump: Duplicate Dump!");
		free(Buffer);
		return INVALID_HANDLE_VALUE;
	}

	WriteLog(__FILEW__, __LINE__, L"PE Dump: No duplicate dump.");

	/* Write raw dump file. */
	HANDLE hFile = CreateFileA(DumpName, GENERIC_READ | GENERIC_WRITE,
		FILE_SHARE_WRITE, NULL, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
	if (hFile == INVALID_HANDLE_VALUE) {
		WriteLog(__FILEW__, __LINE__, L"PE Dump: Fail to call CreateFile");
		free(Buffer);
		return INVALID_HANDLE_VALUE;
	}

	DWORD BytesWritten;

	if (!WriteFile(hFile, uAddr, SizeOfImage, &BytesWritten, NULL) ||
		BytesWritten != SizeOfImage) {
		CloseHandle(hFile);
		WriteLog(__FILEW__, __LINE__, L"PE Dump: Fail to call WriteFile");
		free(Buffer);
		return INVALID_HANDLE_VALUE;
	}

	WriteLog(__FILEW__, __LINE__, L"PE Dump: Raw file is dumped!");
	free(Buffer);

	return hFile;
}

/*F+F+++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++
Function: GetDumpName.

Summary:  Generate dump name.

Returns:  void.
-----------------------------------------------------------------F-F*/
static void GetDumpName(char *DumpName, DWORD len, IMAGE_NT_HEADERS *NtHeader) {
	char *prefix = NULL;
	if (NtHeader->FileHeader.Characteristics & IMAGE_FILE_DLL) {
		prefix = "dll";
	} else if (NtHeader->FileHeader.Characteristics & IMAGE_FILE_SYSTEM) {
		prefix = "sys";
	} else {
		prefix = "exe";
	}

	snprintf(DumpName, len, "Dump%d-%d.%s",
		NtHeader->FileHeader.Characteristics & IMAGE_FILE_32BIT_MACHINE ?
		32 : 64, NumDump, prefix);

	NumDump++;
}

/*F+F+++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++
Function: FixHeaders.

Summary:  Fix sections, image base, relocations.

Returns:  bool.
-----------------------------------------------------------------F-F*/
static bool FixHeaders(BYTE *uAddr, HANDLE hFile) {
	IMAGE_DOS_HEADER DosHeader;
	DWORD NumberOfBytesRead, NumberOfBytesWritten;

	/* Set file pointer to zero. */
	if (SetFilePointer(hFile, 0, NULL, FILE_BEGIN) ==
		INVALID_SET_FILE_POINTER) {
		WriteLog(__FILEW__, __LINE__, L"SetFilePointer failed.");
		return FALSE;
	}

	/* Read DOSHeader. */
	if (!ReadFile(hFile, (LPVOID)&DosHeader, sizeof(IMAGE_DOS_HEADER),
		&NumberOfBytesRead, NULL) ||
		NumberOfBytesRead != sizeof(IMAGE_DOS_HEADER)) {
		WriteLog(__FILEW__, __LINE__, L"ReadFile failed.");
		return FALSE;
	}

	/* sizeof(DWORD): Signature. */
	if (SetFilePointer(hFile, DosHeader.e_lfanew + sizeof(DWORD), NULL,
		FILE_BEGIN) == INVALID_SET_FILE_POINTER) {
		WriteLog(__FILEW__, __LINE__, L"ReadFile failed.");
		return FALSE;
	}

	/* Read NTHeader. */
	IMAGE_FILE_HEADER FileHeader;
	if (!ReadFile(hFile, (LPVOID)&FileHeader, sizeof(IMAGE_FILE_HEADER),
		&NumberOfBytesRead, NULL) ||
		NumberOfBytesRead != sizeof(IMAGE_FILE_HEADER)) {
		WriteLog(__FILEW__, __LINE__, L"ReadFile failed.");
		return FALSE;
	}

	WORD NumSections = FileHeader.NumberOfSections;

	IMAGE_SECTION_HEADER *ImageSectionHeader = (IMAGE_SECTION_HEADER *)calloc(
		NumSections, sizeof(IMAGE_SECTION_HEADER));
	if (!ImageSectionHeader) {
		WriteLog(__FILEW__, __LINE__, L"Calloc failed.");
		return FALSE;
	}

	/* Set file pointer to first IMAGE_SECTION_HEADER. */
	if (SetFilePointer(hFile, DosHeader.e_lfanew + sizeof(IMAGE_NT_HEADERS),
		NULL, FILE_BEGIN) == INVALID_SET_FILE_POINTER) {
		WriteLog(__FILEW__, __LINE__, L"SetFilePointer failed.");
		free(ImageSectionHeader);
		return FALSE;
	}

	/* Read all sections. */
	if (!ReadFile(hFile, (LPVOID)ImageSectionHeader,
		sizeof(IMAGE_SECTION_HEADER) * NumSections, &NumberOfBytesRead, NULL) ||
		NumberOfBytesRead != sizeof(IMAGE_SECTION_HEADER) * NumSections) {
		WriteLog(__FILEW__, __LINE__, L"ReadFile failed.");
		free(ImageSectionHeader);
		return FALSE;
	}

	/* Reset file pointer to first IMAGE_SECTION_HEADER. */
	if (SetFilePointer(hFile, DosHeader.e_lfanew + sizeof(IMAGE_NT_HEADERS),
		NULL, FILE_BEGIN) == INVALID_SET_FILE_POINTER) {
		WriteLog(__FILEW__, __LINE__, L"SetFilePointer failed.");
		free(ImageSectionHeader);
		return FALSE;
	}

	IMAGE_SECTION_HEADER *CurrImageSection = ImageSectionHeader;

	/* Fix sections. */
	for (WORD i = 0; i < NumSections; i++) {
		/* Since dumped PE is aligned with PAGE_SIZE, Raw offset & size should
		* be replaced.
		*/
		CurrImageSection->SizeOfRawData = CurrImageSection->Misc.VirtualSize;
		CurrImageSection->PointerToRawData = CurrImageSection->VirtualAddress;

		/* Write back. */
		if (!WriteFile(hFile, (LPVOID)CurrImageSection,
			sizeof(IMAGE_SECTION_HEADER), &NumberOfBytesWritten, NULL) ||
			NumberOfBytesWritten != sizeof(IMAGE_SECTION_HEADER)) {
			WriteLog(__FILEW__, __LINE__, L"WriteFile failed.");
			free(ImageSectionHeader);
			return FALSE;
		}

		CurrImageSection++;
	}

	free(ImageSectionHeader);

	/* Set pointer to optional header. */
	IMAGE_OPTIONAL_HEADER OptionalHeader;
	if (SetFilePointer(hFile,
		DosHeader.e_lfanew + sizeof(DWORD) + sizeof(IMAGE_FILE_HEADER), NULL,
		FILE_BEGIN) == INVALID_SET_FILE_POINTER) {
		WriteLog(__FILEW__, __LINE__, L"ReadFile failed.");
		return FALSE;
	}

	/* Read IMAGE_OPTIONAL_HEADER sections. */
	if (!ReadFile(hFile, (LPVOID)&OptionalHeader,
		sizeof(IMAGE_OPTIONAL_HEADER), &NumberOfBytesRead, NULL) ||
		NumberOfBytesRead != sizeof(IMAGE_OPTIONAL_HEADER)) {
		WriteLog(__FILEW__, __LINE__, L"ReadFile failed.");
		return FALSE;
	}

	/* Modify ImageBase to fix relocations.*/
	OptionalHeader.ImageBase = (DWORD)uAddr;
	OptionalHeader.FileAlignment = PAGE_SIZE;

	/* Set pointer to optional header. */
	if (SetFilePointer(hFile,
		DosHeader.e_lfanew + sizeof(DWORD) + sizeof(IMAGE_FILE_HEADER), NULL,
		FILE_BEGIN) == INVALID_SET_FILE_POINTER) {
		WriteLog(__FILEW__, __LINE__, L"ReadFile failed.");
		return FALSE;
	}

	/* Write back. */
	if (!WriteFile(hFile, (LPVOID)&OptionalHeader,
		sizeof(IMAGE_OPTIONAL_HEADER), &NumberOfBytesWritten, NULL) ||
		NumberOfBytesWritten != sizeof(IMAGE_OPTIONAL_HEADER)) {
		WriteLog(__FILEW__, __LINE__, L"WriteFile failed.");
		free(ImageSectionHeader);
		return FALSE;
	}

	return TRUE;
}

/*F+F+++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++
Function: FixRawFile.

Summary:  Fix sections, image base, relocations by FixHeaders. Then FixRawFile
		  fixes IAT.

Returns:  bool.
-----------------------------------------------------------------F-F*/
static bool FixRawFile(BYTE *uAddr, HANDLE hFile) {

	/* Fix sections, image base. */
	if (!FixHeaders(uAddr, hFile)) {
		return FALSE;
	}
	
	/* Fix IAT. */
	IMAGE_DOS_HEADER DosHeader;
	DWORD NumberOfBytesRead, NumberOfBytesWritten;

	/* Set file pointer to zero. */
	if (SetFilePointer(hFile, 0, NULL, FILE_BEGIN) ==
		INVALID_SET_FILE_POINTER) {
		WriteLog(__FILEW__, __LINE__, L"SetFilePointer failed.");
		return FALSE;
	}

	/* Read DOSHeader. */
	if (!ReadFile(hFile, (LPVOID)&DosHeader, sizeof(IMAGE_DOS_HEADER),
		&NumberOfBytesRead, NULL) ||
		NumberOfBytesRead != sizeof(IMAGE_DOS_HEADER)) {
		WriteLog(__FILEW__, __LINE__, L"ReadFile failed.");
		return FALSE;
	}

	/* Set pointer to optional header. */
	IMAGE_OPTIONAL_HEADER OptionalHeader;
	if (SetFilePointer(hFile,
		DosHeader.e_lfanew + sizeof(DWORD) + sizeof(IMAGE_FILE_HEADER), NULL,
		FILE_BEGIN) == INVALID_SET_FILE_POINTER) {
		WriteLog(__FILEW__, __LINE__, L"SetFilePointer failed.");
		return FALSE;
	}

	/* Read IMAGE_OPTIONAL_HEADER sections. */
	if (!ReadFile(hFile, (LPVOID)&OptionalHeader,
		sizeof(IMAGE_OPTIONAL_HEADER), &NumberOfBytesRead, NULL) ||
		NumberOfBytesRead != sizeof(IMAGE_OPTIONAL_HEADER)) {
		WriteLog(__FILEW__, __LINE__, L"ReadFile failed.");
		return FALSE;
	}

	IMAGE_IMPORT_DESCRIPTOR *StartImageImportDescriptor =
		OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].
		VirtualAddress;

	WriteLog(__FILEW__, __LINE__, L"IMAGE_IMPORT_DESCRIPTOR = %p",
		StartImageImportDescriptor);

	/* Set pointer to first IMAGE_IMPORT_DESCRIPTOR. */
	if (SetFilePointer(hFile, (ULONG)StartImageImportDescriptor, NULL,
		FILE_BEGIN) == INVALID_SET_FILE_POINTER) {
		WriteLog(__FILEW__, __LINE__, L"SetFilePointer failed.");
		return FALSE;
	}

	/* Traverse all IMAGE_IMPORT_DESCRIPTOR. */
	IMAGE_IMPORT_DESCRIPTOR CurrImageImportDescriptor;

	while (1) {
		if (!ReadFile(hFile, (LPVOID)&CurrImageImportDescriptor,
			sizeof(IMAGE_IMPORT_DESCRIPTOR), &NumberOfBytesRead, NULL) ||
			NumberOfBytesRead != sizeof(IMAGE_IMPORT_DESCRIPTOR)) {
			WriteLog(__FILEW__, __LINE__, L"ReadFile failed.");
			return FALSE;
		}

		if (CurrImageImportDescriptor.Characteristics == 0 &&
			CurrImageImportDescriptor.FirstThunk == 0 &&
			CurrImageImportDescriptor.ForwarderChain == 0 &&
			CurrImageImportDescriptor.Name == 0 &&
			CurrImageImportDescriptor.OriginalFirstThunk == 0 &&
			CurrImageImportDescriptor.TimeDateStamp == 0) {
			WriteLog(__FILEW__, __LINE__, L"IAT Repair is end.");
			break;
		}

		DWORD CurrFilePointer = SetFilePointer(hFile, 0, 0, FILE_CURRENT);
		/* We have already read one IMAGE_IMPORT_DESCRIPTOR. */
		CurrFilePointer -= sizeof(IMAGE_IMPORT_DESCRIPTOR);

		/* Repair FirstThunk. */
		CurrImageImportDescriptor.FirstThunk =
			CurrImageImportDescriptor.OriginalFirstThunk;

		WriteLog(__FILEW__, __LINE__, L"OriginalFirstThunk = %x",
			CurrImageImportDescriptor.OriginalFirstThunk);

		/* Print DLL name. */

		/* Set file pointer to DLL name. */
		if (SetFilePointer(hFile, (LONG)CurrImageImportDescriptor.Name, NULL,
			FILE_BEGIN) == INVALID_SET_FILE_POINTER) {
			WriteLog(__FILEW__, __LINE__, L"SetFilePointer failed.");
			return FALSE;
		}

		char DllName[IMPORT_DLL_NAME_LEN + 1];
		if (!ReadFile(hFile, (LPVOID)DllName, IMPORT_DLL_NAME_LEN,
			&NumberOfBytesRead, NULL) ||
			NumberOfBytesRead == 0) {
			WriteLog(__FILEW__, __LINE__, L"ReadFile failed.");
			return FALSE;
		}

		DllName[IMPORT_DLL_NAME_LEN] = '\x00';
		WriteLog(__FILEW__, __LINE__, L"Repair IAT about %S", DllName);

		/* Set file pointer back. */
		if (SetFilePointer(hFile, (LONG)CurrFilePointer, NULL,
			FILE_BEGIN) == INVALID_SET_FILE_POINTER) {
			WriteLog(__FILEW__, __LINE__, L"SetFilePointer failed.");
			return FALSE;
		}

		/* Write back. */
		if (!WriteFile(hFile, (LPVOID)&CurrImageImportDescriptor,
			sizeof(IMAGE_IMPORT_DESCRIPTOR), &NumberOfBytesWritten, NULL) ||
			NumberOfBytesWritten != sizeof(IMAGE_IMPORT_DESCRIPTOR)) {
			WriteLog(__FILEW__, __LINE__, L"WriteFile failed.");
			return FALSE;
		}
	}

	return TRUE;
}

/*F+F+++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++
Function: filter.

Summary:  Filter SEH error code. If error code is EXCEPTION_ACCESS_VIOLATION,
          it's highly likely that malware is tricking us.

Returns:  int.
-----------------------------------------------------------------F-F*/
static int filter(unsigned int code, struct _EXCEPTION_POINTERS *ep) {
	if (code == EXCEPTION_ACCESS_VIOLATION) {
		return EXCEPTION_EXECUTE_HANDLER;
	} else {
		return EXCEPTION_CONTINUE_SEARCH;
	}
}

/*F+F+++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++
Function: DumpFile.

Summary:  If the signatures are valid, DumpFile dumps the raw image file and fix
		  the dump image.

Returns:  bool.
-----------------------------------------------------------------F-F*/
static bool DumpFile(HANDLE hProcess, unsigned char *uAddr) {
	IMAGE_DOS_HEADER *DosHeader = uAddr;
	IMAGE_NT_HEADERS32 *NtHeader;
	DWORD SizeOfImage;

	__try {
		/* Get NTHeader. */
		NtHeader = uAddr + DosHeader->e_lfanew;

		if (NtHeader->Signature != 0x4550) {
			WriteLog(__FILEW__, __LINE__, L"Bad NT Sig %x",
				NtHeader->Signature);
		}

		/* Check machine and characteristics. */
		if (NtHeader->FileHeader.Machine != IMAGE_FILE_MACHINE_I386) {
			/* TODO: Support PE32+. Return FALSE may not be a good option. */
			WriteLog(__FILEW__, __LINE__, L"Unsupported PE Type %d",
				NtHeader->FileHeader.Machine);
		}

		/* Print PE Characteristics for logging. */
		PrintPECharacteristic(NtHeader->FileHeader.Characteristics);

		IMAGE_OPTIONAL_HEADER32 *OptionalHeader = &NtHeader->OptionalHeader;

		/* Get PE format. */
		if (OptionalHeader->Magic == 0x10b) {
			WriteLog(__FILEW__, __LINE__, L"PE format: PE32.");
		}
		else if (OptionalHeader->Magic == 0x20b) {
			WriteLog(__FILEW__, __LINE__, L"PE format: PE32+. Not supported.");
			return FALSE;
		}
		else {
			WriteLog(__FILEW__, __LINE__, L"PE format: Unknown %x",
				OptionalHeader->Magic);
		}

		SizeOfImage = PAGE_ALIGN(OptionalHeader->SizeOfImage);
		DWORD RealSizeOfImage;
		WriteLog(__FILEW__, __LINE__, L"PE size: 0x%x", SizeOfImage);
		WriteLog(__FILEW__, __LINE__, L"Attempt to dump PE Image!");

		IMAGE_SECTION_HEADER *SectionHeaders = (IMAGE_SECTION_HEADER *)((char *)
			OptionalHeader + sizeof(OptionalHeader));

		IMAGE_SECTION_HEADER *LastSection = &SectionHeaders[
			NtHeader->FileHeader.NumberOfSections - 1];

		RealSizeOfImage = PAGE_ALIGN(LastSection->VirtualAddress +
			LastSection->Misc.VirtualSize);

		if (SizeOfImage != RealSizeOfImage && RealSizeOfImage > 0) {
			WriteLog(__FILEW__, __LINE__,
				L"Fix bad SizeOfImage. RealSizeOfImage = %x, SizeOfImage = %x",
				RealSizeOfImage, SizeOfImage);
			SizeOfImage = RealSizeOfImage;
		}

	} __except (filter(GetExceptionCode(), GetExceptionInformation())) {
		WriteLog(__FILEW__, __LINE__, L"Bad offset.");

		/* TODO: Fix possible bad offset. */
		return FALSE;
	}

	DisableHook();

	/* Get dump file name. */
	char DumpName[DUMP_FILE_NAME_LEN + 1];
	HANDLE hRawFile = INVALID_HANDLE_VALUE;
	GetDumpName(DumpName, DUMP_FILE_NAME_LEN, NtHeader);

	if (ProbeForReadMem(hProcess, uAddr, SizeOfImage)) {
		hRawFile = DumpRawFile(hProcess, uAddr, SizeOfImage, DumpName);
	}

	if (hRawFile == INVALID_HANDLE_VALUE) {
		WriteLog(__FILEW__, __LINE__, L"Dump failed / duplicate.");
	} else {
		WriteLog(__FILEW__, __LINE__, L"Dump is OK!");

		/* Fix dump file. */
		if (!FixRawFile(uAddr, hRawFile)) {
			WriteLog(__FILEW__, __LINE__, L"Fail to fix dump!");
		}
		else {
			WriteLog(__FILEW__, __LINE__, L"Dump %S is fixed!", DumpName);
		}
	}

	CloseHandle(hRawFile);

	EnableHook();

	return TRUE;
}

/*F+F+++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++
Function: SearchPEImage.

Summary:  Search new unpacked PE image by VirtualQueryEx and call DumpFile if
		  MZ signature is found.

Returns:  Void.
-----------------------------------------------------------------F-F*/
void SearchPEImage() {
	unsigned char* uAddr = 0;
	HANDLE hProcess = GetCurrentProcess();

	while (1)
	{
		MEMORY_BASIC_INFORMATION mbi = { 0 };
		if (VirtualQueryEx(hProcess, uAddr, &mbi,
			sizeof(MEMORY_BASIC_INFORMATION)) == 0) {
			break;
		}

		if ((mbi.State & MEM_COMMIT) && mbi.Protect != PAGE_GUARD) {
			/* Search PE signature. */
			char Sig[2];
			SIZE_T BytesRead;

			/* Even if page property is RW, we must check memory validity by
			 * ReadProcessMemory.
			 */
			if (ReadProcessMemory(hProcess, (void *)uAddr, Sig, 2, &BytesRead)
				&& BytesRead == 2) {
				/* Check MZ Signature. */
				if (Sig[0] == 'M' && Sig[1] == 'Z') {
					if (CheckModuleRange(uAddr)) {
						WriteLog(__FILEW__, __LINE__, L"Find PE image in %p",
							(PVOID)uAddr);
						DumpFile(hProcess, uAddr);
					}
				}
			}
		}

		uAddr = (unsigned char*)mbi.BaseAddress + mbi.RegionSize;
	}
}

/*F+F+++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++
Function: MemoryForensics.

Summary:  Search new unpacked PE image in the process memory and dump it if
		  possible.

Returns:  Void.
-----------------------------------------------------------------F-F*/
void MemoryForensics() {
	WriteLog(__FILEW__, __LINE__, L"Begin to search memory");
	SearchPEImage();
	WriteLog(__FILEW__, __LINE__, L"Search memory ended.");
}
