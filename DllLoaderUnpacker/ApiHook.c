#include <windows.h>
#include <stdio.h>
#include "../Logger/Include/logger.h"
#include "Include/ApiHook.h"
#include "Include/Forensics.h"
#include <ntstatus.h>
#include "Include/pagelist.h"
#include <tlhelp32.h>
#include <Psapi.h>

/*F+F+++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++
Function: GetProtectString.

Summary:  Return memory protection string (e.g. PAGE_READONLY) for logging.

Returns:  wchar_t *.
-----------------------------------------------------------------F-F*/
static wchar_t *GetProtectString(ULONG Protect) {
	wchar_t *str_protect = NULL;
	switch (Protect) {
	case PAGE_NOACCESS: 
		str_protect = L"PAGE_NOACCESS";
		break;

	case PAGE_READONLY:
		str_protect = L"PAGE_READONLY";
		break;

	case PAGE_READWRITE:
		str_protect = L"PAGE_READWRITE";
		break;

	case PAGE_WRITECOPY:
		str_protect = L"PAGE_WRITECOPY";
		break;

	case PAGE_EXECUTE:
		str_protect = L"PAGE_EXECUTE";
		break;

	case PAGE_EXECUTE_READ:
		str_protect = L"PAGE_EXECUTE_READ";
		break;

	case PAGE_EXECUTE_READWRITE:
		str_protect = L"PAGE_EXECUTE_READWRITE";
		break;

	case PAGE_EXECUTE_WRITECOPY:
		str_protect = L"PAGE_EXECUTE_WRITECOPY";
		break;

	case PAGE_GUARD:
		str_protect = L"PAGE_GUARD";
		break;

	default:
		str_protect = NULL;
		break;
	}

	return str_protect;
}

/*F+F+++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++
Function: GetAllocationType.

Summary:  Return memory allocation type string (e.g. MEM_COMMIT) for logging.

Returns:  wchar_t *.
-----------------------------------------------------------------F-F*/
static wchar_t *GetAllocationType(ULONG AllocationType) {
	wchar_t *str = NULL;
	switch (AllocationType) {
	case (MEM_RESERVE | MEM_COMMIT):
		str = L"MEM_RESERVE | MEM_COMMIT";
		break;

	case MEM_COMMIT:
		str = L"MEM_COMMIT";
		break;

	case MEM_PHYSICAL:
		str = L"MEM_PHYSICAL";
		break;

	case MEM_RESERVE:
		str = L"MEM_RESERVE";
		break;

	case MEM_RESET:
		str = L"MEM_RESET";
		break;

	case MEM_TOP_DOWN:
		str = L"MEM_TOP_DOWN";
		break;

	default:
		str = NULL;
		break;
	}

	return str;
}

/*F+F+++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++
Function: GetAllocationType.

Summary:  Record memory base address and its region size & protection.

Returns:  void.
-----------------------------------------------------------------F-F*/
void AddMemEntry(PVOID lBaseAddress, SIZE_T lRegionSize, ULONG lProtect) {
	/*
	WriteLog(__FILEW__, __LINE__,
		L"!!! Adding entry: Addr=0x%p, Size=%d, Protect=0x%08lx (%s)",
		lBaseAddress, lRegionSize, lProtect, GetProtectString(lProtect));
	*/
	ListNodeT *node = ListNodeNew(lBaseAddress, lRegionSize, lProtect);
	ListNodeInsert(node);
}

/*F+F+++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++
Function: LogExecutableCall.

Summary:  Print memory operation.

Returns:  void.
-----------------------------------------------------------------F-F*/
static void LogExecutableCall(PVOID *BaseAddress, PSIZE_T RegionSize,
	ULONG Protect, wchar_t *prefix) {
	wchar_t *str_protect = GetProtectString(Protect);
	if (str_protect != NULL) {
		WriteLog(__FILEW__, __LINE__, L"%s: BaseAddress=0x%p, "
			L"RegionSize=%d, Protect=%s",
			prefix, *BaseAddress, *RegionSize, str_protect);
	} else {
		WriteLog(__FILEW__, __LINE__, L"%s: BaseAddress=0x%p, "
			L"RegionSize=%d, Unknown Protect=0x%08x",
			prefix, *BaseAddress, *RegionSize, Protect);
	}
}

/*F+F+++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++
Function: HackProtect.

Summary:  Change executable memory permission to non-executable. E.g.
		  PAGE_EXECUTE_READ -> PAGE_READONLY. Some special memory permissions
		  like PAGE_GUARD is omitted.

Returns:  void.
-----------------------------------------------------------------F-F*/
void HackProtect(ULONG Protect, ULONG *HackedProtect) {

	switch (Protect) {
	case PAGE_EXECUTE_READ:
		*HackedProtect = PAGE_READONLY;
		break;

	case PAGE_EXECUTE_READWRITE:
		*HackedProtect = PAGE_READWRITE;
		break;

	default:
		*HackedProtect = Protect;
		break;
	}
}

/*F+F+++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++
Function: PrintProcessName.

Summary:  Print process name by handle.

Returns:  void.
-----------------------------------------------------------------F-F*/
static void PrintProcessName(HANDLE ProcessHandle, const wchar_t *LogPrefix) {
	wchar_t NewProcessName[MAX_PROCESS_NAME + 1];
	if (GetModuleFileNameExW(ProcessHandle, NULL, NewProcessName,
		MAX_PROCESS_NAME) == 0) {
		WriteLog(__FILEW__, __LINE__, L"%s: Fail to call ."
			L"GetModuleFileNameExW error = %d, handle = %d",
			LogPrefix, GetLastError(), ProcessHandle);
	} else {
		WriteLog(__FILEW__, __LINE__, L"%s: Ignored other process %s.",
			LogPrefix, NewProcessName);
	}
}

/*F+F+++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++
Function: MineZwAllocateVirtualMemory.

Summary:  MineZwAllocateVirtualMemory will execute real ZwAllocateVirtualMemory
		  when: 1. Hook is disabled. 2. ProcessHandle is others'. 3. Memory
		  allocation type is not MEM_COMMIT (we don't care reserved memory).
		  When malware attempts to allocate memory with executable permission,
		  MineZwAllocateVirtualMemory will hack the protect to non-executable.

Returns:  NTSTATUS.
-----------------------------------------------------------------F-F*/
NTSTATUS MineZwAllocateVirtualMemory(
	HANDLE    ProcessHandle,
	PVOID     *BaseAddress,
	ULONG_PTR ZeroBits,
	PSIZE_T   RegionSize,
	ULONG     AllocationType,
	ULONG     Protect
) {
	/* Check hook status. */
	if (IsHookDisabled()) {
		WriteLog(__FILEW__, __LINE__, L"Alloc: HookFlag is 0. Ignored.");
		return RealZwAllocateVirtualMemory(ProcessHandle, BaseAddress,
			ZeroBits, RegionSize, AllocationType, Protect);
	}

	/* Check process handle. */
	if (ProcessHandle != GetCurrentProcess()) {

		/* Windows 7 should use QueryFullProcessImageName. 
		 * https://blogs.msdn.microsoft.com/oldnewthing/20150716-00/?p=45131
		 */
		PrintProcessName(ProcessHandle, L"Alloc");

		return RealZwAllocateVirtualMemory(ProcessHandle, BaseAddress,
			ZeroBits, RegionSize, AllocationType, Protect);
	}

	/* If MEM_COMMIT bit is not set, ignore */
	if ((AllocationType & MEM_COMMIT) == 0) {
		WriteLog(__FILEW__, __LINE__, L"Alloc: MEM_COMMIT not set. Ignored.");
		return RealZwAllocateVirtualMemory(ProcessHandle, BaseAddress,
			ZeroBits, RegionSize, AllocationType, Protect);
	}

	ULONG NewProtect = Protect;
	// BUG: Changing the protect crashes the app but the VEH doesn't catch it.
	HackProtect(Protect, &NewProtect);

	NTSTATUS Result = RealZwAllocateVirtualMemory(ProcessHandle, BaseAddress, 
		ZeroBits, RegionSize, AllocationType, NewProtect);

	/* Handle error here */
	if (Result != STATUS_SUCCESS) {
		WriteLog(__FILEW__, __LINE__, L"Change Protect failed.");

		return Result;
		/* TerminateProcess(GetCurrentProcess(), 0); */
	}

	if (Protect != NewProtect) {
		LogExecutableCall(BaseAddress, RegionSize, Protect, L"AllocHacked");

		wchar_t *str = GetAllocationType(AllocationType);
		if (str) {
			Log(L"AllocationType=%s", str); 
		} else {
			Log(L"Unknown AllocationType=0x%08lx", AllocationType);
		}

		/* Add to linked list. */
		AddMemEntry(*BaseAddress, *RegionSize, Protect);
	}

	return Result;
}

/*F+F+++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++
Function: IsAddressInModule.

Summary:  Check if addr is in process's module.

Returns:  bool.
-----------------------------------------------------------------F-F*/
static bool IsAddressInModule(ULONG uAddr) {
	char *ModuleBaseAddress = (char *)GetModuleHandle(NULL);
	
	IMAGE_DOS_HEADER *DosHeader = (IMAGE_DOS_HEADER *)ModuleBaseAddress;
	LONG e_lfanew = DosHeader->e_lfanew;

	IMAGE_NT_HEADERS *NtHeader = (IMAGE_NT_HEADERS *)(ModuleBaseAddress +
		e_lfanew);

	/* TODO: SizeOfImage is likely to be tricked by malware. */
	char *ModuleEndAddress = ModuleBaseAddress + 
		NtHeader->OptionalHeader.SizeOfImage;

	return (uAddr >= (ULONG)ModuleBaseAddress &&
		uAddr < (ULONG)ModuleEndAddress);
}

/*F+F+++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++
Function: MineZwProtectVirtualMemory.

Summary:  MineZwProtectVirtualMemory will execute real
		  MineZwProtectVirtualMemory when: 1. Hook is disabled. 2. ProcessHandle
		  is others'. 3. Memory allocation type is not MEM_IMAGE. 4. The base
		  address is in the process module.
		  When malware attempts to allocate memory with executable permission,
		  MineZwProtectVirtualMemory will hack the protect to non-executable.

Returns:  NTSTATUS.
-----------------------------------------------------------------F-F*/
NTSTATUS MineZwProtectVirtualMemory(
	HANDLE ProcessHandle,
	PVOID* BaseAddress,
	SIZE_T* NumberOfBytesToProtect,
	ULONG NewAccessProtection,
	PULONG OldAccessProtection
) {
	/* Check hook status. */
	if (IsHookDisabled()) {
		WriteLog(__FILEW__, __LINE__, L"Prot: HookFlag is 0. Ignored.");
		return RealZwProtectVirtualMemory(ProcessHandle, BaseAddress,
			NumberOfBytesToProtect, NewAccessProtection, OldAccessProtection);
	}

	/* Check process handle. */
	if (ProcessHandle != GetCurrentProcess()) {		
		PrintProcessName(ProcessHandle, L"Prot");
		return RealZwProtectVirtualMemory(ProcessHandle, BaseAddress,
			NumberOfBytesToProtect, NewAccessProtection, OldAccessProtection);
	}

	// TODO: Check BaseAddress pointer.
	ULONG NewNewAccessProtection = NewAccessProtection;
	
	/* We must check page type and base address. */
	MEMORY_BASIC_INFORMATION mbi;

	if (VirtualQuery(*BaseAddress, &mbi, sizeof(MEMORY_BASIC_INFORMATION))
		&& (IsAddressInModule((ULONG)*BaseAddress) || mbi.Type != MEM_IMAGE)) {

		HackProtect(NewAccessProtection, &NewNewAccessProtection);
	}

	NTSTATUS Result = RealZwProtectVirtualMemory(ProcessHandle, BaseAddress,
		NumberOfBytesToProtect, NewNewAccessProtection, OldAccessProtection);

	if (Result != STATUS_SUCCESS) {
		WriteLog(__FILEW__, __LINE__, L"Change Protect failed.");
		
		return Result;
		/* TerminateProcess(GetCurrentProcess(), 0); */
	}

	if (NewAccessProtection != NewNewAccessProtection) {
		LogExecutableCall(BaseAddress, NumberOfBytesToProtect,
			NewNewAccessProtection, L"ProtHacked");
		/* If the address already exists, replace the original value. */
		/* RegionSize unknown here. Ignore. */
		AddMemEntry(*BaseAddress, *NumberOfBytesToProtect,
			NewAccessProtection);
	}

	return Result;
}

/*F+F+++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++
Function: VEHExceptionHandler.

Summary:  If page fault is happened and the fault memory address is already
		  recorded in the linked list, try to dump malware unpacked image.

Returns:  LONG.
-----------------------------------------------------------------F-F*/
LONG WINAPI VEHExceptionHandler(struct _EXCEPTION_POINTERS *ExceptionInfo) {

	DWORD dwExceptionCode = ExceptionInfo->ExceptionRecord->ExceptionCode;
	DWORD dwNumParameters = ExceptionInfo->ExceptionRecord->NumberParameters;
	DWORD dwEIP = ExceptionInfo->ContextRecord->Eip;
	
	/* Warning: No VEH in OutputDebugString. */
	if (dwExceptionCode == STATUS_ACCESS_VIOLATION && dwNumParameters == 2
		&& dwEIP == ExceptionInfo->ExceptionRecord->ExceptionInformation[1]) {
		/* Page fault. */

		WriteLog(__FILEW__, __LINE__, L"Handling Exception! EIP=0x%08x", dwEIP);

		ListPrint();

		/* Get the possible entry from the linked list first */
		PVOID Address = (PVOID)dwEIP;
		ListNodeT *node = ListNodeFindLower(Address);
		if (node == NULL) {
			WriteLog(__FILEW__, __LINE__, L"Unexpected: List node not found");
			TerminateProcess(GetCurrentProcess(), 0);
		}
		else {
			WriteLog(__FILEW__, __LINE__, 
				L"node->BaseAddress=0x%p, RegionSize=%d, Protect=0x%08lx",
				node->BaseAddress, node->RegionSize, node->Protect);
		}

		/* Checking validity using RegionSize / NumberOfBytesToProtect */
		ULONG AddressRegionEnd = (ULONG)(node->BaseAddress);
		AddressRegionEnd += (ULONG)(node->RegionSize) - 1;
		if ((ULONG)Address > AddressRegionEnd) {
			WriteLog(__FILEW__, __LINE__, L"Unexpected: Out of boundary");
			TerminateProcess(GetCurrentProcess(), 0);
		}

		ULONG OldProtect;

		/* Set the Protect bits back */
		NTSTATUS Result = RealZwProtectVirtualMemory(GetCurrentProcess(), 
			&(node->BaseAddress), &(node->RegionSize), 
			node->Protect, &OldProtect);

		/* Handle error */
		if (Result != STATUS_SUCCESS) {
			WriteLog(__FILEW__, __LINE__, L"Restore Protect failed.");
			TerminateProcess(GetCurrentProcess(), 0);
		}
		else {
			WriteLog(__FILEW__, __LINE__, L"Restore Protect success.");
		}

		/* Remove the node from the list */
		ListNodeDelete(node);
		free(node);

		/* Attempt to dump unpacked malware. */
		MemoryForensics();

		return EXCEPTION_CONTINUE_EXECUTION;
	}

	return EXCEPTION_CONTINUE_SEARCH;
}

/*F+F+++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++
Function: EnableHook.

Summary:  Enable hook.

Returns:  void.
-----------------------------------------------------------------F-F*/
void EnableHook() {
	HookFlag = 1;
}

/*F+F+++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++
Function: DisableHook.

Summary:  Disable hook.

Returns:  void.
-----------------------------------------------------------------F-F*/
void DisableHook() {
	HookFlag = 0;
}

/*F+F+++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++
Function: IsHookDisabled.

Summary:  Check HookFlag.

Returns:  bool.
-----------------------------------------------------------------F-F*/
bool IsHookDisabled() {
	return HookFlag == 0;
}