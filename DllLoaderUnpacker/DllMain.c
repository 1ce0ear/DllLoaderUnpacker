#include <stdio.h>
#include <ole2.h>
#include <io.h>
#include <windows.h>
#include "Detours/include/detours.h"
#include "../Logger/Include/logger.h"
#include "Include/ApiHook.h"
#include "../DllInjector/Include/TLS.h"
#include "../DllInjector/Include/DllInjector.h"

#pragma comment(lib, "detours.lib")

static int (WINAPI * TrueEntryPoint)(VOID) = NULL;
static int (WINAPI * RawEntryPoint)(VOID) = NULL;

/*F+F+++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++
Function: TimedEntryPoint.

Summary:  Enable inline hook before entering true entry point.

Returns:  int.
-----------------------------------------------------------------F-F*/
static int WINAPI TimedEntryPoint(VOID) {
	LONG error;
	
	WriteLog(__FILEW__, __LINE__, L"Enter TimedEntryPoint");

	/* Get address for NtAllocateVirtualMmeory. */
	RealZwAllocateVirtualMemory = (NTSTATUS *)GetProcAddress(
		GetModuleHandle("NTDLL.DLL"), "NtAllocateVirtualMemory"
	);
	if (RealZwAllocateVirtualMemory == NULL) {
		WriteLog(__FILEW__, __LINE__, L"Fail to get NtAllocate addresses");
		return -1;
	}

	/* Get address for NtProtectVirtualMemory. */
	RealZwProtectVirtualMemory = (NTSTATUS *)GetProcAddress(
		GetModuleHandle("NTDLL.DLL"), "NtProtectVirtualMemory"
	);
	if (RealZwProtectVirtualMemory == NULL) {
		WriteLog(__FILEW__, __LINE__, L"Fail to get NtProtect addresses");
		return -1;
	}

	// Begin a new transaction for attaching or detaching detours.
	error = DetourTransactionBegin();
	if (error != NO_ERROR) {
		WriteLog(__FILEW__, __LINE__,
			L".dll: Error detouring DetourTransactionBegin: %d\n", error);
		return -1;
	}

	// Enlist a thread for update in the current transaction.
	error = DetourUpdateThread(GetCurrentThread());
	if (error != NO_ERROR) {
		WriteLog(__FILEW__, __LINE__,
			L".dll: Error detouring DetourUpdateThread: %d\n", error);
		return -1;
	}

	// Attach a detour to a target function.
	if (DetourAttach(&RealZwAllocateVirtualMemory, MineZwAllocateVirtualMemory) 
		!= NO_ERROR || DetourAttach(&RealZwProtectVirtualMemory,
		MineZwProtectVirtualMemory) != NO_ERROR) {
		WriteLog(__FILEW__, __LINE__,
			L"Error calling DetourAttach: %d\n", error);
		return -1;
	}

	// Commit the current transaction.
	error = DetourTransactionCommit();

	if (error == NO_ERROR) {
		WriteLog(__FILEW__, __LINE__, L"API hook is completed.");
	}
	else {
		WriteLog(__FILEW__, __LINE__,
			L"Error detouring NtAllocateVirtualMemory: %d\n", error);
		return -1;
	}

	EnableHook();

	return TrueEntryPoint();
}

/*F+F+++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++
Function: InitializeDEP.

Summary:  Enable DEP. When malware attempts to execute code in non-executable
		  memory, DEP will trigger page fault.

Returns:  bool.
-----------------------------------------------------------------F-F*/
static bool InitializeDEP() {
	DWORD dwDEPFlag;
	BOOL bIsPermanent, bIsDEPEnabled = FALSE;
	
	/* Get current DEP policy. */
	if (!GetProcessDEPPolicy(GetCurrentProcess(), &dwDEPFlag, &bIsPermanent)) {
		WriteLog(__FILEW__, __LINE__, L"GetProcessDEPPolicy Failed.");
		return FALSE;
	}

	/* Check DEP policy. */
	if ((dwDEPFlag & PROCESS_DEP_ENABLE) && bIsPermanent) {
		WriteLog(__FILEW__, __LINE__, L"DEP is already enabled.");
		bIsDEPEnabled = TRUE;
	} else {
		/* If DEP is not enabled, enable DEP policy. */
		if (!SetProcessDEPPolicy(PROCESS_DEP_ENABLE)) {
			WriteLog(__FILEW__, __LINE__, L"SetProcessDEPPolicy failed.");
		} else {
			WriteLog(__FILEW__, __LINE__, L"Enabled DEP.");
			bIsDEPEnabled = TRUE;
		}
	}

	return bIsDEPEnabled;
}

/*F+F+++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++
Function: DllMain.

Summary:  Initialize inline hook, DEP and VEH handler in DLL_PROCESS_ATTACH.
		  Uninitialize in DLL_PROCESS_DETACH.

Returns:  BOOL.
-----------------------------------------------------------------F-F*/
BOOL WINAPI DllMain(HINSTANCE hinstDLL, DWORD fdwReason, LPVOID lpReserved) {
	LONG error;
	PVOID pVEHHandler = NULL;

	(void)hinstDLL;
	(void)lpReserved;

	/* When creating a 32-bit target process from a 64-bit parent process or
	 * creating a 64-bit target process from a 32-bit parent process, we must
	 * check if the current process is helper process or not.
	 */

	if (DetourIsHelperProcess()) {
		return TRUE;
	}

	switch (fdwReason) {

	case DLL_PROCESS_ATTACH: {
		InitializeLog(API_HOOK_LOG);

		/* Restore the contents in memory import table after a process 
		was started with DetourCreateProcessWithDllEx or 
		DetourCreateProcessWithDlls. */
		DetourRestoreAfterWith();

		// NB: DllMain can't call LoadLibrary, so we hook the app entry point.
		TrueEntryPoint = (int (WINAPI *)(VOID))DetourGetEntryPoint(NULL);
		if (!TrueEntryPoint) {
			WriteLog(__FILEW__, __LINE__, L"Detour fails to find OEP.");
			break;
		}
		RawEntryPoint = TrueEntryPoint;

		// Begin a new transaction for attaching or detaching detours.
		error = DetourTransactionBegin();

		if (error != NO_ERROR) {
			WriteLog(__FILEW__, __LINE__, 
				L".dll: Error detouring EntryPoint(): %d\n", error);
			break;
		}

		// Enlist a thread for update in the current transaction.
		error = DetourUpdateThread(GetCurrentThread());

		if (error != NO_ERROR) {
			WriteLog(__FILEW__, __LINE__, 
				L".dll: Error detouring EntryPoint(): %d\n", error);
			break;
		}

		// Attach a detour to a target function.
		error = DetourAttach((PVOID *)&TrueEntryPoint, TimedEntryPoint);
		if (error != NO_ERROR) {
			WriteLog(__FILEW__, __LINE__, 
				L".dll: Error detouring EntryPoint(): %d\n", error);
			break;
		}

		// Commit the current transaction.
		error = DetourTransactionCommit();

		if (error == NO_ERROR) {
			WriteLog(__FILEW__, __LINE__, L"DetourTransactionCommit is ok.");
		}
		else {
			WriteLog(__FILEW__, __LINE__, 
				L".dll: Error detouring EntryPoint(): %d\n", error);
		}

		InitializeDEP();

		pVEHHandler = AddVectoredExceptionHandler(1, VEHExceptionHandler);

		break;
	}

	case DLL_THREAD_ATTACH: {
		break;
	}

	case DLL_THREAD_DETACH: {
		break;
	}

	case DLL_PROCESS_DETACH: {

		DisableHook();
		DetourTransactionBegin();
		DetourUpdateThread(GetCurrentThread());
		if (RealZwAllocateVirtualMemory != NULL) {
			// Attach a detour to a target function.
			DetourDetach(
				&(PVOID)RealZwAllocateVirtualMemory,
				MineZwAllocateVirtualMemory
			);
		}
		DetourDetach((PVOID *)&TrueEntryPoint, TimedEntryPoint);
		error = DetourTransactionCommit();

		/* Clean up. */
		RemoveVectoredExceptionHandler(pVEHHandler);
		WriteLog(__FILEW__, __LINE__, L"Target process is terminated.");
		CloseLog();
		break;
	}
	}

	return TRUE;
}
