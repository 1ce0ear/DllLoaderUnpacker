#include <windows.h>
#include <stdbool.h>
#include <assert.h>
#include <io.h>
#include <stdio.h>
#include "../Logger/Include/logger.h"
#include "Include/DllInjector.h"
#include "Include/TLS.h"

/*F+F+++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++
Function: ParseArguments.

Returns:  bool.
-----------------------------------------------------------------F-F*/
static bool ParseArguments(int argc, char **argv, char **pszDllName,
    char **pszExeName) {
    int iArgsMatched = 0;

    assert(pszDllName && argv);
    
    for (int i = 1; i < argc; i++) {
        if (!strcmp(argv[i], "-d") && i + 1 < argc &&
            _access(argv[i + 1], ACCESS_EXIST) != -1) {
            /* Get dll name from command line arguments. */
            iArgsMatched++;
            *pszDllName = argv[i + 1];
            i++;
        } else if (!strcmp(argv[i], "-e") && i + 1 < argc &&
            _access(argv[i + 1], ACCESS_EXIST) != -1) {
            /* Get exe name from command line arguments. */
            iArgsMatched++;
            *pszExeName = argv[i + 1];
            i++;
        }

        /* If dll exe are found in the command line arguments, return true. */
        if (iArgsMatched == EXPECTED_ARGS) {
            return true;
        }
    }

    return false;
}

/*F+F+++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++
  Function: InjectShellCode.

  Summary:  Initialize shellcode and inject it to the target process.

  Args:     hProcess: Target process handler.
			Eip: Original process EIP.
			pDllString: Allocated memory in the target process contains dll
						path. Used as LoadLibrary argument.
			ShellCodeLen: Get shellcode length.

  Returns:  bool.
-----------------------------------------------------------------F-F*/
PVOID InjectShellCode(HANDLE hProcess, unsigned int Eip, PVOID pDllString,
	int *ShellCodeLen) {
	unsigned char ShellCode[] = {
		0x68, 0xDE, 0x0, 0x0, 0x0, /* push. */
		0x60, /* pushad. */
		0x9C, /* pushaf. */
		0x68, 0xBE, 0x0, 0x0, 0x0, /* push. */
		0xB8, 0x0, 0x0, 0x0, 0x0, /* mov eax, 0x0. */
		0xFF, 0xD0, /* call eax. */
		0x9D, /* popaf. */
		0x61, /* popad. */
		0xc3 /* ret. */
	};

	/* Initialize shellcode. */
	for (int i = 0; i < sizeof(ShellCode); i++) {
		if (ShellCode[i] == 0x68 && i + 1 < sizeof(ShellCode)) {
			if (ShellCode[i + 1] == 0xDE) {
				/* Push original EIP. */
				memcpy(ShellCode + i + 1, &Eip, sizeof(unsigned int));
			} else if (ShellCode[i + 1] == 0xBE) {
				/* Push dll name for LoadLibraryA. */
				memcpy(ShellCode + i + 1, &pDllString, sizeof(PVOID));
			}
		}

		if (ShellCode[i] == 0xB8 && i + 1 < sizeof(ShellCode)) {
			/* Mov eax to LoadLibraryA address from EAT. */
			HMODULE hKernel = LoadLibrary(L"kernel32.dll");
			if (!hKernel) {
				WriteLog(__FILEW__, __LINE__, L"Fail to call LoadLibrary");
				return NULL;
			}

			unsigned int LoadLibraryAddr = (unsigned int)GetProcAddress(
				hKernel, "LoadLibraryA");

			if (LoadLibraryAddr == 0) {
				WriteLog(__FILEW__, __LINE__, L"Fail to call GetProcAddress");
				return NULL;
			}

			memcpy(ShellCode + i + 1, &LoadLibraryAddr,
				sizeof(unsigned int));

			FreeLibrary(hKernel);
		}
	}

	/* Allocate memory for shellcode. */
	PVOID pShellCode = VirtualAllocEx(hProcess, NULL, sizeof(ShellCode),
		MEM_COMMIT, PAGE_EXECUTE_READWRITE);
	if (!pShellCode) {
		WriteLog(__FILEW__, __LINE__, L"Fail to call VirtualAllocEx");
		return NULL;
	}

	WriteLog(__FILEW__, __LINE__, L"Allocate memory for shellcode.");

	/* Write shellcode to process. */
	if (!WriteProcessMemory(hProcess, pShellCode, ShellCode, sizeof(ShellCode),
		NULL)) {
		WriteLog(__FILEW__, __LINE__, L"Fail to call WriteProcessMemory");
		return NULL;
	}

	*ShellCodeLen = sizeof(ShellCode);
	return pShellCode;
}

/*F+F+++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++
  Function: InjectByShellCode.

  Summary:  Inject DLL to target process. First, create a suspended process
			and inject shellcode in the process memory. Second, change the
			thread context and resume the process. The vicitm process will
			execute shellcode first in order to load the injected dll.

			*Only tested in Windows XP x86 so far.*

  Args:     pszDllName: DLL file name.
			pszExeName: Exe file name.

  Returns:  bool.
-----------------------------------------------------------------F-F*/
static bool InjectByShellCode(char *pszDllName, char *pszExeName) {
	PROCESS_INFORMATION pi = { 0 };
	STARTUPINFOA si = { 0 };
	CONTEXT ctx = {
		.ContextFlags = CONTEXT_CONTROL,
	};
	struct InjectorCommunication_s Comm;
	char *MalwareProcess = pszExeName;
	BOOLEAN bIsTLS = CheckTLS(pszExeName, &Comm);

	/* Use commandline to decide whether to execute TLS callback or not. */
	if (bIsTLS) {
		/* If TLS exists, patch exe file. */
		MalwareProcess = TLS_PATCHED_EXE_NAME;
		WriteLog(__FILEW__, __LINE__, L"Run TLS Patched binary instead.");
	}

	/* Create and suspend a process. */
	if (!CreateProcessA(NULL, MalwareProcess, NULL, NULL, 0,
		CREATE_SUSPENDED, NULL, NULL, &si, &pi)) {
		WriteLog(__FILEW__, __LINE__, L"Fail to call CreateProcess");
		return false;
	}

	WriteLog(__FILEW__, __LINE__, L"Malware process is created.");

	/* Allocate a virtual memory in malware process. The dll name will be
	 * stored in the memory.
	 */
	PVOID pDllString = VirtualAllocEx(pi.hProcess, NULL,
		strlen(pszDllName) + 1, MEM_COMMIT, PAGE_READWRITE);

	if (!pDllString || !WriteProcessMemory(pi.hProcess, pDllString, pszDllName,
		strlen(pszDllName) + 1, NULL)) {
		WriteLog(__FILEW__, __LINE__, L"Fail to call Virtual Alloc");
		TerminateProcess(pi.hProcess, 0);
		return false;
	}

	WriteLog(__FILEW__, __LINE__, L"Allocate memory for dll name.");

	/* Get current thread context. */
	if (!GetThreadContext(pi.hThread, &ctx)) {
		WriteLog(__FILEW__, __LINE__, L"Fail to call GetThreadContext.");
		VirtualFree(pDllString, strlen(pszDllName) + 1, MEM_RELEASE);
		TerminateProcess(pi.hProcess, 0);
		return false;
	}

	WriteLog(__FILEW__, __LINE__, L"GetThreadContext.");

	/* Initialize and inject shellcode to target process. */
	int ShellCodeLen;
	PVOID pShellCode = InjectShellCode(pi.hProcess, ctx.Eip, pDllString,
		&ShellCodeLen);
	if (!pShellCode) {
		WriteLog(__FILEW__, __LINE__, L"Fail to call InjectShellCode.");
		VirtualFree(pShellCode, ShellCodeLen, MEM_RELEASE);
		VirtualFree(pDllString, strlen(pszDllName) + 1, MEM_RELEASE);
		TerminateProcess(pi.hProcess, 0);
		return false;
	}

	WriteLog(__FILEW__, __LINE__, L"InjectShellCode.");

	/* Modify thread context. */
	ctx.Eip = (DWORD)pShellCode;
	ctx.ContextFlags = CONTEXT_CONTROL;

	if (!SetThreadContext(pi.hThread, &ctx)) {
		WriteLog(__FILEW__, __LINE__, L"Fail to call SetThreadContext.");
		VirtualFree(pDllString, strlen(pszDllName) + 1, MEM_RELEASE);
		VirtualFree(pShellCode, ShellCodeLen, MEM_RELEASE);
		TerminateProcess(pi.hProcess, 0);
		return false;
	}

	WriteLog(__FILEW__, __LINE__, L"SetThreadContext.");

	/* Resume thread. */
	if (ResumeThread(pi.hThread) == -1) {
		WriteLog(__FILEW__, __LINE__, L"Fail to call ResumeThread.");
		VirtualFree(pDllString, strlen(pszDllName) + 1, MEM_RELEASE);
		VirtualFree(pShellCode, ShellCodeLen, MEM_RELEASE);
		TerminateProcess(pi.hProcess, 0);
		return false;
	}

	WriteLog(__FILEW__, __LINE__, L"DLL injection should be successful.");

	return true;
}

/*F+F+++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++
  Function: main.

  Summary:  Main entry. Current usage: DllInjector.exe -d abcde.dll -e bad.exe.

  Args:     Argc: the number of command line arguments.
            Argv: the array of command line arguments.

  Returns:  Int. 0 for success, else -1.
-----------------------------------------------------------------F-F*/
int main(int argc, char **argv) {
    char *pszDllName, *pszExeName;
    
    /* Parse command line arguments. */
    if (!ParseArguments(argc, argv, &pszDllName, &pszExeName)) {
        printf("Usage: DllInjector.exe -d foo.dll -e bar.exe\n");
        getchar();
        return -1;
    }

    /* Initialize logging function. */
    if (!InitializeLog(LOG_FILE)) {
        printf("Fail to initialize log.\n");
        return -1;
    }
    
	InjectByShellCode(pszDllName, pszExeName);
	CloseLog();

    return 0;
}
