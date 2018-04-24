#ifndef _UNPACKER_API_HOOK_
#define _UNPACKER_API_HOOK_

#define API_HOOK_LOG		L"hook.log"
#define API_LOG_BUF			0x100

NTSTATUS (*RealZwAllocateVirtualMemory)(
	_In_    HANDLE    ProcessHandle,
	_Inout_ PVOID     *BaseAddress,
	_In_    ULONG_PTR ZeroBits,
	_Inout_ PSIZE_T   RegionSize,
	_In_    ULONG     AllocationType,
	_In_    ULONG     Protect
);
NTSTATUS MineZwAllocateVirtualMemory(
	_In_    HANDLE    ProcessHandle,
	_Inout_ PVOID     *BaseAddress,
	_In_    ULONG_PTR ZeroBits,
	_Inout_ PSIZE_T   RegionSize,
	_In_    ULONG     AllocationType,
	_In_    ULONG     Protect
);

NTSTATUS (*RealZwProtectVirtualMemory)(
	HANDLE ProcessHandle,
	PVOID* BaseAddress,
	SIZE_T* NumberOfBytesToProtect,
	ULONG NewAccessProtection,
	PULONG OldAccessProtection
);
NTSTATUS MineZwProtectVirtualMemory(
	HANDLE ProcessHandle,
	PVOID* BaseAddress,
	SIZE_T* NumberOfBytesToProtect,
	ULONG NewAccessProtection,
	PULONG OldAccessProtection
);

#define MAX_PROCESS_NAME		(0x100)

LONG WINAPI VEHExceptionHandler(struct _EXCEPTION_POINTERS *ExceptionInfo);

int HookFlag;

void EnableHook();
void DisableHook();
bool IsHookDisabled();

#endif
