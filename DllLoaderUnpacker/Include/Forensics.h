#ifndef _MEM_FORENSICS_
#define _MEM_FORENSICS_

#include <windows.h>
#include "Include/Crypto.h"
#include "Include/pagelist.h"

#define ADDR_END_MEM				(ULONG)0xffffffff

#define DUMP_FILE_NAME_LEN			(0x20)

#define IMPORT_DLL_NAME_LEN			(0x20)

#define PAGE_MASK					(~(PAGE_SIZE-1))
#define PAGE_ALIGN(addr)			(((addr) + PAGE_SIZE - 1) & PAGE_MASK)

struct DumpHashList {
	BYTE hash[SHA256_HASH_LEN];
	struct DumpHashList *next;
};

struct DumpHashList DumpHashListHeader;
DWORD NumDump;

void MemoryForensics();

#endif
