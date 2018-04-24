#ifndef _MEM_CRYPTO_
#define _MEM_CRYPTO_

#include <windows.h>

#define SHA256_HASH_LEN			(256)

BOOL AcquireSha256Hash(IN const BYTE *Text, OUT BYTE *Hash);

#endif