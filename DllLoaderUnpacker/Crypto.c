#include <windows.h>
#include <wincrypt.h>
#include "Include/Crypto.h"

/*F+F+++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++
Function: AcquireSha256Hash.

Summary:  Generate Sha256 hash for each binary dump.

Returns:  Void.
-----------------------------------------------------------------F-F*/
BOOL AcquireSha256Hash(IN const BYTE *Text, OUT BYTE *Hash) {
	HCRYPTPROV hProv = NULL;
	HCRYPTPROV hHashProv = NULL;

	if (!CryptAcquireContext(&hProv, NULL, NULL, PROV_RSA_AES,
		CRYPT_VERIFYCONTEXT)) {
		return FALSE;
	}

	if (CryptCreateHash(hProv, CALG_SHA_256, 0, 0, &hHashProv)) {
		CryptReleaseContext(hProv, 0);
		return FALSE;
	}

	if (!CryptHashData(hHashProv, Text, SHA256_HASH_LEN, 0)) {
		CryptDestroyHash(hHashProv);
		CryptReleaseContext(hProv, 0);
		return FALSE;
	}

	DWORD dwHashSize = SHA256_HASH_LEN;
	if (!CryptGetHashParam(hHashProv, HP_HASHVAL, Hash, &dwHashSize, 0)) {
		CryptDestroyHash(hHashProv);
		CryptReleaseContext(hProv, 0);
		return FALSE;
	}

	CryptDestroyHash(hHashProv);
	CryptReleaseContext(hProv, 0);

	return TRUE;
}