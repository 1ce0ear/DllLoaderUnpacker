#ifndef _DLLINJECTOR_TLS_H
#define _DLLINJECTOR_TLS_H

/* TODO: write TLS callback info to files.
* Maybe we should use named pipe later if DllInjector becomes more complex.
*/
#define DLL_CONFIG				"unpacker_config.ini"

#define TLS_PATCHED_EXE_NAME	"PatchedTLS.exe"

BOOLEAN CheckTLS(char *PEFileName, struct InjectorCommunication_s *Comm);

struct InjectorCommunication_s {
	DWORD dwNumTLSCallbacks;
	ULONG *TLSCallbacks;
};

#endif
