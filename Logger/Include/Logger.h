#ifndef _UNPACKER_LOGGER_
#define _UNPACKER_LOGGER_

#include <stdbool.h>

#define MAX_LOG_BUFFER	(MAX_PATH + 0x40)

#define CRLF_LEN		0x2

bool InitializeLog(wchar_t *pszLog);
bool WriteLog(wchar_t *pszSourceFile, int line, wchar_t *format, ...);
bool CloseLog(void);

#endif