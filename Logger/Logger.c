#include <SDKDDKVer.h>
#include <windows.h>
#include <stdio.h>
#include <stdbool.h>
#include <shlwapi.h>
#include "Include\logger.h"

static HANDLE g_hLog;

bool InitializeLog(wchar_t *pszLog) {
	g_hLog = CreateFileW(pszLog, FILE_ALL_ACCESS, FILE_SHARE_READ | FILE_SHARE_WRITE, NULL,
		CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);

	return g_hLog != INVALID_HANDLE_VALUE;
}

bool WriteLog(wchar_t *pszSourceFile, int line, wchar_t *format, ...) {
	wchar_t pszLog[MAX_LOG_BUFFER + 1];
	wchar_t *pszShortFileName;
	DWORD dwBytesWritten = 0;
	va_list vl;

	/* Check handle first. */
	if (g_hLog == INVALID_HANDLE_VALUE) {
		return false;
	}

	va_start(vl, format);

	pszShortFileName = PathFindFileName(pszSourceFile);

	/* Initialize log prefix. */
	DWORD PrintedBytes = wsprintf(pszLog, L"[%s:%d] - ", pszShortFileName,
line);
	PrintedBytes *= sizeof(wchar_t);

	/* Write log prefix first. */

	if (!WriteFile(g_hLog, pszLog, PrintedBytes, &dwBytesWritten, NULL) ||
		dwBytesWritten != PrintedBytes || !FlushFileBuffers(g_hLog)) {
		va_end(vl);
		return false;
	}

	/* Initialize log comment. */
	PrintedBytes = _vsnwprintf_s(pszLog, MAX_LOG_BUFFER, _TRUNCATE,
		format, vl);

	/* Append CRLF to log comment.*/
	if (MAX_LOG_BUFFER - 1 - PrintedBytes >= CRLF_LEN) {
		wcscat_s(pszLog, MAX_LOG_BUFFER, L"\r\n", CRLF_LEN);
	}

	PrintedBytes += CRLF_LEN;
	PrintedBytes *= sizeof(wchar_t);

	va_end(vl);

	/* Write comment to file. */
	if (!WriteFile(g_hLog, pszLog, PrintedBytes, &dwBytesWritten, NULL) ||
		dwBytesWritten != PrintedBytes || !FlushFileBuffers(g_hLog)) {
		return false;
	}

	return true;
}

bool CloseLog(void) {
	return CloseHandle(g_hLog);
}