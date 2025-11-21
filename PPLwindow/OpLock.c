#include "OpLock.h"

#pragma warning( disable : 6258)

BOOL OpLockFile(const WCHAR* filename, DWORD sharemode, BOOL exclusive, POPLOCK_FILE_CONTEXT ofc)
{
	DWORD bret = 0;
	REQUEST_OPLOCK_INPUT_BUFFER roib;
	REQUEST_OPLOCK_OUTPUT_BUFFER roob;
	DWORD flags = 0;

	if (!filename)
	{
		return FALSE;
	}
	if (!ofc)
	{
		return FALSE;
	}
	if (ofc->len < sizeof(OPLOCK_FILE_CONTEXT))
	{
		return FALSE;
	}

	memset(&ofc->overlapped, 0, sizeof(OVERLAPPED));
	memset(&roib, 0, sizeof(roib));
	memset(&roob, 0, sizeof(roob));
	roib.StructureLength = sizeof(roib);
	roib.StructureVersion = REQUEST_OPLOCK_CURRENT_VERSION;
	roib.RequestedOplockLevel = OPLOCK_LEVEL_CACHE_READ | OPLOCK_LEVEL_CACHE_HANDLE;
	roib.Flags = REQUEST_OPLOCK_INPUT_FLAG_REQUEST;
	roob.StructureLength = sizeof(roob);
	roob.StructureVersion = REQUEST_OPLOCK_CURRENT_VERSION;
	ofc->overlapped.hEvent = CreateEvent(NULL, TRUE, FALSE, NULL);

	if (!ofc->overlapped.hEvent)
	{
		return FALSE;
	}
	flags = FILE_FLAG_OVERLAPPED;
	if (GetFileAttributesW(filename) & FILE_ATTRIBUTE_DIRECTORY)
	{
		flags |= FILE_FLAG_BACKUP_SEMANTICS | FILE_FLAG_OPEN_REPARSE_POINT;
	}

	ofc->file = CreateFileW(filename, GENERIC_READ, sharemode, NULL, OPEN_EXISTING, flags, NULL);
	if (ofc->file == INVALID_HANDLE_VALUE)
	{
		return FALSE;
	}

	if (exclusive)
	{
		bret = 0;
		DeviceIoControl(ofc->file, FSCTL_REQUEST_OPLOCK_LEVEL_1, NULL, 0, NULL, 0, &bret, &ofc->overlapped);
	}
	else
	{
		DeviceIoControl(ofc->file, FSCTL_REQUEST_OPLOCK, &roib, sizeof(roib), &roob, sizeof(roob), NULL, &ofc->overlapped);
	}

	if (GetLastError() != ERROR_IO_PENDING)
	{
		return FALSE;
	}

	return TRUE;
}

DWORD WINAPI WaitForOpLockThread(LPVOID p)
{
	DWORD bret = 0;
	POPLOCK_FILE_CONTEXT ofc = (POPLOCK_FILE_CONTEXT)p;

	if (!p)
	{
		return 0;
	}

	bret = 0;
	if (!GetOverlappedResult(ofc->file, &ofc->overlapped, &bret, TRUE))
	{
		return 0;
	}

	return 1;
}

BOOL WaitForOpLock(POPLOCK_FILE_CONTEXT ofc, DWORD timeout)
{
	DWORD exitcode = 0;
	HANDLE thread = NULL;

	if (!ofc)
	{
		return FALSE;
	}
	if (ofc->len < sizeof(OPLOCK_FILE_CONTEXT))
	{
		return FALSE;
	}

	thread = CreateThread(NULL, 0x1000, (LPTHREAD_START_ROUTINE)WaitForOpLockThread, (LPVOID)ofc, STACK_SIZE_PARAM_IS_A_RESERVATION, NULL);
	if (thread)
	{
		if (WaitForSingleObject(thread, timeout) != WAIT_OBJECT_0)
		{
			TerminateThread(thread, 0);
			CloseHandle(thread);
			return FALSE;
		}
		if (!GetExitCodeThread(thread, &exitcode))
		{
			CloseHandle(thread);
			return FALSE;
		}
		CloseHandle(thread);
		return TRUE;
	}

	return FALSE;
}

BOOL ReleaseOpLock(POPLOCK_FILE_CONTEXT ofc)
{
	if (!ofc)
	{
		return FALSE;
	}
	if (ofc->len < sizeof(OPLOCK_FILE_CONTEXT))
	{
		return FALSE;
	}

	CloseHandle(ofc->overlapped.hEvent);
	CloseHandle(ofc->file);

	return TRUE;
}
