#pragma once

#include <windows.h>
#include <malloc.h>


int _strcmp(const char* a, const char* b);

HMODULE WINAPI hlpGetModuleHandle(LPCWSTR sModuleName);
FARPROC WINAPI hlpGetProcAddress(HMODULE hMod, char * sProcName);
