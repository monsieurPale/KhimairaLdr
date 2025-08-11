#include <windows.h>
#include <stdio.h>

#define HASHA(API) (CRC32BA((LPCSTR) API))

SIZE_T _strlenA(IN LPCSTR String);
UINT32 CRC32BA(LPCSTR cString);
FARPROC GetProcAddressH(IN HMODULE hModule, IN UINT32 uApiHash);
HMODULE GetModuleHandleH(IN UINT32 uDllNameHash);
