#include <Windows.h>
#include <stdio.h>

#include "Structs.h"
#include "Core.h"
#include "ApiHashing.h"
#include "HellsHall.h"


#define	SYSCALL_STUB_SIZE		0x20		

#define SEARCH_UP               ( -1 * SYSCALL_STUB_SIZE )
#define SEARCH_DOWN             SYSCALL_STUB_SIZE
#define SEARCH_RANGE            0xFF


typedef struct _NTDLL_CONFIG
{
    PDWORD      pdwArrayOfAddresses;
    PDWORD      pdwArrayOfNames;
    PWORD       pwArrayOfOrdinals;
    DWORD       dwNumberOfNames;
    ULONG_PTR   uModule;

}NTDLL_CONFIG, * PNTDLL_CONFIG;


NTDLL_CONFIG g_NtdllConf = { 0 };

BOOL InitNtdllConfigStructure(OUT PNTDLL_CONFIG pNtdllConfig) {

    PPEB                        pPEB = NULL;
    PLDR_DATA_TABLE_ENTRY       pDataTableEntry = NULL;
    ULONG_PTR                   uNtdllModule = NULL;
    PIMAGE_NT_HEADERS           pImgNtHdrs = NULL;
    PIMAGE_EXPORT_DIRECTORY     pImgExpDir = NULL;

    if ((pPEB = (PPEB)__readgsqword(0x60))->OSMajorVersion != 0xA)
        return FALSE;

    pDataTableEntry = (PLDR_DATA_TABLE_ENTRY)((PBYTE)pPEB->Ldr->InMemoryOrderModuleList.Flink->Flink - sizeof(LIST_ENTRY));

    if (!(uNtdllModule = (ULONG_PTR)(pDataTableEntry->DllBase)))
        return FALSE;

    pImgNtHdrs = (PIMAGE_NT_HEADERS)(uNtdllModule + ((PIMAGE_DOS_HEADER)uNtdllModule)->e_lfanew);
    if (pImgNtHdrs->Signature != IMAGE_NT_SIGNATURE)
        return FALSE;

    pImgExpDir = (PIMAGE_EXPORT_DIRECTORY)(uNtdllModule + pImgNtHdrs->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress);

    pNtdllConfig->uModule = uNtdllModule;
    pNtdllConfig->dwNumberOfNames = pImgExpDir->NumberOfNames;
    pNtdllConfig->pdwArrayOfNames = (PDWORD)(uNtdllModule + pImgExpDir->AddressOfNames);
    pNtdllConfig->pdwArrayOfAddresses = (PDWORD)(uNtdllModule + pImgExpDir->AddressOfFunctions);
    pNtdllConfig->pwArrayOfOrdinals = (PWORD)(uNtdllModule + pImgExpDir->AddressOfNameOrdinals);

    if (!pNtdllConfig->uModule || !pNtdllConfig->dwNumberOfNames || !pNtdllConfig->pdwArrayOfNames || !pNtdllConfig->pdwArrayOfAddresses || !pNtdllConfig->pwArrayOfOrdinals)
        return FALSE;

    return TRUE;
}

BOOL FetchNtSyscall(IN DWORD dwSyscallHash, OUT PNT_SYSCALL pNtSyscall) {

    ULONG_PTR uSyscallInstAddress = NULL;

    if (!g_NtdllConf.uModule) {
        if (!InitNtdllConfigStructure(&g_NtdllConf))
            return FALSE;
    }

    for (DWORD i = 0; i < g_NtdllConf.dwNumberOfNames; i++) {

        PCHAR   pcFuncName = (PCHAR)(g_NtdllConf.uModule + g_NtdllConf.pdwArrayOfNames[i]);
        PVOID   pFuncAddress = (PVOID)(g_NtdllConf.uModule + g_NtdllConf.pdwArrayOfAddresses[g_NtdllConf.pwArrayOfOrdinals[i]]);


        if (HASH(pcFuncName) == dwSyscallHash) {

            pNtSyscall->pSyscallAddress = pFuncAddress;

            if (*((PBYTE)pFuncAddress) == 0x4C
                && *((PBYTE)pFuncAddress + 1) == 0x8B
                && *((PBYTE)pFuncAddress + 2) == 0xD1
                && *((PBYTE)pFuncAddress + 3) == 0xB8
                && *((PBYTE)pFuncAddress + 6) == 0x00
                && *((PBYTE)pFuncAddress + 7) == 0x00) {

                BYTE high = *((PBYTE)pFuncAddress + 5);
                BYTE low = *((PBYTE)pFuncAddress + 4);
                pNtSyscall->dwSSn = (high << 8) | low;
                break;
            }

            if (*((PBYTE)pFuncAddress) == 0xE9) {

                for (WORD idx = 1; idx <= SEARCH_RANGE; idx++) {
                    if (*((PBYTE)pFuncAddress + idx * SEARCH_DOWN) == 0x4C
                        && *((PBYTE)pFuncAddress + 1 + idx * SEARCH_DOWN) == 0x8B
                        && *((PBYTE)pFuncAddress + 2 + idx * SEARCH_DOWN) == 0xD1
                        && *((PBYTE)pFuncAddress + 3 + idx * SEARCH_DOWN) == 0xB8
                        && *((PBYTE)pFuncAddress + 6 + idx * SEARCH_DOWN) == 0x00
                        && *((PBYTE)pFuncAddress + 7 + idx * SEARCH_DOWN) == 0x00) {

                        BYTE high = *((PBYTE)pFuncAddress + 5 + idx * SEARCH_DOWN);
                        BYTE low = *((PBYTE)pFuncAddress + 4 + idx * SEARCH_DOWN);
                        pNtSyscall->dwSSn = (high << 8) | low - idx;
                        break;
                    }
                    if (*((PBYTE)pFuncAddress + idx * SEARCH_UP) == 0x4C
                        && *((PBYTE)pFuncAddress + 1 + idx * SEARCH_UP) == 0x8B
                        && *((PBYTE)pFuncAddress + 2 + idx * SEARCH_UP) == 0xD1
                        && *((PBYTE)pFuncAddress + 3 + idx * SEARCH_UP) == 0xB8
                        && *((PBYTE)pFuncAddress + 6 + idx * SEARCH_UP) == 0x00
                        && *((PBYTE)pFuncAddress + 7 + idx * SEARCH_UP) == 0x00) {

                        BYTE high = *((PBYTE)pFuncAddress + 5 + idx * SEARCH_UP);
                        BYTE low = *((PBYTE)pFuncAddress + 4 + idx * SEARCH_UP);
                        pNtSyscall->dwSSn = (high << 8) | low + idx;
                        break;
                    }
                }
            }

            if (*((PBYTE)pFuncAddress + 3) == 0xE9) {

                for (WORD idx = 1; idx <= SEARCH_RANGE; idx++) {
                    if (*((PBYTE)pFuncAddress + idx * SEARCH_DOWN) == 0x4C
                        && *((PBYTE)pFuncAddress + 1 + idx * SEARCH_DOWN) == 0x8B
                        && *((PBYTE)pFuncAddress + 2 + idx * SEARCH_DOWN) == 0xD1
                        && *((PBYTE)pFuncAddress + 3 + idx * SEARCH_DOWN) == 0xB8
                        && *((PBYTE)pFuncAddress + 6 + idx * SEARCH_DOWN) == 0x00
                        && *((PBYTE)pFuncAddress + 7 + idx * SEARCH_DOWN) == 0x00) {

                        BYTE high = *((PBYTE)pFuncAddress + 5 + idx * SEARCH_DOWN);
                        BYTE low = *((PBYTE)pFuncAddress + 4 + idx * SEARCH_DOWN);
                        pNtSyscall->dwSSn = (high << 8) | low - idx;
                        break;
                    }
                    if (*((PBYTE)pFuncAddress + idx * SEARCH_UP) == 0x4C
                        && *((PBYTE)pFuncAddress + 1 + idx * SEARCH_UP) == 0x8B
                        && *((PBYTE)pFuncAddress + 2 + idx * SEARCH_UP) == 0xD1
                        && *((PBYTE)pFuncAddress + 3 + idx * SEARCH_UP) == 0xB8
                        && *((PBYTE)pFuncAddress + 6 + idx * SEARCH_UP) == 0x00
                        && *((PBYTE)pFuncAddress + 7 + idx * SEARCH_UP) == 0x00) {

                        BYTE high = *((PBYTE)pFuncAddress + 5 + idx * SEARCH_UP);
                        BYTE low = *((PBYTE)pFuncAddress + 4 + idx * SEARCH_UP);
                        pNtSyscall->dwSSn = (high << 8) | low + idx;
                        break;
                    }
                }
            }

            break;
        }

    }

    if (!pNtSyscall->pSyscallAddress || !pNtSyscall->dwSSn)
        return FALSE;

    HMODULE hKernel32Base = GetModuleHandleH(0x377D97D5); 
    fnGetTickCount64 pGetTickCount64 = (fnGetTickCount64)GetProcAddressH(hKernel32Base, 0xE57849D2);

    uSyscallInstAddress = (ULONG_PTR)pNtSyscall->pSyscallAddress + (pGetTickCount64() % 0xFF);
    for (DWORD z = 0, x = 1; z <= SEARCH_RANGE; z++, x++) {
        if (*((PBYTE)uSyscallInstAddress + z) == 0x0F && *((PBYTE)uSyscallInstAddress + x) == 0x05) {
            pNtSyscall->pSyscallInstAddress = ((ULONG_PTR)uSyscallInstAddress + z);
            return TRUE;
        }
    }

    return FALSE;
}


