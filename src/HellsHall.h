#include <Windows.h>
#include "ApiHashing.h"

#ifndef HELLHALL_H
#define HELLHALL_H

typedef struct _NT_SYSCALL
{
    DWORD   dwSSn;
    PVOID   pSyscallAddress;
    PVOID   pSyscallInstAddress;

} NT_SYSCALL, * PNT_SYSCALL;

BOOL    FetchNtSyscall(IN DWORD dwSysHash, OUT PNT_SYSCALL pNtSys);

extern VOID SetSSn(IN DWORD dwSSn, IN PVOID pSyscallInstAddress);
extern      RunSyscall();

#define SET_SYSCALL(NtSys)(SetSSn((DWORD)NtSys.dwSSn,(PVOID)NtSys.pSyscallInstAddress))
#define HASH(String)(CRC32BA((LPCSTR)String))

#endif 



