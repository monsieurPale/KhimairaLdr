#include <windows.h>
#include <stdio.h>

#include "Structs.h"
#include "ApiHashing.h"
#include "Core.h"

#define INITIAL_SEED	1337

SIZE_T _strlenA(IN LPCSTR String)
{
	LPCSTR String2;
	for (String2 = String; *String2; ++String2);
	return (String2 - String);
}

UINT32 CRC32BA(LPCSTR cString)
{

	UINT32      uMask = 0x00,
		uHash = 0xFFFFEFFF;
	INT         i = 0x00;
	while (cString[i] != 0) {
		uHash = uHash ^ (UINT32)cString[i];
		for (int ii = 0; ii < 8; ii++) {
			uMask = -1 * (uHash & 1);
			uHash = (uHash >> 1) ^ (0xEDB88320 & uMask);
		}
		i++;
	}
	return ~uHash;

}

HMODULE GetModuleHandleH(IN UINT32 uDllNameHash)
{

	PPEB                    pPeb = NULL;
	PPEB_LDR_DATA           pLdrData = NULL;
	PLDR_DATA_TABLE_ENTRY   pDataTableEntry = NULL;

#ifdef _WIN64
	pPeb = (PEB*)(__readgsqword(0x60));
#elif _WIN32
	pPeb = (PEB*)(__readfsdword(0x30));
#endif

	pLdrData = (PPEB_LDR_DATA)(pPeb->Ldr);
	pDataTableEntry = (PLDR_DATA_TABLE_ENTRY)(pLdrData->InMemoryOrderModuleList.Flink);

	if (!uDllNameHash)
		return (HMODULE)(pDataTableEntry->InInitializationOrderLinks.Flink);

	while (pDataTableEntry->FullDllName.Buffer)
	{
		if (pDataTableEntry->FullDllName.Length > 0x00 && pDataTableEntry->FullDllName.Length < MAX_PATH) {

			CHAR	cUprDllFileName[MAX_PATH] = { 0x00 };
			for (int i = 0; i < pDataTableEntry->FullDllName.Length; i++) {
				if (pDataTableEntry->FullDllName.Buffer[i] >= 'a' && pDataTableEntry->FullDllName.Buffer[i] <= 'z')
					cUprDllFileName[i] = pDataTableEntry->FullDllName.Buffer[i] - 'a' + 'A';
				else
					cUprDllFileName[i] = pDataTableEntry->FullDllName.Buffer[i];
			}
			if (CRC32BA(cUprDllFileName) == uDllNameHash)
				return (HMODULE)(pDataTableEntry->InInitializationOrderLinks.Flink);
		}
		pDataTableEntry = *(PLDR_DATA_TABLE_ENTRY*)(pDataTableEntry);
	}
	return NULL;
}

FARPROC GetProcAddressH(IN HMODULE hModule, IN UINT32 uApiHash)
{

	PBYTE                       pBase = (PBYTE)hModule;
	PIMAGE_NT_HEADERS           pImgNtHdrs = NULL;
	PIMAGE_EXPORT_DIRECTORY     pImgExportDir = NULL;
	PDWORD                      pdwFunctionNameArray = NULL;
	PDWORD                      pdwFunctionAddressArray = NULL;
	PWORD                       pwFunctionOrdinalArray = NULL;
	DWORD                       dwImgExportDirSize = 0x00;

	if (!hModule || !uApiHash)
		return NULL;

	pImgNtHdrs = (PIMAGE_NT_HEADERS)(pBase + ((PIMAGE_DOS_HEADER)pBase)->e_lfanew);
	if (pImgNtHdrs->Signature != IMAGE_NT_SIGNATURE)
		return NULL;

	pImgExportDir = (PIMAGE_EXPORT_DIRECTORY)(pBase + pImgNtHdrs->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress);
	dwImgExportDirSize = pImgNtHdrs->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].Size;
	pdwFunctionNameArray = (PDWORD)(pBase + pImgExportDir->AddressOfNames);
	pdwFunctionAddressArray = (PDWORD)(pBase + pImgExportDir->AddressOfFunctions);
	pwFunctionOrdinalArray = (PWORD)(pBase + pImgExportDir->AddressOfNameOrdinals);


	if (uApiHash <= 0xFFFF) {
		WORD wOrdinal = IMAGE_ORDINAL(uApiHash);
		if (wOrdinal < pImgExportDir->Base || (wOrdinal >= pImgExportDir->Base + pImgExportDir->NumberOfFunctions))
			return NULL;
		return (PVOID)(pBase + pdwFunctionAddressArray[wOrdinal - pImgExportDir->Base]);
	}

	for (DWORD i = 0; i < pImgExportDir->NumberOfFunctions; i++) {

		CHAR* pFunctionName = (CHAR*)(pBase + pdwFunctionNameArray[i]);
		PVOID	pFunctionAddress = (PVOID)(pBase + pdwFunctionAddressArray[pwFunctionOrdinalArray[i]]);

		if (CRC32BA(pFunctionName) == uApiHash) {

			if ((((ULONG_PTR)pFunctionAddress) >= ((ULONG_PTR)pImgExportDir)) &&
				(((ULONG_PTR)pFunctionAddress) < ((ULONG_PTR)pImgExportDir) + dwImgExportDirSize)
				) {

				CHAR			cForwarderName[MAX_PATH] = { 0 };
				DWORD			dwDotOffset = 0x00;
				PCHAR			pcFunctionMod = NULL;
				PCHAR			pcFunctionName = NULL;

				_memcpy(cForwarderName, pFunctionAddress, _strlenA((PCHAR)pFunctionAddress));
				for (int i = 0; i < _strlenA((PCHAR)cForwarderName); i++) {

					if (((PCHAR)cForwarderName)[i] == '.') {
						dwDotOffset = i;
						cForwarderName[i] = NULL;

						break;
					}
				}

				pcFunctionMod = cForwarderName;
				pcFunctionName = cForwarderName + dwDotOffset + 1;

				return GetProcAddressH(LdrLoadDll(pcFunctionMod), CRC32BA(pcFunctionName));
			}

			return (FARPROC)pFunctionAddress;
		}

	}

	return NULL;
}