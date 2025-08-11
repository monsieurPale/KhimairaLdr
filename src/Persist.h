#include <Windows.h>
#include <shobjidl.h>
#include <shlguid.h>
#include <objbase.h>
#include <shlobj_core.h>
#include <stdio.h>

BOOL CreateShortcut(LPCWSTR ExePath, LPCWSTR Arguments, LPCWSTR LnkPath);
BOOL PersistViaStartup();

BOOL WriteToRegKeyW(IN HKEY hKey, IN LPCWSTR szSubKey, IN LPCWSTR szRegName, IN PBYTE pRegData, IN DWORD dwDataSize);
BOOL PersistViaRegKey(); 