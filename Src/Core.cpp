#include "Core.h"
#include <System.hpp>
#include <System.Classes.hpp>
#include <cstdio>
#include <SysUtils.hpp>

_RtlAdjustPrivilege pRtlAdjustPrivilege = NULL;
_LogonUserExExW pLogonUserExExW = NULL;

void ResolveDynamicFunctions()
{
    HMODULE ntdll = GetModuleHandleW(L"ntdll.dll");
    if (ntdll)
    {
        pRtlAdjustPrivilege = (_RtlAdjustPrivilege)GetProcAddress(ntdll, "RtlAdjustPrivilege");
    }

    HMODULE hAdvapi32 = GetModuleHandleW(L"advapi32.dll");
    if (hAdvapi32)
    {
        pLogonUserExExW = (_LogonUserExExW)GetProcAddress(hAdvapi32, "LogonUserExExW");
    }
}

bool EnablePrivilege(bool impersonating, int privilege_value)
{
    if (!pRtlAdjustPrivilege)
    {
        return false;
    }

    bool previous;
    NTSTATUS status = pRtlAdjustPrivilege(privilege_value, true, impersonating, &previous);
    return NT_SUCCESS(status);
}

bool ImpersonateTcbToken()
{
    HANDLE hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (hSnapshot == INVALID_HANDLE_VALUE)
    {
        return false;
    }

    PROCESSENTRY32W entry = { 0 };
    entry.dwSize = sizeof(entry);

    if (!Process32FirstW(hSnapshot, &entry))
    {
        CloseHandle(hSnapshot);
        return false;
    }

    DWORD winlogonPid = 0;
    do
    {
        if (!_wcsicmp(L"winlogon.exe", entry.szExeFile))
        {
            winlogonPid = entry.th32ProcessID;
            break;
        }
    } while (Process32NextW(hSnapshot, &entry));

    CloseHandle(hSnapshot);

    if (!winlogonPid)
    {
        return false;
    }

    HANDLE hProcess = OpenProcess(PROCESS_QUERY_INFORMATION, FALSE, winlogonPid);
    if (!hProcess)
    {
        return false;
    }

    HANDLE hToken;
    bool tokenSuccess = OpenProcessToken(hProcess, TOKEN_QUERY | TOKEN_DUPLICATE | TOKEN_IMPERSONATE, &hToken);

    CloseHandle(hProcess);

    if (!tokenSuccess)
    {
        return false;
    }

    bool impersonateSuccess = ImpersonateLoggedOnUser(hToken);

    CloseHandle(hToken);

    if (!impersonateSuccess)
    {
        return false;
    }

    return true;
}

HANDLE GetTrustedInstallerToken()
{
    bool impersonating = false;
    HANDLE trustedInstallerToken = NULL;
    PSID trustedInstallerSid = NULL;

    do
    {
        if (!EnablePrivilege(false, SeTcbPrivilege))
        {
            if (!EnablePrivilege(false, SeDebugPrivilege))
            {
                break;
            }

            impersonating = ImpersonateTcbToken();
            if (!impersonating || !EnablePrivilege(impersonating, SeTcbPrivilege))
            {
                break;
            }
        }

        if (!ConvertStringSidToSidA(TRUSTED_INSTALLER_SID, &trustedInstallerSid))
        {
            break;
        }

        HANDLE currentToken;
        PTOKEN_GROUPS tokenGroups = NULL;

        if (impersonating)
        {
            if (!OpenThreadToken(GetCurrentThread(), TOKEN_QUERY, FALSE, &currentToken))
            {
                break;
            }
        }
        else
        {
            if (!OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &currentToken))
            {
                break;
            }
        }

        DWORD tokenGroupsSize;
        GetTokenInformation(currentToken, TokenGroups, NULL, 0, &tokenGroupsSize);
        tokenGroups = (PTOKEN_GROUPS)LocalAlloc(LPTR, tokenGroupsSize);
        if (!tokenGroups)
        {
            CloseHandle(currentToken);
            break;
        }

        if (!GetTokenInformation(currentToken, TokenGroups, tokenGroups, tokenGroupsSize, &tokenGroupsSize))
        {
            LocalFree(tokenGroups);
            CloseHandle(currentToken);
            break;
        }

        DWORD lastGroupIndex = tokenGroups->GroupCount - 1;
        tokenGroups->Groups[lastGroupIndex].Sid = trustedInstallerSid;
        tokenGroups->Groups[lastGroupIndex].Attributes = SE_GROUP_OWNER | SE_GROUP_ENABLED;

        bool logonSuccess = pLogonUserExExW(
            (LPWSTR)L"SYSTEM",
            (LPWSTR)L"NT AUTHORITY",
            NULL,
            LOGON32_LOGON_SERVICE,
            LOGON32_PROVIDER_WINNT50,
            tokenGroups,
            &trustedInstallerToken,
            NULL, NULL, NULL, NULL
        );

        CloseHandle(currentToken);
        LocalFree(tokenGroups);

        if (!logonSuccess)
        {
            DWORD logonError = GetLastError();
        }

    } while (false);

    if (impersonating)
    {
        RevertToSelf();
    }

    if (trustedInstallerSid)
    {
        FreeSid(trustedInstallerSid);
    }

    return trustedInstallerToken;
}

bool CreateProcessWithTIToken(LPCWSTR targetPath, DWORD priority)
{
    if (!EnablePrivilege(false, SeImpersonatePrivilege))
    {
        return false;
    }

    HANDLE tiToken = GetTrustedInstallerToken();
    if (!tiToken)
    {
        return false;
    }

    STARTUPINFOW si = { 0 };
    si.cb = sizeof(si);
    si.lpDesktop = (LPWSTR)L"winsta0\\default";

    PROCESS_INFORMATION pi = { 0 };

    DWORD creationFlags = priority | CREATE_NEW_CONSOLE;

    bool success = CreateProcessWithTokenW(
        tiToken,
        0,
        NULL,
        (LPWSTR)targetPath,
        creationFlags,
        NULL,
        NULL,
        &si,
        &pi
    );

    if (success)
    {
        CloseHandle(pi.hProcess);
        CloseHandle(pi.hThread);
    }

    CloseHandle(tiToken);
    return success;
}

BOOL CheckAdministratorPrivileges()
{
    SID_IDENTIFIER_AUTHORITY NtAuthority = SECURITY_NT_AUTHORITY;
    PSID AdministratorsGroup;
    if (!AllocateAndInitializeSid(&NtAuthority, 2,
        SECURITY_BUILTIN_DOMAIN_RID, DOMAIN_ALIAS_RID_ADMINS,
        0, 0, 0, 0, 0, 0, &AdministratorsGroup))
    {
        return FALSE;
    }

    BOOL bMember = FALSE;
    if (CheckTokenMembership(NULL, AdministratorsGroup, &bMember) != ERROR_SUCCESS)
    {
        bMember = FALSE;
    }
    FreeSid(AdministratorsGroup);

    if (!bMember) return FALSE;

    HANDLE hToken = NULL;
    if (!OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &hToken))
        return FALSE;

    TOKEN_ELEVATION elevation;
    DWORD dwSize;
    BOOL bElevated = FALSE;
    if (GetTokenInformation(hToken, TokenElevation, &elevation, sizeof(elevation), &dwSize))
    {
        bElevated = elevation.TokenIsElevated;
    }
    CloseHandle(hToken);

    return bElevated;
}

bool ValidateExecutablePath(const AnsiString& path)
{
    if (path.IsEmpty()) return false;
    if (path.Length() > MAX_PATH) return false;

    if (!IsPathTraversalSafe(path)) return false;

    AnsiString validatedPath = path;

    // If file doesn't exist at given path, try to find it in PATH
    if (!FileExists(validatedPath)) {
        AnsiString exeName = ExtractFileName(validatedPath);
        AnsiString foundPath = FindExecutableInPath(exeName);
        if (!foundPath.IsEmpty()) {
            validatedPath = foundPath;
        } else {
            return false; // File not found in PATH either
        }
    }

    AnsiString ext = ExtractFileExt(validatedPath).LowerCase();
    if (ext != ".exe" && ext != ".bat" && ext != ".cmd" && ext != ".com") return false;

    return IsValidExecutable(validatedPath);
}

bool SanitizePath(AnsiString& path)
{
    path = path.Trim();

    // If path doesn't contain drive letter and doesn't start with backslash
    if (!IsPathDelimiter(path, 1) && path.Pos(":") != 2) {
        // Check if it's just a filename that might exist in PATH
        if (path.Pos("\\") == 0 && path.Pos("/") == 0) {
            // It's just a filename, don't modify it - let ValidateExecutablePath handle PATH search
        } else {
            // It has relative path components, add current directory
            char currentDir[MAX_PATH];
            if (GetCurrentDirectoryA(MAX_PATH, currentDir)) {
                path = AnsiString(currentDir) + "\\" + path;
            }
        }
    }

    path = StringReplace(path, "/", "\\", TReplaceFlags() << rfReplaceAll);

    while (path.Pos("\\\\") > 0) {
        path = StringReplace(path, "\\\\", "\\", TReplaceFlags() << rfReplaceAll);
    }

    return !path.IsEmpty();
}

bool IsPathTraversalSafe(const AnsiString& path)
{
    if (path.Pos("..\\") > 0 || path.Pos("../") > 0) return false;
    if (path.Pos("\\..") > 0 || path.Pos("/..") > 0) return false;

    const char* suspiciousChars = "<>\"|?*";
    for (int i = 1; i <= path.Length(); i++) {
        if (strchr(suspiciousChars, path[i])) return false;
    }

    return true;
}

bool ValidatePriorityValue(int priority)
{
    return (priority == IDLE_PRIORITY_CLASS ||
            priority == BELOW_NORMAL_PRIORITY_CLASS ||
            priority == NORMAL_PRIORITY_CLASS ||
            priority == ABOVE_NORMAL_PRIORITY_CLASS ||
            priority == HIGH_PRIORITY_CLASS ||
            priority == REALTIME_PRIORITY_CLASS);
}

bool IsValidExecutable(const AnsiString& path)
{
    DWORD handle;
    DWORD size = GetFileVersionInfoSizeA(path.c_str(), &handle);

    if (size == 0) {
        DWORD error = GetLastError();
        return false;
    }

    HANDLE hFile = CreateFileA(path.c_str(), GENERIC_READ, FILE_SHARE_READ,
                              NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);

    if (hFile == INVALID_HANDLE_VALUE) {
        return false;
    }

    CloseHandle(hFile);
    return true;
}

AnsiString FindExecutableInPath(const AnsiString& exeName)
{
    // Get PATH environment variable
    char* pathEnv = getenv("PATH");
    if (!pathEnv) return "";

    AnsiString pathStr = pathEnv;
    AnsiString result = "";

    // If exeName doesn't have extension, add .exe
    AnsiString searchName = exeName;
    if (ExtractFileExt(searchName).IsEmpty()) {
        searchName += ".exe";
    }

    // Split PATH by semicolons
    TStringList* pathList = new TStringList();
    try {
        pathList->Delimiter = ';';
        pathList->DelimitedText = pathStr;

        // Check each directory in PATH
        for (int i = 0; i < pathList->Count; i++) {
            AnsiString dir = pathList->Strings[i].Trim();
            if (dir.IsEmpty()) continue;

            // Ensure directory ends with backslash
            if (!dir.IsEmpty() && dir[dir.Length() - 1] != '\\') {
                dir += "\\";
            }

            AnsiString fullPath = dir + searchName;

            // Check if file exists
            if (FileExists(fullPath)) {
                result = fullPath;
                break;
            }
        }
    }
    __finally {
        delete pathList;
    }

    return result;
}

AnsiString GetErrorMessage(const AnsiString& message)
{
    return AnsiString("Error: ") + message;
}

AnsiString GetErrorMessageCode(const AnsiString& message, DWORD errorCode)
{
    char buffer[32];
    sprintf(buffer, "%lu", errorCode);
    return AnsiString("Error: ") + message + AnsiString(" (Error Code: ") + AnsiString(buffer) + ")";
}
