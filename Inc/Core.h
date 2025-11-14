#ifndef RASTI_H
#define RASTI_H

#include <Windows.h>
#include <stdio.h>
#include <tlhelp32.h>
#include <sddl.h>
#include <tchar.h>
#include <System.hpp>

#define NT_SUCCESS(status) ((status) >= 0)
#define GLE GetLastError()

#define SeTcbPrivilege 7
#define SeDebugPrivilege 20
#define SeImpersonatePrivilege 29

#define TRUSTED_INSTALLER_SID "S-1-5-80-956008885-3418522649-1831038044-1853292631-2271478464"

typedef NTSTATUS(NTAPI* _RtlAdjustPrivilege)(int Privilege, bool Enable, bool ThreadPrivilege, bool* Previous);

typedef BOOL(WINAPI* _LogonUserExExW)(
    _In_      LPWSTR        lpszUsername,
    _In_opt_  LPWSTR        lpszDomain,
    _In_opt_  LPWSTR        lpszPassword,
    _In_      DWORD         dwLogonType,
    _In_      DWORD         dwLogonProvider,
    _In_opt_  PTOKEN_GROUPS pTokenGroups,
    _Out_opt_ PHANDLE       phToken,
    _Out_opt_ PSID* ppLogonSid,
    _Out_opt_ PVOID* ppProfileBuffer,
    _Out_opt_ LPDWORD       pdwProfileLength,
    _Out_opt_ PQUOTA_LIMITS pQuotaLimits
);

extern _RtlAdjustPrivilege pRtlAdjustPrivilege;
extern _LogonUserExExW pLogonUserExExW;

void ResolveDynamicFunctions();
bool EnablePrivilege(bool impersonating, int privilege_value);
bool ImpersonateTcbToken();
HANDLE GetTrustedInstallerToken();
bool CreateProcessWithTIToken(LPCWSTR targetPath, DWORD priority);

BOOL CheckAdministratorPrivileges();

bool ValidateExecutablePath(const AnsiString& path);
bool SanitizePath(AnsiString& path);
bool IsPathTraversalSafe(const AnsiString& path);
bool ValidatePriorityValue(int priority);
bool IsValidExecutable(const AnsiString& path);
AnsiString FindExecutableInPath(const AnsiString& exeName);

AnsiString GetErrorMessage(const AnsiString& message);
AnsiString GetErrorMessageCode(const AnsiString& message, DWORD errorCode);

#endif
