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

#define SE_CREATE_TOKEN_PRIVILEGE 1
#define SE_ASSIGNPRIMARYTOKEN_PRIVILEGE 3
#define SE_LOCK_MEMORY_PRIVILEGE 4
#define SE_INCREASE_QUOTA_PRIVILEGE 5
#define SE_UNSOLICITED_INPUT_PRIVILEGE 6
#define SE_MACHINE_ACCOUNT_PRIVILEGE 11
#define SE_TCB_PRIVILEGE 7
#define SE_SECURITY_PRIVILEGE 8
#define SE_TAKE_OWNERSHIP_PRIVILEGE 9
#define SE_LOAD_DRIVER_PRIVILEGE 10
#define SE_SYSTEM_PROFILE_PRIVILEGE 12
#define SE_SYSTEMTIME_PRIVILEGE 12
#define SE_PROF_SINGLE_PROCESS_PRIVILEGE 13
#define SE_INC_BASE_PRIORITY_PRIVILEGE 14
#define SE_CREATE_PAGEFILE_PRIVILEGE 15
#define SE_CREATE_PERMANENT_PRIVILEGE 16
#define SE_BACKUP_PRIVILEGE 17
#define SE_RESTORE_PRIVILEGE 18
#define SE_SHUTDOWN_PRIVILEGE 19
#define SE_DEBUG_PRIVILEGE 20
#define SE_AUDIT_PRIVILEGE 21
#define SE_SYSTEM_ENVIRONMENT_PRIVILEGE 22
#define SE_CHANGE_NOTIFY_PRIVILEGE 23
#define SE_REMOTE_SHUTDOWN_PRIVILEGE 24
#define SE_UNDOCK_PRIVILEGE 25
#define SE_SYNC_AGENT_PRIVILEGE 26
#define SE_ENABLE_DELEGATION_PRIVILEGE 27
#define SE_MANAGE_VOLUME_PRIVILEGE 28
#define SE_IMPERSONATE_PRIVILEGE 29
#define SE_CREATE_GLOBAL_PRIVILEGE 30
#define SE_TRUSTED_CREDMAN_ACCESS_PRIVILEGE 31
#define SE_RELABEL_PRIVILEGE 32
#define SE_INC_WORKING_SET_PRIVILEGE 33
#define SE_TIME_ZONE_PRIVILEGE 34
#define SE_CREATE_SYMBOLIC_LINK_PRIVILEGE 35

// Backward compatibility
#define SeTcbPrivilege SE_TCB_PRIVILEGE
#define SeDebugPrivilege SE_DEBUG_PRIVILEGE
#define SeImpersonatePrivilege SE_IMPERSONATE_PRIVILEGE

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
