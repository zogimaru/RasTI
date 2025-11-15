/**
 * @file Core.cpp
 * @brief Implementasi Core Engine untuk RasTI
 *
 * File ini berisi implementasi fungsi-fungsi privilege escalation dan
 * manajemen Trusted Installer token. Menggunakan teknik-teknik Windows
 * security untuk mendapatkan akses elevated.
 *
 * @author RasTI Development Team
 * @version 1.1.0.0
 * @date 2025
 */

#include "Core.h"
#include <System.hpp>
#include <System.Classes.hpp>
#include <cstdio>
#include <SysUtils.hpp>

//==============================================================================
// GLOBAL FUNCTION POINTERS
//==============================================================================

/** @brief Global function pointer untuk RtlAdjustPrivilege dari ntdll.dll */
_RtlAdjustPrivilege pRtlAdjustPrivilege = NULL;

/** @brief Global function pointer untuk LogonUserExExW dari advapi32.dll */
_LogonUserExExW pLogonUserExExW = NULL;

//==============================================================================
// DYNAMIC FUNCTION RESOLUTION
//==============================================================================

/**
 * @brief Menginisialisasi function pointers untuk dynamic linking
 *
 * Function ini memuat alamat fungsi dari DLL sistem menggunakan GetProcAddress.
 * Diperlukan karena beberapa fungsi Windows tidak tersedia dalam header standar
 * dan harus diakses secara dynamic untuk menghindari dependency issues.
 *
 * Loaded functions:
 * - RtlAdjustPrivilege: Untuk mengatur privilege process/thread
 * - LogonUserExExW: Untuk membuat logon session dengan custom token groups
 *
 * @note Harus dipanggil sekali di awal aplikasi sebelum menggunakan privilege functions
 * @warning Jika loading gagal, privilege operations akan tidak berfungsi
 */
void ResolveDynamicFunctions()
{
    // Load RtlAdjustPrivilege dari ntdll.dll
    // ntdll.dll selalu loaded di setiap process Windows
    HMODULE ntdll = GetModuleHandleW(L"ntdll.dll");
    if (ntdll)
    {
        // Cast function pointer ke tipe yang benar
        pRtlAdjustPrivilege = (_RtlAdjustPrivilege)GetProcAddress(ntdll, "RtlAdjustPrivilege");
    }

    // Load LogonUserExExW dari advapi32.dll
    // advapi32.dll berisi Advanced API functions
    HMODULE hAdvapi32 = GetModuleHandleW(L"advapi32.dll");
    if (hAdvapi32)
    {
        // Cast function pointer ke tipe yang benar
        pLogonUserExExW = (_LogonUserExExW)GetProcAddress(hAdvapi32, "LogonUserExExW");
    }
}

/**
 * @brief Mengaktifkan privilege Windows untuk process atau thread
 *
 * Function ini menggunakan RtlAdjustPrivilege (undocumented Windows API) untuk
 * mengaktifkan privilege tertentu. Privilege yang didukung dibatasi untuk keamanan.
 *
 * Privilege yang didukung:
 * - SE_TCB_PRIVILEGE: Trusted Computing Base (akses sistem terbatas)
 * - SE_DEBUG_PRIVILEGE: Debug privilege (akses process lain)
 * - SE_IMPERSONATE_PRIVILEGE: Impersonation privilege (meniru user lain)
 *
 * @param impersonating true jika sedang menjalankan dalam konteks thread impersonation
 * @param privilege_value Konstanta privilege yang akan diaktifkan
 * @return true jika privilege berhasil diaktifkan, false jika gagal
 *
 * @note Function ini hanya menerima privilege yang telah divalidasi untuk mencegah abuse
 * @warning Memerlukan function pointer pRtlAdjustPrivilege yang sudah diinisialisasi
 * @see ResolveDynamicFunctions untuk inisialisasi function pointer
 */
bool EnablePrivilege(bool impersonating, int privilege_value)
{
    // Pastikan function pointer sudah di-load
    if (!pRtlAdjustPrivilege)
    {
        return false;
    }

    // SECURITY: Validasi privilege value - hanya izinkan privilege yang diketahui aman
    // Ini mencegah abuse dengan privilege arbitrer yang berpotensi berbahaya
    switch (privilege_value)
    {
    case SE_TCB_PRIVILEGE:       // Trusted Computing Base - akses sistem terbatas
    case SE_DEBUG_PRIVILEGE:     // Debug privilege - akses process debugging
    case SE_IMPERSONATE_PRIVILEGE: // Impersonation - meniru security context lain
        break; // Privilege valid, lanjutkan
    default:
        return false; // Privilege tidak dikenal atau berbahaya - tolak
    }

    // Panggil RtlAdjustPrivilege untuk mengaktifkan privilege
    // Parameter: privilege, enable=true, thread_privilege, previous_value
    bool previous; // Akan berisi status privilege sebelum perubahan
    NTSTATUS status = pRtlAdjustPrivilege(privilege_value, true, impersonating, &previous);

    // Return true jika operasi NT berhasil (status >= 0)
    return NT_SUCCESS(status);
}

/**
 * @brief Impersonate token dari winlogon.exe untuk mendapatkan TCB privilege
 *
 * Teknik privilege escalation ini digunakan ketika proses tidak memiliki
 * SeTcbPrivilege secara langsung. Winlogon.exe berjalan sebagai LocalSystem
 * dan memiliki TCB privilege yang dapat diimpersonate.
 *
 * Algoritma:
 * 1. Enumerasi semua proses menggunakan ToolHelp32 API
 * 2. Cari proses winlogon.exe (PID yang dibutuhkan)
 * 3. Buka handle ke proses winlogon dengan PROCESS_QUERY_INFORMATION
 * 4. Ekstrak access token dari proses tersebut
 * 5. Impersonate token menggunakan ImpersonateLoggedOnUser
 *
 * @return true jika impersonation berhasil, false jika gagal
 *
 * @warning Memerlukan SeDebugPrivilege untuk mengakses process token winlogon
 * @note Winlogon.exe selalu berjalan dan memiliki LocalSystem privileges
 * @see EnablePrivilege untuk mengaktifkan SeDebugPrivilege yang diperlukan
 */
bool ImpersonateTcbToken()
{
    // STEP 1: Buat snapshot dari semua proses yang sedang berjalan
    // TH32CS_SNAPPROCESS = snapshot process list
    HANDLE hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (hSnapshot == INVALID_HANDLE_VALUE)
    {
        return false; // Gagal membuat snapshot
    }

    // STEP 2: Persiapkan struktur untuk enumerasi proses
    PROCESSENTRY32W entry = { 0 };
    entry.dwSize = sizeof(entry); // Wajib diisi untuk Process32First/Next

    // Mulai enumerasi dari proses pertama
    if (!Process32FirstW(hSnapshot, &entry))
    {
        CloseHandle(hSnapshot);
        return false; // Tidak ada proses atau error
    }

    // STEP 3: Cari proses winlogon.exe dalam snapshot
    DWORD winlogonPid = 0;
    do
    {
        // Bandingkan nama executable (case-insensitive)
        if (!_wcsicmp(L"winlogon.exe", entry.szExeFile))
        {
            winlogonPid = entry.th32ProcessID; // Simpan PID winlogon
            break; // Keluar dari loop jika ditemukan
        }
    } while (Process32NextW(hSnapshot, &entry)); // Lanjut ke proses berikutnya

    // Cleanup snapshot handle
    CloseHandle(hSnapshot);

    // Jika winlogon tidak ditemukan, return false
    if (!winlogonPid)
    {
        return false;
    }

    // STEP 4: Buka handle ke proses winlogon
    // PROCESS_QUERY_INFORMATION = dapat query informasi proses
    HANDLE hProcess = OpenProcess(PROCESS_QUERY_INFORMATION, FALSE, winlogonPid);
    if (!hProcess)
    {
        return false; // Gagal membuka proses (kemungkinan permission denied)
    }

    // STEP 5: Ekstrak access token dari proses winlogon
    HANDLE hToken;
    // TOKEN_QUERY = dapat query token information
    // TOKEN_DUPLICATE = dapat duplicate token
    // TOKEN_IMPERSONATE = dapat impersonate token
    bool tokenSuccess = OpenProcessToken(hProcess, TOKEN_QUERY | TOKEN_DUPLICATE | TOKEN_IMPERSONATE, &hToken);

    // Cleanup process handle (sudah tidak diperlukan)
    CloseHandle(hProcess);

    if (!tokenSuccess)
    {
        return false; // Gagal mendapatkan token
    }

    // STEP 6: Impersonate token winlogon
    // Ini memberikan kita LocalSystem privileges termasuk TCB privilege
    bool impersonateSuccess = ImpersonateLoggedOnUser(hToken);

    // Cleanup token handle
    CloseHandle(hToken);

    if (!impersonateSuccess)
    {
        return false; // Impersonation gagal
    }

    // SUCCESS: Sekarang thread ini berjalan dengan LocalSystem privileges
    return true;
}

/**
 * @brief Mendapatkan handle ke Trusted Installer access token
 *
 * Function utama untuk privilege escalation. Membuat token dengan privilege
 * Trusted Installer menggunakan teknik logon session dengan custom token groups.
 *
 * Algoritma Privilege Escalation:
 * 1. Coba aktifkan SeTcbPrivilege secara langsung
 * 2. Jika gagal, aktifkan SeDebugPrivilege dan impersonate winlogon.exe
 * 3. Convert Trusted Installer SID string ke binary SID
 * 4. Dapatkan token groups dari current process/thread
 * 5. Tambahkan Trusted Installer SID ke token groups
 * 6. Buat logon session menggunakan LogonUserExExW dengan custom groups
 *
 * Teknik ini memanfaatkan fakta bahwa LogonUserExExW dapat membuat token
 * dengan privilege level tertinggi jika diberikan custom token groups yang
 * mengandung Trusted Installer SID.
 *
 * @return HANDLE ke Trusted Installer token, atau NULL jika gagal
 *
 * @note Token harus ditutup dengan CloseHandle() setelah digunakan
 * @warning Memerlukan administrator privileges untuk berfungsi
 * @see ImpersonateTcbToken untuk fallback impersonation technique
 * @see CreateProcessWithTIToken untuk penggunaan token ini
 */
HANDLE GetTrustedInstallerToken()
{
    // Inisialisasi variabel lokal
    bool impersonating = false;                    // Flag apakah sedang impersonating
    HANDLE trustedInstallerToken = NULL;          // Output: TI token handle
    PSID trustedInstallerSid = NULL;              // TI SID dalam format binary
    HANDLE currentToken = NULL;                   // Token dari current process/thread
    PTOKEN_GROUPS tokenGroups = NULL;             // Custom token groups untuk logon

    // Gunakan do-while(false) pattern untuk error handling yang bersih
    // Break dari loop = early return dengan cleanup
    do
    {
        // STEP 1: Pastikan kita memiliki TCB privilege
        // Coba aktifkan SeTcbPrivilege secara langsung terlebih dahulu
        if (!EnablePrivilege(false, SeTcbPrivilege))
        {
            // Jika gagal, coba teknik impersonation sebagai fallback
            // Pertama aktifkan SeDebugPrivilege untuk mengakses process lain
            if (!EnablePrivilege(false, SeDebugPrivilege))
            {
                break; // Tidak dapat mendapatkan privilege yang diperlukan
            }

            // Impersonate winlogon.exe untuk mendapatkan LocalSystem privileges
            impersonating = ImpersonateTcbToken();
            if (!impersonating || !EnablePrivilege(impersonating, SeTcbPrivilege))
            {
                break; // Impersonation atau privilege activation gagal
            }
        }

        // STEP 2: Convert Trusted Installer SID dari string ke binary format
        // TRUSTED_INSTALLER_SID = "S-1-5-80-956008885-3418522649-1831038044-1853292631-2271478464"
        if (!ConvertStringSidToSidA(TRUSTED_INSTALLER_SID, &trustedInstallerSid))
        {
            break; // SID conversion gagal
        }

        // STEP 3: Dapatkan handle ke current access token
        // Jika sedang impersonating, gunakan thread token, jika tidak gunakan process token
        if (impersonating)
        {
            // Dalam konteks impersonation, gunakan thread token
            if (!OpenThreadToken(GetCurrentThread(), TOKEN_QUERY, FALSE, &currentToken))
            {
                break; // Gagal mendapatkan thread token
            }
        }
        else
        {
            // Gunakan process token
            if (!OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &currentToken))
            {
                break; // Gagal mendapatkan process token
            }
        }

        // STEP 4: Query informasi token groups untuk mengetahui ukuran buffer yang dibutuhkan
        DWORD tokenGroupsSize = 0;
        if (!GetTokenInformation(currentToken, TokenGroups, NULL, 0, &tokenGroupsSize) &&
            GetLastError() != ERROR_INSUFFICIENT_BUFFER)
        {
            break; // Error selain insufficient buffer (unexpected error)
        }

        // Alokasikan memory untuk token groups
        tokenGroups = (PTOKEN_GROUPS)LocalAlloc(LPTR, tokenGroupsSize);
        if (!tokenGroups)
        {
            break; // Memory allocation gagal
        }

        // STEP 5: Query token groups information
        if (!GetTokenInformation(currentToken, TokenGroups, tokenGroups, tokenGroupsSize, &tokenGroupsSize))
        {
            break; // Gagal mendapatkan token groups
        }

        // STEP 6: Tambahkan Trusted Installer SID ke token groups
        // Kita akan menimpa group terakhir dengan TI SID
        DWORD lastGroupIndex = tokenGroups->GroupCount - 1;
        tokenGroups->Groups[lastGroupIndex].Sid = trustedInstallerSid;
        tokenGroups->Groups[lastGroupIndex].Attributes = SE_GROUP_OWNER | SE_GROUP_ENABLED;

        // STEP 7: Buat logon session dengan custom token groups
        // LogonUserExExW dengan custom groups dapat membuat token dengan privilege tinggi
        bool logonSuccess = pLogonUserExExW(
            (LPWSTR)L"SYSTEM",                    // Username: SYSTEM
            (LPWSTR)L"NT AUTHORITY",              // Domain: NT AUTHORITY
            NULL,                                 // Password: NULL (service logon)
            LOGON32_LOGON_SERVICE,                // Logon type: Service
            LOGON32_PROVIDER_WINNT50,             // Provider: WinNT 5.0
            tokenGroups,                          // Custom token groups dengan TI SID
            &trustedInstallerToken,               // Output: TI token handle
            NULL, NULL, NULL, NULL                // Parameter lainnya tidak digunakan
        );

        // Catat error jika logon gagal (untuk debugging)
        if (!logonSuccess)
        {
            DWORD logonError = GetLastError();
            (void)logonError; // Suppress unused variable warning
        }

    } while (false); // End of do-while error handling pattern

    // CLEANUP: Pastikan semua resources dibersihkan
    if (tokenGroups)
    {
        LocalFree(tokenGroups); // Bebaskan memory token groups
    }

    if (currentToken)
    {
        CloseHandle(currentToken); // Tutup token handle
    }

    if (impersonating)
    {
        RevertToSelf(); // Kembali ke security context asli
    }

    if (trustedInstallerSid)
    {
        FreeSid(trustedInstallerSid); // Bebaskan SID memory
    }

    // Return TI token handle (NULL jika gagal, valid handle jika berhasil)
    return trustedInstallerToken;
}

/**
 * @brief Membuat proses baru dengan Trusted Installer token
 *
 * Function ini adalah endpoint utama aplikasi. Menggunakan token Trusted Installer
 * yang didapat dari GetTrustedInstallerToken() untuk menjalankan executable
 * dengan privilege tertinggi di sistem.
 *
 * @param targetPath Path lengkap ke executable yang akan dijalankan
 * @param priority Class priority untuk proses baru (IDLE_PRIORITY_CLASS, etc.)
 * @return true jika proses berhasil dibuat, false jika gagal
 *
 * @note Proses akan berjalan dengan Trusted Installer privileges
 * @warning Executable path harus sudah tervalidasi sebelum pemanggilan
 * @see GetTrustedInstallerToken untuk akuisisi token
 * @see ValidateExecutablePath untuk validasi path
 */
bool CreateProcessWithTIToken(LPCWSTR targetPath, DWORD priority)
{
    // STEP 1: Pastikan kita memiliki SeImpersonatePrivilege
    // Diperlukan untuk CreateProcessWithTokenW
    if (!EnablePrivilege(false, SeImpersonatePrivilege))
    {
        return false; // Gagal mengaktifkan privilege yang diperlukan
    }

    // STEP 2: Dapatkan Trusted Installer token
    HANDLE tiToken = GetTrustedInstallerToken();
    if (!tiToken)
    {
        return false; // Gagal mendapatkan TI token
    }

    // STEP 3: Persiapkan struktur STARTUPINFO untuk proses baru
    STARTUPINFOW si = { 0 };
    si.cb = sizeof(si); // Wajib diisi dengan ukuran struktur
    si.lpDesktop = (LPWSTR)L"winsta0\\default"; // Desktop untuk proses baru

    // Struktur untuk menerima informasi proses yang dibuat
    PROCESS_INFORMATION pi = { 0 };

    // STEP 4: Gabungkan priority dengan CREATE_NEW_CONSOLE flag
    DWORD creationFlags = priority | CREATE_NEW_CONSOLE;

    // STEP 5: Buat proses dengan Trusted Installer token
    // CreateProcessWithTokenW akan menjalankan proses dengan security context TI
    bool success = CreateProcessWithTokenW(
        tiToken,              // Token untuk menjalankan proses
        0,                    // Logon flags (tidak digunakan)
        NULL,                 // Application name (NULL = gunakan command line)
        (LPWSTR)targetPath,   // Command line (executable path)
        creationFlags,        // Creation flags (priority + new console)
        NULL,                 // Environment (inherit dari parent)
        NULL,                 // Current directory (inherit dari parent)
        &si,                  // Startup info
        &pi                   // Process information output
    );

    // STEP 6: Cleanup handles jika proses berhasil dibuat
    if (success)
    {
        // Tutup handles ke proses dan thread yang baru dibuat
        // Proses akan terus berjalan secara independen
        CloseHandle(pi.hProcess);
        CloseHandle(pi.hThread);
    }

    // Cleanup TI token handle
    CloseHandle(tiToken);

    // Return status keberhasilan
    return success;
}

/**
 * @brief Mengecek apakah proses memiliki administrator privileges
 *
 * Function ini melakukan pemeriksaan bertingkat untuk menentukan level privilege proses:
 * 1. Pertama cek apakah memiliki Trusted Installer privilege (SeTcbPrivilege)
 * 2. Jika tidak, cek traditional administrator group membership
 * 3. Jika member admin group, cek apakah token elevated (UAC)
 *
 * @return TRUE jika memiliki admin privileges atau TI privileges, FALSE jika tidak
 *
 * @note Trusted Installer privilege dianggap sebagai "super admin" level
 * @see GetTrustedInstallerToken untuk privilege escalation
 */
BOOL CheckAdministratorPrivileges()
{
    // STEP 1: Cek apakah sudah memiliki Trusted Installer privileges
    // TCB privilege menunjukkan proses sudah berjalan sebagai Trusted Installer
    HANDLE hToken = NULL;
    if (OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &hToken))
    {
        PTOKEN_PRIVILEGES privileges = NULL;
        DWORD privilegesSize;

        // Query ukuran buffer yang dibutuhkan untuk privilege information
        GetTokenInformation(hToken, TokenPrivileges, NULL, 0, &privilegesSize);
        privileges = (PTOKEN_PRIVILEGES)LocalAlloc(LPTR, privilegesSize);

        if (privileges)
        {
            // Query privilege information
            if (GetTokenInformation(hToken, TokenPrivileges, privileges, privilegesSize, &privilegesSize))
            {
                // Iterasi melalui semua privileges yang dimiliki token
                for (DWORD i = 0; i < privileges->PrivilegeCount; i++)
                {
                    // Cek apakah memiliki SeTcbPrivilege dan privilege tersebut enabled
                    if (privileges->Privileges[i].Luid.LowPart == SE_TCB_PRIVILEGE &&
                        (privileges->Privileges[i].Attributes & SE_PRIVILEGE_ENABLED))
                    {
                        // SUCCESS: Memiliki Trusted Installer privilege
                        LocalFree(privileges);
                        CloseHandle(hToken);
                        return TRUE; // Has TCB privilege (Trusted Installer)
                    }
                }
            }
            LocalFree(privileges);
        }
        CloseHandle(hToken);
    }

    // STEP 2: Cek traditional administrator privileges
    // Jika tidak memiliki TI privilege, cek apakah member dari Administrators group

    // Buat SID untuk Built-in Administrators group
    // S-1-5-32-544 = DOMAIN_ALIAS_RID_ADMINS
    SID_IDENTIFIER_AUTHORITY NtAuthority = SECURITY_NT_AUTHORITY;
    PSID AdministratorsGroup;
    if (!AllocateAndInitializeSid(&NtAuthority, 2,
        SECURITY_BUILTIN_DOMAIN_RID, DOMAIN_ALIAS_RID_ADMINS,
        0, 0, 0, 0, 0, 0, &AdministratorsGroup))
    {
        return FALSE; // Gagal membuat SID
    }

    // Cek apakah current user adalah member dari Administrators group
    BOOL bMember = FALSE;
    if (CheckTokenMembership(NULL, AdministratorsGroup, &bMember) != ERROR_SUCCESS)
    {
        bMember = FALSE; // Error dalam pengecekan, anggap bukan member
    }
    FreeSid(AdministratorsGroup); // Cleanup SID

    if (!bMember) return FALSE; // Bukan member admin group

    // STEP 3: Cek apakah admin token elevated (UAC)
    // Di Windows Vista+, admin accounts memiliki dua token:
    // - Filtered token (limited privileges) - digunakan secara default
    // - Elevated token (full privileges) - digunakan ketika UAC elevation

    hToken = NULL;
    if (!OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &hToken))
        return FALSE; // Gagal mendapatkan token

    TOKEN_ELEVATION elevation;
    DWORD dwSize;
    BOOL bElevated = FALSE;

    // Query elevation status dari token
    if (GetTokenInformation(hToken, TokenElevation, &elevation, sizeof(elevation), &dwSize))
    {
        bElevated = elevation.TokenIsElevated; // TRUE jika elevated
    }
    CloseHandle(hToken);

    // Return TRUE hanya jika admin group member DAN token elevated
    return bElevated;
}

/**
 * @brief Validasi komprehensif untuk path executable
 *
 * Melakukan multiple validation layers:
 * 1. Path tidak kosong dan tidak terlalu panjang
 * 2. Tidak mengandung path traversal attacks
 * 3. File exists (atau dapat ditemukan di PATH)
 * 4. Extension valid (.exe, .bat, .cmd, .com)
 * 5. File dapat diakses dan merupakan executable valid
 *
 * @param path Path yang akan divalidasi
 * @return true jika semua validasi berhasil, false jika ada yang gagal
 *
 * @note Menggunakan FindExecutableInPath jika file tidak ditemukan di path spesifik
 * @see SanitizePath untuk normalisasi path sebelum validasi
 * @see IsPathTraversalSafe untuk security checks
 */
bool ValidateExecutablePath(const AnsiString& path)
{
    // VALIDATION 1: Basic path checks
    if (path.IsEmpty()) return false; // Path kosong tidak valid
    if (path.Length() > MAX_PATH) return false; // Path terlalu panjang

    // VALIDATION 2: Path traversal security check
    if (!IsPathTraversalSafe(path)) return false; // Mengandung traversal attacks

    AnsiString validatedPath = path;

    // VALIDATION 3: File existence check
    // Jika file tidak ada di path spesifik, coba cari di PATH environment
    if (!FileExists(validatedPath)) {
        AnsiString exeName = ExtractFileName(validatedPath); // Ambil nama file saja
        AnsiString foundPath = FindExecutableInPath(exeName); // Cari di PATH
        if (!foundPath.IsEmpty()) {
            validatedPath = foundPath; // Gunakan path dari PATH
        } else {
            return false; // File tidak ditemukan di path spesifik maupun PATH
        }
    }

    // VALIDATION 4: Extension check
    AnsiString ext = ExtractFileExt(validatedPath).LowerCase();
    if (ext != ".exe" && ext != ".bat" && ext != ".cmd" && ext != ".com") return false;

    // VALIDATION 5: Executable validation
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
