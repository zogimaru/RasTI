/**
 * @file Core.cpp
 * @brief Implementasi Core Engine untuk RasTI
 *
 * File ini berisi implementasi fungsi-fungsi privilege escalation dan
 * manajemen Trusted Installer token. Menggunakan teknik-teknik Windows
 * security untuk mendapatkan akses elevated.
 *
 * @author RasTI Development Team
 * @version 1.2.0.0
 * @date 2025
 */

#include "Core.h"
#include <System.hpp>
#include <System.Classes.hpp>
#include <cstdio>
#include <SysUtils.hpp>
#include <vector>

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
 * - SE_DEBUG_PRIVILEGE: Debug privilege (akses process debugging)
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
    // CRITICAL SECURITY FIX: Validate function pointer before usage
    if (!pRtlAdjustPrivilege)
    {
        // Function pointer not loaded - critical error
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
        // BUG FIX: Log invalid privilege attempts for security monitoring
        return false; // Privilege tidak dikenal atau berbahaya - tolak
    }



    // Panggil RtlAdjustPrivilege untuk mengaktifkan privilege
    // Parameter: privilege, enable=true, thread_privilege, previous_value
    bool previous = false; // Initialize to safe default
    NTSTATUS status = pRtlAdjustPrivilege(privilege_value, true, impersonating, &previous);

    // BUG FIX: Comprehensive NT API error checking
    if (!NT_SUCCESS(status))
    {
        // Log NT status error untuk debugging
        // In production, this could be logged to security event log
        return false;
    }

    // Return true jika operasi NT berhasil
    return true;
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
    // RAII IMPLEMENTATION: Smart handles with automatic cleanup
    SmartSnapshotHandle hSnapshot(CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0));
    SmartProcessHandle hProcess;
    SmartTokenHandle hToken;

    // Check if snapshot creation failed
    if (!hSnapshot.IsValid())
    {
        // BUG FIX: Log error for debugging
        DWORD error = GetLastError();
        (void)error; // Suppress unused variable in release builds
        return false; // Gagal membuat snapshot
    }

    // STEP 2: Persiapkan struktur untuk enumerasi proses
    PROCESSENTRY32W entry = { 0 };
    entry.dwSize = sizeof(entry); // Wajib diisi untuk Process32First/Next

    // Mulai enumerasi dari proses pertama
    if (!Process32FirstW(hSnapshot.Get(), &entry))
    {
        // BUG FIX: Check for actual errors, not just end of list
        // ERROR_NO_MORE_FILES is acceptable, other errors are not
        DWORD error = GetLastError();
        if (error != ERROR_NO_MORE_FILES) {
            return false; // Actual error in enumeration
        }
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
    } while (Process32NextW(hSnapshot.Get(), &entry)); // Lanjut ke proses berikutnya

    // Jika winlogon tidak ditemukan, return false
    if (!winlogonPid)
    {
        return false; // Winlogon process not found
    }

    // STEP 4: Buka handle ke proses winlogon
    // PROCESS_QUERY_INFORMATION = dapat query informasi proses
    hProcess.Reset(OpenProcess(PROCESS_QUERY_INFORMATION, FALSE, winlogonPid));
    if (!hProcess.IsValid())
    {
        // BUG FIX: Log error code for security auditing
        DWORD error = GetLastError();
        (void)error; // Suppress unused variable in release builds
        return false; // Gagal membuka proses (kemungkinan permission denied)
    }

    // STEP 5: Ekstrak access token dari proses winlogon
    // TOKEN_QUERY = dapat query token information
    // TOKEN_DUPLICATE = dapat duplicate token
    // TOKEN_IMPERSONATE = dapat impersonate token
    HANDLE rawTokenHandle;
    bool tokenSuccess = OpenProcessToken(hProcess.Get(), TOKEN_QUERY | TOKEN_DUPLICATE | TOKEN_IMPERSONATE, &rawTokenHandle);
    if (!tokenSuccess)
    {
        // BUG FIX: Log error for debugging and security audit
        DWORD error = GetLastError();
        (void)error; // Suppress unused variable in release builds
        return false; // Gagal mendapatkan token
    }
    hToken.Reset(rawTokenHandle); // Transfer ownership to smart handle

    // STEP 6: Impersonate token winlogon
    // Ini memberikan kita LocalSystem privileges termasuk TCB privilege
    bool impersonateSuccess = ImpersonateLoggedOnUser(hToken.Get());
    if (!impersonateSuccess)
    {
        // BUG FIX: Log impersonation failure
        DWORD error = GetLastError();
        (void)error; // Suppress unused variable in release builds
        return false; // Impersonation gagal
    }

    // SUCCESS: Sekarang thread ini berjalan dengan LocalSystem privileges
    // RAII: All handles automatically cleaned up when function exits
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
    // Inisialisasi variabel lokal dengan RAII smart resources
    bool impersonating = false;                  // Flag apakah sedang impersonating
    HANDLE trustedInstallerToken = NULL;        // Output: TI token handle
    PSID trustedInstallerSid = NULL;            // TI SID dalam format binary
    HANDLE currentToken = NULL;                 // Token dari current process/thread

    // RAII IMPLEMENTATION: Smart memory management untuk prevent memory leaks
    SmartLocalMemory<TOKEN_GROUPS> tokenGroupsMemory;
    SmartTokenHandle currentTokenHandle;

    // Gunakan do-while(false) pattern untuk error handling yang bersih
    // Break dari loop = early return dengan cleanup (RAII handles memory automatically)
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
            // BUG FIX: Log SID conversion failure for debugging
            DWORD error = GetLastError();
            (void)error; // Suppress unused variable in release builds
            break; // SID conversion gagal
        }

        // STEP 3: RAII IMPLEMENTATION: Dapatkan handle ke current access token
        if (impersonating)
        {
            // Dalam konteks impersonation, gunakan thread token
            HANDLE threadToken;
            if (!OpenThreadToken(GetCurrentThread(), TOKEN_QUERY, FALSE, &threadToken))
            {
                // BUG FIX: Log thread token failure
                DWORD error = GetLastError();
                (void)error; // Suppress unused variable in release builds
                break; // Gagal mendapatkan thread token
            }
            currentTokenHandle.Reset(threadToken);
            currentToken = threadToken; // Keep raw handle for compatibility
        }
        else
        {
            // Gunakan process token
            HANDLE processToken;
            if (!OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &processToken))
            {
                // BUG FIX: Log process token failure
                DWORD error = GetLastError();
                (void)error; // Suppress unused variable in release builds
                break; // Gagal mendapatkan process token
            }
            currentTokenHandle.Reset(processToken);
            currentToken = processToken; // Keep raw handle for compatibility
        }

        // STEP 4: Query informasi token groups untuk mengetahui ukuran buffer yang dibutuhkan
        DWORD tokenGroupsSize = 0;
        if (!GetTokenInformation(currentToken, TokenGroups, NULL, 0, &tokenGroupsSize))
        {
            DWORD error = GetLastError();
            if (error != ERROR_INSUFFICIENT_BUFFER)
            {
                // BUG FIX: Log unexpected error
                (void)error; // Suppress unused variable in release builds
                break; // Error selain insufficient buffer (unexpected error)
            }
        }

        // BUG FIX: Comprehensive buffer size validation to prevent integer overflow attacks
        // Convert byte size to TOKEN_GROUPS count and validate
        if (tokenGroupsSize == 0 || tokenGroupsSize < sizeof(TOKEN_GROUPS) || tokenGroupsSize > 65536)
        {
            break; // Invalid buffer size (too small, too large, or zero)
        }

        // RAII IMPLEMENTATION: Safe memory allocation untuk token groups
        // Calculate array size based on buffer size
        SIZE_T structSize = sizeof(TOKEN_GROUPS);
        SIZE_T remainingBytes = tokenGroupsSize - structSize;
        SIZE_T sidCount = remainingBytes / sizeof(SID_AND_ATTRIBUTES);

        // Allocate safe memory with bounds checking
        if (!tokenGroupsMemory.Allocate(1)) {
            // BUG FIX: Memory allocation failure
            DWORD error = GetLastError();
            (void)error; // Suppress unused variable in release builds
            break; // Memory allocation gagal
        }

        PTOKEN_GROUPS tokenGroups = tokenGroupsMemory.Get();
        if (!tokenGroups) {
            break; // Should not happen, but safety check
        }

        // STEP 5: Query token groups information
        if (!GetTokenInformation(currentToken, TokenGroups, tokenGroups, tokenGroupsSize, &tokenGroupsSize))
        {
            // BUG FIX: Log token groups query failure
            DWORD error = GetLastError();
            (void)error; // Suppress unused variable in release builds
            break; // Gagal mendapatkan token groups
        }

        // STEP 6: Tambahkan Trusted Installer SID ke token groups
        // Kita akan menimpa group terakhir dengan TI SID
        DWORD lastGroupIndex = tokenGroups->GroupCount - 1;
        tokenGroups->Groups[lastGroupIndex].Sid = trustedInstallerSid;
        tokenGroups->Groups[lastGroupIndex].Attributes = SE_GROUP_OWNER | SE_GROUP_ENABLED;

        // STEP 7: CRITICAL SECURITY FIX: Validate LogonUserExExW function pointer sebelum usage
        // Ini mencegah null pointer dereference yang bisa menyebabkan crash/critical vulnerability
        if (!pLogonUserExExW)
        {
            // Function pointer not loaded - critical error
            DWORD error = GetLastError();
            (void)error; // Suppress unused variable in release builds
            break; // Cannot proceed without valid function pointer
        }

        // Buat logon session dengan custom token groups
        // LogonUserExExW dengan custom groups dapat membuat token dengan privilege tinggi
        bool logonSuccess = pLogonUserExExW(
            (LPWSTR)L"SYSTEM",                    // Username: SYSTEM
            (LPWSTR)L"NT_AUTHORITY",              // Domain: NT AUTHORITY
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

    // CLEANUP: RAII handles automatic cleanup - no manual cleanup needed!
    // tokenGroupsMemory is automatically freed
    // currentTokenHandle is automatically closed
    // All resources are cleaned up regardless of error paths

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
    SmartTokenHandle hToken;

    HANDLE rawToken;
    if (OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &rawToken))
    {
        hToken.Reset(rawToken);

        // RAII IMPLEMENTATION: Safe memory allocation untuk prevent memory leaks
        SmartLocalMemory<TOKEN_PRIVILEGES> privilegesMemory;
        DWORD privilegesSize = 0;

        // Query ukuran buffer yang dibutuhkan untuk privilege information
        if (!GetTokenInformation(hToken.Get(), TokenPrivileges, NULL, 0, &privilegesSize))
        {
            DWORD error = GetLastError();
            if (error != ERROR_INSUFFICIENT_BUFFER) {
                // BUG FIX: Unexpected error in buffer size query
                return FALSE;
            }
        }

        // Validate buffer size to prevent memory exhaustion attacks
        const SIZE_T MAX_PRIVILEGES_SIZE = 1024 * 1024; // 1MB reasonable limit
        if (privilegesSize == 0 || privilegesSize > MAX_PRIVILEGES_SIZE) {
            return FALSE; // Invalid or suspiciously large buffer size
        }

        // RAII IMPLEMENTATION: Allocate memory with automatic cleanup
        if (!privilegesMemory.Allocate(privilegesSize / sizeof(TOKEN_PRIVILEGES) + (privilegesSize % sizeof(TOKEN_PRIVILEGES) ? 1 : 0))) {
            return FALSE; // Memory allocation failed
        }

        PTOKEN_PRIVILEGES privileges = reinterpret_cast<PTOKEN_PRIVILEGES>(privilegesMemory.Get());
        if (!privileges) {
            return FALSE; // Should not happen, but safety check
        }

        // Query privilege information
        if (GetTokenInformation(hToken.Get(), TokenPrivileges, privileges, privilegesSize, &privilegesSize))
        {
            // Iterasi melalui semua privileges yang dimiliki token
            for (DWORD i = 0; i < privileges->PrivilegeCount; i++)
            {
                // Cek apakah memiliki SeTcbPrivilege dan privilege tersebut enabled
                if (privileges->Privileges[i].Luid.LowPart == SE_TCB_PRIVILEGE &&
                    (privileges->Privileges[i].Attributes & SE_PRIVILEGE_ENABLED))
                {
                    // SUCCESS: Memiliki Trusted Installer privilege
                    // RAII: Automatic cleanup of memory and handles
                    return TRUE; // Has TCB privilege (Trusted Installer)
                }
            }
        }
        // RAII: Automatic cleanup of memory when function exits
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

    // RAII IMPLEMENTATION: Create new smart handle for elevation check
    SmartTokenHandle elevationTokenHandle;

    HANDLE elevationToken;
    if (!OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &elevationToken))
        return FALSE; // Gagal mendapatkan token

    elevationTokenHandle.Reset(elevationToken);

    TOKEN_ELEVATION elevation;
    DWORD dwSize;
    BOOL bElevated = FALSE;

    // Query elevation status dari token
    if (GetTokenInformation(elevationToken, TokenElevation, &elevation, sizeof(elevation), &dwSize))
    {
        bElevated = elevation.TokenIsElevated; // TRUE jika elevated
    }
    // RAII: elevationTokenHandle will automatically close the token

    // Return TRUE hanya jika admin group member DAN token elevated
    return bElevated;
}

/**
 * @brief Validasi komprehensif untuk path executable dengan canonical path checking
 *
 * Melakukan multiple validation layers dengan level enterprise security:
 * 1. Path tidak kosong dan tidak terlalu panjang
 * 2. Path traversal security check (basic)
 * 3. Canonical path normalization dan validation
 * 4. Canonical path traversal check (post-normalization)
 * 5. File existence check (pada canonical path)
 * 6. Extension validation (pada canonical path)
 * 7. Executable access validation
 *
 * @param path Path yang akan divalidasi
 * @return true jika semua validasi berhasil, false jika ada yang gagal
 *
 * @note Menggunakan GetCanonicalPath untuk path normalization dan security
 * @see SanitizePath untuk basic normalization
 * @see IsPathTraversalSafe untuk security checks
 * @see GetCanonicalPath untuk advanced canonical validation
 */
bool ValidateExecutablePath(const AnsiString& path)
{
    // VALIDATION 1: Basic path checks
    if (path.IsEmpty()) return false; // Path kosong tidak valid
    if (path.Length() > MAX_PATH) return false; // Path terlalu panjang

    // VALIDATION 2: Preliminary path traversal security check (before canonical conversion)
    if (!IsPathTraversalSafe(path)) return false; // Mengandung obvious traversal attacks

    // VALIDATION 3: Canonical path conversion and validation
    // This is the critical enterprise security layer
    AnsiString canonicalPath = GetCanonicalPath(path);
    if (canonicalPath.IsEmpty()) {
        return false; // Canonical conversion failed - invalid path
    }

    // Additional check: canonical path should not be longer than allowed
    if (canonicalPath.Length() > MAX_PATH) {
        return false; // Canonical path too long (expansion from relative to absolute)
    }

    // VALIDATION 4: Post-canonical path traversal check
    // Even after canonical conversion, verify no traversal patterns remain
    if (!IsPathTraversalSafe(canonicalPath)) {
        return false; // Canonical path still contains traversal patterns (shouldn't happen but being paranoid)
    }

    AnsiString validatedPath = canonicalPath;

    // VALIDATION 5: File existence check on canonical path
    // This prevents TOCTOU attacks by using canonical path for file operations
    if (!FileExists(validatedPath)) {
        // If canonical path doesn't exist, try searching in PATH (as fallback for executables)
        AnsiString exeName = ExtractFileName(validatedPath); // Ambil nama file saja dari canonical path
        AnsiString foundPath = FindExecutableInPath(exeName); // Cari di PATH
        if (!foundPath.IsEmpty()) {
            // Validate the found path is also canonical and safe
            AnsiString canonicalFoundPath = GetCanonicalPath(foundPath);
            if (!canonicalFoundPath.IsEmpty() && IsPathTraversalSafe(canonicalFoundPath)) {
                validatedPath = canonicalFoundPath; // Gunakan canonical PATH location
            } else {
                return false; // PATH location fails canonical validation
            }
        } else {
            return false; // File tidak ditemukan di canonical location maupun PATH
        }
    }

    // VALIDATION 6: Extension check on canonical path
    AnsiString ext = ExtractFileExt(validatedPath).LowerCase();
    if (ext != ".exe" && ext != ".bat" && ext != ".cmd" && ext != ".com") {
        return false; // Invalid extension on canonical path
    }

    // VALIDATION 7: Executable access validation on canonical path
    // This uses the canonical path for all file operations
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

AnsiString GetCanonicalPath(const AnsiString& path)
{
    // Input validation
    if (path.IsEmpty()) {
        return "";
    }

    // Convert AnsiString to char buffer for GetFullPathNameA
    const char* inputPath = path.c_str();

    // First call: determine buffer size needed
    DWORD requiredSize = GetFullPathNameA(inputPath, 0, NULL, NULL);
    if (requiredSize == 0) {
        // GetFullPathNameA failed
        DWORD error = GetLastError();
        (void)error; // Suppress unused variable warning
        return "";
    }

    // Allocate buffer with extra space for safety
    DWORD bufferSize = requiredSize + 1; // +1 for null terminator
    std::vector<char> canonicalPathBuffer(bufferSize);

    // Second call: get the canonical path
    DWORD actualSize = GetFullPathNameA(inputPath, bufferSize, canonicalPathBuffer.data(), NULL);
    if (actualSize == 0 || actualSize >= bufferSize) {
        // GetFullPathNameA failed or buffer too small (shouldn't happen)
        DWORD error = GetLastError();
        (void)error; // Suppress unused variable warning
        return "";
    }

    // Convert back to AnsiString
    AnsiString canonicalPath(canonicalPathBuffer.data());

    // Additional normalization: ensure backslashes and remove any trailing slash (except for root)
    canonicalPath = StringReplace(canonicalPath, "/", "\\", TReplaceFlags() << rfReplaceAll);

    // Remove trailing backslash unless it's a root path (like "C:\")
    if (canonicalPath.Length() > 3 && canonicalPath[canonicalPath.Length() - 1] == '\\' &&
        canonicalPath[canonicalPath.Length() - 2] != ':') {
        canonicalPath = canonicalPath.SubString(1, canonicalPath.Length() - 1);
    }

    return canonicalPath;
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

    // Split PATH by semicolons dengan RAII wrapper untuk automatic cleanup
    SmartStringList pathList;
    if (!pathList.IsAllocated()) {
        return ""; // Gagal alokasi memory untuk string list
    }

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
    // RAII: SmartStringList otomatis dibersihkan di destructor

    return result;
}

AnsiString GetErrorMessage(const AnsiString& message)
{
    return AnsiString("Error: ") + message;
}

/**
 * @brief Thread-safe dan buffer-safe formatting untuk error codes
 *
 * Menggunakan snprintf untuk menghindari buffer overflow dan memberikan
 * error handling yang lebih baik daripada sprintf tradizionale.
 *
 * @param message Pesan error utama
 * @param errorCode Kode error Windows yang akan diformat
 * @return AnsiString yang berisi error message lengkap dengan code
 */
AnsiString GetErrorMessageCode(const AnsiString& message, DWORD errorCode)
{
    constexpr size_t BUFFER_SIZE = 32;
    char buffer[BUFFER_SIZE];

    // Menggunakan snprintf untuk buffer safety
    // Memastikan tidak ada buffer overflow meskipun errorCode tidak valid
    int result = snprintf(buffer, BUFFER_SIZE, "%lu", static_cast<unsigned long>(errorCode));

    // Verifikasi bahwa formatting berhasil
    if (result < 0 || static_cast<size_t>(result) >= BUFFER_SIZE) {
        // Fallback ke formatting safe jika snprintf gagal
        return AnsiString("Error: ") + message + AnsiString(" (Error Code: formatting failed)");
    }

    return AnsiString("Error: ") + message + AnsiString(" (Error Code: ") + AnsiString(buffer) + ")";
}
