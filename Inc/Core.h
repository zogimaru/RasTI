/**
 * @file Core.h
 * @brief Header file untuk RasTI Core Engine
 *
 * File ini berisi deklarasi fungsi-fungsi utama untuk privilege escalation
 * dan manajemen Trusted Installer token dalam sistem Windows.
 *
 * @author RasTI Development Team
 * @version 1.1.0.0
 * @date 2025
 */

#ifndef RASTI_H
#define RASTI_H

#include <Windows.h>
#include <stdio.h>
#include <tlhelp32.h>
#include <sddl.h>
#include <tchar.h>
#include <System.hpp>

//==============================================================================
// MACRO DEFINITIONS
//==============================================================================

/** @brief Macro untuk mengecek status NT API yang berhasil */
#define NT_SUCCESS(status) ((status) >= 0)

/** @brief Macro shortcut untuk GetLastError() */
#define GLE GetLastError()

//==============================================================================
// WINDOWS PRIVILEGE CONSTANTS
//==============================================================================

/** @brief Konstanta privilege Windows untuk berbagai operasi sistem
 *
 * Privilege ini digunakan untuk mengontrol akses ke berbagai fitur sistem.
 * Hanya privilege yang relevan dengan aplikasi ini yang didefinisikan.
 */
#define SE_CREATE_TOKEN_PRIVILEGE 1           /**< Membuat token akses */
#define SE_ASSIGNPRIMARYTOKEN_PRIVILEGE 3     /**< Mengassign primary token */
#define SE_LOCK_MEMORY_PRIVILEGE 4            /**< Mengunci memory */
#define SE_INCREASE_QUOTA_PRIVILEGE 5         /**< Meningkatkan quota */
#define SE_UNSOLICITED_INPUT_PRIVILEGE 6      /**< Input tidak diminta */
#define SE_MACHINE_ACCOUNT_PRIVILEGE 11       /**< Akun mesin */
#define SE_TCB_PRIVILEGE 7                    /**< Trusted Computing Base */
#define SE_SECURITY_PRIVILEGE 8               /**< Operasi keamanan */
#define SE_TAKE_OWNERSHIP_PRIVILEGE 9         /**< Mengambil ownership */
#define SE_LOAD_DRIVER_PRIVILEGE 10           /**< Memuat driver */
#define SE_SYSTEM_PROFILE_PRIVILEGE 12        /**< System profiling */
#define SE_SYSTEMTIME_PRIVILEGE 12            /**< Mengubah waktu sistem */
#define SE_PROF_SINGLE_PROCESS_PRIVILEGE 13   /**< Profile single process */
#define SE_INC_BASE_PRIORITY_PRIVILEGE 14     /**< Meningkatkan base priority */
#define SE_CREATE_PAGEFILE_PRIVILEGE 15       /**< Membuat pagefile */
#define SE_CREATE_PERMANENT_PRIVILEGE 16      /**< Membuat objek permanent */
#define SE_BACKUP_PRIVILEGE 17                /**< Backup operations */
#define SE_RESTORE_PRIVILEGE 18               /**< Restore operations */
#define SE_SHUTDOWN_PRIVILEGE 19              /**< Shutdown sistem */
#define SE_DEBUG_PRIVILEGE 20                 /**< Debug privilege */
#define SE_AUDIT_PRIVILEGE 21                 /**< Audit operations */
#define SE_SYSTEM_ENVIRONMENT_PRIVILEGE 22    /**< System environment */
#define SE_CHANGE_NOTIFY_PRIVILEGE 23         /**< Change notifications */
#define SE_REMOTE_SHUTDOWN_PRIVILEGE 24       /**< Remote shutdown */
#define SE_UNDOCK_PRIVILEGE 25                /**< Undock privilege */
#define SE_SYNC_AGENT_PRIVILEGE 26            /**< Sync agent */
#define SE_ENABLE_DELEGATION_PRIVILEGE 27     /**< Enable delegation */
#define SE_MANAGE_VOLUME_PRIVILEGE 28         /**< Manage volume */
#define SE_IMPERSONATE_PRIVILEGE 29           /**< Impersonate privilege */
#define SE_CREATE_GLOBAL_PRIVILEGE 30         /**< Create global objects */
#define SE_TRUSTED_CREDMAN_ACCESS_PRIVILEGE 31/**< Trusted credential manager */
#define SE_RELABEL_PRIVILEGE 32               /**< Relabel privilege */
#define SE_INC_WORKING_SET_PRIVILEGE 33       /**< Increase working set */
#define SE_TIME_ZONE_PRIVILEGE 34             /**< Time zone privilege */
#define SE_CREATE_SYMBOLIC_LINK_PRIVILEGE 35  /**< Create symbolic links */

//==============================================================================
// BACKWARD COMPATIBILITY ALIASES
//==============================================================================

/** @brief Alias untuk kompatibilitas backward dengan kode lama */
#define SeTcbPrivilege SE_TCB_PRIVILEGE
#define SeDebugPrivilege SE_DEBUG_PRIVILEGE
#define SeImpersonatePrivilege SE_IMPERSONATE_PRIVILEGE

//==============================================================================
// SECURITY IDENTIFIERS
//==============================================================================

/** @brief SID untuk Trusted Installer service
 *
 * SID ini mengidentifikasi Trusted Installer service di Windows.
 * Trusted Installer memiliki privilege tertinggi di sistem.
 */
#define TRUSTED_INSTALLER_SID "S-1-5-80-956008885-3418522649-1831038044-1853292631-2271478464"

//==============================================================================
// FUNCTION POINTER TYPE DEFINITIONS
//==============================================================================

/**
 * @brief Function pointer untuk RtlAdjustPrivilege dari ntdll.dll
 *
 * @param Privilege Konstanta privilege yang akan diaktifkan/dinonaktifkan
 * @param Enable true untuk mengaktifkan, false untuk menonaktifkan
 * @param ThreadPrivilege true untuk thread, false untuk process
 * @param Previous Pointer ke boolean yang akan menerima status sebelumnya
 * @return NTSTATUS menunjukkan keberhasilan operasi
 */
typedef NTSTATUS(NTAPI* _RtlAdjustPrivilege)(int Privilege, bool Enable, bool ThreadPrivilege, bool* Previous);

/**
 * @brief Function pointer untuk LogonUserExExW dari advapi32.dll
 *
 * Function ini digunakan untuk membuat logon session dengan custom token groups.
 * Digunakan dalam proses akuisisi Trusted Installer token.
 */
typedef BOOL(WINAPI* _LogonUserExExW)(
    _In_      LPWSTR        lpszUsername,        /**< Username untuk logon */
    _In_opt_  LPWSTR        lpszDomain,          /**< Domain (opsional) */
    _In_opt_  LPWSTR        lpszPassword,        /**< Password (opsional) */
    _In_      DWORD         dwLogonType,         /**< Tipe logon */
    _In_      DWORD         dwLogonProvider,     /**< Logon provider */
    _In_opt_  PTOKEN_GROUPS pTokenGroups,       /**< Custom token groups */
    _Out_opt_ PHANDLE       phToken,             /**< Output token handle */
    _Out_opt_ PSID* ppLogonSid,                  /**< Output logon SID */
    _Out_opt_ PVOID* ppProfileBuffer,            /**< Output profile buffer */
    _Out_opt_ LPDWORD       pdwProfileLength,    /**< Output profile length */
    _Out_opt_ PQUOTA_LIMITS pQuotaLimits         /**< Output quota limits */
);

//==============================================================================
// RAII SMART HANDLE CLASSES FOR RESOURCE MANAGEMENT
//==============================================================================

/**
 * @brief Smart handle base class untuk Windows HANDLE objects
 *
 * Menggunakan RAII pattern untuk automatic resource cleanup.
 * CloseHandle() dipanggil otomatis pada destruction.
 */
class SmartHandle {
protected:
    HANDLE handle_;

public:
    /** @brief Default constructor dengan invalid handle */
    SmartHandle() : handle_(INVALID_HANDLE_VALUE) {}

    /** @brief Constructor dengan existing handle */
    explicit SmartHandle(HANDLE h) : handle_(h) {}

    /** @brief Move constructor */
    SmartHandle(SmartHandle&& other) noexcept : handle_(other.handle_) {
        other.handle_ = INVALID_HANDLE_VALUE;
    }

    /** @brief Move assignment operator */
    SmartHandle& operator=(SmartHandle&& other) noexcept {
        if (this != &other) {
            CloseHandle(handle_); // Cleanup existing handle
            handle_ = other.handle_;
            other.handle_ = INVALID_HANDLE_VALUE;
        }
        return *this;
    }

    /** @brief Destructor - automatic cleanup */
    ~SmartHandle() {
        if (IsValid()) {
            CloseHandle(handle_);
        }
    }

    /** @brief Check if handle is valid */
    bool IsValid() const { return handle_ != INVALID_HANDLE_VALUE && handle_ != NULL; }

    /** @brief Get raw handle (use carefully) */
    HANDLE Get() const { return handle_; }

    /** @brief Release ownership tanpa cleanup */
    HANDLE Release() {
        HANDLE temp = handle_;
        handle_ = INVALID_HANDLE_VALUE;
        return temp;
    }

    /** @brief Reset dengan handle baru */
    void Reset(HANDLE h = INVALID_HANDLE_VALUE) {
        if (IsValid()) {
            CloseHandle(handle_);
        }
        handle_ = h;
    }

    // Prevent copying for safety
    SmartHandle(const SmartHandle&) = delete;
    SmartHandle& operator=(const SmartHandle&) = delete;
};

/**
 * @brief Smart handle untuk process handles (OpenProcess result)
 */
class SmartProcessHandle : public SmartHandle {
public:
    SmartProcessHandle() : SmartHandle() {}
    explicit SmartProcessHandle(HANDLE h) : SmartHandle(h) {}
    SmartProcessHandle(SmartProcessHandle&& other) noexcept = default;
    SmartProcessHandle& operator=(SmartProcessHandle&& other) noexcept = default;
};

/**
 * @brief Smart handle untuk access token handles (OpenProcessToken result)
 */
class SmartTokenHandle : public SmartHandle {
public:
    SmartTokenHandle() : SmartHandle() {}
    explicit SmartTokenHandle(HANDLE h) : SmartHandle(h) {}
    SmartTokenHandle(SmartTokenHandle&& other) noexcept = default;
    SmartTokenHandle& operator=(SmartTokenHandle&& other) noexcept = default;
};

/**
 * @brief Smart handle untuk ToolHelp snapshots (CreateToolhelp32Snapshot result)
 */
class SmartSnapshotHandle : public SmartHandle {
public:
    SmartSnapshotHandle() : SmartHandle() {}
    explicit SmartSnapshotHandle(HANDLE h) : SmartHandle(h) {}
    SmartSnapshotHandle(SmartSnapshotHandle&& other) noexcept = default;
    SmartSnapshotHandle& operator=(SmartSnapshotHandle&& other) noexcept = default;
};

//==============================================================================
// GLOBAL FUNCTION POINTERS
//==============================================================================

/** @brief Global function pointer untuk RtlAdjustPrivilege dari ntdll.dll */
extern _RtlAdjustPrivilege pRtlAdjustPrivilege;

/** @brief Global function pointer untuk LogonUserExExW dari advapi32.dll */
extern _LogonUserExExW pLogonUserExExW;

/**
 * @brief Menginisialisasi function pointers untuk dynamic linking
 *
 * Function ini memuat alamat fungsi RtlAdjustPrivilege dan LogonUserExExW
 * dari DLL sistem (ntdll.dll dan advapi32.dll) menggunakan GetProcAddress.
 * Ini diperlukan karena fungsi-fungsi ini tidak tersedia dalam header standar.
 *
 * @note Harus dipanggil sebelum menggunakan privilege functions
 */
void ResolveDynamicFunctions();

/**
 * @brief Mengaktifkan atau menonaktifkan privilege Windows
 *
 * @param impersonating true jika sedang impersonating thread lain
 * @param privilege_value Konstanta privilege yang akan diaktifkan (SE_*_PRIVILEGE)
 * @return true jika berhasil, false jika gagal
 *
 * @note Hanya menerima privilege yang telah divalidasi untuk keamanan
 * @see EnablePrivilege untuk list privilege yang didukung
 */
bool EnablePrivilege(bool impersonating, int privilege_value);

/**
 * @brief Impersonate token dari winlogon.exe untuk mendapatkan TCB privilege
 *
 * Teknik ini digunakan ketika proses tidak memiliki SeTcbPrivilege secara langsung.
 * Winlogon.exe memiliki TCB privilege karena berjalan sebagai LocalSystem.
 *
 * @return true jika impersonation berhasil, false jika gagal
 *
 * @warning Function ini memerlukan SeDebugPrivilege
 * @note Menggunakan Process32 API untuk menemukan winlogon.exe
 */
bool ImpersonateTcbToken();

/**
 * @brief Mendapatkan handle ke Trusted Installer token
 *
 * Function utama untuk privilege escalation. Membuat token dengan
 * Trusted Installer SID menggunakan LogonUserExExW dengan custom token groups.
 *
 * @return HANDLE ke Trusted Installer token, atau NULL jika gagal
 *
 * @note Memerlukan SeTcbPrivilege atau SeDebugPrivilege + impersonation
 * @warning Token harus ditutup dengan CloseHandle() setelah digunakan
 */
HANDLE GetTrustedInstallerToken();

/**
 * @brief Membuat proses baru dengan Trusted Installer token
 *
 * @param targetPath Path lengkap ke executable yang akan dijalankan
 * @param priority Class priority untuk proses baru (IDLE_PRIORITY_CLASS, etc.)
 * @return true jika proses berhasil dibuat, false jika gagal
 *
 * @note Menggunakan CreateProcessWithTokenW untuk elevated execution
 * @see ValidateExecutablePath untuk validasi path sebelum pemanggilan
 */
bool CreateProcessWithTIToken(LPCWSTR targetPath, DWORD priority);

//==============================================================================
// ADMINISTRATOR PRIVILEGE CHECKING
//==============================================================================

/**
 * @brief Mengecek apakah proses memiliki administrator privileges
 *
 * Melakukan dua jenis pemeriksaan:
 * 1. Token groups untuk Trusted Installer privilege (SeTcbPrivilege)
 * 2. Traditional administrator group membership + elevation status
 *
 * @return TRUE jika memiliki admin privileges, FALSE jika tidak
 *
 * @note Trusted Installer privilege dianggap sebagai "super admin"
 */
BOOL CheckAdministratorPrivileges();

//==============================================================================
// PATH AND EXECUTABLE VALIDATION
//==============================================================================

/**
 * @brief Validasi komprehensif untuk path executable
 *
 * Melakukan multiple validation:
 * - Path sanitization
 * - Path traversal check
 * - File existence check
 * - Extension validation (.exe, .bat, .cmd, .com)
 *
 * @param path Path yang akan divalidasi
 * @return true jika path valid dan aman, false jika tidak
 *
 * @note Menggunakan FindExecutableInPath jika file tidak ditemukan di path spesifik
 */
bool ValidateExecutablePath(const AnsiString& path);

/**
 * @brief Membersihkan dan menormalkan path string
 *
 * Operasi yang dilakukan:
 * - Trim whitespace
 * - Normalize path separators (/ ke \)
 * - Remove duplicate separators
 * - Convert relative path ke absolute jika perlu
 *
 * @param path String path yang akan disanitasi (modified in-place)
 * @return true jika sanitasi berhasil, false jika path kosong setelah sanitasi
 */
bool SanitizePath(AnsiString& path);

/**
 * @brief Mengecek apakah path mengandung path traversal attacks
 *
 * Mencegah directory traversal dengan mendeteksi:
 * - "../" atau "..\" patterns
 * - Karakter berbahaya: < > | ? *
 *
 * @param path Path yang akan diperiksa
 * @return true jika path aman, false jika mengandung traversal
 */
bool IsPathTraversalSafe(const AnsiString& path);

/**
 * @brief Validasi nilai priority class Windows
 *
 * @param priority Nilai priority yang akan divalidasi
 * @return true jika priority valid, false jika tidak
 *
 * @note Mendukung semua priority class standar Windows
 */
bool ValidatePriorityValue(int priority);

/**
 * @brief Mengecek apakah file adalah executable yang valid
 *
 * @param path Path lengkap ke file
 * @return true jika file executable valid, false jika tidak
 *
 * @note Menggunakan CreateFile untuk verifikasi akses dan GetFileVersionInfoSize
 */
bool IsValidExecutable(const AnsiString& path);

/**
 * @brief Mencari executable dalam PATH environment variable
 *
 * @param exeName Nama executable (dengan atau tanpa .exe extension)
 * @return Path lengkap jika ditemukan, string kosong jika tidak
 *
 * @note Menambahkan .exe extension jika tidak ada
 */
AnsiString FindExecutableInPath(const AnsiString& exeName);

//==============================================================================
// ERROR MESSAGE FORMATTING
//==============================================================================

/**
 * @brief Format pesan error standar
 *
 * @param message Pesan error yang akan diformat
 * @return String error yang telah diformat dengan prefix "Error: "
 */
AnsiString GetErrorMessage(const AnsiString& message);

/**
 * @brief Format pesan error dengan kode error Windows
 *
 * @param message Pesan error
 * @param errorCode Kode error dari GetLastError() atau API lain
 * @return String error yang telah diformat dengan kode error
 */
AnsiString GetErrorMessageCode(const AnsiString& message, DWORD errorCode);

#endif
