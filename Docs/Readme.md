# RasTI

[English](#english) | [Bahasa Indonesia](#bahasa-indonesia)

---

## English

RasTI is a Windows utility application that allows running executables with Trusted Installer privileges, providing full system access for operations that require the highest privileges.

## Main Features
- **Privilege Escalation**: Run processes as Trusted Installer
- **Dual Mode**: GUI (VCL) interface and CLI mode for usage flexibility
- **Priority Control**: Set process priority from 1 (IDLE) to 6 (REALTIME)
- **Security Validation**: Comprehensive validation for executable paths and prevention of path traversal

## System Requirements
- Windows 7/8/9/10/11 (32-bit or 64-bit)
- For developers: RAD Studio C++ Builder that supports VCL
- Windows SDK for development

## Build Instructions
1. Open the project in RAD Studio C++ Builder
2. Compile with Release/Win32 or Win64 target
3. The output executable will be in the Bin/ folder

## Usage

### GUI Mode
Run `RasTI.exe` without parameters to display the graphical interface.

### CLI Mode
```
RasTI.exe "path\to\executable.exe" [/priority:N]
```

**Priority parameters:**
- `1` - IDLE_PRIORITY_CLASS
- `2` - BELOW_NORMAL_PRIORITY_CLASS
- `3` - NORMAL_PRIORITY_CLASS (default)
- `4` - ABOVE_NORMAL_PRIORITY_CLASS
- `5` - HIGH_PRIORITY_CLASS
- `6` - REALTIME_PRIORITY_CLASS

**Example:**
```
RasTI.exe "C:\Windows\regedit.exe" /priority:5
```

## How RasTI Works

RasTI leverages Windows privileges to achieve Trusted Installer access through the following process:

### Privilege Acquisition
RasTI uses SeTcbPrivilege (Trusted Computing Base) or SeDebugPrivilege to impersonate Trusted Installer tokens:
- Checks for native SeTcbPrivilege in current token
- If unavailable, uses SeDebugPrivilege + winlogon.exe impersonation to gain TCB privilege
- Creates new Trusted Installer token using LogonUserExExW API with custom token groups

### Process Creation
- Uses CreateProcessWithTokenW to start executables with TI privileges
- Maintains process priority control from IDLE to REALTIME
- Implements comprehensive security validations before execution

### Trusted Installer Privilege
Trusted Installer privilege provides the highest level of system access:
- Ownership of all system files and directories
- Full control over Windows components
- Ability to modify protected system registry keys
- Installation of device drivers and system services

**Note**: Requires administrator privileges and proper Windows configuration for Trusted Installer token creation.

## Security Features

RasTI implements multiple layers of security:

### Input Validation
- **Path Sanitization**: Normalizes paths, removes duplicates, converts relative to absolute paths
- **Traversal Protection**: Blocks "../", "..\", and dangerous characters (< > | ? *)
- **Extension Validation**: Only allows .exe, .bat, .cmd, .com file extensions
- **File Existence Check**: Verifies executable exists and is accessible

### Privilege Escalation Controls
- Custom token creation with minimal required privileges
- Priority value bounds checking and validation
- Secure string conversion with overflow protection
- RAII-based resource management preventing memory leaks

### Audit Trail
- Detailed console output during CLI execution
- Error code reporting for troubleshooting
- Comprehensive input validation logging

## Troubleshooting

### Common Issues

**"Error: Path not valid"**
- Ensure executable path uses double quotes for paths with spaces
- Verify file exists and you have read access
- Check for special characters in path

**Privilege Escalation Failed**
- Run RasTI as Administrator first
- Check Windows User Account Control settings
- Verify SeDebugPrivilege or SeTcbPrivilege availability
- Disable third-party antivirus temporarily (may block token operations)

**GUI Won't Start**
- Ensure VCL runtime libraries are available
- Check administrator privileges
- Verify no conflicting processes

**Priority Setting Ignored**
- Use CLI mode for priority control
- Priority values must be 1-6 (integers only)
- Higher priorities may require additional privileges

### Error Codes
- **1**: Command line argument error
- **0**: Success (CLI mode)
- GUI mode: Windows error codes through standard message boxes

### System Compatibility
- Tested on Windows 7, 8, 8.1, 10, 11
- Both 32-bit and 64-bit architectures
- May require updates for newer Windows builds

## Project Structure

```
RasTI/
├── Bin/              # Compiled executables
├── Docs/             # Documentation
│   ├── Readme.md     # This file
│   └── cppcheck_report.txt  # Static analysis report
├── Inc/              # Header files
│   ├── Core.h        # Core engine declarations
│   └── Form.h        # GUI form declarations
├── Src/              # Source code
│   ├── Main.cpp      # Entry point and dual-mode logic
│   ├── Core.cpp      # Privilege escalation implementation
│   └── Form.cpp      # GUI implementation
├── Test/             # Unit tests
└── Tmp/             # Build temporary files
```

### Key Components

**Core.cpp**: Contains privilege escalation logic using NT APIs
**Main.cpp**: WinMain and mode detection (GUI vs CLI)
**Form.cpp**: VCL-based graphical interface
**Test.cpp**: Unit tests for Core functionality

## FAQ

**Q: What's the difference between RasTI and "Run as Administrator"?**
A: Standard administrator accounts have restrictions on Trusted Installer-owned files. RasTI enables full Trusted Installer privilege escalation for complete system access.

**Q: Is RasTI safe to use?**
A: Yes, with proper validation. RasTI only runs validated executables with explicit user consent. Invalid paths are rejected, and all operations are logged.

**Q: Why do I need Trusted Installer privileges?**
A: For system maintenance tasks like: modifying protected Windows files, installing drivers, changing critical registry keys, and repair operations requiring highest privileges.

**Q: Can RasTI be used in enterprise environments?**
A: Yes, but requires proper administrator rights and understanding of security implications. Suitable for IT professionals and system administrators.

**Q: Why does RasTI need administrator privileges to run?**
A: TI token creation requires SeDebugPrivilege or SeTcbPrivilege, which are only available to administrators. This is Windows security design.

## Version Information

- **Current Version**: 1.2.0.0
- **Release Date**: 2025
- **Supported Platforms**: Windows 7-11 (32/64-bit)
- **Requirements**: RAD Studio C++ Builder, Windows SDK

## License

This project is licensed under the MIT License - see license terms for details.

## Contributing
1. Fork the repository
2. Create a branch for new features/fixes
3. Test in Windows environment
4. Submit a pull request with a clear description

---

## Bahasa Indonesia

RasTI adalah aplikasi utility Windows yang memungkinkan menjalankan executable dengan privilege Trusted Installer, memberikan akses penuh ke sistem untuk operasi yang memerlukan privilege tertinggi.

## Fitur Utama
- **Privilege Escalation**: Menjalankan proses sebagai Trusted Installer
- **Dual Mode**: Antarmuka GUI (VCL) dan mode CLI untuk fleksibilitas penggunaan
- **Kontrol Priority**: Atur priority process dari 1 (IDLE) sampai 6 (REALTIME)
- **Validasi Keamanan**: Validasi komprehensif untuk path executable dan pencegahan path traversal

## Persyaratan Sistem
- Windows 7/8/9/10/11 (32-bit atau 64-bit)
- Bagi pengembang: RAD Studio C++ Builder yang mendukung VCL
- Windows SDK untuk pengembangan

## Build Instructions
1. Buka project di RAD Studio C++ Builder
2. Compile dengan target Release/Win32 atau Win64
3. Output executable akan berada di folder Bin/

## Penggunaan

### Mode GUI
Jalankan `RasTI.exe` tanpa parameter untuk menampilkan antarmuka grafis.

### Mode CLI
```
RasTI.exe "path\to\executable.exe" [/priority:N]
```

**Parameter priority:**
- `1` - IDLE_PRIORITY_CLASS
- `2` - BELOW_NORMAL_PRIORITY_CLASS
- `3` - NORMAL_PRIORITY_CLASS (default)
- `4` - ABOVE_NORMAL_PRIORITY_CLASS
- `5` - HIGH_PRIORITY_CLASS
- `6` - REALTIME_PRIORITY_CLASS

**Contoh:**
```
RasTI.exe "C:\Windows\regedit.exe" /priority:5
```

## Cara Kerja RasTI

RasTI memanfaatkan privilege Windows untuk mencapai akses Trusted Installer melalui proses berikut:

### Pengakuisisian Privilege
RasTI menggunakan SeTcbPrivilege (Trusted Computing Base) atau SeDebugPrivilege untuk mengimpersonasi token Trusted Installer:
- Memeriksa SeTcbPrivilege asli dalam token saat ini
- Jika tidak tersedia, menggunakan SeDebugPrivilege + impersonasi winlogon.exe untuk mendapatkan privilege TCB
- Membuat token Trusted Installer baru menggunakan LogonUserExExW API dengan custom token groups

### Pembuatan Proses
- Menggunakan CreateProcessWithTokenW untuk menjalankan executable dengan privilege TI
- Menjaga kontrol priority proses dari IDLE sampai REALTIME
- Menerapkan validasi keamanan komprehensif sebelum eksekusi

### Privilege Trusted Installer
Privilege Trusted Installer memberikan tingkat akses sistem tertinggi:
- Ownership dari semua file dan direktori sistem
- Kontrol penuh terhadap komponen Windows
- Kemampuan memodifikasi kunci registry sistem yang dilindungi
- Instalasi device drivers dan system services

**Catatan**: Memerlukan privilege administrator dan konfigurasi Windows yang benar untuk pembuatan token Trusted Installer.

## Fitur Keamanan

RasTI menerapkan banyak lapisan keamanan:

### Validasi Input
- **Sanitisasi Path**: Menormalkan path, menghapus duplikat, mengkonversi relative ke absolute paths
- **Proteksi Traversal**: Memblokir "../", "..\", dan karakter berbahaya (< > | ? *)
- **Validasi Extension**: Hanya mengizinkan .exe, .bat, .cmd, .com extensions
- **Pemeriksaan File Ada**: Memverifikasi executable ada dan dapat diakses

### Kontrol Privilege Escalation
- Pembuatan token custom dengan privilege minimal yang diperlukan
- Pemeriksaan batas dan validasi nilai priority
- Konversi string aman dengan proteksi overflow
- Manajemen resource berbasis RAII mencegah memory leaks

### Audit Trail
- Output console detail selama eksekusi CLI
- Pelaporan kode error untuk troubleshooting
- Logging validasi input komprehensif

## Troubleshooting

### Masalah Umum

**"Error: Path tidak valid"**
- Pastikan path executable menggunakan double quotes untuk path dengan spasi
- Verifikasi file ada dan Anda memiliki akses baca
- Periksa karakter spesial dalam path

**Privilege Escalation Gagal**
- Jalankan RasTI sebagai Administrator terlebih dahulu
- Periksa pengaturan Windows User Account Control
- Verifikasi ketersediaan SeDebugPrivilege atau SeTcbPrivilege
- Nonaktifkan antivirus pihak ketiga sementara (mungkin memblokir operasi token)

**GUI Tidak Berjalan**
- Pastikan VCL runtime libraries tersedia
- Periksa privilege administrator
- Verifikasi tidak ada proses yang konflik

**Pengaturan Priority Diabaikan**
- Gunakan mode CLI untuk kontrol priority
- Nilai priority harus 1-6 (hanya integer)
- Priority lebih tinggi mungkin memerlukan privilege tambahan

### Kode Error
- **1**: Error argument command line
- **0**: Berhasil (mode CLI)
- Mode GUI: Kode error Windows melalui message box standar

### Kompatibilitas Sistem
- Diuji pada Windows 7, 8, 8.1, 10, 11
- Arsitektur 32-bit dan 64-bit
- Mungkin memerlukan update untuk build Windows yang lebih baru

## Struktur Project

```
RasTI/
├── Bin/              # Executable hasil kompilasi
├── Docs/             # Dokumentasi
│   ├── Readme.md     # File ini
│   └── cppcheck_report.txt  # Laporan analisis statis
├── Inc/              # Header files
│   ├── Core.h        # Deklarasi Core engine
│   └── Form.h        # Deklarasi form GUI
├── Src/              # Source code
│   ├── Main.cpp      # Entry point dan logika dual-mode
│   ├── Core.cpp      # Implementasi privilege escalation
│   └── Form.cpp      # Implementasi GUI
├── Test/             # Unit tests
└── Tmp/             # File temporary build
```

### Komponen Utama

**Core.cpp**: Berisi logika privilege escalation menggunakan NT APIs
**Main.cpp**: WinMain dan deteksi mode (GUI vs CLI)
**Form.cpp**: Interface grafis berbasis VCL
**Test.cpp**: Unit tests untuk fungsionalitas Core

## FAQ

**T: Apa perbedaan antara RasTI dan "Run as Administrator"?**
J: Akun administrator standar memiliki pembatasan pada file yang dimiliki Trusted Installer. RasTI memungkinkan privilege escalation Trusted Installer penuh untuk akses sistem lengkap.

**T: Apakah RasTI aman digunakan?**
J: Ya, dengan validasi yang benar. RasTI hanya menjalankan executable yang tervalidasi dengan persetujuan user eksplisit. Path tidak valid ditolak, dan semua operasi dicatat.

**T: Mengapa saya butuh privilege Trusted Installer?**
J: Untuk tugas maintenance sistem seperti: memodifikasi file Windows yang dilindungi, menginstall driver, mengubah kunci registry kritikal, dan operasi repair yang memerlukan privilege tertinggi.

**T: Dapatkah RasTI digunakan di environment enterprise?**
J: Ya, tetapi memerlukan hak administrator yang benar dan pemahaman implikasi keamanan. Cocok untuk IT professional dan system administrator.

**T: Mengapa RasTI butuh privilege administrator untuk berjalan?**
J: Pembuatan TI token memerlukan SeDebugPrivilege atau SeTcbPrivilege, yang hanya tersedia untuk administrator. Ini adalah desain keamanan Windows.

## Informasi Versi

- **Versi Saat Ini**: 1.2.0.0
- **Tanggal Rilis**: 2025
- **Platform Didukung**: Windows 7-11 (32/64-bit)
- **Kebutuhan**: RAD Studio C++ Builder, Windows SDK

## Lisensi

Project ini dilisensikan di bawah MIT License - lihat syarat lisensi untuk detail.

## Kontribusi
1. Fork repository
2. Buat branch untuk fitur/fix baru
3. Test pada Windows environment
4. Submit pull request dengan deskripsi yang jelas
