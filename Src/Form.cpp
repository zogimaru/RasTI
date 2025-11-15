/**
 * @file Form.cpp
 * @brief Implementasi GUI untuk RasTI (Run as TrustedInstaller)
 *
 * File ini berisi implementasi form utama aplikasi dengan interface VCL.
 * Menangani interaksi user dan menjalankan operasi privilege escalation
 * melalui event handlers untuk tombol dan kontrol GUI.
 *
 * @author RasTI Development Team
 * @version 1.1.0.0
 * @date 2025
 */

#include <vcl.h>
#pragma hdrstop

#include <string>

#include "Form.h"
#include "Core.h"

#pragma package(smart_init)
#pragma resource "*.dfm"

//==============================================================================
// GLOBAL FORM INSTANCE
//==============================================================================

/** @brief Instance global dari form utama aplikasi */
TMain *Main;

//==============================================================================
// FORM CONSTRUCTOR
//==============================================================================

/**
 * @brief Constructor untuk form utama RasTI
 *
 * Menginisialisasi form dan mempersiapkan aplikasi untuk operasi privilege escalation.
 * Function ini dipanggil otomatis saat form pertama kali dibuat.
 *
 * @param Owner Komponen parent (biasanya Application)
 */
__fastcall TMain::TMain(TComponent* Owner)
	: TForm(Owner)
{
	// Inisialisasi function pointers untuk dynamic linking
	// Diperlukan sebelum operasi privilege escalation dapat dilakukan
	ResolveDynamicFunctions();

	// Tampilkan pesan inisialisasi di status memo
	// Memberi tahu user bahwa aplikasi siap digunakan
	StatusMemo->Lines->Add("RasTI initialized. Ready to run executables as TrustedInstaller.");
}


/**
 * @brief Event handler untuk tombol Browse
 *
 * Membuka dialog file browser untuk memilih executable yang akan dijalankan.
 * Ketika user memilih file, path akan otomatis diisi ke PathEdit.
 *
 * @param Sender Object yang memicu event (BrowseButton)
 */
void __fastcall TMain::BrowseButtonClick(TObject *Sender)
{
	// Tampilkan open file dialog dengan filter executable files
	// OpenDialog1 sudah dikonfigurasi dengan filter "*.exe|All Files|*.*"
	if (OpenDialog1->Execute())
	{
		// Jika user memilih file, isi PathEdit dengan path lengkap file tersebut
		PathEdit->Text = OpenDialog1->FileName;
	}
	// Jika user membatalkan dialog, tidak ada yang dilakukan
}


/**
 * @brief Event handler utama untuk tombol Run - menjalankan privilege escalation
 *
 * Function ini adalah core logic aplikasi yang menangani seluruh proses
 * dari input validation hingga eksekusi dengan Trusted Installer privileges.
 * Melakukan multiple validation layers sebelum menjalankan executable.
 *
 * @param Sender Object yang memicu event (RunButton)
 */
void __fastcall TMain::RunButtonClick(TObject *Sender)
{
	//======================================================================
	// STEP 1: INPUT VALIDATION - Path executable
	//======================================================================

	// Ambil dan trim path dari input user
	AnsiString path = PathEdit->Text.Trim();
	if (path.IsEmpty())
	{
		// VALIDATION FAILED: Path kosong
		StatusMemo->Lines->Add(GetErrorMessage("Path executable tidak boleh kosong"));
		return;
	}

	//======================================================================
	// STEP 2: PATH SANITIZATION - Normalisasi dan cleanup
	//======================================================================

	if (!SanitizePath(path))
	{
		// SANITIZATION FAILED: Path tidak valid setelah normalisasi
		StatusMemo->Lines->Add(GetErrorMessage("Path tidak valid setelah sanitasi"));
		return;
	}

	//======================================================================
	// STEP 3: COMPREHENSIVE EXECUTABLE VALIDATION
	//======================================================================

	if (!ValidateExecutablePath(path))
	{
		// VALIDATION FAILED: Path tidak aman atau executable tidak valid
		StatusMemo->Lines->Add(GetErrorMessage("Path executable tidak aman atau tidak valid: " + path));
		StatusMemo->Lines->Add("Pastikan file executable valid dan path tidak mengandung karakter berbahaya");
		return;
	}

	//======================================================================
	// STEP 4: PRIORITY SELECTION VALIDATION
	//======================================================================

	// Ambil index dari combo box priority (0-5 untuk 6 level priority)
	int priorityIndex = PriorityCombo->ItemIndex;
	if (priorityIndex < 0) priorityIndex = 2; // Default ke NORMAL jika belum dipilih

	// Convert combo box index ke Windows priority constants
	DWORD priority;
	switch (priorityIndex + 1) // +1 karena combo mulai dari 1, bukan 0
	{
	case 1: priority = IDLE_PRIORITY_CLASS; break;        // 1 - IDLE
	case 2: priority = BELOW_NORMAL_PRIORITY_CLASS; break; // 2 - BELOW NORMAL
	case 3: priority = NORMAL_PRIORITY_CLASS; break;      // 3 - NORMAL
	case 4: priority = ABOVE_NORMAL_PRIORITY_CLASS; break; // 4 - ABOVE NORMAL
	case 5: priority = HIGH_PRIORITY_CLASS; break;        // 5 - HIGH
	case 6: priority = REALTIME_PRIORITY_CLASS; break;    // 6 - REALTIME
	default: priority = NORMAL_PRIORITY_CLASS; break;     // Fallback ke NORMAL
	}

	// Validasi nilai priority yang sudah dikonversi
	if (!ValidatePriorityValue(priority))
	{
		StatusMemo->Lines->Add(GetErrorMessage("Nilai priority tidak valid"));
		return;
	}

	//======================================================================
	// STEP 5: LOG OPERATION DETAILS
	//======================================================================

	// Tampilkan header operasi
	StatusMemo->Lines->Add("=========================================");
	StatusMemo->Lines->Add("Menjalankan: " + path);
	StatusMemo->Lines->Add("Priority: " + PriorityCombo->Text);
	StatusMemo->Lines->Add(""); // Baris kosong untuk readability

	//======================================================================
	// STEP 6: STRING CONVERSION - ANSI ke Unicode
	//======================================================================

	// Hitung ukuran buffer yang dibutuhkan untuk konversi ke wide string
	int wPathLen = MultiByteToWideChar(CP_ACP, 0, path.c_str(), -1, NULL, 0);
	if (wPathLen == 0 || wPathLen > MAX_PATH) {
		StatusMemo->Lines->Add(GetErrorMessage("Failed to convert path to wide string or path too long"));
		return;
	}

	// Alokasikan buffer untuk wide string
	std::wstring wPath(wPathLen, 0);

	// Lakukan konversi ANSI ke Unicode
	int result = MultiByteToWideChar(CP_ACP, 0, path.c_str(), -1, &wPath[0], wPathLen);
	if (result == 0) {
		StatusMemo->Lines->Add(GetErrorMessage("Failed to convert path to wide string"));
		return;
	}

	// Remove null terminator dari akhir string
	wPath.resize(wPathLen - 1);

	//======================================================================
	// STEP 7: EXECUTE PRIVILEGE ESCALATION
	//======================================================================

	// Log status: mulai mendapatkan Trusted Installer token
	StatusMemo->Lines->Add("[+] Mendapatkan TrustedInstaller token...");

	// EXECUTE: Jalankan proses dengan Trusted Installer privileges
	bool success = CreateProcessWithTIToken(wPath.c_str(), priority);

	//======================================================================
	// STEP 8: REPORT RESULTS
	//======================================================================

	if (success)
	{
		// SUCCESS: Proses berhasil dijalankan
		StatusMemo->Lines->Add("[+] Proses berhasil dijalankan sebagai TrustedInstaller!");
	}
	else
	{
		// FAILURE: Proses gagal dijalankan, tampilkan error code
		DWORD errorCode = GetLastError();
		StatusMemo->Lines->Add(GetErrorMessageCode("Gagal menjalankan proses", errorCode));
	}

	// Tutup log section
	StatusMemo->Lines->Add("=========================================");
	StatusMemo->Lines->Add(""); // Baris kosong untuk operasi berikutnya
}


/**
 * @brief Event handler untuk tombol Clear Log
 *
 * Membersihkan semua teks di status memo dan menampilkan pesan
 * konfirmasi bahwa log telah dibersihkan dan aplikasi siap untuk operasi baru.
 *
 * @param Sender Object yang memicu event (ClearButton)
 */
void __fastcall TMain::ClearButtonClick(TObject *Sender)
{
	// Bersihkan semua baris di status memo
	StatusMemo->Clear();

	// Tampilkan pesan konfirmasi dan status ready
	StatusMemo->Lines->Add("Log cleared. Ready for new operations.");
}

/**
 * @brief Event handler untuk key press di PathEdit
 *
 * Menangani shortcut keyboard - ketika user menekan Enter di field path,
 * secara otomatis akan menjalankan operasi Run (seperti klik tombol Run).
 * Ini memberikan UX yang lebih baik dengan keyboard navigation.
 *
 * @param Sender Object yang memicu event (PathEdit)
 * @param Key Karakter yang ditekan (modified by reference)
 */
void __fastcall TMain::PathEditKeyPress(TObject *Sender, System::WideChar &Key)
{
	// Cek apakah key yang ditekan adalah Enter (VK_RETURN)
	if (Key == VK_RETURN)
	{
		// Consume the Enter key - cegah karakter Enter masuk ke edit box
		Key = 0;

		// Jalankan operasi Run secara programmatic
		RunButtonClick(NULL);
	}
	// Key lainnya dibiarkan normal (masuk ke edit box)
}
