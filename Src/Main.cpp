/**
 * @file Main.cpp
 * @brief Entry point aplikasi RasTI
 *
 * File ini berisi WinMain function dan logika dual-mode aplikasi:
 * - GUI Mode: Menampilkan form utama dengan interface VCL
 * - CLI Mode: Menjalankan executable langsung dari command line
 *
 * Aplikasi dapat berjalan dalam dua mode tergantung parameter command line.
 *
 * @author RasTI Development Team
 * @version 1.1.0.0
 * @date 2025
 */

#include <vcl.h>
#pragma hdrstop
#include <tchar.h>
#include <string>
#include <cctype>
#include "Core.h"
//---------------------------------------------------------------------------
USEFORM("GUI.cpp", Main);  /**< Form utama untuk GUI mode */
//---------------------------------------------------------------------------

//==============================================================================
// FORWARD DECLARATIONS
//==============================================================================

/** @brief Forward declaration untuk function CLI execution */
bool RunExecutableFromCommandLine(const AnsiString& exePath, int priority);

//---------------------------------------------------------------------------
/**
 * @brief Entry point utama aplikasi RasTI (WinMain)
 *
 * Function ini adalah entry point Windows application yang menentukan mode aplikasi:
 * - CLI Mode: Jika ada command line arguments, jalankan executable langsung
 * - GUI Mode: Jika tidak ada arguments, tampilkan form utama VCL
 *
 * Command Line Syntax:
 *   RasTI.exe "path\to\executable" [/priority:N]
 *
 * @param hInstanceCurrent  Handle ke instance aplikasi saat ini
 * @param hInstancePrevious Handle ke instance aplikasi sebelumnya (selalu NULL di modern Windows)
 * @param lpCmdLine          Command line string (tidak digunakan, gunakan ParamStr)
 * @param nCmdShow          Flag untuk menampilkan window (tidak digunakan di VCL)
 * @return Exit code aplikasi (0 = success, 1 = error)
 */
int WINAPI _tWinMain(HINSTANCE, HINSTANCE, LPTSTR, int)
{
	try
	{
		//======================================================================
		// MODE DETECTION: CLI vs GUI
		//======================================================================

		// Cek apakah ada command line arguments
		if (ParamCount() > 0)
		{
			//==================================================================
			// CLI MODE: Command Line Interface
			//==================================================================

			// Ambil executable path dari argument pertama
			AnsiString exePath = ParamStr(1);
			int priority = NORMAL_PRIORITY_CLASS; // Default priority

			//==================================================================
			// PARSE COMMAND LINE ARGUMENTS
			//==================================================================

			// Parse additional arguments untuk priority (mulai dari argumen ke-2)
			for (int i = 2; i <= ParamCount(); i++)
			{
				AnsiString param = ParamStr(i);

				// Cek apakah parameter adalah priority flag (/priority:N atau -priority:N)
				if (param.Pos("/priority:") == 1 || param.Pos("-priority:") == 1)
				{
					// Extract nilai priority setelah colon
					AnsiString priorityStr = param.SubString(param.Pos(":") + 1, param.Length());

					// VALIDATION: Pastikan priority string hanya berisi digit
					bool isValidPriorityStr = true;
					for (int j = 1; j <= priorityStr.Length(); j++) {
						if (!isdigit(priorityStr[j])) {
							isValidPriorityStr = false;
							break;
						}
					}

					if (!isValidPriorityStr) {
						printf("Error: Invalid priority format. Use numbers 1-6.\n");
						return 1; // Exit dengan error code
					}

					// Convert string ke integer dengan default NORMAL (3)
					int prioValue = StrToIntDef(priorityStr, 3);

					// VALIDATION: Pastikan priority dalam range 1-6
					if (prioValue < 1 || prioValue > 6) {
						printf("Error: Priority must be between 1 and 6.\n");
						return 1; // Exit dengan error code
					}

					// Convert nomor priority ke Windows priority constants
					switch (prioValue)
					{
					case 1: priority = IDLE_PRIORITY_CLASS; break;
					case 2: priority = BELOW_NORMAL_PRIORITY_CLASS; break;
					case 3: priority = NORMAL_PRIORITY_CLASS; break;
					case 4: priority = ABOVE_NORMAL_PRIORITY_CLASS; break;
					case 5: priority = HIGH_PRIORITY_CLASS; break;
					case 6: priority = REALTIME_PRIORITY_CLASS; break;
					default: priority = NORMAL_PRIORITY_CLASS; break;
					}
				}
				else
				{
					// ERROR: Parameter tidak dikenal
					printf("Error: Unknown parameter '%s'. Supported parameters: /priority:N or -priority:N\n", param.c_str());
					return 1; // Exit dengan error code
				}
			}

			//==================================================================
			// EXECUTE CLI MODE
			//==================================================================

			// Jalankan executable dan exit dengan return code yang sesuai
			bool success = RunExecutableFromCommandLine(exePath, priority);
			return success ? 0 : 1; // 0 = success, 1 = failure
		}
		else
		{
			//==================================================================
			// GUI MODE: Graphical User Interface
			//==================================================================

			// Inisialisasi VCL Application
			Application->Initialize();
			Application->MainFormOnTaskBar = true; // Tampilkan form di taskbar

			// Buat dan tampilkan form utama
			Application->CreateForm(__classid(TMain), &Main);

			// Jalankan message loop VCL (blocking call)
			Application->Run();
		}
	}
	catch (Exception &exception)
	{
		// EXCEPTION HANDLING: VCL Exceptions
		Application->ShowException(&exception);
	}
	catch (...)
	{
		// EXCEPTION HANDLING: Unknown exceptions
		try
		{
			throw Exception(""); // Convert ke VCL exception
		}
		catch (Exception &exception)
		{
			Application->ShowException(&exception);
		}
	}

	// Normal exit (GUI mode) atau setelah CLI execution
	return 0;
}
//---------------------------------------------------------------------------

/**
 * @brief Menjalankan executable dari command line dengan Trusted Installer privileges
 *
 * Function ini adalah versi CLI dari RunButtonClick. Melakukan validasi dan eksekusi
 * privilege escalation dengan output ke console (stdout/stderr) instead of GUI.
 *
 * @param exePath Path ke executable yang akan dijalankan
 * @param priority Windows priority class untuk proses baru
 * @return true jika berhasil, false jika gagal
 *
 * @note Function ini menggunakan printf untuk output karena dalam konteks CLI
 * @see RunButtonClick untuk versi GUI dengan logic serupa
 */
bool RunExecutableFromCommandLine(const AnsiString& exePath, int priority)
{
	// Inisialisasi function pointers untuk dynamic linking
	ResolveDynamicFunctions();

	//======================================================================
	// INPUT VALIDATION (mirip dengan GUI version)
	//======================================================================

	AnsiString path = exePath.Trim();
	if (path.IsEmpty())
	{
		printf("Error: Path executable tidak boleh kosong\n");
		return false;
	}

	if (!SanitizePath(path))
	{
		printf("Error: Path tidak valid setelah sanitasi\n");
		return false;
	}

	if (!ValidateExecutablePath(path))
	{
		printf("Error: Path executable tidak aman atau tidak valid: %s\n", path.c_str());
		printf("Pastikan file executable valid dan path tidak mengandung karakter berbahaya\n");
		return false;
	}

	if (!ValidatePriorityValue(priority))
	{
		printf("Error: Nilai priority tidak valid\n");
		return false;
	}

	//======================================================================
	// LOG OPERATION DETAILS
	//======================================================================

	printf("=========================================\n");
	printf("Menjalankan: %s\n", path.c_str());

	// Convert priority constant ke nama yang readable untuk display
	const char* priorityNames[] = {"IDLE", "BELOW NORMAL", "NORMAL", "ABOVE NORMAL", "HIGH", "REALTIME"};
	int prioIndex = 2; // Default NORMAL
	if (priority == IDLE_PRIORITY_CLASS) prioIndex = 0;
	else if (priority == BELOW_NORMAL_PRIORITY_CLASS) prioIndex = 1;
	else if (priority == NORMAL_PRIORITY_CLASS) prioIndex = 2;
	else if (priority == ABOVE_NORMAL_PRIORITY_CLASS) prioIndex = 3;
	else if (priority == HIGH_PRIORITY_CLASS) prioIndex = 4;
	else if (priority == REALTIME_PRIORITY_CLASS) prioIndex = 5;

	printf("Priority: %d - %s\n", prioIndex + 1, priorityNames[prioIndex]);
	printf("\n");

	//======================================================================
	// STRING CONVERSION: ANSI ke Unicode (sama dengan GUI)
	//======================================================================

	int wPathLen = MultiByteToWideChar(CP_ACP, 0, path.c_str(), -1, NULL, 0);
	if (wPathLen == 0 || wPathLen > MAX_PATH) {
		printf("Error: Failed to convert path to wide string or path too long\n");
		return false;
	}
	std::wstring wPath(wPathLen, 0);
	int result = MultiByteToWideChar(CP_ACP, 0, path.c_str(), -1, &wPath[0], wPathLen);
	if (result == 0) {
		printf("Error: Failed to convert path to wide string\n");
		return false;
	}
	wPath.resize(wPathLen - 1);

	//======================================================================
	// EXECUTE PRIVILEGE ESCALATION
	//======================================================================

	printf("[+] Mendapatkan TrustedInstaller token...\n");

	// Jalankan proses dengan Trusted Installer privileges
	bool success = CreateProcessWithTIToken(wPath.c_str(), priority);

	//======================================================================
	// REPORT RESULTS
	//======================================================================

	if (success)
	{
		printf("[+] Proses berhasil dijalankan sebagai TrustedInstaller!\n");
	}
	else
	{
		DWORD errorCode = GetLastError();
		printf("[-] Gagal menjalankan proses (Error Code: %lu)\n", errorCode);
	}

	printf("=========================================\n");
	return success;
}
//---------------------------------------------------------------------------
