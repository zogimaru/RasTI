//---------------------------------------------------------------------------

#include <vcl.h>
#pragma hdrstop
#include <tchar.h>
#include <string>
#include "Core.h"
//---------------------------------------------------------------------------
USEFORM("GUI.cpp", Main);
//---------------------------------------------------------------------------

// Forward declaration
bool RunExecutableFromCommandLine(const AnsiString& exePath, int priority);

//---------------------------------------------------------------------------
int WINAPI _tWinMain(HINSTANCE, HINSTANCE, LPTSTR, int)
{
	try
	{
		// Check for command line arguments
		if (ParamCount() > 0)
		{
			// Command line mode - run executable directly
			AnsiString exePath = ParamStr(1);
			int priority = NORMAL_PRIORITY_CLASS; // Default priority

			// Parse additional arguments for priority
			for (int i = 2; i <= ParamCount(); i++)
			{
				AnsiString param = ParamStr(i);
				if (param.Pos("/priority:") == 1 || param.Pos("-priority:") == 1)
				{
					// Extract priority value
					AnsiString priorityStr = param.SubString(param.Pos(":") + 1, param.Length());
					int prioValue = StrToIntDef(priorityStr, 3); // Default to 3 (NORMAL)

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
			}

			// Run executable and exit
			bool success = RunExecutableFromCommandLine(exePath, priority);
			return success ? 0 : 1;
		}
		else
		{
			// GUI mode - show main form
			Application->Initialize();
			Application->MainFormOnTaskBar = true;
			Application->CreateForm(__classid(TMain), &Main);
			Application->Run();
		}
	}
	catch (Exception &exception)
	{
		Application->ShowException(&exception);
	}
	catch (...)
	{
		try
		{
			throw Exception("");
		}
		catch (Exception &exception)
		{
			Application->ShowException(&exception);
		}
	}
	return 0;
}
//---------------------------------------------------------------------------

bool RunExecutableFromCommandLine(const AnsiString& exePath, int priority)
{
	ResolveDynamicFunctions();

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

	printf("=========================================\n");
	printf("Menjalankan: %s\n", path.c_str());

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

	int wPathLen = MultiByteToWideChar(CP_ACP, 0, path.c_str(), -1, NULL, 0);
	std::wstring wPath(wPathLen, 0);
	MultiByteToWideChar(CP_ACP, 0, path.c_str(), -1, &wPath[0], wPathLen);
	wPath.resize(wPathLen - 1);

	printf("[+] Mendapatkan TrustedInstaller token...\n");

	bool success = CreateProcessWithTIToken(wPath.c_str(), priority);

	if (success)
	{
		printf("[+] Proses berhasil dijalankan sebagai TrustedInstaller!\n");
	}
	else
	{
		printf("[-] Gagal menjalankan proses (Error Code: %lu)\n", GetLastError());
	}

	printf("=========================================\n");
	return success;
}
//---------------------------------------------------------------------------
