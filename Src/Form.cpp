#include <vcl.h>
#pragma hdrstop

#include <string>

#include "Form.h"
#include "Core.h"

#pragma package(smart_init)
#pragma resource "*.dfm"
TMain *Main;

__fastcall TMain::TMain(TComponent* Owner)
	: TForm(Owner)
{
	ResolveDynamicFunctions();

	StatusMemo->Lines->Add("RasTI initialized. Ready to run executables as TrustedInstaller.");
}


void __fastcall TMain::BrowseButtonClick(TObject *Sender)
{
	if (OpenDialog1->Execute())
	{
		PathEdit->Text = OpenDialog1->FileName;
	}
}


void __fastcall TMain::RunButtonClick(TObject *Sender)
{
	AnsiString path = PathEdit->Text.Trim();
	if (path.IsEmpty())
	{
		StatusMemo->Lines->Add(GetErrorMessage("Path executable tidak boleh kosong"));
		return;
	}

	if (!SanitizePath(path))
	{
		StatusMemo->Lines->Add(GetErrorMessage("Path tidak valid setelah sanitasi"));
		return;
	}

	if (!ValidateExecutablePath(path))
	{
		StatusMemo->Lines->Add(GetErrorMessage("Path executable tidak aman atau tidak valid: " + path));
		StatusMemo->Lines->Add("Pastikan file executable valid dan path tidak mengandung karakter berbahaya");
		return;
	}

	int priorityIndex = PriorityCombo->ItemIndex;
	if (priorityIndex < 0) priorityIndex = 2;

	DWORD priority;
	switch (priorityIndex + 1)
	{
	case 1: priority = IDLE_PRIORITY_CLASS; break;
	case 2: priority = BELOW_NORMAL_PRIORITY_CLASS; break;
	case 3: priority = NORMAL_PRIORITY_CLASS; break;
	case 4: priority = ABOVE_NORMAL_PRIORITY_CLASS; break;
	case 5: priority = HIGH_PRIORITY_CLASS; break;
	case 6: priority = REALTIME_PRIORITY_CLASS; break;
	default: priority = NORMAL_PRIORITY_CLASS; break;
	}

	if (!ValidatePriorityValue(priority))
	{
		StatusMemo->Lines->Add(GetErrorMessage("Nilai priority tidak valid"));
		return;
	}

	StatusMemo->Lines->Add("=========================================");
	StatusMemo->Lines->Add("Menjalankan: " + path);
	StatusMemo->Lines->Add("Priority: " + PriorityCombo->Text);
	StatusMemo->Lines->Add("");

	int wPathLen = MultiByteToWideChar(CP_ACP, 0, path.c_str(), -1, NULL, 0);
	if (wPathLen == 0 || wPathLen > MAX_PATH) {
		StatusMemo->Lines->Add(GetErrorMessage("Failed to convert path to wide string or path too long"));
		return;
	}
	std::wstring wPath(wPathLen, 0);
	int result = MultiByteToWideChar(CP_ACP, 0, path.c_str(), -1, &wPath[0], wPathLen);
	if (result == 0) {
		StatusMemo->Lines->Add(GetErrorMessage("Failed to convert path to wide string"));
		return;
	}
	wPath.resize(wPathLen - 1);

	StatusMemo->Lines->Add("[+] Mendapatkan TrustedInstaller token...");

	bool success = CreateProcessWithTIToken(wPath.c_str(), priority);

	if (success)
	{
		StatusMemo->Lines->Add("[+] Proses berhasil dijalankan sebagai TrustedInstaller!");
	}
	else
	{
		DWORD errorCode = GetLastError();
		StatusMemo->Lines->Add(GetErrorMessageCode("Gagal menjalankan proses", errorCode));
	}

	StatusMemo->Lines->Add("=========================================");
	StatusMemo->Lines->Add("");
}


void __fastcall TMain::ClearButtonClick(TObject *Sender)
{
	StatusMemo->Clear();
	StatusMemo->Lines->Add("Log cleared. Ready for new operations.");
}

void __fastcall TMain::PathEditKeyPress(TObject *Sender, System::WideChar &Key)
{
	if (Key == VK_RETURN)
	{
		Key = 0; // Consume the Enter key
		RunButtonClick(NULL);
	}
}
