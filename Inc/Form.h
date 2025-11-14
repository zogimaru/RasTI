//---------------------------------------------------------------------------

#ifndef GUIH
#define GUIH
//---------------------------------------------------------------------------
#include <System.Classes.hpp>
#include <Vcl.Controls.hpp>
#include <Vcl.StdCtrls.hpp>
#include <Vcl.Forms.hpp>
#include <Vcl.Dialogs.hpp>
//---------------------------------------------------------------------------
class TMain : public TForm
{
__published:	// IDE-managed Components
	TLabel *Label1;
	TLabel *Label2;
	TLabel *Label3;
	TLabel *WarningLabel;
	TEdit *PathEdit;
	TButton *BrowseButton;
	TComboBox *PriorityCombo;
	TButton *RunButton;
	TMemo *StatusMemo;
	TButton *ClearButton;
	TOpenDialog *OpenDialog1;
	TLabel *Label4;
	TLabel *Label5;
	TLabel *Label6;
	void __fastcall BrowseButtonClick(TObject *Sender);
	void __fastcall RunButtonClick(TObject *Sender);
	void __fastcall ClearButtonClick(TObject *Sender);
	void __fastcall PathEditKeyPress(TObject *Sender, System::WideChar &Key);
private:	// User declarations
public:		// User declarations
	__fastcall TMain(TComponent* Owner);
};
//---------------------------------------------------------------------------
extern PACKAGE TMain *Main;
//---------------------------------------------------------------------------
#endif
