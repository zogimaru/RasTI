object Main: TMain
  Left = 0
  Top = 0
  Caption = 'RasTI - Run as TrustedInstaller'
  ClientHeight = 352
  ClientWidth = 700
  Color = clBtnFace
  Font.Charset = DEFAULT_CHARSET
  Font.Color = clWindowText
  Font.Height = -12
  Font.Name = 'Segoe UI'
  Font.Style = []
  PixelsPerInch = 96
  TextHeight = 15
  object Label1: TLabel
    Left = 20
    Top = 20
    Width = 83
    Height = 15
    Caption = 'Executable Path'
  end
  object Label2: TLabel
    Left = 20
    Top = 60
    Width = 41
    Height = 15
    Caption = 'Priority:'
  end
  object Label3: TLabel
    Left = 20
    Top = 100
    Width = 35
    Height = 15
    Caption = 'Status:'
  end
  object WarningLabel: TLabel
    Left = 20
    Top = 330
    Width = 277
    Height = 15
    Caption = 'WARNING: Harap berhati-hati dalam penggunaan.'
    Font.Charset = DEFAULT_CHARSET
    Font.Color = clRed
    Font.Height = -12
    Font.Name = 'Segoe UI'
    Font.Style = [fsBold]
    ParentFont = False
    WordWrap = True
  end
  object Label4: TLabel
    Left = 119
    Top = 21
    Width = 3
    Height = 15
    Caption = ':'
  end
  object Label5: TLabel
    Left = 119
    Top = 60
    Width = 3
    Height = 15
    Caption = ':'
  end
  object Label6: TLabel
    Left = 119
    Top = 100
    Width = 3
    Height = 15
    Caption = ':'
  end
  object PathEdit: TEdit
    Left = 150
    Top = 15
    Width = 450
    Height = 23
    TabOrder = 0
    OnKeyPress = PathEditKeyPress
  end
  object BrowseButton: TButton
    Left = 610
    Top = 15
    Width = 75
    Height = 25
    Caption = 'Browse...'
    TabOrder = 1
    OnClick = BrowseButtonClick
  end
  object PriorityCombo: TComboBox
    Left = 150
    Top = 55
    Width = 200
    Height = 23
    Style = csDropDownList
    ItemIndex = 2
    TabOrder = 2
    Text = '3 - NORMAL'
    Items.Strings = (
      '1 - IDLE'
      '2 - BELOW NORMAL'
      '3 - NORMAL'
      '4 - ABOVE NORMAL'
      '5 - HIGH'
      '6 - REALTIME')
  end
  object RunButton: TButton
    Left = 592
    Top = 60
    Width = 100
    Height = 35
    Caption = 'Run'
    Font.Charset = DEFAULT_CHARSET
    Font.Color = clWindowText
    Font.Height = -13
    Font.Name = 'Segoe UI'
    Font.Style = [fsBold]
    ParentFont = False
    TabOrder = 3
    OnClick = RunButtonClick
  end
  object StatusMemo: TMemo
    Left = 20
    Top = 122
    Width = 665
    Height = 200
    ReadOnly = True
    ScrollBars = ssVertical
    TabOrder = 4
  end
  object ClearButton: TButton
    Left = 486
    Top = 61
    Width = 100
    Height = 35
    Caption = 'Clear Log'
    TabOrder = 5
    OnClick = ClearButtonClick
  end
  object OpenDialog1: TOpenDialog
    Filter = 'Executable Files|*.exe|All Files|*.*'
    Title = 'Select Executable to Run as TrustedInstaller'
    Left = 640
    Top = 8
  end
end
