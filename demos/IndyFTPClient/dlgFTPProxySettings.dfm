object frmFTPProxySettings: TfrmFTPProxySettings
  Left = 0
  Top = 0
  BorderStyle = bsDialog
  Caption = 'frmFTPProxySettings'
  ClientHeight = 187
  ClientWidth = 472
  Color = clBtnFace
  Font.Charset = DEFAULT_CHARSET
  Font.Color = clWindowText
  Font.Height = -12
  Font.Name = 'Segoe UI'
  Font.Style = []
  Position = poDesktopCenter
  TextHeight = 15
  object lblProxyPort: TLabel
    Left = 64
    Top = 132
    Width = 25
    Height = 15
    Caption = 'P&ort:'
    Enabled = False
  end
  object lblProxyServerPassword: TLabel
    Left = 40
    Top = 103
    Width = 53
    Height = 15
    Caption = 'Password:'
    Enabled = False
    FocusControl = edtProxyServerPassword
  end
  object lblProxyServerUserName: TLabel
    Left = 38
    Top = 74
    Width = 56
    Height = 15
    Caption = 'Username:'
    Enabled = False
    FocusControl = edtProxyServerUserName
  end
  object lblProxyServerName: TLabel
    Left = 26
    Top = 46
    Width = 68
    Height = 15
    Caption = 'Proxy &Server:'
    Enabled = False
    FocusControl = edtProxyServerName
  end
  object lblProxyType: TLabel
    Left = 64
    Top = 16
    Width = 27
    Height = 15
    Caption = '&Type:'
    FocusControl = cboProxyType
  end
  object Panel2: TPanel
    Left = 0
    Top = 153
    Width = 472
    Height = 34
    Align = alBottom
    BevelOuter = bvNone
    Font.Charset = DEFAULT_CHARSET
    Font.Color = clBtnText
    Font.Height = -12
    Font.Name = 'Segoe UI'
    Font.Style = []
    ParentColor = True
    ParentFont = False
    TabOrder = 0
    DesignSize = (
      472
      34)
    object OKBtn: TButton
      Left = 311
      Top = 2
      Width = 75
      Height = 25
      Anchors = [akTop, akRight]
      Caption = 'OK'
      Default = True
      ModalResult = 1
      TabOrder = 0
    end
    object CancelBtn: TButton
      Left = 392
      Top = 2
      Width = 75
      Height = 25
      Anchors = [akTop, akRight]
      Cancel = True
      Caption = 'Cancel'
      ModalResult = 2
      TabOrder = 1
    end
  end
  object spededtProxyPort: TSpinEdit
    Left = 95
    Top = 129
    Width = 121
    Height = 24
    Enabled = False
    MaxValue = 65535
    MinValue = 1
    TabOrder = 5
    Value = 1
  end
  object edtProxyServerPassword: TEdit
    Left = 97
    Top = 100
    Width = 369
    Height = 23
    Enabled = False
    PasswordChar = '*'
    TabOrder = 4
  end
  object edtProxyServerUserName: TEdit
    Left = 95
    Top = 71
    Width = 369
    Height = 23
    Enabled = False
    TabOrder = 3
  end
  object edtProxyServerName: TEdit
    Left = 97
    Top = 42
    Width = 369
    Height = 23
    Enabled = False
    TabOrder = 2
  end
  object cboProxyType: TComboBox
    Left = 97
    Top = 13
    Width = 369
    Height = 23
    Style = csDropDownList
    TabOrder = 1
    OnChange = cboProxyTypeChange
    Items.Strings = (
      'None'
      'Send command USER user@hostname - USER after login'
      'Send command SITE (with logon)'
      'Send command OPEN'
      'USER user@firewalluser@hostname / PASS pass@firewallpass'
      
        'First use the USER and PASS command with the firewall username a' +
        'nd password, and then with the target host username and password' +
        '.'
      'USER hostuserId@hostname firewallUsername'
      'Novell BorderManager Proxy')
  end
end
