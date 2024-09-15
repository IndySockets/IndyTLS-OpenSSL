object frmCertViewer: TfrmCertViewer
  Left = 0
  Top = 0
  Caption = 'frmCertViewer'
  ClientHeight = 385
  ClientWidth = 558
  Color = clBtnFace
  Font.Charset = DEFAULT_CHARSET
  Font.Color = clBtnText
  Font.Height = -12
  Font.Name = 'Segoe UI'
  Font.Style = []
  Position = poDesktopCenter
  OnCreate = FormCreate
  DesignSize = (
    558
    385)
  TextHeight = 15
  object lblErrorMessage: TLabel
    Left = 8
    Top = 8
    Width = 542
    Height = 74
    Anchors = [akLeft, akTop, akRight]
    AutoSize = False
    FocusControl = redtCertView
    WordWrap = True
  end
  object lblAcceptThisCertificate: TLabel
    Left = 8
    Top = 88
    Width = 119
    Height = 15
    Caption = 'A&ccept this certificate?'
    FocusControl = redtCertView
  end
  object Panel2: TPanel
    Left = 0
    Top = 351
    Width = 558
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
      558
      34)
    object OKBtn: TButton
      Left = 318
      Top = 2
      Width = 75
      Height = 25
      Anchors = [akTop, akRight]
      Caption = '&Yes'
      Default = True
      ModalResult = 6
      TabOrder = 0
    end
    object CancelBtn: TButton
      Left = 398
      Top = 2
      Width = 75
      Height = 25
      Anchors = [akTop, akRight]
      Cancel = True
      Caption = '&No'
      ModalResult = 7
      TabOrder = 1
    end
    object HelpBtn: TButton
      Left = 478
      Top = 2
      Width = 75
      Height = 25
      Anchors = [akTop, akRight]
      Caption = '&Help'
      TabOrder = 2
    end
  end
  object redtCertView: TRichEdit
    Left = 8
    Top = 104
    Width = 542
    Height = 217
    Anchors = [akLeft, akTop, akRight, akBottom]
    Font.Charset = ANSI_CHARSET
    Font.Color = clWindowText
    Font.Height = -12
    Font.Name = 'Lucida Console'
    Font.Style = []
    Lines.Strings = (
      'redtCertView')
    ParentFont = False
    ReadOnly = True
    ScrollBars = ssBoth
    TabOrder = 1
    WantTabs = True
    WantReturns = False
    WordWrap = False
  end
  object chkacceptOnlyOnce: TCheckBox
    Left = 8
    Top = 328
    Width = 542
    Height = 17
    Anchors = [akLeft, akRight, akBottom]
    Caption = '&Accept Certificate Only Once'
    TabOrder = 2
  end
end
