object frmFTPSites: TfrmFTPSites
  Left = 0
  Top = 0
  BorderStyle = bsDialog
  Caption = 'FTP Sites'
  ClientHeight = 294
  ClientWidth = 267
  Color = clBtnFace
  Font.Charset = DEFAULT_CHARSET
  Font.Color = clWindowText
  Font.Height = -12
  Font.Name = 'Segoe UI'
  Font.Style = []
  Position = poScreenCenter
  OnCreate = FormCreate
  OnDestroy = FormDestroy
  DesignSize = (
    267
    294)
  TextHeight = 15
  object lblFTPSites: TLabel
    Left = 8
    Top = 11
    Width = 46
    Height = 15
    Caption = '&FTP Sites'
    FocusControl = lbxFTPSites
  end
  object Panel2: TPanel
    Left = 0
    Top = 260
    Width = 267
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
      267
      34)
    object OKBtn: TButton
      Left = 106
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
      Left = 187
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
  object lbxFTPSites: TListBox
    Left = 8
    Top = 32
    Width = 173
    Height = 228
    Anchors = [akLeft, akTop, akRight, akBottom]
    ItemHeight = 15
    TabOrder = 1
  end
  object Button1: TButton
    Left = 187
    Top = 32
    Width = 75
    Height = 25
    Action = actFTPSitesNew
    Anchors = [akTop, akRight]
    TabOrder = 2
  end
  object Button2: TButton
    Left = 187
    Top = 63
    Width = 75
    Height = 25
    Action = actFTPSitesEdit
    Anchors = [akTop, akRight]
    TabOrder = 3
  end
  object Button4: TButton
    Left = 187
    Top = 94
    Width = 75
    Height = 25
    Action = actFTPSiteDelete
    Anchors = [akTop, akRight]
    TabOrder = 4
  end
  object actLstFTPSites: TActionList
    Left = 160
    Top = 224
    object actFTPSitesNew: TAction
      Caption = '&New...'
      OnExecute = actFTPSitesNewExecute
    end
    object actFTPSitesEdit: TAction
      Caption = '&Edit...'
      OnExecute = actFTPSitesEditExecute
      OnUpdate = actFTPSitesEditUpdate
    end
    object actFTPSiteDelete: TAction
      Caption = '&Delete'
      OnExecute = actFTPSiteDeleteExecute
      OnUpdate = actFTPSiteDeleteUpdate
    end
  end
end
