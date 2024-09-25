object frmFileProgress: TfrmFileProgress
  Left = 0
  Top = 0
  BorderStyle = bsDialog
  Caption = 'frmFileProgress'
  ClientHeight = 170
  ClientWidth = 386
  Color = clBtnFace
  Font.Charset = DEFAULT_CHARSET
  Font.Color = clWindowText
  Font.Height = -12
  Font.Name = 'Segoe UI'
  Font.Style = []
  Position = poMainFormCenter
  TextHeight = 15
  object lblAction: TLabel
    Left = 8
    Top = 16
    Width = 370
    Height = 15
    AutoSize = False
    Caption = 'lblAction'
  end
  object lblProgress: TLabel
    Left = 8
    Top = 80
    Width = 370
    Height = 15
    AutoSize = False
    Caption = 'lblProgress'
  end
  object Panel2: TPanel
    Left = 0
    Top = 136
    Width = 386
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
      386
      34)
    object CancelBtn: TButton
      Left = 306
      Top = 2
      Width = 75
      Height = 25
      Anchors = [akTop, akRight]
      Cancel = True
      Caption = 'Cancel'
      Default = True
      ModalResult = 2
      TabOrder = 0
      OnClick = CancelBtnClick
    end
  end
  object prgbrDownloadUpload: TProgressBar
    Left = 8
    Top = 45
    Width = 370
    Height = 17
    TabOrder = 1
  end
end
