unit settingsdlg;

interface

uses Winapi.Windows, System.SysUtils, System.Classes, Vcl.Graphics, Vcl.Forms,
  Vcl.Controls, Vcl.StdCtrls, Vcl.Buttons, Vcl.ComCtrls, Vcl.ExtCtrls,
  System.ImageList, Vcl.ImgList, Vcl.VirtualImageList, Vcl.BaseImageCollection,
  Vcl.ImageCollection, Vcl.Dialogs, Vcl.CheckLst;

type
  TfrmSettings = class(TForm)
    Panel1: TPanel;
    Panel2: TPanel;
    PageControl1: TPageControl;
    TabSheet1: TTabSheet;
    TabSheet2: TTabSheet;
    TabSheet3: TTabSheet;
    OKBtn: TButton;
    CancelBtn: TButton;
    HelpBtn: TButton;
    cboTransferTypes: TComboBox;
    lblTransferType: TLabel;
    ImageCollection1: TImageCollection;
    VirtualImageList1: TVirtualImageList;
    FontDialog1: TFontDialog;
    redtLog: TRichEdit;
    Button1: TButton;
    chklbAdvancedOptions: TCheckListBox;
    lblAdvancedOptions: TLabel;
    procedure Button1Click(Sender: TObject);
    procedure FormCreate(Sender: TObject);
    procedure chklbAdvancedOptionsClickCheck(Sender: TObject);
    procedure FormShow(Sender: TObject);
  private
    function GetUsePortTransferType: Boolean;
    procedure SetUsePortTransferType(const Value: Boolean);
    procedure EnableDisableCheckBoxes;
    { Private declarations }
  public
    { Public declarations }
    property UsePortTransferType: Boolean read GetUsePortTransferType
      write SetUsePortTransferType;

  end;

var
  frmSettings: TfrmSettings;

implementation
uses IdSSLOpenSSL, ProgUtils;

{$R *.dfm}
{ TfrmSettings }

procedure TfrmSettings.Button1Click(Sender: TObject);
begin
  FontDialog1.Font := Self.redtLog.Font;
  if FontDialog1.Execute then begin
    Self.redtLog.Font := FontDialog1.Font;
  end;
end;

procedure TfrmSettings.chklbAdvancedOptionsClickCheck(Sender: TObject);
begin
  EnableDisableCheckBoxes;
end;

procedure TfrmSettings.EnableDisableCheckBoxes;
begin
  if chklbAdvancedOptions.Checked[1] = False then begin
     chklbAdvancedOptions.ItemEnabled[2] := False;
  end else begin
     chklbAdvancedOptions.ItemEnabled[2] := True;
  end;
end;

procedure TfrmSettings.FormCreate(Sender: TObject);
begin
  redtLog.Lines.Clear;
  redtLog.Lines.Add('Operating System: ' + TOSVersion.ToString);
  redtLog.Lines.Add('     RTL Version: ' + IntToStr(Hi(GetRTLVersion)) + '.' +
    IntToStr(Lo(GetRTLVersion)));
{$IFDEF WIN64}
  redtLog.Lines.Add('    Compiled For: Win64');
{$ELSE}
  redtLog.Lines.Add('    Compiled For: Win32');
{$ENDIF}
  redtLog.Lines.Add(' OpenSSL Version: ' + IdSSLOpenSSL.OpenSSLVersion);
  ScrollToEnd(redtLog);
  chklbAdvancedOptions.ItemEnabled[2] := False;
end;

procedure TfrmSettings.FormShow(Sender: TObject);
begin
  EnableDisableCheckBoxes;
end;

function TfrmSettings.GetUsePortTransferType: Boolean;
begin
  Result := cboTransferTypes.ItemIndex = 1;
end;

procedure TfrmSettings.SetUsePortTransferType(const Value: Boolean);
begin
  if Value then
  begin
    cboTransferTypes.ItemIndex := 1;
  end
  else
  begin
    cboTransferTypes.ItemIndex := 0;
  end;
end;

end.
