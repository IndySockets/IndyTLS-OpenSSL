unit settingsdlg;

interface

uses Winapi.Windows, System.SysUtils, System.Classes, Vcl.Graphics, Vcl.Forms,
  Vcl.Controls, Vcl.StdCtrls, Vcl.Buttons, Vcl.ComCtrls, Vcl.ExtCtrls,
  System.ImageList, Vcl.ImgList, Vcl.VirtualImageList, Vcl.BaseImageCollection,
  Vcl.ImageCollection, Vcl.Dialogs, Vcl.CheckLst, Vcl.Samples.Spin;

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
    cboTransferTypes: TComboBox;
    lblTransferType: TLabel;
    ImageCollection1: TImageCollection;
    VirtualImageList1: TVirtualImageList;
    FontDialog1: TFontDialog;
    redtLog: TRichEdit;
    btnFontSelect: TButton;
    chklbAdvancedOptions: TCheckListBox;
    lblAdvancedOptions: TLabel;
    redtTextSamples: TRichEdit;
    ScrollBox1: TScrollBox;
    lblErrors: TLabel;
    lblTLSMessages: TLabel;
    lblDirOutput: TLabel;
    cboErrorForeground: TColorBox;
    cboErrorBackground: TColorBox;
    cboTLSMessageForeground: TColorBox;
    cboTLSMessageBackground: TColorBox;
    cboDirOutputForeground: TColorBox;
    cboDirOutputBackground: TColorBox;
    lblForeground: TLabel;
    lblBackground: TLabel;
    cboDebugForeground: TColorBox;
    cboDebugBackground: TColorBox;
    lblDebugOutput: TLabel;
    TabSheet4: TTabSheet;
    chkLogDebug: TCheckBox;
    btnNATSettings: TButton;
    btnTransparentProxy: TButton;
    btnFTPProxySettings: TButton;
    procedure btnFontSelectClick(Sender: TObject);
    procedure FormCreate(Sender: TObject);
    procedure chklbAdvancedOptionsClickCheck(Sender: TObject);
    procedure FormShow(Sender: TObject);
    procedure cboErrorForegroundChange(Sender: TObject);
    procedure cboErrorBackgroundChange(Sender: TObject);
    procedure cboTLSMessageBackgroundChange(Sender: TObject);
    procedure cboTLSMessageForegroundChange(Sender: TObject);
    procedure cboDirOutputForegroundChange(Sender: TObject);
    procedure cboDirOutputBackgroundChange(Sender: TObject);
    procedure cboDebugForegroundSelect(Sender: TObject);
    procedure cboDebugBackgroundSelect(Sender: TObject);
    procedure edtExternalIPAddressChange(Sender: TObject);
    procedure spnedtPortMinimumChange(Sender: TObject);
    procedure spnedtPortMaxChange(Sender: TObject);
    procedure cboProxyTypeChange(Sender: TObject);
    procedure edtProxyServerNameChange(Sender: TObject);
    procedure btnNATSettingsClick(Sender: TObject);
    procedure btnTransparentProxyClick(Sender: TObject);
    procedure btnFTPProxySettingsClick(Sender: TObject);
  protected
    FErrorForeground: TColor;
    FErrorBackground: TColor;
    FSSLMessageForeground: TColor;
    FSSLMessageBackground: TColor;
    FDirOutputForeground: TColor;
    FDirOutputBackground: TColor;
    FDebugForeground: TColor;
    FDebugBackground: TColor;
    //proxy/firewall settings for subdialog-boxes
    FNATPortMin : Word;
    FNATPortMax : Word;
    FNATIPAddress : String;
    FProxyPort : Word;
    FProxyHost : String;
    FProxyUsername : String;
    FProxyPassword : String;
    FProxyType : Integer;
    FFTPProxyPort: Word;
    FFTPProxyType: Integer;
    FFTPProxyPassword: String;
    FFTPProxyHost: String;
    FFTPProxyUsername: String;
    //
    procedure ValidateFeilds;
    function GetUsePortTransferType: Boolean;
    procedure SetUsePortTransferType(const Value: Boolean);
    procedure EnableDisableCheckBoxes;
    procedure DisplaySampleTexts;
    procedure SetDirOutputBackground(const Value: TColor);
    procedure SetDirOutputForeground(const Value: TColor);
    procedure SetErrorBackground(const Value: TColor);
    procedure SetErrorForeground(const Value: TColor);
    procedure SetSSLMessageBackground(const Value: TColor);
    procedure SetSSLMessageForeground(const Value: TColor);
    function GetDirOutputBackground: TColor;
    function GetDirOutputForeground: TColor;
    function GetErrorBackground: TColor;
    function GetErrorForeground: TColor;
    function GetSSLMessageBackground: TColor;
    function GetSSLMessageForeground: TColor;
    function GetDebugBackground: TColor;
    function GetDebugForeground: TColor;
    procedure SetDebugBackground(const Value: TColor);
    procedure SetDebugForeground(const Value: TColor);
    { Private declarations }
  public
    { Public declarations }
    property UsePortTransferType: Boolean read GetUsePortTransferType
      write SetUsePortTransferType;
    property ErrorForeground: TColor read GetErrorForeground
      write SetErrorForeground;
    property ErrorBackground: TColor read GetErrorBackground
      write SetErrorBackground;
    property SSLMessageForeground: TColor read GetSSLMessageForeground
      write SetSSLMessageForeground;
    property SSLMessageBackground: TColor read GetSSLMessageBackground
      write SetSSLMessageBackground;
    property DirOutputForeground: TColor read GetDirOutputForeground
      write SetDirOutputForeground;
    property DirOutputBackground: TColor read GetDirOutputBackground
      write SetDirOutputBackground;
    property DebugForeground: TColor read GetDebugForeground
      write SetDebugForeground;
    property DebugBackground: TColor read GetDebugBackground
      write SetDebugBackground;
    property NATPortMin : Word read FNATPortMin write FNATPortMin;
    property NATPortMax : Word read FNATPortMax write FNATPortMax;
    property NATIPAddress : String read FNATIPAddress write FNATIPAddress;
    property ProxyPort : Word read FProxyPort write FProxyPort;
    property ProxyHost : String read FProxyHost write FProxyHost;
    property ProxyUsername : String read FProxyUsername write FProxyUsername;
    property ProxyPassword : String read FProxyPassword write FProxyPassword;
    property ProxyType : Integer read FProxyType write FProxyType;

    property FTPProxyPort : Word read FFTPProxyPort write FFTPProxyPort;
    property FTPProxyHost : String read FFTPProxyHost write FFTPProxyHost;
    property FTPProxyUsername : String read FFTPProxyUsername write FFTPProxyUsername;
    property FTPProxyPassword : String read FFTPProxyPassword write FFTPProxyPassword;
    property FTPProxyType : Integer read FFTPProxyType write FFTPProxyType;

  end;

var
  frmSettings: TfrmSettings;

implementation

uses IdSSLOpenSSL, ProgUtils, dlgNATSettings, dlgFTPProxySettings, dlgProxySettings;

{$R *.dfm}
{ TfrmSettings }

procedure TfrmSettings.btnFontSelectClick(Sender: TObject);
begin
  FontDialog1.Font := redtLog.Font;
  if FontDialog1.Execute then
  begin
    redtLog.Font := FontDialog1.Font;
  end;
end;

procedure TfrmSettings.cboDirOutputBackgroundChange(Sender: TObject);
begin
  FDirOutputBackground := cboDirOutputBackground.Selected;
  DisplaySampleTexts;
end;

procedure TfrmSettings.cboDirOutputForegroundChange(Sender: TObject);
begin
  FDirOutputForeground := cboDirOutputForeground.Selected;
  DisplaySampleTexts;
end;

procedure TfrmSettings.cboErrorBackgroundChange(Sender: TObject);
begin
  FErrorBackground := cboErrorBackground.Selected;
  DisplaySampleTexts;
end;

procedure TfrmSettings.cboErrorForegroundChange(Sender: TObject);
begin
  FErrorForeground := cboErrorForeground.Selected;
  DisplaySampleTexts;
end;

procedure TfrmSettings.cboProxyTypeChange(Sender: TObject);
begin
  ValidateFeilds;
end;

procedure TfrmSettings.cboTLSMessageBackgroundChange(Sender: TObject);
begin
  FSSLMessageBackground := cboTLSMessageBackground.Selected;
  DisplaySampleTexts;
end;

procedure TfrmSettings.cboTLSMessageForegroundChange(Sender: TObject);
begin
  FSSLMessageForeground := cboTLSMessageForeground.Selected;
  DisplaySampleTexts;
end;

procedure TfrmSettings.chklbAdvancedOptionsClickCheck(Sender: TObject);
begin
  EnableDisableCheckBoxes;
end;

procedure TfrmSettings.btnFTPProxySettingsClick(Sender: TObject);
var Lfrm : TfrmFTPProxySettings;
begin
  LFrm := TfrmFTPProxySettings.Create(Application);
  try
    LFrm.Caption := StringReplace(btnFTPProxySettings.Caption,'&','',[]);
    LFrm.cboProxyType.ItemIndex := FFTPProxyType;
    LFrm.edtProxyServerName.Text := FFTPProxyHost;
    LFrm.edtProxyServerUserName.Text := FFTPProxyUsername;
    LFrm.edtProxyServerPassword.Text := FFTPProxyPassword;
    LFrm.spededtProxyPort.Value := FFTPProxyPort;
    if LFrm.ShowModal = mrOk then
    begin
      FFTPProxyType := LFrm.cboProxyType.ItemIndex;
      FFTPProxyHost := LFrm.edtProxyServerName.Text;
      FFTPProxyUsername := LFrm.edtProxyServerUserName.Text;
      FFTPProxyPassword := LFrm.edtProxyServerPassword.Text;
      FFTPProxyPort := LFrm.spededtProxyPort.Value;
    end;
  finally
    FreeAndNil(LFrm);
  end;
end;

procedure TfrmSettings.btnNATSettingsClick(Sender: TObject);
var LFrm : TfrmNATSettings;
begin
  LFrm := TfrmNATSettings.Create(Application);
  try
    LFrm.Caption := StringReplace(btnNATSettings.Caption,'&','',[]);
    LFrm.edtExternalIPAddress.Text := FNATIPAddress;
    LFrm.spnedtPortMinimum.Value := FNATPortMin;
    LFrm.spnedtPortMaximum.Value := FNATPortMax;
    if LFrm.ShowModal = mrOk then begin
      FNATIPAddress := LFrm.edtExternalIPAddress.Text;
      FNATPortMin := LFrm.spnedtPortMinimum.Value;
      FNATPortMax := LFrm.spnedtPortMaximum.Value;
    end;
  finally
    FreeAndNil(LFrm);
  end;
end;

procedure TfrmSettings.btnTransparentProxyClick(Sender: TObject);
var LFrm : TfrmProxySettings;
begin
  LFrm := TfrmProxySettings.Create(Application);
  try
    LFrm.Caption := StringReplace(btnTransparentProxy.Caption,'&','',[]);
    LFrm.cboProxyType.ItemIndex := FProxyType;
    LFrm.edtProxyServerName.Text := FProxyHost;
    LFrm.edtProxyServerUserName.Text := FProxyUsername;
    LFrm.edtProxyServerPassword.Text := FProxyPassword;
    LFrm.spededtProxyPort.Value := FProxyPort;
    if LFrm.ShowModal = mrOk then
    begin
      FProxyType := LFrm.cboProxyType.ItemIndex;
      FProxyHost := LFrm.edtProxyServerName.Text;
      FProxyUsername := LFrm.edtProxyServerUserName.Text;
      FProxyPassword := LFrm.edtProxyServerPassword.Text;
      FProxyPort := LFrm.spededtProxyPort.Value;
    end;
  finally
    FreeAndNil(LFrm);
  end;
end;

procedure TfrmSettings.cboDebugBackgroundSelect(Sender: TObject);
begin
  FDebugBackground := cboDebugBackground.Selected;
  DisplaySampleTexts;
end;

procedure TfrmSettings.cboDebugForegroundSelect(Sender: TObject);
begin
  FDebugForeground := cboDebugForeground.Selected;
  DisplaySampleTexts;
end;

procedure TfrmSettings.DisplaySampleTexts;
begin
  redtTextSamples.Lines.Clear;
  redtTextSamples.SelAttributes.Color := FErrorForeground;
  cboErrorForeground.Selected := FErrorForeground;
  redtTextSamples.SelAttributes.BackColor := FErrorBackground;
  cboErrorBackground.Selected := FErrorBackground;
  redtTextSamples.Lines.Add('Error Text');
  redtTextSamples.SelAttributes.Color := FSSLMessageForeground;
  cboTLSMessageForeground.Selected := FSSLMessageForeground;
  redtTextSamples.SelAttributes.BackColor := FSSLMessageBackground;
  cboTLSMessageBackground.Selected := FSSLMessageBackground;
  redtTextSamples.Lines.Add('SSL Information');
  redtTextSamples.SelAttributes.Color := FDirOutputForeground;
  cboDirOutputForeground.Selected := FDirOutputForeground;
  redtTextSamples.SelAttributes.BackColor := FDirOutputBackground;
  cboDirOutputBackground.Selected := FDirOutputBackground;
  redtTextSamples.Lines.Add('Directory List Output');
  redtTextSamples.SelAttributes.Color := FDebugForeground;
  redtTextSamples.SelAttributes.BackColor := FDebugBackground;
  cboDebugForeground.Selected := FDebugForeground;
  cboDebugBackground.Selected := FDebugBackground;
  redtTextSamples.Lines.Add('Debug Output');
  ScrollToTop(redtTextSamples);
end;

procedure TfrmSettings.edtExternalIPAddressChange(Sender: TObject);
begin
  ValidateFeilds;
end;

procedure TfrmSettings.edtProxyServerNameChange(Sender: TObject);
begin
  ValidateFeilds;
end;

procedure TfrmSettings.EnableDisableCheckBoxes;
begin
  if chklbAdvancedOptions.Checked[1] = False then
  begin
    chklbAdvancedOptions.ItemEnabled[2] := False;
  end
  else
  begin
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
  DisplaySampleTexts;
end;

procedure TfrmSettings.FormShow(Sender: TObject);
begin
  EnableDisableCheckBoxes;
  ValidateFeilds;
end;

function TfrmSettings.GetDebugBackground: TColor;
begin
  Result := cboDebugBackground.Selected;
end;

function TfrmSettings.GetDebugForeground: TColor;
begin
  Result := cboDebugForeground.Selected;
end;

function TfrmSettings.GetDirOutputBackground: TColor;
begin
  Result := cboDirOutputBackground.Selected;
end;

function TfrmSettings.GetDirOutputForeground: TColor;
begin
  Result := cboDirOutputForeground.Selected;
end;

function TfrmSettings.GetErrorBackground: TColor;
begin
  Result := cboErrorBackground.Selected;
end;

function TfrmSettings.GetErrorForeground: TColor;
begin
  Result := cboErrorForeground.Selected;
end;

function TfrmSettings.GetSSLMessageBackground: TColor;
begin
  Result := cboTLSMessageBackground.Selected;
end;

function TfrmSettings.GetSSLMessageForeground: TColor;
begin
  Result := cboTLSMessageForeground.Selected;
end;

function TfrmSettings.GetUsePortTransferType: Boolean;
begin
  Result := cboTransferTypes.ItemIndex = 1;
end;

procedure TfrmSettings.SetDebugBackground(const Value: TColor);
begin
  Self.FDebugBackground := Value;
  DisplaySampleTexts;
end;

procedure TfrmSettings.SetDebugForeground(const Value: TColor);
begin
  FDebugForeground := Value;
  DisplaySampleTexts;
end;

procedure TfrmSettings.SetDirOutputBackground(const Value: TColor);
begin
  FDirOutputBackground := Value;
  DisplaySampleTexts;
end;

procedure TfrmSettings.SetDirOutputForeground(const Value: TColor);
begin
  FDirOutputForeground := Value;
  DisplaySampleTexts;
end;

procedure TfrmSettings.SetErrorBackground(const Value: TColor);
begin
  FErrorBackground := Value;
  DisplaySampleTexts;
end;

procedure TfrmSettings.SetErrorForeground(const Value: TColor);
begin
  FErrorForeground := Value;
  DisplaySampleTexts;
end;

procedure TfrmSettings.SetSSLMessageBackground(const Value: TColor);
begin
  FSSLMessageBackground := Value;
  DisplaySampleTexts;
end;

procedure TfrmSettings.SetSSLMessageForeground(const Value: TColor);
begin
  FSSLMessageForeground := Value;
  DisplaySampleTexts;
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

procedure TfrmSettings.spnedtPortMaxChange(Sender: TObject);
begin
  ValidateFeilds;
end;

procedure TfrmSettings.spnedtPortMinimumChange(Sender: TObject);
begin
  ValidateFeilds;
end;

procedure TfrmSettings.ValidateFeilds;
begin

end;

end.
