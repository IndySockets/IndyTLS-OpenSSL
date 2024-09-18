unit dkgFTPConnect;

interface

uses Winapi.Windows, System.SysUtils, System.Classes, Vcl.Graphics, Vcl.Forms,
  Vcl.Controls, Vcl.StdCtrls, Vcl.Buttons, Vcl.ComCtrls, Vcl.ExtCtrls,
  System.ImageList, Vcl.ImgList, Vcl.VirtualImageList, Vcl.BaseImageCollection,
  Vcl.ImageCollection, IdExplicitTLSClientServerBase;

type
  TfrmConnect = class(TForm)
    Panel1: TPanel;
    Panel2: TPanel;
    PageControl1: TPageControl;
    TabSheet1: TTabSheet;
    TabSheet2: TTabSheet;
    OKBtn: TButton;
    CancelBtn: TButton;
    edtHostname: TEdit;
    lblHost: TLabel;
    chkAnonymousFTP: TCheckBox;
    edtUsername: TEdit;
    edtPassword: TEdit;
    lblUsername: TLabel;
    lblPassword: TLabel;
    cboConnectionType: TComboBox;
    ImageCollection1: TImageCollection;
    VirtualImageList1: TVirtualImageList;
    cboTransferTypes: TComboBox;
    lblTransferType: TLabel;
    edtProfileName: TEdit;
    lblProfileName: TLabel;
    lblConnectionType: TLabel;
    procedure chkAnonymousFTPClick(Sender: TObject);
    procedure edtProfileNameChange(Sender: TObject);
    procedure edtHostnameChange(Sender: TObject);
    procedure edtUsernameChange(Sender: TObject);
    procedure edtPasswordChange(Sender: TObject);
  private
    FQuickConnect: Boolean;
    function GetHost: String;
    procedure SetHost(const Value: String);
    function GetUsername: String;
    procedure SetUsername(const Value: String);
    function GetPassword: String;
    procedure SetPassword(const Value: String);
    function GetUseTLS: TIdUseTLS;
    procedure SetUseTLS(const Value: TIdUseTLS);
    function GetUsePortTransferType: Boolean;
    procedure SetUsePortTransferType(const Value: Boolean);
    function GetQuickConnect: Boolean;
    procedure SetQuickConnect(const Value: Boolean);
    function IsAnonymousOrLoginCompleted: Boolean;
    procedure ValidateOkBtn;
    { Private declarations }
  public
    { Public declarations }

    property QuickConnect: Boolean read GetQuickConnect write SetQuickConnect;

    property Host: String read GetHost write SetHost;
    property Username: String read GetUsername write SetUsername;
    property Password: String read GetPassword write SetPassword;
    property UseTLS: TIdUseTLS read GetUseTLS write SetUseTLS;
    property UsePortTransferType: Boolean read GetUsePortTransferType
      write SetUsePortTransferType;
  end;

var
  frmConnect: TfrmConnect;

function GetIniFilePath: String;

function ReadTransferDefault: Boolean;

implementation

uses System.IniFiles, System.IOUtils;

function GetIniFilePath: String;
begin
  Result := System.IOUtils.TPath.GetHomePath + '\IndyFTPClient';
  if not DirectoryExists(Result) then
  begin
    CreateDir(Result);
  end;
  Result := Result + '\config.ini';
end;

{$R *.dfm}
{ TfrmConnect }

procedure TfrmConnect.chkAnonymousFTPClick(Sender: TObject);
begin
  if Self.chkAnonymousFTP.Checked then
  begin
    Self.edtUsername.Enabled := False;
    Self.edtPassword.Enabled := False;
    Self.lblUsername.Enabled := False;
    Self.lblPassword.Enabled := False;
  end
  else
  begin
    Self.edtUsername.Enabled := True;
    Self.edtPassword.Enabled := True;
    Self.lblUsername.Enabled := True;
    Self.lblPassword.Enabled := True;
  end;
  ValidateOkBtn;
end;

procedure TfrmConnect.edtHostnameChange(Sender: TObject);
begin
  ValidateOkBtn;
end;

procedure TfrmConnect.edtPasswordChange(Sender: TObject);
begin
  ValidateOkBtn;
end;

procedure TfrmConnect.edtProfileNameChange(Sender: TObject);
begin
  ValidateOkBtn;
end;

procedure TfrmConnect.edtUsernameChange(Sender: TObject);
begin
  ValidateOkBtn;
end;

function TfrmConnect.GetHost: String;
begin
  Result := edtHostname.Text;
end;

function TfrmConnect.GetPassword: String;
begin
  if Self.chkAnonymousFTP.Checked then
  begin
    Result := 'a@b';
  end
  else
  begin
    Result := Self.edtPassword.Text;
  end;
end;

function TfrmConnect.GetQuickConnect: Boolean;
begin
  Result := FQuickConnect;
end;

function ReadTransferDefault: Boolean;
var
  LIni: TIniFile;
begin
  LIni := TIniFile.Create(GetIniFilePath);
  try
    Result := LIni.ReadBool('Transfers', 'Use_PORT_Transfers', False);
  finally
    FreeAndNil(LIni);
  end;

end;

function TfrmConnect.GetUsePortTransferType: Boolean;
begin

  Result := ReadTransferDefault;
  case Self.cboTransferTypes.ItemIndex of
    // Use Default Setting
    // Use PASV Transfers
    // Use PORT Transfers
    1:
      Result := False;
    2:
      Result := True;
  end;
end;

function TfrmConnect.GetUsername: String;
begin
  if Self.chkAnonymousFTP.Checked then
  begin
    Result := 'anonymous';
  end
  else
  begin
    Result := Self.edtUsername.Text;
  end;
end;

function TfrmConnect.GetUseTLS: TIdUseTLS;
begin
  Result := utUseExplicitTLS;;
  case cboConnectionType.ItemIndex of
    0:
      Result := utNoTLSSupport;
    1:
      Result := utUseExplicitTLS;
    2:
      Result := utUseImplicitTLS;
  end;

end;

function TfrmConnect.IsAnonymousOrLoginCompleted: Boolean;
begin
  Result := Self.chkAnonymousFTP.Checked;
  if not Result then
  begin
    Result := (Self.edtUsername.Text <> '') and (Self.edtPassword.Text <> '')
  end;
end;

procedure TfrmConnect.SetHost(const Value: String);
begin
  Self.edtHostname.Text := Value;
end;

procedure TfrmConnect.SetPassword(const Value: String);
begin
  Self.edtPassword.Text := Value;
end;

procedure TfrmConnect.SetQuickConnect(const Value: Boolean);
begin
  FQuickConnect := Value;
  if FQuickConnect then
  begin
    edtProfileName.Visible := False;
    lblProfileName.Visible := False;
    edtHostname.Top := 13;
    lblHost.Top := 16;
    Self.chkAnonymousFTP.Top := 50;
    Self.edtUsername.Top := 87;
    Self.lblUsername.Top := 90;
    Self.edtPassword.Top := 124;
    Self.lblPassword.Top := 127;
    Self.cboConnectionType.Top := 161;
    Self.lblConnectionType.Top := 165;
  end
  else
  begin

  end;
end;

procedure TfrmConnect.SetUsePortTransferType(const Value: Boolean);
begin

end;

procedure TfrmConnect.SetUsername(const Value: String);
begin
  Self.edtUsername.Text := Value;
end;

procedure TfrmConnect.SetUseTLS(const Value: TIdUseTLS);
begin
  Self.cboConnectionType.ItemIndex := 1;
  case Value of
    utNoTLSSupport:
      cboConnectionType.ItemIndex := 0;
    utUseExplicitTLS:
      cboConnectionType.ItemIndex := 1;
    utUseImplicitTLS:
      cboConnectionType.ItemIndex := 2;
  end;
end;

procedure TfrmConnect.ValidateOkBtn;
var
  LRes: Boolean;
begin
  LRes := False;
  if not Self.QuickConnect then
  begin
    if Self.edtProfileName.Text <> '' then
    begin
      LRes := (Self.edtHostname.Text <> '') and IsAnonymousOrLoginCompleted;
    end;
  end
  else
  begin
    LRes := (Self.edtHostname.Text <> '') and IsAnonymousOrLoginCompleted;
  end;
  Self.OKBtn.Enabled := LRes;
end;

end.
