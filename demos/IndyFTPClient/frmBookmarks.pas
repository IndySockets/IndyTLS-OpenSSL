unit frmBookmarks;

interface

uses
  Winapi.Windows, Winapi.Messages, System.SysUtils, System.Variants,
  System.Classes, Vcl.Graphics,
  Vcl.Controls, Vcl.Forms, Vcl.Dialogs, Vcl.StdCtrls, Vcl.ExtCtrls,
  Vcl.BaseImageCollection, Vcl.ImageCollection, System.ImageList, Vcl.ImgList,
  Vcl.VirtualImageList, System.Actions, System.Generics.Collections,
  Vcl.ActnList, IniFiles;

type
  TFTPSite = class(TObject)
  protected
    FSiteName: String;
    FHostName: String;
    FAnonymous: Boolean;
    FUserName: String;
    FPassword: String;
    FAccount: String;
    FFTPPRotocol: Integer;
    FTransferMode: Integer;
    FPort : Integer;
    FPrivateKey : String;
    FPublicKey : String;
    FCAKey : String;
  public
    constructor Create(const AName: String); overload;
    constructor Create(const AName: String; AIni: TIniFile); overload;
    procedure Save(AIni: TIniFile);
    property SiteName: String read FSiteName write FSiteName;
    property HostName: String read FHostName write FHostName;
    property Anonymous: Boolean read FAnonymous write FAnonymous;
    property UserName: String read FUserName write FUserName;
    property Password: String read FPassword write FPassword;
    property Account: String read FAccount write FAccount;
    property FTPPRotocol: Integer read FFTPPRotocol write FFTPPRotocol;
    property TransferMode: Integer read FTransferMode write FTransferMode;
    property Port : Integer read FPort write FPort;
    property PrivateKey : String read FPrivateKey write FPrivateKey;
    property PublicKey : String read FPublicKey write FPublicKey;
    property CAKey : String read FCAKey write FCAKey;
  end;

  TfrmFTPSites = class(TForm)
    Panel2: TPanel;
    OKBtn: TButton;
    CancelBtn: TButton;
    lbxFTPSites: TListBox;
    lblFTPSites: TLabel;
    Button1: TButton;
    Button2: TButton;
    actLstFTPSites: TActionList;
    actFTPSitesNew: TAction;
    actFTPSitesEdit: TAction;
    actFTPSiteDelete: TAction;
    Button4: TButton;
    procedure actFTPSitesNewExecute(Sender: TObject);
    procedure FormCreate(Sender: TObject);
    procedure FormDestroy(Sender: TObject);
    procedure actFTPSitesEditExecute(Sender: TObject);
    procedure actFTPSitesEditUpdate(Sender: TObject);
    procedure actFTPSiteDeleteExecute(Sender: TObject);
    procedure actFTPSiteDeleteUpdate(Sender: TObject);
  private
    { Private declarations }
    FFTPSites: TObjectList<TFTPSite>;
  public
    { Public declarations }
    property FTPSites: TObjectList<TFTPSite> read FFTPSites;
  end;

var
  frmFTPSites: TfrmFTPSites;

function GetFTPSitesIniFilePath: String;

implementation

uses dkgFTPConnect, IOUtils, System.UITypes;

function GetFTPSitesIniFilePath: String;
begin
  Result := System.IOUtils.TPath.GetHomePath + '\IndyFTPClient';
  if not DirectoryExists(Result) then
  begin
    CreateDir(Result);
  end;
  Result := Result + '\ftpsites.ini';
end;

{$R *.dfm}

procedure TfrmFTPSites.actFTPSiteDeleteExecute(Sender: TObject);
begin
  if MessageDlg('Delete ' + FTPSites[lbxFTPSites.ItemIndex].SiteName + '?',
    mtConfirmation, [mbYes, mbNo], 0) = mrYes then
  begin
    FTPSites.Delete(lbxFTPSites.ItemIndex);
    lbxFTPSites.Items.Delete(lbxFTPSites.ItemIndex);
  end;
end;

procedure TfrmFTPSites.actFTPSiteDeleteUpdate(Sender: TObject);
begin
  actFTPSiteDelete.Enabled := lbxFTPSites.ItemIndex > -1;
end;

procedure TfrmFTPSites.actFTPSitesEditExecute(Sender: TObject);
var
  LFrm: TfrmConnect;
  LFTP: TFTPSite;
begin
  LFrm := TfrmConnect.Create(nil);
  try
    LFrm.Caption := 'Edit FTP Site';
    LFTP := FTPSites[lbxFTPSites.ItemIndex];
    LFrm.edtProfileName.Text := LFTP.SiteName;
    LFrm.edtHostname.Text := LFTP.FHostName;
    LFrm.chkAnonymousFTP.Checked := LFTP.Anonymous;
    LFrm.edtUsername.Text := LFTP.UserName;
    LFrm.edtPassword.Text := LFTP.Password;
    LFrm.edtAccount.Text := LFTP.Account;
    LFrm.cboConnectionType.ItemIndex := LFTP.FTPPRotocol;
    LFrm.cboTransferTypes.ItemIndex := LFTP.TransferMode;
    LFrm.spnedtPort.Value := LFTP.Port;
    LFrm.edtPrivateKeyFile.Text := LFTP.PrivateKey;
    LFrm.edtPublicKey.Text := LFTP.PublicKey;
    LFrm.edtCAKey.Text := LFTP.CAKey;
    if LFrm.ShowModal = mrOk then
    begin
      LFTP.SiteName := LFrm.edtProfileName.Text;
      LFTP.FHostName := LFrm.edtHostname.Text;
      LFTP.Anonymous := LFrm.chkAnonymousFTP.Checked;
      LFTP.UserName := LFrm.edtUsername.Text;
      LFTP.Password := LFrm.edtPassword.Text;
      LFTP.Account := LFrm.edtAccount.Text;
      LFTP.FTPPRotocol := LFrm.cboConnectionType.ItemIndex;
      LFTP.TransferMode := LFrm.cboTransferTypes.ItemIndex;
      LFTP.Port := LFrm.spnedtPort.Value;
      LFTP.PrivateKey := LFrm.edtPrivateKeyFile.Text;
      LFTP.PublicKey := LFrm.edtPublicKey.Text;
      LFTP.CAKey := LFrm.edtCAKey.Text;
    end;
  finally
    FreeAndNil(LFrm);
  end;
end;

procedure TfrmFTPSites.actFTPSitesEditUpdate(Sender: TObject);
begin
  actFTPSitesEdit.Enabled := lbxFTPSites.ItemIndex > -1;
end;

procedure TfrmFTPSites.actFTPSitesNewExecute(Sender: TObject);
var
  LFrm: TfrmConnect;
  LFTP: TFTPSite;
begin
  LFrm := TfrmConnect.Create(nil);
  try
    LFrm.Caption := 'New FTP Site';
    LFrm.cboTransferTypes.ItemIndex := 0;
    if LFrm.ShowModal = mrOk then
    begin
      lbxFTPSites.Items.Add(LFrm.edtProfileName.Text);
      LFTP := TFTPSite.Create(LFrm.edtProfileName.Text);
      LFTP.FHostName := LFrm.edtHostname.Text;
      LFTP.Anonymous := LFrm.chkAnonymousFTP.Checked;
      LFTP.UserName := LFrm.edtUsername.Text;
      LFTP.Password := LFrm.edtPassword.Text;
      LFTP.Account := LFrm.edtAccount.Text;
      LFTP.FTPPRotocol := LFrm.cboConnectionType.ItemIndex;
      LFTP.TransferMode := LFrm.cboTransferTypes.ItemIndex;
      LFTP.Port := LFrm.spnedtPort.Value;
      LFTP.PrivateKey := LFrm.edtPrivateKeyFile.Text;
      LFTP.PublicKey := LFrm.edtPublicKey.Text;
      LFTP.CAKey := LFrm.edtCAKey.Text;
      FFTPSites.Add(LFTP);
    end;
  finally
    FreeAndNil(LFrm);
  end;

end;

procedure TfrmFTPSites.FormCreate(Sender: TObject);
var
  LIni: TIniFile;
  LSections: TStringList;
  i: Integer;
begin
  FFTPSites := TObjectList<TFTPSite>.Create;
  LIni := TIniFile.Create(GetFTPSitesIniFilePath);
  LSections := TStringList.Create;
  try
    LIni.ReadSections(LSections);
    for i := 0 to LSections.Count - 1 do
    begin
      FFTPSites.Add(TFTPSite.Create(LSections[i], LIni));
      lbxFTPSites.Items.Add(LSections[i]);
    end;
  finally
    FreeAndNil(LSections);
    FreeAndNil(LIni);
  end;
end;

procedure TfrmFTPSites.FormDestroy(Sender: TObject);
var
  i: Integer;
  LIni: TIniFile;
begin
  // save profiles
  System.SysUtils.DeleteFile(GetFTPSitesIniFilePath);
  LIni := TIniFile.Create(GetFTPSitesIniFilePath);
  try
    for i := 0 to FFTPSites.Count - 1 do
    begin
      FFTPSites[i].Save(LIni);
    end;
  finally
    FreeAndNil(LIni);
  end;
  FreeAndNil(FFTPSites);
end;

{ TFTPSite }

constructor TFTPSite.Create(const AName: String; AIni: TIniFile);
begin
  inherited Create;
  FSiteName := AName;
  FHostName := AIni.ReadString(AName, 'Host', '');
  FAnonymous := AIni.ReadBool(AName, 'Anonymous', False);
  FUserName := AIni.ReadString(AName, 'User_Name', '');
  FPassword := AIni.ReadString(AName, 'Password', '');
  FAccount := AIni.ReadString(AName, 'Account','');
  FFTPPRotocol := AIni.ReadInteger(AName, 'Protocol', 0);
  FTransferMode := AIni.ReadInteger(AName, 'Transfer_Mode', 0);
  FPort := AIni.ReadInteger(AName, 'Port',21);
  FPrivateKey := AIni.ReadString(AName, 'Private_Key', '');
  FPublicKey := AIni.ReadString(AName,'Public_Key','');
  FCAKey := AIni.ReadString(AName,'Certificate_Authority_Key','');
end;

procedure TFTPSite.Save(AIni: TIniFile);
begin
  AIni.WriteString(FSiteName, 'Host', FHostName);
  AIni.WriteBool(FSiteName, 'Anonymous', FAnonymous);
  AIni.WriteString(FSiteName, 'User_Name', FUserName);
  AIni.WriteString(FSiteName, 'Password', FPassword);
  AIni.WriteString(FSiteName, 'Account', FAccount);
  AIni.WriteInteger(FSiteName, 'Protocol', FFTPPRotocol);
  AIni.WriteInteger(FSiteName, 'Transfer_Mode', FTransferMode);
  AIni.WriteInteger(FSiteName, 'Port', FPort);
  AIni.WriteString(FSiteName, 'Private_Key', FPrivateKey);
  AIni.WriteString(FSiteName,'Public_Key',FPublicKey);
  AIni.WriteString(FSiteName,'Certificate_Authority_Key',FCAKey);
end;

constructor TFTPSite.Create(const AName: String);
begin
  inherited Create;
  Self.FSiteName := AName;
end;

end.
