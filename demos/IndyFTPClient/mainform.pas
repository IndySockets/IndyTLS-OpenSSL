unit mainform;

interface

uses
  Winapi.Windows, Winapi.Messages, System.SysUtils, System.Variants,
  System.Classes, Vcl.Graphics,
  Vcl.Controls, Vcl.Forms, Vcl.Dialogs, Vcl.BaseImageCollection,
  Vcl.ImageCollection, System.ImageList, Vcl.ImgList, Vcl.VirtualImageList,
  System.Actions, Vcl.ActnList, Vcl.ComCtrls, Vcl.StdCtrls, Vcl.ExtCtrls,
  Vcl.ToolWin, IdBaseComponent, IdComponent, IdTCPConnection, IdTCPClient,
  IdExplicitTLSClientServerBase, IdFTP, IdCTypes, IdOpenSSLHeaders_ossl_typ,
  IdIOHandler, IdIOHandlerSocket, IdIOHandlerStack, IdSSL, IdSSLOpenSSL,
  IdIntercept, IdLogBase, IdLogEvent, Vcl.Menus, Vcl.StdActns,
  IdZLibCompressorBase, IdCompressorZLib, IdSync, IdConnectThroughHttpProxy,
  IdCustomTransparentProxy, IdSocks;

type
  TfrmMainForm = class(TForm)
    vimglstMainProgram: TVirtualImageList;
    imgcolMainProgram: TImageCollection;
    actlstMainProgram: TActionList;
    actFileDownload: TAction;
    actFileUpload: TAction;
    sbrMainForm: TStatusBar;
    pnlLog: TPanel;
    tbrMainProgram: TToolBar;
    spltrLog: TSplitter;
    pnlMainWindow: TPanel;
    pnlLocalBrowser: TPanel;
    pnlRemoteBrowser: TPanel;
    actFileConnect: TAction;
    ToolButton1: TToolButton;
    IdFTPClient: TIdFTP;
    iosslFTP: TIdSSLIOHandlerSocketOpenSSL;
    ToolButton2: TToolButton;
    actFileDisconnect: TAction;
    FIdLog: TIdLogEvent;
    ToolButton3: TToolButton;
    ppmnuLog: TPopupMenu;
    EditCopy1: TEditCopy;
    EditSelectAll1: TEditSelectAll;
    Copy1: TMenuItem;
    N1: TMenuItem;
    SelectAll1: TMenuItem;
    vimglstSmall: TVirtualImageList;
    IdCompressorZLib1: TIdCompressorZLib;
    MainMenu1: TMainMenu;
    File1: TMenuItem;
    Connect1: TMenuItem;
    Disonnct1: TMenuItem;
    Edit1: TMenuItem;
    Copy2: TMenuItem;
    N2: TMenuItem;
    SelectAll2: TMenuItem;
    View1: TMenuItem;
    Help1: TMenuItem;
    actViewSetting: TAction;
    Settings1: TMenuItem;
    FileExit1: TFileExit;
    actFileFTPSites: TAction;
    N3: TMenuItem;
    FTPSites1: TMenuItem;
    ToolButton4: TToolButton;
    ToolButton5: TToolButton;
    N4: TMenuItem;
    Exit1: TMenuItem;
    actHelpAbout: TAction;
    About1: TMenuItem;
    lvLocalFiles: TListView;
    lvRemoteFiles: TListView;
    cboLocalCurrentDir: TComboBox;
    cboRemoteCurrentDir: TComboBox;
    lblLocalCurrentDir: TLabel;
    lblRemotDir: TLabel;
    N5: TMenuItem;
    Dowload1: TMenuItem;
    Upload1: TMenuItem;
    redtLog: TRichEdit;
    Splitter1: TSplitter;
    actFileRemoteDelete: TAction;
    actFileLocalDelete: TAction;
    ppmnuRemote: TPopupMenu;
    ppmnuLocal: TPopupMenu;
    Upload2: TMenuItem;
    N6: TMenuItem;
    actFileLocalDelete1: TMenuItem;
    Dowload2: TMenuItem;
    N7: TMenuItem;
    Delete1: TMenuItem;
    actFileRemoteRename: TAction;
    actFileLocalRename: TAction;
    Rename1: TMenuItem;
    Rename2: TMenuItem;
    actFileRemoteMakeDirectory: TAction;
    actFileLocalMakeDirectory: TAction;
    N8: TMenuItem;
    MakeDirectory1: TMenuItem;
    N9: TMenuItem;
    actFileLocalMakeDirectory1: TMenuItem;
    ToolButton6: TToolButton;
    ToolButton7: TToolButton;
    SocksInfo: TIdSocksInfo;
    HTTPConnectThrough: TIdConnectThroughHttpProxy;
    procedure FormCreate(Sender: TObject);
    procedure actFileConnectExecute(Sender: TObject);
    procedure actFileConnectUpdate(Sender: TObject);
    procedure actFileDisconnectExecute(Sender: TObject);
    procedure actFileDisconnectUpdate(Sender: TObject);
    procedure FIdLogReceived(ASender: TComponent; const AText, AData: string);
    procedure FIdLogSent(ASender: TComponent; const AText, AData: string);
    procedure iosslFTPStatusInfoEx(ASender: TObject; const AsslSocket: PSSL;
      const AWhere, Aret: TIdC_INT; const AType, AMsg: string);
    procedure iosslFTPOnSSLNegotiated(ASender: TIdSSLIOHandlerSocketOpenSSL);
    procedure actHelpAboutExecute(Sender: TObject);
    procedure actViewSettingExecute(Sender: TObject);
    procedure FormClose(Sender: TObject; var Action: TCloseAction);
    procedure lvRemoteFilesColumnClick(Sender: TObject; Column: TListColumn);
    procedure lvRemoteFilesCompare(Sender: TObject; Item1, Item2: TListItem;
      Data: Integer; var Compare: Integer);
    procedure lvRemoteFilesDblClick(Sender: TObject);
    procedure lvLocalFilesCompare(Sender: TObject; Item1, Item2: TListItem;
      Data: Integer; var Compare: Integer);
    procedure lvLocalFilesColumnClick(Sender: TObject; Column: TListColumn);
    procedure lvLocalFilesDblClick(Sender: TObject);
    procedure FIdLogStatus(ASender: TComponent; const AText: string);
    procedure actFileFTPSitesExecute(Sender: TObject);
    procedure actFileFTPSitesUpdate(Sender: TObject);
    procedure cboRemoteCurrentDirKeyDown(Sender: TObject; var Key: Word;
      Shift: TShiftState);
    procedure actFileUploadExecute(Sender: TObject);
    procedure actFileDownloadExecute(Sender: TObject);
    procedure actFileUploadUpdate(Sender: TObject);
    procedure actFileDownloadUpdate(Sender: TObject);
    procedure cboLocalCurrentDirKeyDown(Sender: TObject; var Key: Word;
      Shift: TShiftState);
    procedure actFileRemoteDeleteUpdate(Sender: TObject);
    procedure actFileRemoteDeleteExecute(Sender: TObject);
    procedure actFileLocalDeleteExecute(Sender: TObject);
    procedure actFileLocalDeleteUpdate(Sender: TObject);
    procedure actFileLocalRenameExecute(Sender: TObject);
    procedure actFileLocalRenameUpdate(Sender: TObject);
    procedure actFileRemoteRenameExecute(Sender: TObject);
    procedure actFileRemoteRenameUpdate(Sender: TObject);
    procedure actFileRemoteMakeDirectoryExecute(Sender: TObject);
    procedure actFileRemoteMakeDirectoryUpdate(Sender: TObject);
    procedure actFileLocalMakeDirectoryExecute(Sender: TObject);
    procedure actFileLocalMakeDirectoryUpdate(Sender: TObject);
  private
    { Private declarations }
    LocalColumnToSort: Integer;
    LocalAscending: Boolean;

    RemoteColumnToSort: Integer;
    RemoteAscending: Boolean;

    FThreadRunning: Boolean;

    // colors
    FErrorForeground: TColor;
    FErrorBackground: TColor;
    FSSLMessageForeground: TColor;
    FSSLMessageBackground: TColor;
    FDirOutputForeground: TColor;
    FDirOutputBackground: TColor;
    FDebugForeground: TColor;
    FDebugBackground: TColor;
    FLogDebugOutput: Boolean;
    procedure InitLog;
    // Thread procedure starts
    procedure ConnectFTP;
    procedure ChangeLocalDir(const ADir: String);
    procedure ChangeRemoteDir(const ADir: String);
    //
    procedure PopulateLocalFiles;
    procedure PopulateRemoteFiles(const ACurDir: String);
    procedure RemoteLvClearArrows;
    procedure LocalClearArrows;
    procedure DownloadFile(const AFile: String);
    procedure UploadFile(const AFile: String);
    procedure LocalDeleteFile(const AFile: String);
    procedure RemoteDeleteFile(const AFile: String);
    procedure LocalRemoveDir(const ADir: String);
    procedure RemoteRemoveDir(const ADir: String);
    procedure LocalRename(const AOldPathName, ANewPathName: String);
    procedure RemoteRename(const AOldPathName, ANewPathName: String);
    procedure LocalMakeDir(const ADir: String);
    procedure RemoteMakeDir(const ADir: String);
    procedure SetProxyType(const AType: Integer);
  public
    { Public declarations }
  end;

  TFTPThread = class(TThread)
  protected
    FVerifyResult: Boolean;
    FError: Integer;
    FDepth: Integer;
    FX509: TIdX509;
    FFTP: TIdFTP;
    procedure PromptVerifyCert;
    function DoVerifyPeer(Certificate: TIdX509; AOk: Boolean;
      ADepth, AError: Integer): Boolean;
  public
    constructor Create(AFTP: TIdFTP);
    destructor Destroy; override;
  end;

  TConnectThread = class(TFTPThread)
  public
    procedure Execute(); override;
  end;

  TRemoteChangeDirThread = class(TFTPThread)
  protected
    FNewDir: String;
  public
    constructor Create(AFTP: TIdFTP; ANewDir: String); reintroduce;
    procedure Execute(); override;
  end;

  TFileThread = class(TFTPThread)
  protected
    FFile: String;
  public
    constructor Create(AFTP: TIdFTP; AFile: String); reintroduce;
  end;

  TDownloadFileThread = class(TFileThread)
  public
    procedure Execute(); override;
  end;

  TUploadFileThread = class(TFileThread)
  public
    procedure Execute(); override;
  end;

  TDeleteFileThread = class(TFileThread)
  public
    procedure Execute(); override;
  end;

  TRemoveDirThread = class(TFileThread)
  public
    procedure Execute(); override;
  end;

  TRenamePathThread = class(TFileThread)
  protected
    FNewName: String;
  public
    constructor Create(AFTP: TIdFTP; const AOldName, ANewName: String);
      reintroduce;
    procedure Execute(); override;
  end;

  TMakeDirThread = class(TFileThread)
  public
    procedure Execute(); override;
  end;

  TLogEventNotify = class(TIdNotify)
  protected
    FStr: String;
    procedure DoNotify; override;
  public
    class procedure NotifyString(const AStr: String); virtual;
  end;

  TLogFTPError = class(TLogEventNotify)
  protected
    procedure DoNotify; override;
  public
    class procedure NotifyString(const AStr: String); override;
  end;

  TSSLEvent = class(TLogEventNotify)
  protected
    procedure DoNotify; override;
  public
    class procedure NotifyString(const AStr: String); override;
  end;

  TSSLCipherEvent = class(TLogEventNotify)
  protected
    procedure DoNotify; override;
  public
    class procedure NotifyString(const AStr: String); override;
  end;

  TStatusBarEvent = class(TLogEventNotify)
  protected
    procedure DoNotify; override;
  public
    class procedure NotifyString(const AStr: String); override;
  end;

  TPopulateRemoteListNotify = class(TIdNotify)
  protected
    FCurrentDir: String;
    procedure DoNotify; override;
  public
    class procedure PopulateRemoteList(const ACurrentDir: String);
  end;

  TPopulateLocalListNotify = class(TIdNotify)
  protected
    procedure DoNotify; override;
  public
    class procedure PopulateLocalList;
  end;

  TLogDirListingEvent = class(TIdNotify)
  protected
    FDirListing: TStrings;
    procedure DoNotify; override;
  public
    class procedure LogDirListing(AStrings: TStrings);
  end;

  TThreadStartNotify = class(TIdNotify)
  protected
    procedure DoNotify; override;
  public
    class procedure StartThread;
  end;

  TThreadFinishedNotify = class(TIdNotify)
  protected
    procedure DoNotify; override;
  public
    class procedure EndThread;
  end;

var
  frmMainForm: TfrmMainForm;

implementation

uses dkgFTPConnect, settingsdlg, frmAbout, frmBookmarks, CertViewer,
  IdException,
  IdAllFTPListParsers,
  IdFTPCommon,
  IdFTPList, IdGlobal, IdReplyRFC, IdSSLOpenSSLLoader,
  System.IOUtils, System.IniFiles, System.UITypes,
  Winapi.CommCtrl, ProgUtils, AcceptableCerts;

const
  DIR_IMAGE_IDX = 6;
  FILE_IMAGE_IDX = 7;
  ARROW_UP_IMAGE_IDX = 8;
  ARROW_DOWN_IMAGE_IDX = 9;

{$R *.dfm}

procedure TfrmMainForm.actFileDisconnectExecute(Sender: TObject);
begin
  IdFTPClient.Disconnect;
  lvRemoteFiles.Items.Clear;
end;

procedure TfrmMainForm.actFileDisconnectUpdate(Sender: TObject);
begin
  actFileDisconnect.Enabled := (not FThreadRunning) and IdFTPClient.Connected;
end;

procedure TfrmMainForm.actFileDownloadExecute(Sender: TObject);
var
  Li: TListItem;
begin
  if lvRemoteFiles.ItemIndex > -1 then
  begin
    Li := lvRemoteFiles.Items[lvRemoteFiles.ItemIndex];
    DownloadFile(Li.Caption);
  end;
end;

procedure TfrmMainForm.actFileDownloadUpdate(Sender: TObject);
var
  Li: TListItem;
begin

  actFileDownload.Enabled := (not FThreadRunning) and IdFTPClient.Connected and
    (lvRemoteFiles.ItemIndex > -1);
  if actFileDownload.Enabled then
  begin
    Li := lvRemoteFiles.Items[lvRemoteFiles.ItemIndex];
    actFileDownload.Enabled := Li.ImageIndex = FILE_IMAGE_IDX;
  end;
end;

procedure TfrmMainForm.actFileFTPSitesExecute(Sender: TObject);
var
  LFrm: TfrmFTPSites;
  LFTPSite: TFTPSite;
begin
  LFrm := TfrmFTPSites.Create(nil);
  try
    if LFrm.ShowModal = mrOk then
    begin
      if LFrm.lbxFTPSites.ItemIndex > -1 then
      begin
        LFTPSite := LFrm.FTPSites[LFrm.lbxFTPSites.ItemIndex];
        IdFTPClient.Host := LFTPSite.HostName;
        IdFTPClient.Username := LFTPSite.Username;
        IdFTPClient.Password := LFTPSite.Password;
        case LFTPSite.FTPPRotocol of
          0:
            IdFTPClient.UseTLS := utNoTLSSupport;
          1:
            IdFTPClient.UseTLS := utUseExplicitTLS;
          2:
            IdFTPClient.UseTLS := utUseImplicitTLS;
        end;
        case LFTPSite.TransferMode of
          0:
            IdFTPClient.Passive := not ReadTransferDefault;
          1:
            IdFTPClient.Passive := True;
          2:
            IdFTPClient.Passive := False;
        end;

        ConnectFTP;
      end;
    end;
  finally
    FreeAndNil(LFrm);
  end;
end;

procedure TfrmMainForm.actFileFTPSitesUpdate(Sender: TObject);
begin
  actFileFTPSites.Enabled := (not FThreadRunning) and not IdFTPClient.Connected;
end;

procedure TfrmMainForm.actFileLocalDeleteExecute(Sender: TObject);
var
  Li: TListItem;
begin
  if lvLocalFiles.ItemIndex > -1 then
  begin
    Li := lvLocalFiles.Items[lvLocalFiles.ItemIndex];
    case Li.ImageIndex of
      FILE_IMAGE_IDX:
        LocalDeleteFile(Li.Caption);
      DIR_IMAGE_IDX:
        LocalRemoveDir(Li.Caption);
    end;
  end;
end;

procedure TfrmMainForm.actFileLocalDeleteUpdate(Sender: TObject);
var
  Li: TListItem;
  LRes: Boolean;
begin
  LRes := (not FThreadRunning) and (lvLocalFiles.ItemIndex > -1);
  if LRes then
  begin
    Li := lvLocalFiles.Items[lvLocalFiles.ItemIndex];
    LRes := Li.ImageIndex in [FILE_IMAGE_IDX, DIR_IMAGE_IDX];
  end;
  actFileLocalDelete.Enabled := LRes;
end;

procedure TfrmMainForm.actFileLocalMakeDirectoryExecute(Sender: TObject);
var
  LNewDir: String;
begin
  if InputQuery('Make Directory', 'New Directory Name: ', LNewDir) then
  begin
    if LNewDir <> '' then
    begin
      LocalMakeDir(LNewDir);
    end;
  end;
end;

procedure TfrmMainForm.actFileLocalMakeDirectoryUpdate(Sender: TObject);
begin
  actFileLocalMakeDirectory.Enabled := (not FThreadRunning);
end;

procedure TfrmMainForm.actFileLocalRenameExecute(Sender: TObject);
var
  Li: TListItem;
  LNewName: String;
begin
  if lvLocalFiles.ItemIndex > -1 then
  begin
    Li := lvLocalFiles.Items[lvLocalFiles.ItemIndex];
    if Li.ImageIndex in [FILE_IMAGE_IDX, DIR_IMAGE_IDX] then
    begin
      if InputQuery('Rename', 'Rename ' + Li.Caption + ' to:', LNewName) then
      begin
        if LNewName <> '' then
        begin
          LocalRename(Li.Caption, LNewName);
        end;
      end;
    end;
  end;
end;

procedure TfrmMainForm.actFileLocalRenameUpdate(Sender: TObject);
var
  Li: TListItem;
  LRes: Boolean;
begin
  LRes := (not FThreadRunning) and (lvLocalFiles.ItemIndex > -1);
  if LRes then
  begin
    Li := lvLocalFiles.Items[lvLocalFiles.ItemIndex];
    LRes := Li.ImageIndex in [FILE_IMAGE_IDX, DIR_IMAGE_IDX];
  end;
  actFileLocalRename.Enabled := LRes;

end;

procedure TfrmMainForm.actFileRemoteDeleteExecute(Sender: TObject);
var
  Li: TListItem;
begin
  if lvRemoteFiles.ItemIndex > -1 then
  begin
    Li := lvRemoteFiles.Items[lvRemoteFiles.ItemIndex];
    case Li.ImageIndex of
      FILE_IMAGE_IDX:
        RemoteDeleteFile(Li.Caption);
      DIR_IMAGE_IDX:
        RemoteRemoveDir(Li.Caption);
    end;

  end;
end;

procedure TfrmMainForm.actFileRemoteDeleteUpdate(Sender: TObject);
var
  Li: TListItem;
  LRes: Boolean;
begin
  LRes := (not FThreadRunning) and IdFTPClient.Connected and
    (lvRemoteFiles.ItemIndex > -1);
  if LRes then
  begin
    Li := lvRemoteFiles.Items[lvRemoteFiles.ItemIndex];
    LRes := Li.ImageIndex in [FILE_IMAGE_IDX, DIR_IMAGE_IDX];
  end;
  actFileRemoteDelete.Enabled := LRes;
end;

procedure TfrmMainForm.actFileRemoteMakeDirectoryExecute(Sender: TObject);
var
  LNewDir: String;
begin
  if InputQuery('Make Directory', 'New Directory Name: ', LNewDir) then
  begin
    if LNewDir <> '' then
    begin
      RemoteMakeDir(LNewDir);
    end;
  end;
end;

procedure TfrmMainForm.actFileRemoteMakeDirectoryUpdate(Sender: TObject);
begin
  actFileRemoteMakeDirectory.Enabled := (not FThreadRunning) and
    IdFTPClient.Connected
end;

procedure TfrmMainForm.actFileRemoteRenameExecute(Sender: TObject);
var
  Li: TListItem;
  LNewName: String;
begin
  if lvRemoteFiles.ItemIndex > -1 then
  begin
    Li := lvRemoteFiles.Items[lvRemoteFiles.ItemIndex];
    if Li.ImageIndex in [FILE_IMAGE_IDX, DIR_IMAGE_IDX] then
    begin
      if InputQuery('Rename', 'Rename ' + Li.Caption + ' to:', LNewName) then
      begin
        if LNewName <> '' then
        begin
          RemoteRename(Li.Caption, LNewName);
        end;
      end;
    end;
  end;
end;

procedure TfrmMainForm.actFileRemoteRenameUpdate(Sender: TObject);
var
  Li: TListItem;
  LRes: Boolean;
begin
  LRes := (not FThreadRunning) and IdFTPClient.Connected and
    (lvRemoteFiles.ItemIndex > -1);
  if LRes then
  begin
    Li := lvRemoteFiles.Items[lvRemoteFiles.ItemIndex];
    LRes := Li.ImageIndex in [FILE_IMAGE_IDX, DIR_IMAGE_IDX];
  end;
  actFileRemoteRename.Enabled := LRes;

end;

procedure TfrmMainForm.actFileUploadExecute(Sender: TObject);
var
  Li: TListItem;
begin
  if lvLocalFiles.ItemIndex > -1 then
  begin
    Li := lvLocalFiles.Items[lvLocalFiles.ItemIndex];
    UploadFile(Li.Caption);
  end;
end;

procedure TfrmMainForm.actFileUploadUpdate(Sender: TObject);
var
  Li: TListItem;
begin
  actFileUpload.Enabled := (not FThreadRunning) and IdFTPClient.Connected and
    (lvLocalFiles.ItemIndex > -1);
  if actFileUpload.Enabled then
  begin
    Li := lvLocalFiles.Items[lvLocalFiles.ItemIndex];
    actFileUpload.Enabled := Li.ImageIndex = FILE_IMAGE_IDX;
  end;
end;

procedure TfrmMainForm.actHelpAboutExecute(Sender: TObject);
var
  LFrm: TAboutBox;
begin
  LFrm := TAboutBox.Create(nil);
  try
    LFrm.ShowModal;
  finally
    FreeAndNil(LFrm);
  end;
end;

procedure TfrmMainForm.actViewSettingExecute(Sender: TObject);
var
  LFrm: TfrmSettings;
  LIni: TIniFile;
begin
  LFrm := TfrmSettings.Create(Application);
  try
    LIni := TIniFile.Create(GetIniFilePath);
    try
      LFrm.UsePortTransferType := LIni.ReadBool('Transfers',
        'Use_PORT_Transfers', False);
      LFrm.redtLog.Font.Name := redtLog.Font.Name;
      LFrm.redtTextSamples.Font.Name := LFrm.redtLog.Font.Name;
      LFrm.redtLog.Font.Size := redtLog.Font.Size;
      LFrm.redtTextSamples.Font.Size := LFrm.redtLog.Font.Size;
      LFrm.ErrorForeground := FErrorForeground;
      LFrm.ErrorBackground := FErrorBackground;
      LFrm.SSLMessageForeground := FSSLMessageForeground;
      LFrm.SSLMessageBackground := FSSLMessageBackground;
      LFrm.DirOutputForeground := FDirOutputForeground;
      LFrm.DirOutputBackground := FDirOutputBackground;
      LFrm.DebugForeground := FDebugForeground;
      LFrm.DebugBackground := FDebugBackground;
      LFrm.NATIPAddress := IdFTPClient.ExternalIP;
      LFrm.NATPortMin := IdFTPClient.DataPortMin;
      LFrm.NATPortMax := IdFTPClient.DataPortMax;
      LFrm.chklbAdvancedOptions.Checked[0] := IdFTPClient.UseHOST;
      LFrm.chklbAdvancedOptions.Checked[1] := IdFTPClient.UseExtensionDataPort;
      LFrm.chklbAdvancedOptions.Checked[2] := IdFTPClient.TryNATFastTrack;
      LFrm.chklbAdvancedOptions.Checked[3] := IdFTPClient.UseMLIS;
      if not Assigned(iosslFTP.TransparentProxy) then
      begin
        // 0 - none
        LFrm.ProxyType := 0;
      end
      else
      begin
        // 1 - HTTP Connect Proxy
        if iosslFTP.TransparentProxy = HTTPConnectThrough then
        begin
          LFrm.ProxyType := 1;
        end
        else
        begin
          case SocksInfo.Version of
            // 2 - SOCKS4
            svSocks4:
              begin
                LFrm.ProxyType := 2;
              end;
            // 3 - SOCKS4A
            svSocks4A:
              begin
                LFrm.ProxyType := 3;
              end;
            // 4 - SOCKS5
            svSocks5:
              begin
                LFrm.ProxyType := 4;
              end;
          end;
        end;
      end;
      LFrm.ProxyHost := SocksInfo.Host;
      LFrm.ProxyUsername := SocksInfo.Username;
      LFrm.ProxyPassword := SocksInfo.Password;
      LFrm.ProxyPort := SocksInfo.Port;
      LFrm.FTPProxyType := Ord(IdFTPClient.ProxySettings.ProxyType);
      LFrm.FTPProxyHost := IdFTPClient.ProxySettings.Host;
      LFrm.FTPProxyPort := IdFTPClient.ProxySettings.Port;
      LFrm.FTPProxyUsername := IdFTPClient.ProxySettings.UserName;
      LFrm.FTPProxyPassword := IdFTPClient.ProxySettings.Password;
      if LFrm.ShowModal = mrOk then
      begin
        FErrorForeground := LFrm.ErrorForeground;
        FErrorBackground := LFrm.ErrorBackground;
        FSSLMessageForeground := LFrm.SSLMessageForeground;
        FSSLMessageBackground := LFrm.SSLMessageBackground;
        FDirOutputForeground := LFrm.DirOutputForeground;
        FDirOutputBackground := LFrm.DirOutputBackground;
        FDebugForeground := LFrm.DebugForeground;
        FDebugBackground := LFrm.DebugBackground;
        IdFTPClient.UseHOST := LFrm.chklbAdvancedOptions.Checked[0];
        IdFTPClient.ExternalIP := LFrm.NATIPAddress;
        IdFTPClient.DataPortMin := LFrm.NATPortMin;
        IdFTPClient.DataPortMax := LFrm.NATPortMax;
        // Do things in a round about way because NAT fasttracking requires extended DataPort commands.
        IdFTPClient.TryNATFastTrack := False;

        IdFTPClient.UseExtensionDataPort :=
          LFrm.chklbAdvancedOptions.Checked[1];
        if IdFTPClient.UseExtensionDataPort then
        begin
          IdFTPClient.TryNATFastTrack := LFrm.chklbAdvancedOptions.Checked[2];
        end;
        IdFTPClient.UseMLIS := LFrm.chklbAdvancedOptions.Checked[3];
        LIni.WriteBool('FTP', 'Use_HOST_Command', IdFTPClient.UseHOST);
        LIni.WriteString('NAT', 'NAT_IP_Address', IdFTPClient.ExternalIP);
        LIni.WriteInteger('NAT', 'Data_PORT_Minimum', IdFTPClient.DataPortMin);
        LIni.WriteInteger('NAT', 'Data_PORT_Maximum', IdFTPClient.DataPortMax);
        LIni.WriteBool('Transfers', 'Use_Extended_Data_Port_Commands',
          IdFTPClient.UseExtensionDataPort);
        LIni.WriteBool('Transfers', 'Try_Using_NAT_Fast_Track',
          IdFTPClient.TryNATFastTrack);
        LIni.WriteBool('FTP', 'Use_MLSD_Command_Instead_Of_DIR_Command',
          IdFTPClient.UseMLIS);

        LIni.WriteBool('Transfers', 'Use_PORT_Transfers',
          LFrm.UsePortTransferType);
        LIni.WriteBool('Transfers', 'Use_EPSV_EPRT_Data_Transfer',
          LFrm.chklbAdvancedOptions.Checked[1]);
        IdFTPClient.Passive := not LFrm.UsePortTransferType;
        LIni.WriteBool('Debug', 'Log_Debug_Output', FLogDebugOutput);
        redtLog.Font := LFrm.redtLog.Font;
        LIni.WriteString('Log_Font', 'Name', redtLog.Font.Name);
        LIni.WriteInteger('Log_Font', 'Size', redtLog.Font.Size);

        LIni.WriteString('Log_Font', 'Name', redtLog.Font.Name);
        LIni.WriteInteger('Log_Font', 'CharSet', redtLog.Font.Charset);
        LIni.WriteInteger('Log_Font', 'Size', redtLog.Font.Size);
        LIni.WriteInteger('Log_Font', 'Style', Byte(redtLog.Font.Style));
        LIni.WriteInteger('Log_Font', 'Error_Foreground', FErrorForeground);
        LIni.WriteInteger('Log_Font', 'Error_Background', FErrorBackground);
        LIni.WriteInteger('Log_Font', 'SSL_Message_Foreground',
          FSSLMessageForeground);
        LIni.WriteInteger('Log_Font', 'SSL_Message_Background',
          FSSLMessageBackground);
        LIni.WriteInteger('Log_Font', 'Directory_Foreground',
          FDirOutputForeground);
        LIni.WriteInteger('Log_Font', 'Directory_Background',
          FDirOutputBackground);
        LIni.WriteInteger('Log_Font', 'Debug_Output_Foreground',
          FDebugForeground);
        LIni.WriteInteger('Log_Font', 'Debug_Output_Background',
          FDebugBackground);
        SetProxyType(LFrm.ProxyType);
        LIni.WriteInteger('Proxy', 'Type', LFrm.ProxyType);
        SocksInfo.Host := LFrm.ProxyHost;
        SocksInfo.Port := LFrm.ProxyPort;
        SocksInfo.Username := LFrm.ProxyUsername;
        SocksInfo.Password := LFrm.ProxyPassword;
        if (SocksInfo.Username <> '') and (SocksInfo.Password <> '') then
        begin
          SocksInfo.Authentication := saUsernamePassword;
        end;
        HTTPConnectThrough.Host := SocksInfo.Host;
        HTTPConnectThrough.Port := SocksInfo.Port;
        HTTPConnectThrough.Username := SocksInfo.Username;
        HTTPConnectThrough.Password := SocksInfo.Password;
        LIni.WriteString('Proxy', 'Server_Name', SocksInfo.Host);
        LIni.WriteString('Proxy', 'User_Name', SocksInfo.Username);
        LIni.WriteString('Proxy', 'Password', SocksInfo.Password);
        LIni.WriteInteger('Proxy','Port',SocksInfo.Port);
        IdFTPClient.ProxySettings.ProxyType := TIdFtpProxyType( LFrm.FTPProxyType );
        IdFTPClient.ProxySettings.Host := LFrm.FTPProxyHost;
        IdFTPClient.ProxySettings.Port := LFrm.FTPProxyPort;
        IdFTPClient.ProxySettings.UserName := LFrm.FTPProxyUsername;
        IdFTPClient.ProxySettings.Password := LFrm.FTPProxyPassword;
        LIni.WriteInteger('FTP_Proxy', 'Type', LFrm.FTPProxyType);
        LIni.WriteString('FTP_Proxy', 'Server_Name', SocksInfo.Host);
        LIni.WriteString('FTP_Proxy', 'User_Name', SocksInfo.Username);
        LIni.WriteString('FTP_Proxy', 'Password', SocksInfo.Password);
        LIni.WriteInteger('FTP_Proxy','Port',SocksInfo.Port);

      end;
    finally
      FreeAndNil(LIni);
    end;
  finally
    FreeAndNil(LFrm);
  end;
end;

procedure TfrmMainForm.cboLocalCurrentDirKeyDown(Sender: TObject; var Key: Word;
  Shift: TShiftState);
begin
  if Key = 13 then
  begin
    ChangeLocalDir(cboLocalCurrentDir.Text);
  end;
end;

procedure TfrmMainForm.cboRemoteCurrentDirKeyDown(Sender: TObject;
  var Key: Word; Shift: TShiftState);
begin
  if Key = 13 then
  begin
    ChangeRemoteDir(cboRemoteCurrentDir.Text);
  end;
end;

procedure TfrmMainForm.ChangeLocalDir(const ADir: String);
begin
  if System.SysUtils.SetCurrentDir(ADir) then
  begin
    PopulateLocalFiles;
  end
  else
  begin
    System.SysUtils.RaiseLastOSError;
  end;
end;

procedure TfrmMainForm.ChangeRemoteDir(const ADir: String);
begin
  TRemoteChangeDirThread.Create(IdFTPClient, ADir);
end;

procedure TfrmMainForm.ConnectFTP;
begin
  if IdFTPClient.UseTLS <> utNoTLSSupport then
  begin
    IdFTPClient.DataPortProtection := ftpdpsPrivate;
  end;
  if IdFTPClient.UseTLS = utUseImplicitTLS then
  begin
    IdFTPClient.Port := 990;
  end
  else
  begin
    IdFTPClient.Port := 21;
  end;
  InitLog;
  TConnectThread.Create(IdFTPClient);
end;

procedure TfrmMainForm.DownloadFile(const AFile: String);
begin
  TDownloadFileThread.Create(IdFTPClient, AFile);
end;

procedure TfrmMainForm.UploadFile(const AFile: String);
begin
  TUploadFileThread.Create(IdFTPClient, AFile);
end;

procedure TfrmMainForm.actFileConnectExecute(Sender: TObject);
var
  LFrm: TfrmConnect;
begin
  LFrm := TfrmConnect.Create(Application);
  try
    LFrm.Caption := 'Connect';
    LFrm.QuickConnect := True;
    LFrm.cboConnectionType.ItemIndex := 0;
    if LFrm.ShowModal = mrOk then
    begin
      IdFTPClient.Host := LFrm.edtHostname.Text;
      IdFTPClient.Username := LFrm.Username;
      IdFTPClient.Password := LFrm.Password;
      IdFTPClient.IOHandler := iosslFTP;
      IdFTPClient.Passive := not LFrm.UsePortTransferType;
      IdFTPClient.UseTLS := LFrm.UseTLS;
      ConnectFTP;

    end;
  finally
    FreeAndNil(LFrm);
  end;
end;

procedure TfrmMainForm.actFileConnectUpdate(Sender: TObject);
begin
  actFileConnect.Enabled := (not FThreadRunning) and not IdFTPClient.Connected;
end;

procedure TfrmMainForm.FormClose(Sender: TObject; var Action: TCloseAction);
begin
  if FThreadRunning then
  begin
    Action := caNone;
  end
  else
  begin
    IdFTPClient.Disconnect;
  end;
end;

procedure TfrmMainForm.FormCreate(Sender: TObject);
var
  LIni: TIniFile;
  i: Integer;
begin
  FThreadRunning := False;
  LocalColumnToSort := 0;
  LocalAscending := True;

  RemoteColumnToSort := 0;
  RemoteAscending := True;

  LocalClearArrows;
  PopulateLocalFiles;
  RemoteLvClearArrows;
  pnlLocalBrowser.Constraints.MinWidth := pnlLocalBrowser.Width;
  // pnlDivider.Constraints.MinWidth := pnlDivider.Width;
  // pnlDivider.Constraints.MaxWidth := pnlDivider.Width;
  pnlMainWindow.Constraints.MinHeight := pnlMainWindow.Height;
  pnlRemoteBrowser.Constraints.MinWidth := pnlRemoteBrowser.Width;
  IdFTPClient.Compressor := IdCompressorZLib1;
  Application.Title := Caption;
  iosslFTP.OnSSLNegotiated := iosslFTPOnSSLNegotiated;
  LIni := TIniFile.Create(GetIniFilePath);
  try
    IdFTPClient.Passive := not LIni.ReadBool('Transfers',
      'Use_PORT_Transfers', False);
    FLogDebugOutput := LIni.ReadBool('Debug', 'Log_Debug_Output', False);
    redtLog.Font.Name := LIni.ReadString('Log_Font', 'Name', redtLog.Font.Name);
    redtLog.Font.Charset := LIni.ReadInteger('Log_Font', 'CharSet',
      redtLog.Font.Charset);
    redtLog.Font.Size := LIni.ReadInteger('Log_Font', 'Size',
      redtLog.Font.Size);
    redtLog.Font.Style := TFontStyles(Byte(LIni.ReadInteger('Log_Font', 'Style',
      Byte(redtLog.Font.Style))));
    FErrorForeground := LIni.ReadInteger('Log_Font', 'Error_Foreground', clRed);
    FErrorBackground := LIni.ReadInteger('Log_Font',
      'Error_Background', clWhite);
    FSSLMessageForeground := LIni.ReadInteger('Log_Font',
      'SSL_Message_Foreground', clTeal);
    FSSLMessageBackground := LIni.ReadInteger('Log_Font',
      'SSL_Message_Background', clWhite);
    FDirOutputForeground := LIni.ReadInteger('Log_Font',
      'Directory_Foreground', clBlue);
    FDirOutputBackground := LIni.ReadInteger('Log_Font',
      'Directory_Background', clWhite);
    FDebugForeground := LIni.ReadInteger('Log_Font', 'Debug_Output_Foreground',
      clPurple);
    FDebugBackground := LIni.ReadInteger('Log_Font',
      'Debug_Output_Background', clWhite);
    IdFTPClient.UseHOST := LIni.ReadBool('FTP', 'Use_HOST_Command',
      IdFTPClient.UseHOST);
    IdFTPClient.UseExtensionDataPort := LIni.ReadBool('Transfers',
      'Use_Extended_Data_Port_Commands', IdFTPClient.UseExtensionDataPort);
    IdFTPClient.TryNATFastTrack := LIni.ReadBool('Transfers',
      'Try_Using_NAT_Fast_Track', IdFTPClient.TryNATFastTrack);
    IdFTPClient.UseMLIS := LIni.ReadBool('FTP',
      'Use_MLSD_Command_Instead_Of_DIR_Command', IdFTPClient.UseMLIS);
    IdFTPClient.ExternalIP := LIni.ReadString('NAT', 'NAT_IP_Address', '');
    IdFTPClient.DataPortMin := LIni.ReadInteger('NAT', 'Data_PORT_Minimum', 0);
    IdFTPClient.DataPortMax := LIni.ReadInteger('NAT', 'Data_PORT_Maximum', 0);
    i := LIni.ReadInteger('Proxy', 'Type', 0);
    SetProxyType(i);
    if (SocksInfo.Username <> '') and (SocksInfo.Password <> '') then
    begin
      SocksInfo.Authentication := saUsernamePassword;
    end;
    SocksInfo.Host := LIni.ReadString('Proxy', 'Server_Name', '');
    SocksInfo.Username := LIni.ReadString('Proxy', 'User_Name', '');
    SocksInfo.Password := LIni.ReadString('Proxy', 'Password', '');
    SocksInfo.Port := LIni.ReadInteger('Proxy','Port',1080);
    HTTPConnectThrough.Username := SocksInfo.Username;
    HTTPConnectThrough.Password := SocksInfo.Password;
    HTTPConnectThrough.Port := SocksInfo.Port;
    IdFTPClient.ProxySettings.ProxyType := TIdFtpProxyType( LIni.ReadInteger('FTP_Proxy', 'Type', 0));
    IdFTPClient.ProxySettings.Host := LIni.ReadString('FTP_Proxy', 'Server_Name', '');
    IdFTPClient.ProxySettings.UserName := LIni.ReadString('FTP_Proxy', 'User_Name', '');
    IdFTPClient.ProxySettings.Password := LIni.ReadString('FTP_Proxy', 'Password', '');
    IdFTPClient.ProxySettings.Port := LIni.ReadInteger('FTP_Proxy','Port',0);
  finally
    FreeAndNil(LIni);
  end;
  InitLog;
end;

procedure TfrmMainForm.InitLog;
var
  i: Integer;
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
  redtLog.Lines.Add('  Failed To Load: ');
  for i := 0 to GetOpenSSLLoader.GetFailedToLoad.Count - 1 do
  begin
    redtLog.Lines.Add(GetOpenSSLLoader.GetFailedToLoad[i]);
  end;
  ScrollToEnd(redtLog);
end;

procedure TfrmMainForm.FIdLogReceived(ASender: TComponent;
  const AText, AData: string);
var
  LData: String;
begin
  LData := Trim(AData);
  if Length(LData) > 0 then
  begin
    if CharInSet(LData[1], ['4', '5']) then
    begin
      TLogFTPError.NotifyString(LData);
    end
    else
    begin
      TLogEventNotify.NotifyString(LData);
    end;
  end;
end;

procedure TfrmMainForm.FIdLogSent(ASender: TComponent;
  const AText, AData: string);
begin
  if IndyPos('PASS ', AData) > 0 then
  begin
    TLogEventNotify.NotifyString('PASS ***');
  end
  else
  begin
    TLogEventNotify.NotifyString(Trim(AData));
  end;
end;

procedure TfrmMainForm.FIdLogStatus(ASender: TComponent; const AText: string);
begin
  TStatusBarEvent.NotifyString(AText);
  lvRemoteFiles.Enabled := IdFTPClient.Connected;
  cboRemoteCurrentDir.Enabled := IdFTPClient.Connected;
  lblRemotDir.Enabled := IdFTPClient.Connected;
end;

procedure TfrmMainForm.iosslFTPOnSSLNegotiated
  (ASender: TIdSSLIOHandlerSocketOpenSSL);
var
  LStr: String;
  LNo: Integer;
begin
  if Assigned(ASender.SSLSocket) then
  begin
    LStr := '';
    case ASender.SSLSocket.SSLProtocolVersion of
      sslvSSLv3:
        LStr := 'SSL 3';
      sslvTLSv1:
        LStr := 'TLS 1.0';
      sslvTLSv1_1:
        LStr := 'TLS 1.1';
      sslvTLSv1_2:
        LStr := 'TLS 1.2';
      sslvTLSv1_3:
        LStr := 'TLS 1.3';
    end;
    if LStr <> '' then
    begin
      TSSLCipherEvent.NotifyString('       TLS Version: ' + LStr);
    end;
    if Assigned(ASender.SSLSocket.Cipher) then
    begin
      LStr := ASender.SSLSocket.Cipher.Name;
      if LStr <> '' then
        TSSLCipherEvent.NotifyString('       Cipher Name: ' + LStr);
      LStr := ASender.SSLSocket.Cipher.Description;
      if LStr <> '' then
        TSSLCipherEvent.NotifyString('Cipher Description: ' + Trim(LStr));
      LStr := ASender.SSLSocket.Cipher.Version;
      if LStr <> '' then
        TSSLCipherEvent.NotifyString('    Cipher Version: ' + LStr);
      LNo := ASender.SSLSocket.Cipher.Bits;
      if LNo <> 0 then
      begin
        TSSLCipherEvent.NotifyString('       Cipher Bits: ' + IntToStr(LNo));
      end;
    end;
  end;
end;

procedure TfrmMainForm.iosslFTPStatusInfoEx(ASender: TObject;
  const AsslSocket: PSSL; const AWhere, Aret: TIdC_INT;
  const AType, AMsg: string);

begin
  TSSLEvent.NotifyString(AType);
  TSSLEvent.NotifyString(AMsg);
end;

procedure TfrmMainForm.LocalClearArrows;
var
  i: Integer;
  LMax: Integer;
begin
  lvLocalFiles.Columns.BeginUpdate;
  try
    LMax := lvRemoteFiles.Columns.Count - 1;
    for i := 0 to LMax do
    begin
      lvLocalFiles.Columns[i].ImageIndex := -1;
    end;
    if RemoteAscending then
    begin
      lvLocalFiles.Columns[LocalColumnToSort].ImageIndex := ARROW_UP_IMAGE_IDX;
    end
    else
    begin
      lvLocalFiles.Columns[LocalColumnToSort].ImageIndex :=
        ARROW_DOWN_IMAGE_IDX;
    end;
  finally
    lvLocalFiles.Columns.EndUpdate;
  end;

end;

procedure TfrmMainForm.LocalDeleteFile(const AFile: String);
begin
  if MessageDlg('Delete ' + AFile + '?', mtConfirmation, [mbYes, mbNo], 0) = mrYes
  then
  begin
    System.SysUtils.DeleteFile(AFile);
    PopulateLocalFiles;
  end;
end;

procedure TfrmMainForm.LocalMakeDir(const ADir: String);
begin
  System.SysUtils.CreateDir(ADir);
  PopulateLocalFiles;
end;

procedure TfrmMainForm.LocalRemoveDir(const ADir: String);
begin
  if MessageDlg('Remove Directory ' + ADir + '?', mtConfirmation, [mbYes, mbNo],
    0) = mrYes then
  begin
    System.SysUtils.RemoveDir(ADir);
    PopulateLocalFiles;
  end;
end;

procedure TfrmMainForm.LocalRename(const AOldPathName, ANewPathName: String);
begin
  System.SysUtils.RenameFile(AOldPathName, ANewPathName);
end;

function CompareCaptions(Item1, Item2: TListItem): Integer;
begin
  if Item1.Caption > Item2.Caption then
  begin
    Result := 1;
  end
  else
  begin
    if Item1.Caption < Item2.Caption then
    begin
      Result := -1;
    end
    else
    begin
      Result := 0;
    end;
  end;
end;

procedure TfrmMainForm.lvLocalFilesColumnClick(Sender: TObject;
  Column: TListColumn);
begin
  if Column.Index = LocalColumnToSort then
  begin
    LocalAscending := not LocalAscending
  end
  else
  begin
    LocalColumnToSort := Column.Index;
  end;
  LocalClearArrows;
  lvLocalFiles.Items.BeginUpdate;
  lvLocalFiles.AlphaSort;
  lvLocalFiles.Items.EndUpdate;
end;

procedure TfrmMainForm.lvLocalFilesCompare(Sender: TObject;
  Item1, Item2: TListItem; Data: Integer; var Compare: Integer);
begin
  //
  case LocalColumnToSort of
    0: // file name
      begin
        Compare := CompareCaptions(Item1, Item2);
      end;
    1: // file type, file name
      begin
        if Item1.SubItems[0] > Item2.SubItems[0] then
        begin
          Compare := 1;
        end
        else
        begin
          if Item1.SubItems[0] > Item2.SubItems[0] then
          begin
            Compare := 1;
          end
          else
          begin
            if Item1.SubItems[0] < Item2.SubItems[0] then
            begin
              Compare := -1;
            end
            else
            begin
              Compare := CompareCaptions(Item1, Item2);
            end;
          end;
        end;
      end;
    2: // file size, file name
      begin
        if Item1.SubItems[1] > Item2.SubItems[1] then
        begin
          Compare := 1;
        end
        else
        begin
          if Item1.SubItems[1] > Item2.SubItems[1] then
          begin
            Compare := 1;
          end
          else
          begin
            if Item1.SubItems[1] < Item2.SubItems[1] then
            begin
              Compare := -1;
            end
            else
            begin
              Compare := CompareCaptions(Item1, Item2);
            end;
          end;
        end;

      end;
    3: // file modified date, file name
      begin
        if Item1.SubItems[2] > Item2.SubItems[2] then
        begin
          Compare := 1;
        end
        else
        begin
          if Item1.SubItems[2] > Item2.SubItems[2] then
          begin
            Compare := 1;
          end
          else
          begin
            if Item1.SubItems[2] < Item2.SubItems[2] then
            begin
              Compare := -1;
            end
            else
            begin
              Compare := CompareCaptions(Item1, Item2);
            end;
          end;
        end;
      end;
  end;
  if LocalAscending then
  begin
    Compare := 0 - Compare;
  end;

end;

procedure TfrmMainForm.lvLocalFilesDblClick(Sender: TObject);
var
  Li: TListItem;
  LCurDir: String;
begin
  //
  if lvLocalFiles.ItemIndex > -1 then
  begin
    Li := lvLocalFiles.Items[lvLocalFiles.ItemIndex];
    if Li.ImageIndex = DIR_IMAGE_IDX then
    begin
      LCurDir := GetCurrentDir;
      LCurDir := LCurDir + '\' + Li.Caption;
      ChangeLocalDir(LCurDir);
    end;
    if Li.ImageIndex = FILE_IMAGE_IDX then
    begin
      UploadFile(Li.Caption);
    end;
  end;
end;

procedure TfrmMainForm.lvRemoteFilesColumnClick(Sender: TObject;
  Column: TListColumn);

begin
  if Column.Index = RemoteColumnToSort then
  begin
    RemoteAscending := not RemoteAscending
  end
  else
  begin
    RemoteColumnToSort := Column.Index;
  end;
  RemoteLvClearArrows;
  lvRemoteFiles.Items.BeginUpdate;
  lvRemoteFiles.AlphaSort;
  lvRemoteFiles.Items.EndUpdate;
end;

procedure TfrmMainForm.lvRemoteFilesCompare(Sender: TObject;
  Item1, Item2: TListItem; Data: Integer; var Compare: Integer);
begin
  //
  case RemoteColumnToSort of
    0: // file name
      begin
        Compare := CompareCaptions(Item1, Item2);
      end;
    1: // file type, file name
      begin
        if Item1.SubItems[0] > Item2.SubItems[0] then
        begin
          Compare := 1;
        end
        else
        begin
          if Item1.SubItems[0] > Item2.SubItems[0] then
          begin
            Compare := 1;
          end
          else
          begin
            if Item1.SubItems[0] < Item2.SubItems[0] then
            begin
              Compare := -1;
            end
            else
            begin
              Compare := CompareCaptions(Item1, Item2);
            end;
          end;
        end;
      end;
    2: // file size, file name
      begin
        if Item1.SubItems[1] > Item2.SubItems[1] then
        begin
          Compare := 1;
        end
        else
        begin
          if Item1.SubItems[1] > Item2.SubItems[1] then
          begin
            Compare := 1;
          end
          else
          begin
            if Item1.SubItems[1] < Item2.SubItems[1] then
            begin
              Compare := -1;
            end
            else
            begin
              Compare := CompareCaptions(Item1, Item2);
            end;
          end;
        end;

      end;
    3: // file modified date, file name
      begin
        if Item1.SubItems[2] > Item2.SubItems[2] then
        begin
          Compare := 1;
        end
        else
        begin
          if Item1.SubItems[2] > Item2.SubItems[2] then
          begin
            Compare := 1;
          end
          else
          begin
            if Item1.SubItems[2] < Item2.SubItems[2] then
            begin
              Compare := -1;
            end
            else
            begin
              Compare := CompareCaptions(Item1, Item2);
            end;
          end;
        end;
      end;
  end;
  if RemoteAscending then
  begin
    Compare := 0 - Compare;
  end;
end;

procedure TfrmMainForm.lvRemoteFilesDblClick(Sender: TObject);
var
  Li: TListItem;
begin
  if lvRemoteFiles.ItemIndex > -1 then
  begin
    Li := lvRemoteFiles.Items[lvRemoteFiles.ItemIndex];
    if Li.ImageIndex = DIR_IMAGE_IDX then
    begin
      ChangeRemoteDir(Li.Caption);
    end;
    if Li.ImageIndex = FILE_IMAGE_IDX then
    begin
      DownloadFile(Li.Caption);
    end;
  end;
end;

procedure TfrmMainForm.PopulateLocalFiles;
var
  Li: TListItem;
  LF: TSearchRec;
begin
  lvLocalFiles.Items.BeginUpdate;
  try
    lvLocalFiles.Items.Clear;
    lvLocalFiles.LargeImages := vimglstMainProgram;
    cboLocalCurrentDir.Text := GetCurrentDir;
    if FindFirst(GetCurrentDir + '\*.*', faAnyFile, LF) = 0 then
    begin
      repeat
        Li := lvLocalFiles.Items.Add;
        Li.Caption := LF.Name;
        if LF.Attr and faDirectory <> 0 then
        begin
          Li.SubItems.Add('Directory');
          Li.ImageIndex := DIR_IMAGE_IDX;
        end
        else
        begin
          Li.SubItems.Add('File');
          Li.ImageIndex := FILE_IMAGE_IDX;
        end;
        Li.SubItems.Add(IntToStr(LF.Size));
        Li.SubItems.Add(DateTimeToStr(LF.TimeStamp));
      until FindNext(LF) <> 0;
      FindClose(LF);
    end;
    lvLocalFiles.AlphaSort;
  finally
    lvLocalFiles.Items.EndUpdate;
  end;
end;

procedure TfrmMainForm.PopulateRemoteFiles(const ACurDir: String);
var
  i: Integer;
  Li: TListItem;
begin
  lvRemoteFiles.Items.BeginUpdate;
  try
    cboRemoteCurrentDir.Text := ACurDir;
    lvRemoteFiles.Items.Clear;
    lvRemoteFiles.LargeImages := vimglstMainProgram;
    for i := 0 to IdFTPClient.DirectoryListing.Count - 1 do
    begin
      Li := lvRemoteFiles.Items.Add;
      Li.Caption := IdFTPClient.DirectoryListing[i].FileName;
      case IdFTPClient.DirectoryListing[i].ItemType of
        ditDirectory:
          begin
            Li.SubItems.Add('Directory');
            Li.ImageIndex := DIR_IMAGE_IDX;
          end;
        ditFile:
          begin
            Li.SubItems.Add('File');
            Li.ImageIndex := FILE_IMAGE_IDX;
          end;
        ditSymbolicLink:
          begin
            Li.SubItems.Add('Symbolic link');
          end;
        ditSymbolicLinkDir:
          begin
            Li.SubItems.Add('Symbolic link');
          end;
        ditBlockDev:
          begin
            Li.SubItems.Add('Block Device');
          end;
        ditCharDev:
          begin
            Li.SubItems.Add('Character Device');
          end;
        ditFIFO:
          begin
            Li.SubItems.Add('Named Pipe');
          end;
        ditSocket:
          begin
            Li.SubItems.Add('Socket');
          end;
      end;
      if IdFTPClient.DirectoryListing[i].SizeAvail then
      begin
        Li.SubItems.Add(IntToStr(IdFTPClient.DirectoryListing[i].Size));
      end
      else
      begin
        Li.SubItems.Add('');
      end;
      if IdFTPClient.DirectoryListing[i].ModifiedAvail then
      begin
        Li.SubItems.Add(DateTimeToStr(IdFTPClient.DirectoryListing[i]
          .ModifiedDate));
      end
      else
      begin
        Li.SubItems.Add('');
      end;
    end;
    lvRemoteFiles.AlphaSort;
  finally
    lvRemoteFiles.Items.EndUpdate;
  end;
end;

procedure TfrmMainForm.RemoteDeleteFile(const AFile: String);
begin
  if MessageDlg('Delete ' + AFile + '?', mtConfirmation, [mbYes, mbNo], 0) = mrYes
  then
  begin
    TDeleteFileThread.Create(IdFTPClient, AFile);
  end;
end;

procedure TfrmMainForm.RemoteLvClearArrows;
var
  i: Integer;
  LMax: Integer;
begin
  lvRemoteFiles.Columns.BeginUpdate;
  try
    LMax := lvRemoteFiles.Columns.Count - 1;
    for i := 0 to LMax do
    begin
      lvRemoteFiles.Columns[i].ImageIndex := -1;
    end;
    if RemoteAscending then
    begin
      lvRemoteFiles.Columns[RemoteColumnToSort].ImageIndex :=
        ARROW_UP_IMAGE_IDX;
    end
    else
    begin
      lvRemoteFiles.Columns[RemoteColumnToSort].ImageIndex :=
        ARROW_DOWN_IMAGE_IDX;
    end;
  finally
    lvRemoteFiles.Columns.EndUpdate;
  end;
end;

procedure TfrmMainForm.RemoteMakeDir(const ADir: String);
begin
  TMakeDirThread.Create(IdFTPClient, ADir);
end;

procedure TfrmMainForm.RemoteRemoveDir(const ADir: String);
begin
  TRemoveDirThread.Create(IdFTPClient, ADir);
end;

procedure TfrmMainForm.RemoteRename(const AOldPathName, ANewPathName: String);
begin
  TRenamePathThread.Create(IdFTPClient, AOldPathName, ANewPathName);
end;

procedure TfrmMainForm.SetProxyType(const AType: Integer);
begin
  case AType of
    0:
      iosslFTP.TransparentProxy := nil;
    1:
      iosslFTP.TransparentProxy := HTTPConnectThrough;
    2:
      begin
        iosslFTP.TransparentProxy := SocksInfo;
        SocksInfo.Version := svSocks4;
      end;
    3:
      begin
        iosslFTP.TransparentProxy := SocksInfo;
        SocksInfo.Version := svSocks4A;
      end;
    4:
      begin
        iosslFTP.TransparentProxy := SocksInfo;
        SocksInfo.Version := svSocks5;
      end;
  end;
end;

{ TFTPThread }

constructor TFTPThread.Create(AFTP: TIdFTP);
begin
  inherited Create(False);
  FFTP := AFTP;

  FreeOnTerminate := True;
end;

destructor TFTPThread.Destroy;
begin
  inherited;
end;

function TFTPThread.DoVerifyPeer(Certificate: TIdX509; AOk: Boolean;
  ADepth, AError: Integer): Boolean;
begin
  FX509 := Certificate;
  FError := AError;
  FDepth := ADepth;
  Synchronize(Self, PromptVerifyCert);
  Result := FVerifyResult;
end;

procedure TFTPThread.PromptVerifyCert;
var
  LFrm: TfrmCertViewer;
begin
  try
    if GAcceptableCertificates.IndexOf(FX509.Fingerprints.SHA512AsString) = -1
    then
    begin
      LFrm := TfrmCertViewer.Create(nil);
      try
        LFrm.ErrorForeground := frmMainForm.FErrorForeground;
        LFrm.ErrorBackground := frmMainForm.FErrorBackground;
        LFrm.X509 := FX509;
        LFrm.Error := FError;
        FVerifyResult := LFrm.ShowModal = mrYes;
        if FVerifyResult and (LFrm.chkacceptOnlyOnce.Checked = False) then
        begin
          GAcceptableCertificates.Add(FX509.Fingerprints.SHA512AsString);
        end;
      finally
        FreeAndNil(LFrm);
      end;
    end
    else
    begin
      FVerifyResult := True;
    end;
    (FFTP.IOHandler as TIdSSLIOHandlerSocketOpenSSL).OnVerifyPeer := nil;
  except
    FVerifyResult := False;
  end;
end;

{ TConnectThread }

procedure TConnectThread.Execute;
var
  LCurDir: String;
begin
  try
    TThreadStartNotify.StartThread;
    (FFTP.IOHandler as TIdSSLIOHandlerSocketOpenSSL).OnVerifyPeer :=
      DoVerifyPeer;
    FFTP.Connect;
    if FFTP.IsCompressionSupported then
    begin
      FFTP.TransferMode(dmDeflate);
    end;
    LCurDir := FFTP.RetrieveCurrentDir;
    FFTP.List;
    TLogDirListingEvent.LogDirListing(FFTP.ListResult);
    TPopulateRemoteListNotify.PopulateRemoteList(LCurDir);
  except
    on E: EIdReplyRFCError do
    begin
      // This is already reported in the FTP log Window
    end;
    on E: Exception do
      TLogFTPError.NotifyString(E.Message);
  end;
  TThreadFinishedNotify.EndThread;
end;

{ TRemoteChangeDirThread }

constructor TRemoteChangeDirThread.Create(AFTP: TIdFTP; ANewDir: String);
begin
  inherited Create(AFTP);
  FNewDir := ANewDir;
end;

procedure TRemoteChangeDirThread.Execute;
var
  LCurDir: String;
begin
  try
    TThreadStartNotify.StartThread;
    FFTP.ChangeDir(FNewDir);
    LCurDir := FFTP.RetrieveCurrentDir;
    FFTP.List;
    TLogDirListingEvent.LogDirListing(FFTP.ListResult);
    TPopulateRemoteListNotify.PopulateRemoteList(LCurDir);
  except
    on E: EIdReplyRFCError do
    begin
      // This is already reported in the FTP log Window
    end;
    on E: Exception do
      TLogFTPError.NotifyString(E.Message);
  end;
  TThreadFinishedNotify.EndThread;
end;

{ TFileThread }

constructor TFileThread.Create(AFTP: TIdFTP; AFile: String);
begin
  inherited Create(AFTP);
  FFile := AFile;
end;

{ TDownloadFileThread }

procedure TDownloadFileThread.Execute;
var
  LFile: TStream;
begin
  try
    TThreadStartNotify.StartThread;
    LFile := TFileStream.Create(FFile, fmCreate);
    try
      FFTP.TransferType := ftBinary;
      FFTP.Get(FFile, LFile);
    finally
      FreeAndNil(LFile);
    end;
    TFile.SetLastWriteTime(FFile, FFTP.FileDate(FFile));
    TPopulateLocalListNotify.PopulateLocalList;
  except
    on E: EIdReplyRFCError do
    begin
      // This is already reported in the FTP log Window
    end;
    on E: Exception do
      TLogFTPError.NotifyString(E.Message);
  end;
  TThreadFinishedNotify.EndThread;
end;

{ TUploadFileThread }

procedure TUploadFileThread.Execute;
var
  LFile: TStream;
  LCurDir: String;
begin
  try
    TThreadStartNotify.StartThread;
    LFile := TFileStream.Create(FFile, fmOpenRead);
    try
      FFTP.TransferType := ftBinary;
      FFTP.Put(LFile, FFile);
    finally
      FreeAndNil(LFile);
    end;
    FFTP.SetModTime(FFile, TFile.GetLastWriteTime(FFile));
    LCurDir := FFTP.RetrieveCurrentDir;
    FFTP.List;
    TLogDirListingEvent.LogDirListing(FFTP.ListResult);
    TPopulateRemoteListNotify.PopulateRemoteList(LCurDir);
  except
    on E: EIdReplyRFCError do
    begin
      // This is already reported in the FTP log Window
    end;
    on E: Exception do
      TLogFTPError.NotifyString(E.Message);
  end;
  TThreadFinishedNotify.EndThread;
end;

{ TDeleteFileThread }

procedure TDeleteFileThread.Execute;
var
  LCurDir: String;
begin
  try
    TThreadStartNotify.StartThread;
    FFTP.Delete(FFile);
    LCurDir := FFTP.RetrieveCurrentDir;
    FFTP.List;
    TLogDirListingEvent.LogDirListing(FFTP.ListResult);
    TPopulateRemoteListNotify.PopulateRemoteList(LCurDir);
  except
    on E: EIdReplyRFCError do
    begin
      // This is already reported in the FTP log Window
    end;
    on E: Exception do
      TLogFTPError.NotifyString(E.Message);
  end;
  TThreadFinishedNotify.EndThread;
end;

{ TRemoveDirThread }

procedure TRemoveDirThread.Execute;
var
  LCurDir: String;
begin
  try
    TThreadStartNotify.StartThread;
    FFTP.RemoveDir(FFile);
    LCurDir := FFTP.RetrieveCurrentDir;
    FFTP.List;
    TLogDirListingEvent.LogDirListing(FFTP.ListResult);
    TPopulateRemoteListNotify.PopulateRemoteList(LCurDir);
  except
    on E: EIdReplyRFCError do
    begin
      // This is already reported in the FTP log Window
    end;
    on E: Exception do
      TLogFTPError.NotifyString(E.Message);
  end;
  TThreadFinishedNotify.EndThread;
end;

{ TRenamePathThread }

constructor TRenamePathThread.Create(AFTP: TIdFTP;
  const AOldName, ANewName: String);
begin
  inherited Create(AFTP, AOldName);
  FNewName := ANewName;
end;

procedure TRenamePathThread.Execute;
var
  LCurDir: String;
begin
  try
    TThreadStartNotify.StartThread;
    FFTP.Rename(FFile, FNewName);
    LCurDir := FFTP.RetrieveCurrentDir;
    FFTP.List;
    TLogDirListingEvent.LogDirListing(FFTP.ListResult);
    TPopulateRemoteListNotify.PopulateRemoteList(LCurDir);
  except
    on E: EIdReplyRFCError do
    begin
      // This is already reported in the FTP log Window
    end;
    on E: Exception do
      TLogFTPError.NotifyString(E.Message);
  end;
  TThreadFinishedNotify.EndThread;

end;

{ TMakeDirThread }

procedure TMakeDirThread.Execute;
var
  LCurDir: String;
begin
  try
    TThreadStartNotify.StartThread;
    FFTP.MakeDir(FFile);
    LCurDir := FFTP.RetrieveCurrentDir;
    FFTP.List;
    TLogDirListingEvent.LogDirListing(FFTP.ListResult);
    TPopulateRemoteListNotify.PopulateRemoteList(LCurDir);
  except
    on E: EIdReplyRFCError do
    begin
      // This is already reported in the FTP log Window
    end;
    on E: Exception do
      TLogFTPError.NotifyString(E.Message);
  end;
  TThreadFinishedNotify.EndThread;

end;

{ TLogEventNotify }

procedure TLogEventNotify.DoNotify;
begin
  frmMainForm.redtLog.Lines.Add(FStr);
  ScrollToEnd(frmMainForm.redtLog);
end;

class procedure TLogEventNotify.NotifyString(const AStr: String);
var
  L: TLogEventNotify;
begin
  L := TLogEventNotify.Create;
  L.FStr := AStr;
  L.Notify;
end;

{ TLogFTPError }

procedure TLogFTPError.DoNotify;
begin
  frmMainForm.redtLog.SelAttributes.Color := frmMainForm.FErrorForeground;
  frmMainForm.redtLog.SelAttributes.BackColor := frmMainForm.FErrorBackground;
  inherited;
end;

class procedure TLogFTPError.NotifyString(const AStr: String);
var
  L: TLogFTPError;
begin
  L := TLogFTPError.Create;
  L.FStr := AStr;
  L.Notify;
end;

{ TSSLEvent }

procedure TSSLEvent.DoNotify;
begin
  if frmMainForm.FLogDebugOutput then
  begin
    frmMainForm.redtLog.SelAttributes.Color := frmMainForm.FDebugForeground;
    frmMainForm.redtLog.SelAttributes.BackColor := frmMainForm.FDebugBackground;
    inherited;
  end;
end;

class procedure TSSLEvent.NotifyString(const AStr: String);
var
  L: TSSLEvent;
begin
  L := TSSLEvent.Create;
  L.FStr := AStr;
  L.Notify;
end;

{ TSSLCipherEvent }

procedure TSSLCipherEvent.DoNotify;
begin
  frmMainForm.redtLog.SelAttributes.Color := frmMainForm.FSSLMessageForeground;
  frmMainForm.redtLog.SelAttributes.BackColor :=
    frmMainForm.FSSLMessageBackground;
  inherited;
end;

class procedure TSSLCipherEvent.NotifyString(const AStr: String);
var
  L: TSSLCipherEvent;
begin
  L := TSSLCipherEvent.Create;
  L.FStr := AStr;
  L.Notify;
end;

{ TStatusBarEvent }

procedure TStatusBarEvent.DoNotify;
begin
  frmMainForm.sbrMainForm.Panels[0].Text := FStr;
end;

class procedure TStatusBarEvent.NotifyString(const AStr: String);
var
  L: TStatusBarEvent;
begin
  L := TStatusBarEvent.Create;
  L.FStr := AStr;
  L.Notify;
end;

{ TPopulateRemoteListNotify }

procedure TPopulateRemoteListNotify.DoNotify;
begin
  frmMainForm.PopulateRemoteFiles(FCurrentDir);
end;

class procedure TPopulateRemoteListNotify.PopulateRemoteList
  (const ACurrentDir: String);
var
  L: TPopulateRemoteListNotify;
begin
  L := TPopulateRemoteListNotify.Create;
  L.FCurrentDir := ACurrentDir;
  L.Notify;
end;

{ TLogDirListingEvent }

procedure TLogDirListingEvent.DoNotify;
var
  i: Integer;
begin
  frmMainForm.redtLog.Lines.BeginUpdate;
  try
    for i := 0 to FDirListing.Count - 1 do
    begin
      frmMainForm.redtLog.SelAttributes.Color :=
        frmMainForm.FDirOutputForeground;
      frmMainForm.redtLog.SelAttributes.BackColor :=
        frmMainForm.FDirOutputBackground;
      frmMainForm.redtLog.Lines.Add(FDirListing[i]);
    end;
  finally
    frmMainForm.redtLog.Lines.EndUpdate;
  end;
  ScrollToEnd(frmMainForm.redtLog);
end;

class procedure TLogDirListingEvent.LogDirListing(AStrings: TStrings);
var
  L: TLogDirListingEvent;
begin
  L := TLogDirListingEvent.Create;
  L.FDirListing := AStrings;
  L.Notify;
end;

{ TThreadFinishedNotify }

procedure TThreadFinishedNotify.DoNotify;
begin
  frmMainForm.FThreadRunning := False;
end;

class procedure TThreadFinishedNotify.EndThread;
var
  L: TThreadFinishedNotify;
begin
  L := TThreadFinishedNotify.Create;
  L.Notify;
end;

{ TThreadStartNotify }

procedure TThreadStartNotify.DoNotify;
begin
  frmMainForm.FThreadRunning := True;
end;

class procedure TThreadStartNotify.StartThread;
var
  L: TThreadStartNotify;
begin
  L := TThreadStartNotify.Create;
  L.Notify;
end;

{ TPopulateLocalListNotify }

procedure TPopulateLocalListNotify.DoNotify;
begin
  frmMainForm.PopulateLocalFiles;
end;

class procedure TPopulateLocalListNotify.PopulateLocalList;
var
  LNotify: TPopulateLocalListNotify;
begin
  LNotify := TPopulateLocalListNotify.Create;
  LNotify.Notify;
end;

initialization

GetOpenSSLLoader.OpenSSLPath := ExtractFilePath(ParamStr(0));

end.
