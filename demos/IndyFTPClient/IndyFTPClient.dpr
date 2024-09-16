program IndyFTPClient;

uses
  Vcl.Forms,
  mainform in 'mainform.pas' {frmMainForm},
  dkgFTPConnect in 'dkgFTPConnect.pas' {frmConnect},
  frmAbout in 'frmAbout.pas' {AboutBox},
  settingsdlg in 'settingsdlg.pas' {frmSettings},
  frmBookmarks in 'frmBookmarks.pas' {frmFTPSites},
  CertViewer in 'CertViewer.pas' {Form1},
  ProgUtils in 'ProgUtils.pas',
  AcceptableCerts in 'AcceptableCerts.pas';

{$R *.res}

begin
  Application.Initialize;
  Application.MainFormOnTaskbar := True;
  Application.CreateForm(TfrmMainForm, frmMainForm);
  Application.Run;
end.
