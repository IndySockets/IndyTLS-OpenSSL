unit frmProgress;

interface

uses
  Winapi.Windows, Winapi.Messages, System.SysUtils, System.Variants, System.Classes, Vcl.Graphics,
  Vcl.Controls, Vcl.Forms, Vcl.Dialogs, Vcl.StdCtrls, Vcl.ExtCtrls, IdComponent,
  Vcl.ComCtrls;

type
  TfrmFileProgress = class(TForm)
    Panel2: TPanel;
    CancelBtn: TButton;
    lblAction: TLabel;
    prgbrDownloadUpload: TProgressBar;
    lblProgress: TLabel;
  private
    { Private declarations }
  public
    { Public declarations }
    procedure UpdateProgressIndicator(const AFileName : String;
      const AWorkMode : TWorkMode; const AWorkCount, AWorkCountMax : Int64);
  end;

var
  frmFileProgress: TfrmFileProgress;

implementation

{$R *.dfm}

{ TfrmFileProgress }

procedure TfrmFileProgress.UpdateProgressIndicator(const AFileName: String;
  const AWorkMode: TWorkMode; const AWorkCount, AWorkCountMax: Int64);
var LStr : String;
  LPerc : Integer;
begin
  if AWorkMode = wmRead then
  begin
    LStr := 'Downloading '+AFileName+'...';
  end
  else
  begin
    LStr := 'Uploading '+AFileName+'...';
  end;
  if AWorkCountMax >= 0 then
  begin
    LPerc := Round((AWorkcount / AWorkCountMax) * 100);
    Self.prgbrDownloadUpload.Position  := LPerc;
    Self.lblProgress.Caption := IntToStr(AWorkCount)+ ' of '+IntToStr(AWorkCountMax) + ' ('+IntToStr(LPerc)+'%)';
  end
  else
  begin
    prgbrDownloadUpload.Style := pbstMarquee;
    Self.lblProgress.Caption := IntToStr(AWorkCount);
  end;
end;

end.
