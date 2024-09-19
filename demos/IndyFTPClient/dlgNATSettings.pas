unit dlgNATSettings;

interface

uses
  Winapi.Windows, Winapi.Messages, System.SysUtils, System.Variants,
  System.Classes, Vcl.Graphics,
  Vcl.Controls, Vcl.Forms, Vcl.Dialogs, Vcl.StdCtrls, Vcl.ExtCtrls,
  Vcl.Samples.Spin;

type
  TfrmNATSettings = class(TForm)
    Panel2: TPanel;
    OKBtn: TButton;
    CancelBtn: TButton;
    spnedtPortMaximum: TSpinEdit;
    lblMaximumPort: TLabel;
    spnedtPortMinimum: TSpinEdit;
    lblMinPort: TLabel;
    lblPorts: TLabel;
    edtExternalIPAddress: TEdit;
    lblNATIPAddress: TLabel;
    procedure edtExternalIPAddressChange(Sender: TObject);
    procedure spnedtPortMinimumChange(Sender: TObject);
    procedure spnedtPortMaximumChange(Sender: TObject);
  private
    { Private declarations }
    procedure ValidateFeilds;
  public
    { Public declarations }
  end;

var
  frmNATSettings: TfrmNATSettings;

implementation

uses IdIPAddress, ProgUtils;

{$R *.dfm}
{ TfrmNATSettings }

procedure TfrmNATSettings.edtExternalIPAddressChange(Sender: TObject);
begin
  ValidateFeilds;
end;

procedure TfrmNATSettings.spnedtPortMaximumChange(Sender: TObject);
begin
  ValidateFeilds;
end;

procedure TfrmNATSettings.spnedtPortMinimumChange(Sender: TObject);
begin
  ValidateFeilds;
end;

procedure TfrmNATSettings.ValidateFeilds;
var
  LIP: String;
  LBool: Boolean;
begin
  LIP := edtExternalIPAddress.Text;
  Self.OKBtn.Enabled := (LIP = '') or IsValidIP(LIP);
  if OKBtn.Enabled then
  begin
    if (spnedtPortMinimum.Value = 0) and (spnedtPortMaximum.Value = 0) then
    begin
      OKBtn.Enabled := True;
    end
    else
    begin
      OKBtn.Enabled := (spnedtPortMinimum.Value < spnedtPortMaximum.Value);
    end;
  end;
end;

end.
