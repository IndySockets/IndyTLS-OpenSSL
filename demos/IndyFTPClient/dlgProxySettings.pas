unit dlgProxySettings;

interface

uses
  Winapi.Windows, Winapi.Messages, System.SysUtils, System.Variants,
  System.Classes, Vcl.Graphics,
  Vcl.Controls, Vcl.Forms, Vcl.Dialogs, Vcl.StdCtrls, Vcl.ExtCtrls,
  Vcl.Samples.Spin;

type
  TfrmProxySettings = class(TForm)
    Panel2: TPanel;
    OKBtn: TButton;
    CancelBtn: TButton;
    spededtProxyPort: TSpinEdit;
    lblProxyPort: TLabel;
    edtProxyServerPassword: TEdit;
    lblProxyServerPassword: TLabel;
    edtProxyServerUserName: TEdit;
    lblProxyServerUserName: TLabel;
    edtProxyServerName: TEdit;
    lblProxyServerName: TLabel;
    cboProxyType: TComboBox;
    lblProxyType: TLabel;
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
  frmProxySettings: TfrmProxySettings;

implementation

uses IdIPAddress, ProgUtils;

{$R *.dfm}
{ TfrmNATSettings }

procedure TfrmProxySettings.edtExternalIPAddressChange(Sender: TObject);
begin
  ValidateFeilds;
end;

procedure TfrmProxySettings.spnedtPortMaximumChange(Sender: TObject);
begin
  ValidateFeilds;
end;

procedure TfrmProxySettings.spnedtPortMinimumChange(Sender: TObject);
begin
  ValidateFeilds;
end;

procedure TfrmProxySettings.ValidateFeilds;
var
  LBool : Boolean;
begin
    if cboProxyType.ItemIndex > 0 then
    begin
      OKBtn.Enabled := (edtProxyServerName.Text <> '');
    end;
  //validate proxy/host feilds - enable or disable appropriately
  LBool := cboProxyType.ItemIndex > 0;
  edtProxyServerName.Enabled := LBool;
  lblProxyServerName.Enabled := LBool;
  edtProxyServerUserName.Enabled := LBool;
  lblProxyServerUserName.Enabled := LBool;
  edtProxyServerPassword.Enabled := LBool;
  lblProxyServerPassword.Enabled := LBool;
  Self.spededtProxyPort.Enabled := LBool;
  Self.lblProxyPort.Enabled := LBool;
end;

end.
