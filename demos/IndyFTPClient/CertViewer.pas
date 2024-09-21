unit CertViewer;

interface

uses
  Winapi.Windows, Winapi.Messages, System.SysUtils, System.Variants,
  System.Classes, Vcl.Graphics,
  Vcl.Controls, Vcl.Forms, Vcl.Dialogs, Vcl.StdCtrls, Vcl.ExtCtrls,
  Vcl.ComCtrls,
  IdSSLOpenSSL;

type
  TfrmCertViewer = class(TForm)
    Panel2: TPanel;
    OKBtn: TButton;
    CancelBtn: TButton;
    redtCertView: TRichEdit;
    lblErrorMessage: TLabel;
    chkacceptOnlyOnce: TCheckBox;
    lblAcceptThisCertificate: TLabel;
    procedure FormCreate(Sender: TObject);
  private
    function GetErrorBackground: TColor;
    function GetErrorForeground: TColor;
    procedure SetErrorBackground(const Value: TColor);
    procedure SetErrorForeground(const Value: TColor);
  protected
    { Private declarations }
    FX509: TIdX509;
    FError: Integer;
    FErrorForeground : TColor;
    FErrorBackground : TColor;
    function GetX509: TIdX509;
    procedure RefreshViewer;
    procedure SetX509(const Value: TIdX509);
    procedure WriteErrorString(const AStr : String);
    procedure WriteWarningString(const AStr : String);
    procedure DumpX509Name(AX509Name: TIdX509Name);
    procedure DumpX509KeyUsage(AX509: TIdX509);
    procedure DumpX509ExtKeyUsage(AX509: TIdX509);
    procedure SetError(const Value: Integer);
  public
    { Public declarations }
    property X509: TIdX509 read GetX509 write SetX509;
    property Error: Integer read FError write SetError;
    property ErrorForeground : TColor read GetErrorForeground write SetErrorForeground;
    property ErrorBackground : TColor read GetErrorBackground write SetErrorBackground;
  end;

var
  frmCertViewer: TfrmCertViewer;

implementation

{$R *.dfm}

uses mainform, dkgFTPConnect, IdCTypes, IniFiles, System.UITypes,
  System.IOUtils,
  ProgUtils, IdOpenSSLHeaders_x509, IdOpenSSLHeaders_x509_vfy;

const
  TAB1 = 32;
  TAB2 = 50;
  TAB3 = 65;

  { TfrmCertViewer }

procedure TfrmCertViewer.DumpX509ExtKeyUsage(AX509: TIdX509);
var
  LStr: String;
  LExtKeyUsage: TIdX509ExtKeyUsage;
begin
  LStr := '';
  LExtKeyUsage := FX509.ExtendedKeyUsage;
  if LExtKeyUsage <> [] then
  begin
    // (Server, Client, SMIME, CodeSign, OCSPSign, TimeStamp, DVCS, AnyEKU);
    if Server in LExtKeyUsage then
    begin
      LStr := LStr + ', Server';
    end;
    if Client in LExtKeyUsage then
    begin
      LStr := LStr + ', client';
    end;
    if SMIME in LExtKeyUsage then
    begin
      LStr := LStr + ', S/MIME';
    end;
    if CodeSign in LExtKeyUsage then
    begin
      LStr := LStr + ', Code Signing';
    end;
    if OCSPSign in LExtKeyUsage then
    begin
      LStr := LStr + ', OCSP Signing';
    end;
    if TimeStamp in LExtKeyUsage then
    begin
      LStr := LStr + ',  TimeStamp';
    end;
    if DVCS in LExtKeyUsage then
    begin
      LStr := LStr + ', DVCS';
    end;
    if AnyEKU in LExtKeyUsage then
    begin
      LStr := LStr + ', Any Extended Key Usage';
    end;
    Delete(LStr, 1, 1);
    LStr := Trim(LStr);
    redtCertView.Lines.Add('');
    Self.redtCertView.Lines.Add(RightJustify('Extended Key Usage: ',
      TAB1) + LStr);
  end;
end;

procedure TfrmCertViewer.DumpX509KeyUsage(AX509: TIdX509);
var
  LKeyUsage: TIdX509KeyUsage;
  LStr: String;
begin
  LStr := '';
  LKeyUsage := FX509.KeyUsage;
  if LKeyUsage <> [] then
  begin
    {
      (DigitalSignature, NonRepudiation, KeyEncipherment,
      DataEncipherment, KeyAgreement, CertSign, CRLSign, EncipherOnly, DecipherOnly);
    }
    if (DigitalSignature in LKeyUsage) then
    begin
      LStr := LStr + ', Digital Signature';
    end;
    if (NonRepudiation in LKeyUsage) then
    begin
      LStr := LStr + ', Non-Repudiation';
    end;
    if (KeyEncipherment in LKeyUsage) then
    begin
      LStr := LStr + ', Key Encipherment';
    end;
    if (DataEncipherment in LKeyUsage) then
    begin
      LStr := LStr + ', Data Encipherment';
    end;
    if (CertSign in LKeyUsage) then
    begin
      LStr := LStr + ', Certificate Signing';
    end;
    if (CRLSign in LKeyUsage) then
    begin
      LStr := LStr + ', CRL Signing';
    end;
    if (EncipherOnly in LKeyUsage) then
    begin
      LStr := LStr + ', Encipher-Only';
    end;
    if (DecipherOnly in LKeyUsage) then
    begin
      LStr := LStr + ', Decipher Only';
    end;
    Delete(LStr, 1, 1);
    LStr := Trim(LStr);
    redtCertView.Lines.Add('');
    Self.redtCertView.Lines.Add(RightJustify('Key Usage: ', TAB1) + LStr);
  end;

end;

procedure TfrmCertViewer.DumpX509Name(AX509Name: TIdX509Name);
var
  LStr: String;
begin
  LStr := AX509Name.CommonName;
  if LStr <> '' then
  begin
    redtCertView.Lines.Add(RightJustify('Common Name: ', TAB1) + LStr);
  end;
  LStr := AX509Name.Organization;
  if LStr <> '' then
  begin
    redtCertView.Lines.Add(RightJustify('Orginization: ', TAB1) + LStr);
  end;
  LStr := AX509Name._Unit;
  if LStr <> '' then
  begin
    redtCertView.Lines.Add(RightJustify('Unit: ', TAB1) + LStr);
  end;
  LStr := AX509Name.EMail;
  if LStr <> '' then
  begin
    redtCertView.Lines.Add(RightJustify('E-Mail Address: ', TAB1) + LStr);
  end;
  LStr := AX509Name.StreetAddress;
  if LStr <> '' then
  begin
    redtCertView.Lines.Add(RightJustify('Street Address: ', TAB1) + LStr);
  end;
  LStr := AX509Name.City;
  if LStr <> '' then
  begin
    redtCertView.Lines.Add(RightJustify('City or Town: ', TAB1) + LStr);
  end;
  LStr := AX509Name.Providence;
  if LStr <> '' then
  begin
    redtCertView.Lines.Add(RightJustify('State or Providence: ', TAB1) + LStr);
  end;
  LStr := AX509Name.Country;
  if LStr <> '' then
  begin
    redtCertView.Lines.Add(RightJustify('Country: ', TAB1) + LStr);
  end;

end;

procedure TfrmCertViewer.FormCreate(Sender: TObject);
var
  LIni: TIniFile;
begin
  LIni := TIniFile.Create(GetIniFilePath);
  try
    Self.redtCertView.Font.Name := LIni.ReadString('Log_Font', 'Name',
      Self.redtCertView.Font.Name);
    Self.redtCertView.Font.Charset := LIni.ReadInteger('Log_Font', 'CharSet',
      Self.redtCertView.Font.Charset);
    Self.redtCertView.Font.Size := LIni.ReadInteger('Log_Font', 'Size',
      Self.redtCertView.Font.Size);
    Self.redtCertView.Font.Style :=
      TFontStyles(Byte(LIni.ReadInteger('Log_Font', 'Style',
      Byte(Self.redtCertView.Font.Style))));
  finally
    FreeAndNil(LIni);
  end;
end;

function TfrmCertViewer.GetErrorBackground: TColor;
begin
  Result := Self.FErrorBackground;
end;

function TfrmCertViewer.GetErrorForeground: TColor;
begin
  Result := Self.FErrorForeground;
end;

function TfrmCertViewer.GetX509: TIdX509;
begin
  Result := FX509;
end;

procedure TfrmCertViewer.RefreshViewer;
var
  LStr: String;
  i: Integer;
  LProxyPathLen: TIdC_LONG;
begin
  redtCertView.Lines.BeginUpdate;
  try
    redtCertView.Lines.Clear;
    if FX509.Errors.InvalidInconsistantValues then
    begin
      WriteErrorString('Invalid or Inconsistant Values - Reject this certificated');
    end;
    if FX509.Errors.InvalidPolicy then
    begin
      WriteErrorString('Invalid Certificate Policy - Reject this certificated');
    end;
    if FX509.Errors.UnhandledCriticalExtention then
    begin
      WriteErrorString('Unhandled Critical Extention - Reject this certificated');
    end;
    if FX509.Warnings.IsObsoleteV1 then
    begin
      WriteWarningString('Certificate is Obsolete Version 1');
    end;
    if FX509.Warnings.IsSelfSigned then
    begin
      WriteWarningString('Certificate is Self-Signed');
    end
    else
    begin
      if FX509.Warnings.SubjectAndIssuerMatch then
      begin
        WriteWarningString('Subject and Issuer match - Implies self-signed');
      end;
    end;
    redtCertView.Lines.Add('Fingerprint: ');
    redtCertView.Lines.Add(RightJustify('SHA1: ', TAB1) +
      FX509.Fingerprints.SHA1AsString);
    redtCertView.Lines.Add(RightJustify('SHA224: ', TAB1) +
      FX509.Fingerprints.SHA224AsString);
    redtCertView.Lines.Add(RightJustify('SHA256: ', TAB1) +
      FX509.Fingerprints.SHA256AsString);
    redtCertView.Lines.Add(RightJustify('SHA384: ', TAB1) +
      FX509.Fingerprints.SHA384AsString);
    redtCertView.Lines.Add(RightJustify('SHA512: ', TAB1) +
      FX509.Fingerprints.SHA512AsString);
    LStr := FX509.SerialNumber;
    redtCertView.Lines.Add('Serial Number: ' + LStr);
    redtCertView.Lines.Add('');
    redtCertView.Lines.Add('Validity Period');
    redtCertView.Lines.Add(RightJustify('Not Before: ', TAB1) +
      DateTimeToStr(FX509.NotBefore));
    redtCertView.Lines.Add(RightJustify('Not After: ', TAB1) +
      DateTimeToStr(FX509.NotAfter));
    redtCertView.Lines.Add('');
    redtCertView.Lines.Add('Subject');
    DumpX509Name(FX509.Subject);
    redtCertView.Lines.Add('');

    if not FX509.Warnings.SubjectAndIssuerMatch then
    begin
      redtCertView.Lines.Add('Issuer');
      DumpX509Name(FX509.Issuer);
    end;
    redtCertView.Lines.Add('');
    redtCertView.Lines.Add('Subject Public Key Info');
    redtCertView.Lines.Add(RightJustify('Alorigthm: ', TAB1) +
      FX509.PublicKey.Algorithm);
    LStr := X509.PublicKey.Encoding;
    if LStr <> '' then
    begin
      redtCertView.Lines.Add(RightJustify('Encoding Size: ', TAB1) +
        IntToStr(FX509.PublicKey.EncodingSize));
      redtCertView.Lines.Add(RightJustify('Encoding: ', TAB1) +
        FX509.PublicKey.Encoding);
    end;
    redtCertView.Lines.Add(RightJustify('Bits: ', TAB1) +
      IntToStr(FX509.PublicKey.Bits) + ' Bits');
    redtCertView.Lines.Add(RightJustify('Security Bits: ', TAB1) +
      IntToStr(FX509.PublicKey.SecurityBits) + ' Bits');
    redtCertView.Lines.Add(RightJustify('Size: ', TAB1) +
      IntToStr(FX509.PublicKey.Size));
    LStr := FX509.PublicKey.Modulus;
    if LStr <> '' then
    begin
      redtCertView.Lines.Add(RightJustify('Modulus: ', TAB1) + LStr);
    end;
    redtCertView.Lines.Add('');
    redtCertView.Lines.Add('Signature');
    redtCertView.Lines.Add(RightJustify('Signature: ', TAB1) +
      X509.SigInfo.Signature);
    redtCertView.Lines.Add(RightJustify('Signature Algorithm: ', TAB1) +
      X509.SigInfo.Algorithm);
    redtCertView.Lines.Add('');

    LStr := FX509.SubjectKeyIdentifier;
    if LStr <> '' then
    begin
      redtCertView.Lines.Add(RightJustify('X509v3 Subject Key Identifier: ',
        TAB1) + LStr);
    end;
    LStr := X509.AuthorityKeyID.KeyID;
    if (LStr <> '') or (FX509.AuthorityKeyID.Serial <> 0) then
    begin
      redtCertView.Lines.Add
        (RightJustify('X509v3 Authority Key Identifier: ', TAB1));
      if LStr <> '' then
      begin
        redtCertView.Lines.Add(RightJustify('Key ID: ', TAB2) + LStr);
      end;
      for i := 0 to FX509.AuthorityKeyID.IssuerCount - 1 do
      begin
        redtCertView.Lines.Add(RightJustify('', TAB2) +
          FX509.AuthorityKeyID.Issuer[i]);
      end;
      if X509.AuthorityKeyID.Serial > -1 then
      begin
        redtCertView.Lines.Add(RightJustify('Serial: ', TAB2) +
          IntToHex(FX509.AuthorityKeyID.Serial));
      end;
    end;
    LStr := X509.BasicConstraints;
    if LStr <> '' then
    begin
      redtCertView.Lines.Add(RightJustify('X509v3 Basic Constraints: ',
        TAB1) + LStr);
    end;
    if X509.AltSubjectNames.ItemsCount > -1 then
    begin
      redtCertView.Lines.Add('');
      redtCertView.Lines.Add(RightJustify(' Subject ALternative Name Count: ',
        TAB2) + IntToStr(FX509.AltSubjectNames.ItemsCount));
      for i := 0 to FX509.AltSubjectNames.ItemsCount - 1 do
      begin
        redtCertView.Lines.Add(RightJustify('Subject ALternate Name ' +
          IntToStr(i) + ': ', TAB1) + FX509.AltSubjectNames.Items[i]);
      end;
    end;
    DumpX509KeyUsage(FX509);
    DumpX509ExtKeyUsage(FX509);
    LProxyPathLen := FX509.ProxyPathLen;
    if LProxyPathLen > -1 then
    begin
      redtCertView.Lines.Add('');
      redtCertView.Lines.Add(RightJustify('Proxy Path Length: ', TAB1) +
        IntToStr(LProxyPathLen));
    end;
    redtCertView.Lines.Add('');
    redtCertView.Lines.Add('Extensions: ');
    redtCertView.Lines.Add(RightJustify('Extension Count: ', TAB1) +
      IntToStr(FX509.ExtensionCount));
    for i := 0 to FX509.ExtensionCount - 1 do
    begin
      LStr := FX509.ExtentionName[i];
      if X509.ExtentionCritical[i] then
      begin
        redtCertView.Lines.Add(RightJustify(LStr + ' (critical): ', TAB2) +
          FX509.ExtensionValues[i]);
      end
      else
      begin
        redtCertView.Lines.Add(RightJustify(LStr + ': ', TAB2) +
          FX509.ExtensionValues[i]);
      end;
    end;

  finally
    Self.redtCertView.Lines.EndUpdate;
  end;
  ScrollToTop(redtCertView);

end;

procedure TfrmCertViewer.SetError(const Value: Integer);
begin
  FError := Value;
  Caption := string(X509_verify_cert_error_string(FError));
  lblErrorMessage.Caption := ProgUtils.CertErrorToStr(Value);
end;

procedure TfrmCertViewer.SetErrorBackground(const Value: TColor);
begin
 Self.FErrorBackground := Value;
end;

procedure TfrmCertViewer.SetErrorForeground(const Value: TColor);
begin
  Self.FErrorForeground := Value;
end;

procedure TfrmCertViewer.SetX509(const Value: TIdX509);
begin
  FX509 := Value;
  RefreshViewer;
end;

procedure TfrmCertViewer.WriteErrorString(const AStr: String);
begin
   redtCertView.SelAttributes.Color := FErrorForeground;
   redtCertView.SelAttributes.Style := [fsBold];
   redtCertView.SelAttributes.BackColor := FErrorBackground;
   redtCertView.Lines.Add(AStr);
end;

procedure TfrmCertViewer.WriteWarningString(const AStr: String);
begin
   redtCertView.SelAttributes.Color := FErrorForeground;
   redtCertView.SelAttributes.Style := [];
   redtCertView.SelAttributes.BackColor := FErrorBackground;
   redtCertView.Lines.Add(AStr);
end;

end.
