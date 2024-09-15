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
    HelpBtn: TButton;
    redtCertView: TRichEdit;
    lblErrorMessage: TLabel;
    chkacceptOnlyOnce: TCheckBox;
    lblAcceptThisCertificate: TLabel;
    procedure FormCreate(Sender: TObject);
  private
    { Private declarations }
    FX509: TIdX509;
    FError: Integer;
    function GetX509: TIdX509;
    procedure SetX509(const Value: TIdX509);
    procedure DumpX509Name(AX509Name: TIdX509Name);
    procedure DumpX509KeyUsage(AX509: TIdX509);
    procedure DumpX509ExtKeyUsage(AX509: TIdX509);
    procedure SetError(const Value: Integer);
  public
    { Public declarations }
    property X509: TIdX509 read GetX509 write SetX509;
    property Error: Integer read FError write SetError;
  end;

var
  frmCertViewer: TfrmCertViewer;


implementation

{$R *.dfm}

uses mainform, dkgFTPConnect, IdCTypes, IniFiles, System.UITypes,
  System.IOUtils,
  ProgUtils, IdOpenSSLHeaders_x509, IdOpenSSLHeaders_x509_vfy;

function RightJustify(const AText: String; ALen: Integer): String;
var
  i: Integer;
begin
  Result := '';
  if ALen > Length(AText) then
  begin
    for i := 0 to ALen - Length(AText) do
    begin
      Result := Result + ' ';
    end;
    Result := Result + AText;
  end
  else
  begin
    Result := AText;
  end;
end;

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

function TfrmCertViewer.GetX509: TIdX509;
begin
  Result := FX509;
end;

procedure TfrmCertViewer.SetError(const Value: Integer);
begin
  FError := Value;
  { Thuis is stuff from: https://linux.die.net/man/3/x509_store_ctx_get_error
    I found that the error message from  X509_verify_cert_error_string does not
    always accurately describe the issue involved. }
  case FError of
    X509_V_ERR_UNABLE_TO_GET_ISSUER_CERT:
      begin
        lblErrorMessage.Caption :=
          'the issuer certificate could not be found: this occurs if the issuer certificate of an untrusted certificate cannot be found. ';
      end;
    X509_V_ERR_UNABLE_TO_GET_CRL:
      begin
        lblErrorMessage.Caption :=
          'the Certificate Revocation List (CRL) of a certificate could not be found. ';
      end;
    X509_V_ERR_UNABLE_TO_DECRYPT_CERT_SIGNATURE:
      begin
        lblErrorMessage.Caption :=
          'The certificate signature could not be decrypted. This means that the actual signature value could not be determined rather than it not matching the expected value, this is only meaningful for RSA keys. ';
      end;
    X509_V_ERR_UNABLE_TO_DECRYPT_CRL_SIGNATURE:
      begin
        lblErrorMessage.Caption :=
          'The Certificate Revocation List (CRL) signature could not be decrypted: this means that the actual signature value could not be determined rather than it not matching the expected value. Unused. ';
      end;
    X509_V_ERR_UNABLE_TO_DECODE_ISSUER_PUBLIC_KEY:
      begin
        lblErrorMessage.Caption :=
          'The public key in the certificate SubjectPublicKeyInfo could not be read. ';
      end;
    X509_V_ERR_CERT_SIGNATURE_FAILURE:
      begin
        lblErrorMessage.Caption :=
          'The signature of the certificate is invalid. ';
      end;
    X509_V_ERR_CRL_SIGNATURE_FAILURE:
      begin
        lblErrorMessage.Caption :=
          'The signature of the Certificate Revocation List (CRL) is invalid. '
      end;
    X509_V_ERR_CERT_NOT_YET_VALID:
      begin
        lblErrorMessage.Caption :=
          'The certificate is not yet valid: the notBefore date is after the current time. ';
      end;
    X509_V_ERR_CERT_HAS_EXPIRED:
      begin
        lblErrorMessage.Caption :=
          'The certificate has expired: that is the notAfter date is before the current time.'
      end;
    X509_V_ERR_CRL_NOT_YET_VALID:
      begin
        lblErrorMessage.Caption :=
          'The Certificate Revocation List (CRL) is not yet valid. ';
      end;
    X509_V_ERR_CRL_HAS_EXPIRED:
      begin
        lblErrorMessage.Caption :=
          'The Certificate Revocation List (CRL) has expired. ';
      end;
    X509_V_ERR_ERROR_IN_CERT_NOT_BEFORE_FIELD:
      begin
        lblErrorMessage.Caption :=
          'The certificate notBefore field contains an invalid time. ';
      end;
    X509_V_ERR_ERROR_IN_CERT_NOT_AFTER_FIELD:
      begin
        lblErrorMessage.Caption :=
          'The certificate notAfter field contains an invalid time.';
      end;
    X509_V_ERR_ERROR_IN_CRL_LAST_UPDATE_FIELD:
      begin
        lblErrorMessage.Caption :=
          'The Certificate Revocation List (CRL) lastUpdate field contains an invalid time.';
      end;
    X509_V_ERR_ERROR_IN_CRL_NEXT_UPDATE_FIELD:
      begin
        lblErrorMessage.Caption :=
          'The Certificate Revocation List (CRL) nextUpdate field contains an invalid time.';
      end;
    X509_V_ERR_OUT_OF_MEM:
      begin
        lblErrorMessage.Caption :=
          'An error occurred trying to allocate memory. This should never happen. ';
      end;

    X509_V_ERR_DEPTH_ZERO_SELF_SIGNED_CERT:
      begin
        lblErrorMessage.Caption :=
          'The passed certificate is self signed and the same certificate cannot be found in the list of trusted certificates. ';
      end;
    X509_V_ERR_SELF_SIGNED_CERT_IN_CHAIN:
      begin
        lblErrorMessage.Caption :=
          'The certificate chain could be built up using the untrusted certificates but the root could not be found locally. ';
      end;
    X509_V_ERR_UNABLE_TO_GET_ISSUER_CERT_LOCALLY:
      begin
        lblErrorMessage.Caption :=
          'The issuer certificate of a locally looked up certificate could not be found. This normally means the list of trusted certificates is not complete. ';
      end;
    X509_V_ERR_UNABLE_TO_VERIFY_LEAF_SIGNATURE:
      begin
        lblErrorMessage.Caption :=
          'No signatures could be verified because the chain contains only one certificate and it is not self signed. ';
      end;
    X509_V_ERR_CERT_CHAIN_TOO_LONG:
      begin
        lblErrorMessage.Caption :=
          'The certificate chain length is greater than the supplied maximum depth. Unused. ';
      end;
    X509_V_ERR_CERT_REVOKED:
      begin
        lblErrorMessage.Caption := 'The certificate has been revoked.';
      end;
    X509_V_ERR_INVALID_CA:
      begin
        lblErrorMessage.Caption :=
          'A Certificate Authority (CA) certificate is invalid. Either it is not a CA or its extensions are not consistent with the supplied purpose.';
      end;
    X509_V_ERR_PATH_LENGTH_EXCEEDED:
      begin
        lblErrorMessage.Caption :=
          'The basicConstraints pathlength parameter has been exceeded. ';
      end;
    X509_V_ERR_INVALID_PURPOSE:
      begin
        lblErrorMessage.Caption :=
          'The supplied certificate cannot be used for the specified purpose. ';
      end;
    X509_V_ERR_CERT_UNTRUSTED:
      begin
        lblErrorMessage.Caption :=
          'The root Certificate Authority (CA) is not marked as trusted for the specified purpose. ';
      end;
    X509_V_ERR_CERT_REJECTED:
      begin
        lblErrorMessage.Caption :=
          'The root Certificate Authority (CA) is marked to reject the specified purpose. ';
      end;
    X509_V_ERR_SUBJECT_ISSUER_MISMATCH:
      begin
        lblErrorMessage.Caption :=
          'The current candidate issuer certificate was rejected because its subject name did not match the issuer name of the current certificate. This is only set if issuer check debugging is enabled it is used for status notification and is not in itself an error. ';
      end;
    X509_V_ERR_AKID_SKID_MISMATCH:
      begin
        lblErrorMessage.Caption :=
          'The current candidate issuer certificate was rejected because its subject key identifier was present and did not match the authority key identifier current certificate. This is only set if issuer check debugging is enabled it is used for status notification and is not in itself an error. ';
      end;
    X509_V_ERR_AKID_ISSUER_SERIAL_MISMATCH:
      begin
        lblErrorMessage.Caption :=
          'The current candidate issuer certificate was rejected because its issuer name and serial number was present and did not match the authority key identifier of the current certificate. This is only set if issuer check debugging is enabled it is used for status notification and is not in itself an error. ';
      end;
    X509_V_ERR_KEYUSAGE_NO_CERTSIGN:
      begin
        lblErrorMessage.Caption :=
          'The current candidate issuer certificate was rejected because its keyUsage extension does not permit certificate signing. This is only set if issuer check debugging is enabled it is used for status notification and is not in itself an error. ';
      end;
    X509_V_ERR_INVALID_EXTENSION:
      begin
        lblErrorMessage.Caption :=
          'A certificate extension had an invalid value (for example an incorrect encoding) or some value inconsistent with other extensions. ';
      end;
    X509_V_ERR_INVALID_POLICY_EXTENSION:
      begin
        lblErrorMessage.Caption :=
          'A certificate policies extension had an invalid value (for example an incorrect encoding) or some value inconsistent with other extensions. This error only occurs if policy processing is enabled. ';
      end;
    X509_V_ERR_NO_EXPLICIT_POLICY:
      begin
        lblErrorMessage.Caption :=
          'The verification flags were set to require and explicit policy but none was present. ';
      end;
    X509_V_ERR_DIFFERENT_CRL_SCOPE:
      begin
        lblErrorMessage.Caption :=
          'The only Certificate Revocation Lists (CRLs) that could be found did not match the scope of the certificate.';
      end;
    X509_V_ERR_UNSUPPORTED_EXTENSION_FEATURE:
      begin
        lblErrorMessage.Caption :=
          'Some feature of a certificate extension is not supported. Unused. ';
      end;
    X509_V_ERR_PERMITTED_VIOLATION:
      begin
        lblErrorMessage.Caption :=
          'A name constraint violation occured in the permitted subtrees. ';
      end;
    X509_V_ERR_EXCLUDED_VIOLATION:
      begin
        lblErrorMessage.Caption :=
          'A name constraint violation occured in the excluded subtrees. ';
      end;
    X509_V_ERR_SUBTREE_MINMAX:
      begin
        lblErrorMessage.Caption :=
          'A certificate name constraints extension included a minimum or maximum field: this is not supported.';
      end;
    X509_V_ERR_UNSUPPORTED_CONSTRAINT_TYPE:
      begin
        lblErrorMessage.Caption :=
          'An unsupported name constraint type was encountered. OpenSSL currently only supports directory name, DNS name, email and URI types. ';
      end;
    X509_V_ERR_UNSUPPORTED_CONSTRAINT_SYNTAX:
      begin
        lblErrorMessage.Caption :=
          'The format of the name constraint is not recognised: for example an email address format of a form not mentioned in RFC3280 . This could be caused by a garbage extension or some new feature not currently supported.';
      end;
    X509_V_ERR_CRL_PATH_VALIDATION_ERROR:
      begin
        lblErrorMessage.Caption :=
          'An error occured when attempting to verify the Certificate Revocation List (CRL) path. This error can only happen if extended CRL checking is enabled.';
      end;
    X509_V_ERR_APPLICATION_VERIFICATION:
      begin
        lblErrorMessage.Caption :=
          'An application specific error. This will never be returned unless explicitly set by an application. ';
      end
  else
    lblErrorMessage.Caption := string(X509_verify_cert_error_string(FError));

  end;
end;

procedure TfrmCertViewer.SetX509(const Value: TIdX509);
var
  LStr: String;
  i: Integer;
  LProxyPathLen: TIdC_LONG;
begin
  FX509 := Value;
  Self.redtCertView.Lines.BeginUpdate;
  try
    redtCertView.Lines.Clear;
    if FX509.Errors.InvalidInconsistantValues then
    begin
      redtCertView.SelAttributes.Color := clRed;
      redtCertView.SelAttributes.Style := [fsBold];
      redtCertView.SelAttributes.BackColor := clWhite;
      redtCertView.Lines.Add
        ('Invalid or inconsistant Values - reject this certificated');
    end;
    if FX509.Errors.InvalidPolicy then
    begin
      redtCertView.SelAttributes.Color := clRed;
      redtCertView.SelAttributes.Style := [fsBold];
      redtCertView.SelAttributes.BackColor := clWhite;
      redtCertView.Lines.Add
        ('Invalid Certificate Policy - reject this certificated');
    end;
    if FX509.Errors.UnhandledCriticalExtention then
    begin
      redtCertView.SelAttributes.Color := clRed;
      redtCertView.SelAttributes.Style := [fsBold];
      redtCertView.SelAttributes.BackColor := clWhite;
      redtCertView.Lines.Add
        ('Unhandled Critical Extention - reject this certificated');
    end;
    if FX509.Warnings.IsSelfSigned then
    begin
      redtCertView.SelAttributes.Color := clRed;
      redtCertView.SelAttributes.BackColor := clWhite;
      redtCertView.Lines.Add('Certificate is Self-Signed');
    end
    else
    begin
      if FX509.Warnings.SubjectAndIssuerMatch then
      begin
        redtCertView.SelAttributes.Color := clRed;
        redtCertView.SelAttributes.BackColor := clWhite;
        redtCertView.Lines.Add
          ('Subject and Issuer match - implies self-signed');
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
    DumpX509Name(X509.Subject);
    redtCertView.Lines.Add('');

    if not FX509.Warnings.SubjectAndIssuerMatch then
    begin
      redtCertView.Lines.Add('Issuer');
      DumpX509Name(X509.Issuer);
    end;
    redtCertView.Lines.Add('');
    redtCertView.Lines.Add('Subject Public Key Info');
    redtCertView.Lines.Add(RightJustify('Alorigthm: ', TAB1) +
      X509.PublicKey.Algorithm);
    LStr := X509.PublicKey.Encoding;
    if LStr <> '' then
    begin
      redtCertView.Lines.Add(RightJustify('Encoding Size: ', TAB1) +
        IntToStr(X509.PublicKey.EncodingSize));
      redtCertView.Lines.Add(RightJustify('Encoding: ', TAB1) +
        X509.PublicKey.Encoding);
    end;
    redtCertView.Lines.Add(RightJustify('Bits: ', TAB1) +
      IntToStr(X509.PublicKey.Bits) + ' Bits');
    redtCertView.Lines.Add(RightJustify('Security Bits: ', TAB1) +
      IntToStr(X509.PublicKey.SecurityBits) + ' Bits');
    redtCertView.Lines.Add(RightJustify('Size: ', TAB1) +
      IntToStr(X509.PublicKey.Size));
    LStr := X509.PublicKey.Modulus;
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

    LStr := X509.SubjectKeyIdentifier;
    if LStr <> '' then
    begin
      redtCertView.Lines.Add(RightJustify('X509v3 Subject Key Identifier: ',
        TAB1) + LStr);
    end;
    LStr := X509.AuthorityKeyID.KeyID;
    if (LStr <> '') or (X509.AuthorityKeyID.Serial <> 0) then
    begin
      redtCertView.Lines.Add
        (RightJustify('X509v3 Authority Key Identifier: ', TAB1));
      if LStr <> '' then
      begin
        redtCertView.Lines.Add(RightJustify('Key ID: ', TAB2) + LStr);
      end;
      for i := 0 to X509.AuthorityKeyID.IssuerCount - 1 do
      begin
        redtCertView.Lines.Add(RightJustify('', TAB2) +
          X509.AuthorityKeyID.Issuer[i]);
      end;
      if X509.AuthorityKeyID.Serial > -1 then
      begin
        redtCertView.Lines.Add(RightJustify('Serial: ', TAB2) +
          IntToHex(X509.AuthorityKeyID.Serial));
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
        TAB2) + IntToStr(X509.AltSubjectNames.ItemsCount));
      for i := 0 to X509.AltSubjectNames.ItemsCount - 1 do
      begin
        redtCertView.Lines.Add(RightJustify('Subject ALternate Name ' +
          IntToStr(i) + ': ', TAB1) + X509.AltSubjectNames.Items[i]);
      end;
    end;
    DumpX509KeyUsage(X509);
    DumpX509ExtKeyUsage(X509);
    LProxyPathLen := X509.ProxyPathLen;
    if LProxyPathLen > -1 then
    begin
      redtCertView.Lines.Add('');
      redtCertView.Lines.Add(RightJustify('Proxy Path Length: ', TAB1) +
        IntToStr(LProxyPathLen));
    end;
    redtCertView.Lines.Add('');
    redtCertView.Lines.Add('Extensions: ');
    redtCertView.Lines.Add(RightJustify('Extension Count: ', TAB1) +
      IntToStr(X509.ExtensionCount));
    for i := 0 to X509.ExtensionCount - 1 do
    begin
      LStr := X509.ExtentionName[i];
      if X509.ExtentionCritical[i] then
      begin
        redtCertView.Lines.Add(RightJustify(LStr + ' (critical): ', TAB2) +
          X509.ExtensionValues[i]);
      end
      else
      begin
        redtCertView.Lines.Add(RightJustify(LStr + ': ', TAB2) +
          X509.ExtensionValues[i]);
      end;
    end;

  finally
    Self.redtCertView.Lines.EndUpdate;
  end;
  ScrollToTop(redtCertView);
end;

end.
