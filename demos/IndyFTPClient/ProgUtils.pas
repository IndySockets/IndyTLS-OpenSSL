unit ProgUtils;

interface

uses Vcl.ComCtrls;

procedure ScrollToTop(ARichEdit: TRichEdit);
procedure ScrollToEnd(ARichEdit: TRichEdit);
function CertErrorToStr(ACertError: Integer): String;
function RightJustify(const AText: String; ALen: Integer): String;
function IsValidIP(const AAddr: String): Boolean;
function DlgCaptionToFormCaption(const ACaption : String) : String;

implementation

uses WinAPI.Messages, IdIPAddress, IdOpenSSLHeaders_x509,
IdOpenSSLHeaders_x509_vfy, System.SysUtils;

function DlgCaptionToFormCaption(const ACaption : String) : String;
var i : Integer;
begin
  Result := StringReplace(ACaption,'&','',[]);
  //remove trailing ...
  for i := Length(Result) downto 1 do
  begin
    if Result[i] = '.' then
    begin
      Delete(Result,i,1);
    end
    else
    begin
      break;
    end;
  end;
end;

function IsValidIP(const AAddr: String): Boolean;
var
  LIP: TIdIPAddress;
begin
  LIP := TIdIPAddress.MakeAddressObject(AAddr);
  Result := Assigned(LIP);
  if Result then
  begin
    FreeAndNil(LIP);
  end;
end;

function CertErrorToStr(ACertError: Integer): String;
begin
  { Thuis is stuff from: https://linux.die.net/man/3/x509_store_ctx_get_error
    I found that the error message from  X509_verify_cert_error_string does not
    always accurately describe the issue involved. }
  case ACertError of
    X509_V_ERR_UNABLE_TO_GET_ISSUER_CERT:
      begin
        Result := 'the issuer certificate could not be found: this occurs if the issuer certificate of an untrusted certificate cannot be found. ';
      end;
    X509_V_ERR_UNABLE_TO_GET_CRL:
      begin
        Result := 'the Certificate Revocation List (CRL) of a certificate could not be found. ';
      end;
    X509_V_ERR_UNABLE_TO_DECRYPT_CERT_SIGNATURE:
      begin
        Result := 'The certificate signature could not be decrypted. This means that the actual signature value could not be determined rather than it not matching the expected value, this is only meaningful for RSA keys. ';
      end;
    X509_V_ERR_UNABLE_TO_DECRYPT_CRL_SIGNATURE:
      begin
        Result := 'The Certificate Revocation List (CRL) signature could not be decrypted: this means that the actual signature value could not be determined rather than it not matching the expected value. Unused. ';
      end;
    X509_V_ERR_UNABLE_TO_DECODE_ISSUER_PUBLIC_KEY:
      begin
        Result := 'The public key in the certificate SubjectPublicKeyInfo could not be read. ';
      end;
    X509_V_ERR_CERT_SIGNATURE_FAILURE:
      begin
        Result := 'The signature of the certificate is invalid. ';
      end;
    X509_V_ERR_CRL_SIGNATURE_FAILURE:
      begin
        Result := 'The signature of the Certificate Revocation List (CRL) is invalid. '
      end;
    X509_V_ERR_CERT_NOT_YET_VALID:
      begin
        Result := 'The certificate is not yet valid: the notBefore date is after the current time. ';
      end;
    X509_V_ERR_CERT_HAS_EXPIRED:
      begin
        Result := 'The certificate has expired: that is the notAfter date is before the current time.'
      end;
    X509_V_ERR_CRL_NOT_YET_VALID:
      begin
        Result := 'The Certificate Revocation List (CRL) is not yet valid. ';
      end;
    X509_V_ERR_CRL_HAS_EXPIRED:
      begin
        Result := 'The Certificate Revocation List (CRL) has expired. ';
      end;
    X509_V_ERR_ERROR_IN_CERT_NOT_BEFORE_FIELD:
      begin
        Result := 'The certificate notBefore field contains an invalid time. ';
      end;
    X509_V_ERR_ERROR_IN_CERT_NOT_AFTER_FIELD:
      begin
        Result := 'The certificate notAfter field contains an invalid time.';
      end;
    X509_V_ERR_ERROR_IN_CRL_LAST_UPDATE_FIELD:
      begin
        Result := 'The Certificate Revocation List (CRL) lastUpdate field contains an invalid time.';
      end;
    X509_V_ERR_ERROR_IN_CRL_NEXT_UPDATE_FIELD:
      begin
        Result := 'The Certificate Revocation List (CRL) nextUpdate field contains an invalid time.';
      end;
    X509_V_ERR_OUT_OF_MEM:
      begin
        Result := 'An error occurred trying to allocate memory. This should never happen. ';
      end;

    X509_V_ERR_DEPTH_ZERO_SELF_SIGNED_CERT:
      begin
        Result := 'The passed certificate is self signed and the same certificate cannot be found in the list of trusted certificates. ';
      end;
    X509_V_ERR_SELF_SIGNED_CERT_IN_CHAIN:
      begin
        Result := 'The certificate chain could be built up using the untrusted certificates but the root could not be found locally. ';
      end;
    X509_V_ERR_UNABLE_TO_GET_ISSUER_CERT_LOCALLY:
      begin
        Result := 'The issuer certificate of a locally looked up certificate could not be found. This normally means the list of trusted certificates is not complete. ';
      end;
    X509_V_ERR_UNABLE_TO_VERIFY_LEAF_SIGNATURE:
      begin
        Result := 'No signatures could be verified because the chain contains only one certificate and it is not self signed. ';
      end;
    X509_V_ERR_CERT_CHAIN_TOO_LONG:
      begin
        Result := 'The certificate chain length is greater than the supplied maximum depth. Unused. ';
      end;
    X509_V_ERR_CERT_REVOKED:
      begin
        Result := 'The certificate has been revoked.';
      end;
    X509_V_ERR_INVALID_CA:
      begin
        Result := 'A Certificate Authority (CA) certificate is invalid. Either it is not a CA or its extensions are not consistent with the supplied purpose.';
      end;
    X509_V_ERR_PATH_LENGTH_EXCEEDED:
      begin
        Result := 'The basicConstraints pathlength parameter has been exceeded. ';
      end;
    X509_V_ERR_INVALID_PURPOSE:
      begin
        Result := 'The supplied certificate cannot be used for the specified purpose. ';
      end;
    X509_V_ERR_CERT_UNTRUSTED:
      begin
        Result := 'The root Certificate Authority (CA) is not marked as trusted for the specified purpose. ';
      end;
    X509_V_ERR_CERT_REJECTED:
      begin
        Result := 'The root Certificate Authority (CA) is marked to reject the specified purpose. ';
      end;
    X509_V_ERR_SUBJECT_ISSUER_MISMATCH:
      begin
        Result := 'The current candidate issuer certificate was rejected because its subject name did not match the issuer name of the current certificate. This is only set if issuer check debugging is enabled it is used for status notification and is not in itself an error. ';
      end;
    X509_V_ERR_AKID_SKID_MISMATCH:
      begin
        Result := 'The current candidate issuer certificate was rejected because its subject key identifier was present and did not match the authority key identifier current certificate. This is only set if issuer check debugging is enabled it is used for status notification and is not in itself an error. ';
      end;
    X509_V_ERR_AKID_ISSUER_SERIAL_MISMATCH:
      begin
        Result := 'The current candidate issuer certificate was rejected because its issuer name and serial number was present and did not match the authority key identifier of the current certificate. This is only set if issuer check debugging is enabled it is used for status notification and is not in itself an error. ';
      end;
    X509_V_ERR_KEYUSAGE_NO_CERTSIGN:
      begin
        Result := 'The current candidate issuer certificate was rejected because its keyUsage extension does not permit certificate signing. This is only set if issuer check debugging is enabled it is used for status notification and is not in itself an error. ';
      end;
    X509_V_ERR_INVALID_EXTENSION:
      begin
        Result := 'A certificate extension had an invalid value (for example an incorrect encoding) or some value inconsistent with other extensions. ';
      end;
    X509_V_ERR_INVALID_POLICY_EXTENSION:
      begin
        Result := 'A certificate policies extension had an invalid value (for example an incorrect encoding) or some value inconsistent with other extensions. This error only occurs if policy processing is enabled. ';
      end;
    X509_V_ERR_NO_EXPLICIT_POLICY:
      begin
        Result := 'The verification flags were set to require and explicit policy but none was present. ';
      end;
    X509_V_ERR_DIFFERENT_CRL_SCOPE:
      begin
        Result := 'The only Certificate Revocation Lists (CRLs) that could be found did not match the scope of the certificate.';
      end;
    X509_V_ERR_UNSUPPORTED_EXTENSION_FEATURE:
      begin
        Result := 'Some feature of a certificate extension is not supported. Unused. ';
      end;
    X509_V_ERR_PERMITTED_VIOLATION:
      begin
        Result := 'A name constraint violation occured in the permitted subtrees. ';
      end;
    X509_V_ERR_EXCLUDED_VIOLATION:
      begin
        Result := 'A name constraint violation occured in the excluded subtrees. ';
      end;
    X509_V_ERR_SUBTREE_MINMAX:
      begin
        Result := 'A certificate name constraints extension included a minimum or maximum field: this is not supported.';
      end;
    X509_V_ERR_UNSUPPORTED_CONSTRAINT_TYPE:
      begin
        Result := 'An unsupported name constraint type was encountered. OpenSSL currently only supports directory name, DNS name, email and URI types. ';
      end;
    X509_V_ERR_UNSUPPORTED_CONSTRAINT_SYNTAX:
      begin
        Result := 'The format of the name constraint is not recognised: for example an email address format of a form not mentioned in RFC3280 . This could be caused by a garbage extension or some new feature not currently supported.';
      end;
    X509_V_ERR_CRL_PATH_VALIDATION_ERROR:
      begin
        Result := 'An error occured when attempting to verify the Certificate Revocation List (CRL) path. This error can only happen if extended CRL checking is enabled.';
      end;
    X509_V_ERR_APPLICATION_VERIFICATION:
      begin
        Result := 'An application specific error. This will never be returned unless explicitly set by an application. ';
      end
  else
    Result := string(X509_verify_cert_error_string(ACertError));

  end;
end;

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

procedure ScrollToEnd(ARichEdit: TRichEdit);
var
  isSelectionHidden: Boolean;
begin
  with ARichEdit do
  begin
    SelStart := Perform(WinAPI.Messages.EM_LINEINDEX, Lines.Count, 0);
    // Set caret at end
    isSelectionHidden := HideSelection;
    try
      HideSelection := False;
      Perform(WinAPI.Messages.EM_SCROLLCARET, 0, 0); // Scroll to caret
    finally
      HideSelection := isSelectionHidden;
    end;
  end;
end;

procedure ScrollToTop(ARichEdit: TRichEdit);
var
  isSelectionHidden: Boolean;
begin
  with ARichEdit do
  begin
    SelStart := Perform(WinAPI.Messages.EM_LINEINDEX, 0, 0); // Set caret at end
    isSelectionHidden := HideSelection;
    try
      HideSelection := False;
      Perform(WinAPI.Messages.EM_SCROLLCARET, 0, 0); // Scroll to caret
    finally
      HideSelection := isSelectionHidden;
    end;
  end;
end;

end.
