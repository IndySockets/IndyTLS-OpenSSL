(* This unit was generated from the source file ocsperr.h2pas 
It should not be modified directly. All changes should be made to ocsperr.h2pas
and this file regenerated *)

{$i IdSSLOpenSSLDefines.inc}

{
    This file is part of the MWA Software Pascal API for OpenSSL .

    The MWA Software Pascal API for OpenSSL is free software: you can redistribute it
    and/or modify it under the terms of the Apache License Version 2.0 (the "License").

    You may not use this file except in compliance with the License.  You can obtain a copy
    in the file LICENSE.txt in the source distribution or at https://www.openssl.org/source/license.html.

    The MWA Software Pascal API for OpenSSL is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the License for more details.

    This file includes software copied from the Indy (Internet Direct) project, and which is offered
    under the dual-licensing agreement described on the Indy website. (https://www.indyproject.org/license/)
    }


unit IdOpenSSLHeaders_ocsperr;


interface

// Headers for OpenSSL 1.1.1
// ocsperr.h


uses
  IdSSLOpenSSLAPI;

const
  (*
   * OCSP function codes.
   *)
  OCSP_F_D2I_OCSP_NONCE = 102;
  OCSP_F_OCSP_BASIC_ADD1_STATUS = 103;
  OCSP_F_OCSP_BASIC_SIGN = 104;
  OCSP_F_OCSP_BASIC_SIGN_CTX = 119;
  OCSP_F_OCSP_BASIC_VERIFY = 105;
  OCSP_F_OCSP_CERT_ID_NEW = 101;
  OCSP_F_OCSP_CHECK_DELEGATED = 106;
  OCSP_F_OCSP_CHECK_IDS = 107;
  OCSP_F_OCSP_CHECK_ISSUER = 108;
  OCSP_F_OCSP_CHECK_VALIDITY = 115;
  OCSP_F_OCSP_MATCH_ISSUERID = 109;
  OCSP_F_OCSP_PARSE_URL = 114;
  OCSP_F_OCSP_REQUEST_SIGN = 110;
  OCSP_F_OCSP_REQUEST_VERIFY = 116;
  OCSP_F_OCSP_RESPONSE_GET1_BASIC = 111;
  OCSP_F_PARSE_HTTP_LINE1 = 118;

  (*
   * OCSP reason codes.
   *)
  OCSP_R_CERTIFICATE_VERIFY_ERROR = 101;
  OCSP_R_DIGEST_ERR = 102;
  OCSP_R_ERROR_IN_NEXTUPDATE_FIELD = 122;
  OCSP_R_ERROR_IN_THISUPDATE_FIELD = 123;
  OCSP_R_ERROR_PARSING_URL = 121;
  OCSP_R_MISSING_OCSPSIGNING_USAGE = 103;
  OCSP_R_NEXTUPDATE_BEFORE_THISUPDATE = 124;
  OCSP_R_NOT_BASIC_RESPONSE = 104;
  OCSP_R_NO_CERTIFICATES_IN_CHAIN = 105;
  OCSP_R_NO_RESPONSE_DATA = 108;
  OCSP_R_NO_REVOKED_TIME = 109;
  OCSP_R_NO_SIGNER_KEY = 130;
  OCSP_R_PRIVATE_KEY_DOES_NOT_MATCH_CERTIFICATE = 110;
  OCSP_R_REQUEST_NOT_SIGNED = 128;
  OCSP_R_RESPONSE_CONTAINS_NO_REVOCATION_DATA = 111;
  OCSP_R_ROOT_CA_NOT_TRUSTED = 112;
  OCSP_R_SERVER_RESPONSE_ERROR = 114;
  OCSP_R_SERVER_RESPONSE_PARSE_ERROR = 115;
  OCSP_R_SIGNATURE_FAILURE = 117;
  OCSP_R_SIGNER_CERTIFICATE_NOT_FOUND = 118;
  OCSP_R_STATUS_EXPIRED = 125;
  OCSP_R_STATUS_NOT_YET_VALID = 126;
  OCSP_R_STATUS_TOO_OLD = 127;
  OCSP_R_UNKNOWN_MESSAGE_DIGEST = 119;
  OCSP_R_UNKNOWN_NID = 120;
  OCSP_R_UNSUPPORTED_REQUESTORNAME_TYPE = 129;

  
{ The EXTERNALSYM directive is ignored by FPC, however, it is used by Delphi as follows: 

The EXTERNALSYM directive prevents the specified Delphi symbol from appearing in header 
files generated for C++. }

{$EXTERNALSYM ERR_load_OCSP_strings}

{$IFDEF OPENSSL_STATIC_LINK_MODEL}
function ERR_load_OCSP_strings: TOpenSSL_C_INT; cdecl; external CLibCrypto;

{$ELSE}

{Declare external function initialisers - should not be called directly}

function Load_ERR_load_OCSP_strings: TOpenSSL_C_INT; cdecl;

var
  ERR_load_OCSP_strings: function : TOpenSSL_C_INT; cdecl = Load_ERR_load_OCSP_strings;
{$ENDIF}

implementation



uses Classes,
     IdSSLOpenSSLExceptionHandlers,
     IdSSLOpenSSLResourceStrings;

{$IFNDEF OPENSSL_STATIC_LINK_MODEL}
{$IFNDEF OPENSSL_NO_LEGACY_SUPPORT}
{$ENDIF} { End of OPENSSL_NO_LEGACY_SUPPORT}
{$ENDIF}
{$IFNDEF OPENSSL_STATIC_LINK_MODEL}
{$IFNDEF OPENSSL_NO_LEGACY_SUPPORT}
{$ENDIF} { End of OPENSSL_NO_LEGACY_SUPPORT}
function Load_ERR_load_OCSP_strings: TOpenSSL_C_INT; cdecl;
begin
  ERR_load_OCSP_strings := LoadLibCryptoFunction('ERR_load_OCSP_strings');
  if not assigned(ERR_load_OCSP_strings) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('ERR_load_OCSP_strings');
  Result := ERR_load_OCSP_strings();
end;


procedure UnLoad;
begin
  ERR_load_OCSP_strings := Load_ERR_load_OCSP_strings;
end;
{$ENDIF}

initialization

{$IFNDEF OPENSSL_STATIC_LINK_MODEL}
Register_SSLUnloader(@Unload);
{$ENDIF}
finalization


end.
