(* This unit was generated from the source file kdferr.h2pas 
It should not be modified directly. All changes should be made to kdferr.h2pas
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


unit IdOpenSSLHeaders_kdferr;


interface

// Headers for OpenSSL 1.1.1
// kdferr.h


uses
  IdSSLOpenSSLAPI;

const
  (*
   * KDF function codes.
   *)
  KDF_F_PKEY_HKDF_CTRL_STR = 103;
  KDF_F_PKEY_HKDF_DERIVE = 102;
  KDF_F_PKEY_HKDF_INIT = 108;
  KDF_F_PKEY_SCRYPT_CTRL_STR = 104;
  KDF_F_PKEY_SCRYPT_CTRL_UINT64 = 105;
  KDF_F_PKEY_SCRYPT_DERIVE = 109;
  KDF_F_PKEY_SCRYPT_INIT = 106;
  KDF_F_PKEY_SCRYPT_SET_MEMBUF = 107;
  KDF_F_PKEY_TLS1_PRF_CTRL_STR = 100;
  KDF_F_PKEY_TLS1_PRF_DERIVE = 101;
  KDF_F_PKEY_TLS1_PRF_INIT = 110;
  KDF_F_TLS1_PRF_ALG = 111;

  (*
   * KDF reason codes.
   *)
  KDF_R_INVALID_DIGEST = 100;
  KDF_R_MISSING_ITERATION_COUNT = 109;
  KDF_R_MISSING_KEY = 104;
  KDF_R_MISSING_MESSAGE_DIGEST = 105;
  KDF_R_MISSING_PARAMETER = 101;
  KDF_R_MISSING_PASS = 110;
  KDF_R_MISSING_SALT = 111;
  KDF_R_MISSING_SECRET = 107;
  KDF_R_MISSING_SEED = 106;
  KDF_R_UNKNOWN_PARAMETER_TYPE = 103;
  KDF_R_VALUE_ERROR = 108;
  KDF_R_VALUE_MISSING = 102;

  
{ The EXTERNALSYM directive is ignored by FPC, however, it is used by Delphi as follows: 

The EXTERNALSYM directive prevents the specified Delphi symbol from appearing in header 
files generated for C++. }

{$EXTERNALSYM ERR_load_KDF_strings}

{$IFDEF OPENSSL_STATIC_LINK_MODEL}
function ERR_load_KDF_strings: TOpenSSL_C_INT; cdecl; external CLibCrypto;

{$ELSE}

{Declare external function initialisers - should not be called directly}

function Load_ERR_load_KDF_strings: TOpenSSL_C_INT; cdecl;

var
  ERR_load_KDF_strings: function : TOpenSSL_C_INT; cdecl = Load_ERR_load_KDF_strings;
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
function Load_ERR_load_KDF_strings: TOpenSSL_C_INT; cdecl;
begin
  ERR_load_KDF_strings := LoadLibCryptoFunction('ERR_load_KDF_strings');
  if not assigned(ERR_load_KDF_strings) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('ERR_load_KDF_strings');
  Result := ERR_load_KDF_strings();
end;


procedure UnLoad;
begin
  ERR_load_KDF_strings := Load_ERR_load_KDF_strings;
end;
{$ENDIF}

initialization

{$IFNDEF OPENSSL_STATIC_LINK_MODEL}
Register_SSLUnloader(@Unload);
{$ENDIF}
finalization


end.
