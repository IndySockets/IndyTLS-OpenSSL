(* This unit was generated from the source file cryptoerr.h2pas 
It should not be modified directly. All changes should be made to cryptoerr.h2pas
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


unit IdOpenSSLHeaders_cryptoerr;


interface

// Headers for OpenSSL 1.1.1
// cryptoerr.h


uses
  IdSSLOpenSSLAPI;

const
  (*
   * CRYPTO function codes.
   *)
  CRYPTO_F_CMAC_CTX_NEW = 120;
  CRYPTO_F_CRYPTO_DUP_EX_DATA = 110;
  CRYPTO_F_CRYPTO_FREE_EX_DATA = 111;
  CRYPTO_F_CRYPTO_GET_EX_NEW_INDEX = 100;
  CRYPTO_F_CRYPTO_MEMDUP = 115;
  CRYPTO_F_CRYPTO_NEW_EX_DATA = 112;
  CRYPTO_F_CRYPTO_OCB128_COPY_CTX = 121;
  CRYPTO_F_CRYPTO_OCB128_INIT = 122;
  CRYPTO_F_CRYPTO_SET_EX_DATA = 102;
  CRYPTO_F_FIPS_MODE_SET = 109;
  CRYPTO_F_GET_AND_LOCK = 113;
  CRYPTO_F_OPENSSL_ATEXIT = 114;
  CRYPTO_F_OPENSSL_BUF2HEXSTR = 117;
  CRYPTO_F_OPENSSL_FOPEN = 119;
  CRYPTO_F_OPENSSL_HEXSTR2BUF = 118;
  CRYPTO_F_OPENSSL_INIT_CRYPTO = 116;
  CRYPTO_F_OPENSSL_LH_NEW = 126;
  CRYPTO_F_OPENSSL_SK_DEEP_COPY = 127;
  CRYPTO_F_OPENSSL_SK_DUP = 128;
  CRYPTO_F_PKEY_HMAC_INIT = 123;
  CRYPTO_F_PKEY_POLY1305_INIT = 124;
  CRYPTO_F_PKEY_SIPHASH_INIT = 125;
  CRYPTO_F_SK_RESERVE = 129;

  (*
   * CRYPTO reason codes.
   *)
  CRYPTO_R_FIPS_MODE_NOT_SUPPORTED = 101;
  CRYPTO_R_ILLEGAL_HEX_DIGIT = 102;
  CRYPTO_R_ODD_NUMBER_OF_DIGITS = 103;

  
{ The EXTERNALSYM directive is ignored by FPC, however, it is used by Delphi as follows: 

The EXTERNALSYM directive prevents the specified Delphi symbol from appearing in header 
files generated for C++. }

{$EXTERNALSYM ERR_load_CRYPTO_strings}

{$IFDEF OPENSSL_STATIC_LINK_MODEL}
function ERR_load_CRYPTO_strings: TOpenSSL_C_INT; cdecl; external CLibCrypto;

{$ELSE}

{Declare external function initialisers - should not be called directly}

function Load_ERR_load_CRYPTO_strings: TOpenSSL_C_INT; cdecl;

var
  ERR_load_CRYPTO_strings: function : TOpenSSL_C_INT; cdecl = Load_ERR_load_CRYPTO_strings;
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
function Load_ERR_load_CRYPTO_strings: TOpenSSL_C_INT; cdecl;
begin
  ERR_load_CRYPTO_strings := LoadLibCryptoFunction('ERR_load_CRYPTO_strings');
  if not assigned(ERR_load_CRYPTO_strings) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('ERR_load_CRYPTO_strings');
  Result := ERR_load_CRYPTO_strings();
end;


procedure UnLoad;
begin
  ERR_load_CRYPTO_strings := Load_ERR_load_CRYPTO_strings;
end;
{$ENDIF}

initialization

{$IFNDEF OPENSSL_STATIC_LINK_MODEL}
Register_SSLUnloader(@Unload);
{$ENDIF}
finalization


end.
