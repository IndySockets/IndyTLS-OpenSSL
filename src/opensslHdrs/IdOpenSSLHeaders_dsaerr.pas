(* This unit was generated from the source file dsaerr.h2pas 
It should not be modified directly. All changes should be made to dsaerr.h2pas
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


unit IdOpenSSLHeaders_dsaerr;


interface

// Headers for OpenSSL 1.1.1
// dsaerr.h


uses
  IdSSLOpenSSLAPI;

const
  ///*
  // * DSA function codes.
  // */
  DSA_F_DSAPARAMS_PRINT = 100;
  DSA_F_DSAPARAMS_PRINT_FP = 101;
  DSA_F_DSA_BUILTIN_PARAMGEN = 125;
  DSA_F_DSA_BUILTIN_PARAMGEN2 = 126;
  DSA_F_DSA_DO_SIGN = 112;
  DSA_F_DSA_DO_VERIFY = 113;
  DSA_F_DSA_METH_DUP = 127;
  DSA_F_DSA_METH_NEW = 128;
  DSA_F_DSA_METH_SET1_NAME = 129;
  DSA_F_DSA_NEW_METHOD = 103;
  DSA_F_DSA_PARAM_DECODE = 119;
  DSA_F_DSA_PRINT_FP = 105;
  DSA_F_DSA_PRIV_DECODE = 115;
  DSA_F_DSA_PRIV_ENCODE = 116;
  DSA_F_DSA_PUB_DECODE = 117;
  DSA_F_DSA_PUB_ENCODE = 118;
  DSA_F_DSA_SIGN = 106;
  DSA_F_DSA_SIGN_SETUP = 107;
  DSA_F_DSA_SIG_NEW = 102;
  DSA_F_OLD_DSA_PRIV_DECODE = 122;
  DSA_F_PKEY_DSA_CTRL = 120;
  DSA_F_PKEY_DSA_CTRL_STR = 104;
  DSA_F_PKEY_DSA_KEYGEN = 121;

  ///*
  // * DSA reason codes.
  // */
  DSA_R_BAD_Q_VALUE = 102;
  DSA_R_BN_DECODE_ERROR = 108;
  DSA_R_BN_ERROR = 109;
  DSA_R_DECODE_ERROR = 104;
  DSA_R_INVALID_DIGEST_TYPE = 106;
  DSA_R_INVALID_PARAMETERS = 112;
  DSA_R_MISSING_PARAMETERS = 101;
  DSA_R_MISSING_PRIVATE_KEY = 111;
  DSA_R_MODULUS_TOO_LARGE = 103;
  DSA_R_NO_PARAMETERS_SET = 107;
  DSA_R_PARAMETER_ENCODING_ERROR = 105;
  DSA_R_Q_NOT_PRIME = 113;
  DSA_R_SEED_LEN_SMALL = 110;

  
{ The EXTERNALSYM directive is ignored by FPC, however, it is used by Delphi as follows: 

The EXTERNALSYM directive prevents the specified Delphi symbol from appearing in header 
files generated for C++. }

{$EXTERNALSYM ERR_load_DSA_strings}

{$IFDEF OPENSSL_STATIC_LINK_MODEL}
function ERR_load_DSA_strings: TOpenSSL_C_INT; cdecl; external CLibCrypto;

{$ELSE}

{Declare external function initialisers - should not be called directly}

function Load_ERR_load_DSA_strings: TOpenSSL_C_INT; cdecl;

var
  ERR_load_DSA_strings: function : TOpenSSL_C_INT; cdecl = Load_ERR_load_DSA_strings;
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
function Load_ERR_load_DSA_strings: TOpenSSL_C_INT; cdecl;
begin
  ERR_load_DSA_strings := LoadLibCryptoFunction('ERR_load_DSA_strings');
  if not assigned(ERR_load_DSA_strings) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('ERR_load_DSA_strings');
  Result := ERR_load_DSA_strings();
end;


procedure UnLoad;
begin
  ERR_load_DSA_strings := Load_ERR_load_DSA_strings;
end;
{$ENDIF}

initialization

{$IFNDEF OPENSSL_STATIC_LINK_MODEL}
Register_SSLUnloader(@Unload);
{$ENDIF}
finalization


end.
