(* This unit was generated from the source file engineerr.h2pas 
It should not be modified directly. All changes should be made to engineerr.h2pas
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


unit IdOpenSSLHeaders_engineerr;


interface

// Headers for OpenSSL 1.1.1
// engineerr.h


uses
  IdSSLOpenSSLAPI;

const
  (*
   * ENGINE function codes.
   *)
  ENGINE_F_DIGEST_UPDATE = 198;
  ENGINE_F_DYNAMIC_CTRL = 180;
  ENGINE_F_DYNAMIC_GET_DATA_CTX = 181;
  ENGINE_F_DYNAMIC_LOAD = 182;
  ENGINE_F_DYNAMIC_SET_DATA_CTX = 183;
  ENGINE_F_ENGINE_ADD = 105;
  ENGINE_F_ENGINE_BY_ID = 106;
  ENGINE_F_ENGINE_CMD_IS_EXECUTABLE = 170;
  ENGINE_F_ENGINE_CTRL = 142;
  ENGINE_F_ENGINE_CTRL_CMD = 178;
  ENGINE_F_ENGINE_CTRL_CMD_STRING = 171;
  ENGINE_F_ENGINE_FINISH = 107;
  ENGINE_F_ENGINE_GET_CIPHER = 185;
  ENGINE_F_ENGINE_GET_DIGEST = 186;
  ENGINE_F_ENGINE_GET_FIRST = 195;
  ENGINE_F_ENGINE_GET_LAST = 196;
  ENGINE_F_ENGINE_GET_NEXT = 115;
  ENGINE_F_ENGINE_GET_PKEY_ASN1_METH = 193;
  ENGINE_F_ENGINE_GET_PKEY_METH = 192;
  ENGINE_F_ENGINE_GET_PREV = 116;
  ENGINE_F_ENGINE_INIT = 119;
  ENGINE_F_ENGINE_LIST_ADD = 120;
  ENGINE_F_ENGINE_LIST_REMOVE = 121;
  ENGINE_F_ENGINE_LOAD_PRIVATE_KEY = 150;
  ENGINE_F_ENGINE_LOAD_PUBLIC_KEY = 151;
  ENGINE_F_ENGINE_LOAD_SSL_CLIENT_CERT = 194;
  ENGINE_F_ENGINE_NEW = 122;
  ENGINE_F_ENGINE_PKEY_ASN1_FIND_STR = 197;
  ENGINE_F_ENGINE_REMOVE = 123;
  ENGINE_F_ENGINE_SET_DEFAULT_STRING = 189;
  ENGINE_F_ENGINE_SET_ID = 129;
  ENGINE_F_ENGINE_SET_NAME = 130;
  ENGINE_F_ENGINE_TABLE_REGISTER = 184;
  ENGINE_F_ENGINE_UNLOCKED_FINISH = 191;
  ENGINE_F_ENGINE_UP_REF = 190;
  ENGINE_F_INT_CLEANUP_ITEM = 199;
  ENGINE_F_INT_CTRL_HELPER = 172;
  ENGINE_F_INT_ENGINE_CONFIGURE = 188;
  ENGINE_F_INT_ENGINE_MODULE_INIT = 187;
  ENGINE_F_OSSL_HMAC_INIT = 200;

  (*
   * ENGINE reason codes.
   *)
  ENGINE_R_ALREADY_LOADED = 100;
  ENGINE_R_ARGUMENT_IS_NOT_A_NUMBER = 133;
  ENGINE_R_CMD_NOT_EXECUTABLE = 134;
  ENGINE_R_COMMAND_TAKES_INPUT = 135;
  ENGINE_R_COMMAND_TAKES_NO_INPUT = 136;
  ENGINE_R_CONFLICTING_ENGINE_ID = 103;
  ENGINE_R_CTRL_COMMAND_NOT_IMPLEMENTED = 119;
  ENGINE_R_DSO_FAILURE = 104;
  ENGINE_R_DSO_NOT_FOUND = 132;
  ENGINE_R_ENGINES_SECTION_ERROR = 148;
  ENGINE_R_ENGINE_CONFIGURATION_ERROR = 102;
  ENGINE_R_ENGINE_IS_NOT_IN_LIST = 105;
  ENGINE_R_ENGINE_SECTION_ERROR = 149;
  ENGINE_R_FAILED_LOADING_PRIVATE_KEY = 128;
  ENGINE_R_FAILED_LOADING_PUBLIC_KEY = 129;
  ENGINE_R_FINISH_FAILED = 106;
  ENGINE_R_ID_OR_NAME_MISSING = 108;
  ENGINE_R_INIT_FAILED = 109;
  ENGINE_R_INTERNAL_LIST_ERROR = 110;
  ENGINE_R_INVALID_ARGUMENT = 143;
  ENGINE_R_INVALID_CMD_NAME = 137;
  ENGINE_R_INVALID_CMD_NUMBER = 138;
  ENGINE_R_INVALID_INIT_VALUE = 151;
  ENGINE_R_INVALID_STRING = 150;
  ENGINE_R_NOT_INITIALISED = 117;
  ENGINE_R_NOT_LOADED = 112;
  ENGINE_R_NO_CONTROL_FUNCTION = 120;
  ENGINE_R_NO_INDEX = 144;
  ENGINE_R_NO_LOAD_FUNCTION = 125;
  ENGINE_R_NO_REFERENCE = 130;
  ENGINE_R_NO_SUCH_ENGINE = 116;
  ENGINE_R_UNIMPLEMENTED_CIPHER = 146;
  ENGINE_R_UNIMPLEMENTED_DIGEST = 147;
  ENGINE_R_UNIMPLEMENTED_PUBLIC_KEY_METHOD = 101;
  ENGINE_R_VERSION_INCOMPATIBILITY = 145;

  
{ The EXTERNALSYM directive is ignored by FPC, however, it is used by Delphi as follows: 

The EXTERNALSYM directive prevents the specified Delphi symbol from appearing in header 
files generated for C++. }

{$EXTERNALSYM ERR_load_ENGINE_strings}

{$IFDEF OPENSSL_STATIC_LINK_MODEL}
function ERR_load_ENGINE_strings: TOpenSSL_C_INT; cdecl; external CLibCrypto;

{$ELSE}

{Declare external function initialisers - should not be called directly}

function Load_ERR_load_ENGINE_strings: TOpenSSL_C_INT; cdecl;

var
  ERR_load_ENGINE_strings: function : TOpenSSL_C_INT; cdecl = Load_ERR_load_ENGINE_strings;
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
function Load_ERR_load_ENGINE_strings: TOpenSSL_C_INT; cdecl;
begin
  ERR_load_ENGINE_strings := LoadLibCryptoFunction('ERR_load_ENGINE_strings');
  if not assigned(ERR_load_ENGINE_strings) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('ERR_load_ENGINE_strings');
  Result := ERR_load_ENGINE_strings();
end;


procedure UnLoad;
begin
  ERR_load_ENGINE_strings := Load_ERR_load_ENGINE_strings;
end;
{$ENDIF}

initialization

{$IFNDEF OPENSSL_STATIC_LINK_MODEL}
Register_SSLUnloader(@Unload);
{$ENDIF}
finalization


end.
