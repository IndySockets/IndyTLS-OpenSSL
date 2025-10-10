(* This unit was generated from the source file uierr.h2pas 
It should not be modified directly. All changes should be made to uierr.h2pas
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


unit IdOpenSSLHeaders_uierr;


interface

// Headers for OpenSSL 1.1.1
// uierr.h


uses
  IdSSLOpenSSLAPI;

const
  (*
   * UI function codes.
   *)
  UI_F_CLOSE_CONSOLE = 115;
  UI_F_ECHO_CONSOLE = 116;
  UI_F_GENERAL_ALLOCATE_BOOLEAN = 108;
  UI_F_GENERAL_ALLOCATE_PROMPT = 109;
  UI_F_NOECHO_CONSOLE = 117;
  UI_F_OPEN_CONSOLE = 114;
  UI_F_UI_CONSTRUCT_PROMPT = 121;
  UI_F_UI_CREATE_METHOD = 112;
  UI_F_UI_CTRL = 111;
  UI_F_UI_DUP_ERROR_STRING = 101;
  UI_F_UI_DUP_INFO_STRING = 102;
  UI_F_UI_DUP_INPUT_BOOLEAN = 110;
  UI_F_UI_DUP_INPUT_STRING = 103;
  UI_F_UI_DUP_USER_DATA = 118;
  UI_F_UI_DUP_VERIFY_STRING = 106;
  UI_F_UI_GET0_RESULT = 107;
  UI_F_UI_GET_RESULT_LENGTH = 119;
  UI_F_UI_NEW_METHOD = 104;
  UI_F_UI_PROCESS = 113;
  UI_F_UI_SET_RESULT = 105;
  UI_F_UI_SET_RESULT_EX = 120;

  (*
   * UI reason codes.
   *)
  UI_R_COMMON_OK_AND_CANCEL_CHARACTERS = 104;
  UI_R_INDEX_TOO_LARGE = 102;
  UI_R_INDEX_TOO_SMALL = 103;
  UI_R_NO_RESULT_BUFFER = 105;
  UI_R_PROCESSING_ERROR = 107;
  UI_R_RESULT_TOO_LARGE = 100;
  UI_R_RESULT_TOO_SMALL = 101;
  UI_R_SYSASSIGN_ERROR = 109;
  UI_R_SYSDASSGN_ERROR = 110;
  UI_R_SYSQIOW_ERROR = 111;
  UI_R_UNKNOWN_CONTROL_COMMAND = 106;
  UI_R_UNKNOWN_TTYGET_ERRNO_VALUE = 108;
  UI_R_USER_DATA_DUPLICATION_UNSUPPORTED = 112;

  
{ The EXTERNALSYM directive is ignored by FPC, however, it is used by Delphi as follows: 

The EXTERNALSYM directive prevents the specified Delphi symbol from appearing in header 
files generated for C++. }

{$EXTERNALSYM ERR_load_UI_strings}

{$IFDEF OPENSSL_STATIC_LINK_MODEL}
function ERR_load_UI_strings: TOpenSSL_C_INT; cdecl; external CLibCrypto;

{$ELSE}

{Declare external function initialisers - should not be called directly}

function Load_ERR_load_UI_strings: TOpenSSL_C_INT; cdecl;

var
  ERR_load_UI_strings: function : TOpenSSL_C_INT; cdecl = Load_ERR_load_UI_strings;
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
function Load_ERR_load_UI_strings: TOpenSSL_C_INT; cdecl;
begin
  ERR_load_UI_strings := LoadLibCryptoFunction('ERR_load_UI_strings');
  if not assigned(ERR_load_UI_strings) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('ERR_load_UI_strings');
  Result := ERR_load_UI_strings();
end;


procedure UnLoad;
begin
  ERR_load_UI_strings := Load_ERR_load_UI_strings;
end;
{$ENDIF}

initialization

{$IFNDEF OPENSSL_STATIC_LINK_MODEL}
Register_SSLUnloader(@Unload);
{$ENDIF}
finalization


end.
