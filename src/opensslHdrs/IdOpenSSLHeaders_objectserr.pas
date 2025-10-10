(* This unit was generated from the source file objectserr.h2pas 
It should not be modified directly. All changes should be made to objectserr.h2pas
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


unit IdOpenSSLHeaders_objectserr;


interface

// Headers for OpenSSL 1.1.1
// objectserr.h


uses
  IdSSLOpenSSLAPI;

const
  (*
   * OBJ function codes.
   *)
  OBJ_F_OBJ_ADD_OBJECT =  105;
  OBJ_F_OBJ_ADD_SIGID =  107;
  OBJ_F_OBJ_CREATE =   100;
  OBJ_F_OBJ_DUP =   101;
  OBJ_F_OBJ_NAME_NEW_INDEX =  106;
  OBJ_F_OBJ_NID2LN =   102;
  OBJ_F_OBJ_NID2OBJ =   103;
  OBJ_F_OBJ_NID2SN =   104;
  OBJ_F_OBJ_TXT2OBJ =   108;

  (*
   * OBJ reason codes.
   *)
  OBJ_R_OID_EXISTS = 102;
  OBJ_R_UNKNOWN_NID = 101;

  
{ The EXTERNALSYM directive is ignored by FPC, however, it is used by Delphi as follows: 

The EXTERNALSYM directive prevents the specified Delphi symbol from appearing in header 
files generated for C++. }

{$EXTERNALSYM ERR_load_OBJ_strings}

{$IFDEF OPENSSL_STATIC_LINK_MODEL}
function ERR_load_OBJ_strings: TOpenSSL_C_INT; cdecl; external CLibCrypto;

{$ELSE}

{Declare external function initialisers - should not be called directly}

function Load_ERR_load_OBJ_strings: TOpenSSL_C_INT; cdecl;

var
  ERR_load_OBJ_strings: function : TOpenSSL_C_INT; cdecl = Load_ERR_load_OBJ_strings;
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
function Load_ERR_load_OBJ_strings: TOpenSSL_C_INT; cdecl;
begin
  ERR_load_OBJ_strings := LoadLibCryptoFunction('ERR_load_OBJ_strings');
  if not assigned(ERR_load_OBJ_strings) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('ERR_load_OBJ_strings');
  Result := ERR_load_OBJ_strings();
end;


procedure UnLoad;
begin
  ERR_load_OBJ_strings := Load_ERR_load_OBJ_strings;
end;
{$ENDIF}

initialization

{$IFNDEF OPENSSL_STATIC_LINK_MODEL}
Register_SSLUnloader(@Unload);
{$ENDIF}
finalization


end.
