(* This unit was generated from the source file conf_api.h2pas 
It should not be modified directly. All changes should be made to conf_api.h2pas
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


unit IdOpenSSLHeaders_conf_api;


interface

// Headers for OpenSSL 1.1.1
// conf_api.h


uses
  IdSSLOpenSSLAPI,
  IdOpenSSLHeaders_conf;

  //* Up until OpenSSL 0.9.5a, this was new_section */
  
{ The EXTERNALSYM directive is ignored by FPC, however, it is used by Delphi as follows: 

The EXTERNALSYM directive prevents the specified Delphi symbol from appearing in header 
files generated for C++. }

{$EXTERNALSYM _CONF_new_section}
{$EXTERNALSYM _CONF_get_section}
{$EXTERNALSYM _CONF_add_string}
{$EXTERNALSYM _CONF_get_string}
{$EXTERNALSYM _CONF_get_number}
{$EXTERNALSYM _CONF_new_data}
{$EXTERNALSYM _CONF_free_data}

{$IFDEF OPENSSL_STATIC_LINK_MODEL}
function _CONF_new_section(conf: PCONF; const section: PAnsiChar): PCONF_VALUE; cdecl; external CLibCrypto;
function _CONF_get_section(const conf: PCONF; const section: PAnsiChar): PCONF_VALUE; cdecl; external CLibCrypto;
function _CONF_add_string(conf: PCONF; section: PCONF_VALUE; value: PCONF_VALUE): TOpenSSL_C_INT; cdecl; external CLibCrypto;
function _CONF_get_string(const conf: PCONF; const section: PAnsiChar; const name: PAnsiChar): PAnsiChar; cdecl; external CLibCrypto;
function _CONF_get_number(const conf: PCONF; const section: PAnsiChar; const name: PAnsiChar): TOpenSSL_C_LONG; cdecl; external CLibCrypto;
function _CONF_new_data(conf: PCONF): TOpenSSL_C_INT; cdecl; external CLibCrypto;
procedure _CONF_free_data(conf: PCONF); cdecl; external CLibCrypto;

{$ELSE}

{Declare external function initialisers - should not be called directly}

function Load__CONF_new_section(conf: PCONF; const section: PAnsiChar): PCONF_VALUE; cdecl;
function Load__CONF_get_section(const conf: PCONF; const section: PAnsiChar): PCONF_VALUE; cdecl;
function Load__CONF_add_string(conf: PCONF; section: PCONF_VALUE; value: PCONF_VALUE): TOpenSSL_C_INT; cdecl;
function Load__CONF_get_string(const conf: PCONF; const section: PAnsiChar; const name: PAnsiChar): PAnsiChar; cdecl;
function Load__CONF_get_number(const conf: PCONF; const section: PAnsiChar; const name: PAnsiChar): TOpenSSL_C_LONG; cdecl;
function Load__CONF_new_data(conf: PCONF): TOpenSSL_C_INT; cdecl;
procedure Load__CONF_free_data(conf: PCONF); cdecl;

var
  _CONF_new_section: function (conf: PCONF; const section: PAnsiChar): PCONF_VALUE; cdecl = Load__CONF_new_section;
  _CONF_get_section: function (const conf: PCONF; const section: PAnsiChar): PCONF_VALUE; cdecl = Load__CONF_get_section;
  _CONF_add_string: function (conf: PCONF; section: PCONF_VALUE; value: PCONF_VALUE): TOpenSSL_C_INT; cdecl = Load__CONF_add_string;
  _CONF_get_string: function (const conf: PCONF; const section: PAnsiChar; const name: PAnsiChar): PAnsiChar; cdecl = Load__CONF_get_string;
  _CONF_get_number: function (const conf: PCONF; const section: PAnsiChar; const name: PAnsiChar): TOpenSSL_C_LONG; cdecl = Load__CONF_get_number;
  _CONF_new_data: function (conf: PCONF): TOpenSSL_C_INT; cdecl = Load__CONF_new_data;
  _CONF_free_data: procedure (conf: PCONF); cdecl = Load__CONF_free_data;
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
function Load__CONF_new_section(conf: PCONF; const section: PAnsiChar): PCONF_VALUE; cdecl;
begin
  _CONF_new_section := LoadLibCryptoFunction('_CONF_new_section');
  if not assigned(_CONF_new_section) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('_CONF_new_section');
  Result := _CONF_new_section(conf,section);
end;

function Load__CONF_get_section(const conf: PCONF; const section: PAnsiChar): PCONF_VALUE; cdecl;
begin
  _CONF_get_section := LoadLibCryptoFunction('_CONF_get_section');
  if not assigned(_CONF_get_section) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('_CONF_get_section');
  Result := _CONF_get_section(conf,section);
end;

function Load__CONF_add_string(conf: PCONF; section: PCONF_VALUE; value: PCONF_VALUE): TOpenSSL_C_INT; cdecl;
begin
  _CONF_add_string := LoadLibCryptoFunction('_CONF_add_string');
  if not assigned(_CONF_add_string) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('_CONF_add_string');
  Result := _CONF_add_string(conf,section,value);
end;

function Load__CONF_get_string(const conf: PCONF; const section: PAnsiChar; const name: PAnsiChar): PAnsiChar; cdecl;
begin
  _CONF_get_string := LoadLibCryptoFunction('_CONF_get_string');
  if not assigned(_CONF_get_string) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('_CONF_get_string');
  Result := _CONF_get_string(conf,section,name);
end;

function Load__CONF_get_number(const conf: PCONF; const section: PAnsiChar; const name: PAnsiChar): TOpenSSL_C_LONG; cdecl;
begin
  _CONF_get_number := LoadLibCryptoFunction('_CONF_get_number');
  if not assigned(_CONF_get_number) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('_CONF_get_number');
  Result := _CONF_get_number(conf,section,name);
end;

function Load__CONF_new_data(conf: PCONF): TOpenSSL_C_INT; cdecl;
begin
  _CONF_new_data := LoadLibCryptoFunction('_CONF_new_data');
  if not assigned(_CONF_new_data) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('_CONF_new_data');
  Result := _CONF_new_data(conf);
end;

procedure Load__CONF_free_data(conf: PCONF); cdecl;
begin
  _CONF_free_data := LoadLibCryptoFunction('_CONF_free_data');
  if not assigned(_CONF_free_data) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('_CONF_free_data');
  _CONF_free_data(conf);
end;


procedure UnLoad;
begin
  _CONF_new_section := Load__CONF_new_section;
  _CONF_get_section := Load__CONF_get_section;
  _CONF_add_string := Load__CONF_add_string;
  _CONF_get_string := Load__CONF_get_string;
  _CONF_get_number := Load__CONF_get_number;
  _CONF_new_data := Load__CONF_new_data;
  _CONF_free_data := Load__CONF_free_data;
end;
{$ENDIF}

initialization

{$IFNDEF OPENSSL_STATIC_LINK_MODEL}
Register_SSLUnloader(@Unload);
{$ENDIF}
finalization


end.
