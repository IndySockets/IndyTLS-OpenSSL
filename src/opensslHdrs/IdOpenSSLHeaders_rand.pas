(* This unit was generated from the source file rand.h2pas 
It should not be modified directly. All changes should be made to rand.h2pas
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


unit IdOpenSSLHeaders_rand;


interface

// Headers for OpenSSL 1.1.1
// rand.h


uses
  IdSSLOpenSSLAPI,
  IdOpenSSLHeaders_ossl_typ;

type
  rand_meth_st_seed = function (const buf: Pointer; num: TOpenSSL_C_INT): TOpenSSL_C_INT; cdecl;
  rand_meth_st_bytes = function (buf: PByte; num: TOpenSSL_C_INT): TOpenSSL_C_INT; cdecl;
  rand_meth_st_cleanup = procedure; cdecl;
  rand_meth_st_add = function (const buf: Pointer; num: TOpenSSL_C_INT; randomness: TOpenSSL_C_DOUBLE): TOpenSSL_C_INT; cdecl;
  rand_meth_st_pseudorand = function (buf: PByte; num: TOpenSSL_C_INT): TOpenSSL_C_INT; cdecl;
  rand_meth_st_status = function: TOpenSSL_C_INT; cdecl;

  rand_meth_st = record
    seed: rand_meth_st_seed;
    bytes: rand_meth_st_bytes;
    cleanup: rand_meth_st_cleanup;
    add: rand_meth_st_add;
    pseudorand: rand_meth_st_pseudorand;
    status: rand_meth_st_status;
  end;

  
{ The EXTERNALSYM directive is ignored by FPC, however, it is used by Delphi as follows: 

The EXTERNALSYM directive prevents the specified Delphi symbol from appearing in header 
files generated for C++. }

{$EXTERNALSYM RAND_set_rand_method}
{$EXTERNALSYM RAND_get_rand_method}
{$EXTERNALSYM RAND_set_rand_engine}
{$EXTERNALSYM RAND_OpenSSL}
{$EXTERNALSYM RAND_bytes}
{$EXTERNALSYM RAND_priv_bytes}
{$EXTERNALSYM RAND_seed}
{$EXTERNALSYM RAND_keep_random_devices_open}
{$EXTERNALSYM RAND_add}
{$EXTERNALSYM RAND_load_file}
{$EXTERNALSYM RAND_write_file}
{$EXTERNALSYM RAND_status}
{$EXTERNALSYM RAND_query_egd_bytes}
{$EXTERNALSYM RAND_egd}
{$EXTERNALSYM RAND_egd_bytes}
{$EXTERNALSYM RAND_poll}

{$IFDEF OPENSSL_STATIC_LINK_MODEL}
function RAND_set_rand_method(const meth: PRAND_METHOD): TOpenSSL_C_INT; cdecl; external CLibCrypto;
function RAND_get_rand_method: PRAND_METHOD; cdecl; external CLibCrypto;
function RAND_set_rand_engine(engine: PENGINE): TOpenSSL_C_INT; cdecl; external CLibCrypto;
function RAND_OpenSSL: PRAND_METHOD; cdecl; external CLibCrypto;
function RAND_bytes(buf: PByte; num: TOpenSSL_C_INT): TOpenSSL_C_INT; cdecl; external CLibCrypto;
function RAND_priv_bytes(buf: PByte; num: TOpenSSL_C_INT): TOpenSSL_C_INT; cdecl; external CLibCrypto;
procedure RAND_seed(const buf: Pointer; num: TOpenSSL_C_INT); cdecl; external CLibCrypto;
procedure RAND_keep_random_devices_open(keep: TOpenSSL_C_INT); cdecl; external CLibCrypto;
procedure RAND_add(const buf: Pointer; num: TOpenSSL_C_INT; randomness: TOpenSSL_C_DOUBLE); cdecl; external CLibCrypto;
function RAND_load_file(const file_: PAnsiChar; max_bytes: TOpenSSL_C_LONG): TOpenSSL_C_INT; cdecl; external CLibCrypto;
function RAND_write_file(const file_: PAnsiChar): TOpenSSL_C_INT; cdecl; external CLibCrypto;
function RAND_status: TOpenSSL_C_INT; cdecl; external CLibCrypto;
function RAND_query_egd_bytes(const path: PAnsiChar; buf: PByte; bytes: TOpenSSL_C_INT): TOpenSSL_C_INT; cdecl; external CLibCrypto;
function RAND_egd(const path: PAnsiChar): TOpenSSL_C_INT; cdecl; external CLibCrypto;
function RAND_egd_bytes(const path: PAnsiChar; bytes: TOpenSSL_C_INT): TOpenSSL_C_INT; cdecl; external CLibCrypto;
function RAND_poll: TOpenSSL_C_INT; cdecl; external CLibCrypto;

{$ELSE}

{Declare external function initialisers - should not be called directly}

function Load_RAND_set_rand_method(const meth: PRAND_METHOD): TOpenSSL_C_INT; cdecl;
function Load_RAND_get_rand_method: PRAND_METHOD; cdecl;
function Load_RAND_set_rand_engine(engine: PENGINE): TOpenSSL_C_INT; cdecl;
function Load_RAND_OpenSSL: PRAND_METHOD; cdecl;
function Load_RAND_bytes(buf: PByte; num: TOpenSSL_C_INT): TOpenSSL_C_INT; cdecl;
function Load_RAND_priv_bytes(buf: PByte; num: TOpenSSL_C_INT): TOpenSSL_C_INT; cdecl;
procedure Load_RAND_seed(const buf: Pointer; num: TOpenSSL_C_INT); cdecl;
procedure Load_RAND_keep_random_devices_open(keep: TOpenSSL_C_INT); cdecl;
procedure Load_RAND_add(const buf: Pointer; num: TOpenSSL_C_INT; randomness: TOpenSSL_C_DOUBLE); cdecl;
function Load_RAND_load_file(const file_: PAnsiChar; max_bytes: TOpenSSL_C_LONG): TOpenSSL_C_INT; cdecl;
function Load_RAND_write_file(const file_: PAnsiChar): TOpenSSL_C_INT; cdecl;
function Load_RAND_status: TOpenSSL_C_INT; cdecl;
function Load_RAND_query_egd_bytes(const path: PAnsiChar; buf: PByte; bytes: TOpenSSL_C_INT): TOpenSSL_C_INT; cdecl;
function Load_RAND_egd(const path: PAnsiChar): TOpenSSL_C_INT; cdecl;
function Load_RAND_egd_bytes(const path: PAnsiChar; bytes: TOpenSSL_C_INT): TOpenSSL_C_INT; cdecl;
function Load_RAND_poll: TOpenSSL_C_INT; cdecl;

var
  RAND_set_rand_method: function (const meth: PRAND_METHOD): TOpenSSL_C_INT; cdecl = Load_RAND_set_rand_method;
  RAND_get_rand_method: function : PRAND_METHOD; cdecl = Load_RAND_get_rand_method;
  RAND_set_rand_engine: function (engine: PENGINE): TOpenSSL_C_INT; cdecl = Load_RAND_set_rand_engine;
  RAND_OpenSSL: function : PRAND_METHOD; cdecl = Load_RAND_OpenSSL;
  RAND_bytes: function (buf: PByte; num: TOpenSSL_C_INT): TOpenSSL_C_INT; cdecl = Load_RAND_bytes;
  RAND_priv_bytes: function (buf: PByte; num: TOpenSSL_C_INT): TOpenSSL_C_INT; cdecl = Load_RAND_priv_bytes;
  RAND_seed: procedure (const buf: Pointer; num: TOpenSSL_C_INT); cdecl = Load_RAND_seed;
  RAND_keep_random_devices_open: procedure (keep: TOpenSSL_C_INT); cdecl = Load_RAND_keep_random_devices_open;
  RAND_add: procedure (const buf: Pointer; num: TOpenSSL_C_INT; randomness: TOpenSSL_C_DOUBLE); cdecl = Load_RAND_add;
  RAND_load_file: function (const file_: PAnsiChar; max_bytes: TOpenSSL_C_LONG): TOpenSSL_C_INT; cdecl = Load_RAND_load_file;
  RAND_write_file: function (const file_: PAnsiChar): TOpenSSL_C_INT; cdecl = Load_RAND_write_file;
  RAND_status: function : TOpenSSL_C_INT; cdecl = Load_RAND_status;
  RAND_query_egd_bytes: function (const path: PAnsiChar; buf: PByte; bytes: TOpenSSL_C_INT): TOpenSSL_C_INT; cdecl = Load_RAND_query_egd_bytes;
  RAND_egd: function (const path: PAnsiChar): TOpenSSL_C_INT; cdecl = Load_RAND_egd;
  RAND_egd_bytes: function (const path: PAnsiChar; bytes: TOpenSSL_C_INT): TOpenSSL_C_INT; cdecl = Load_RAND_egd_bytes;
  RAND_poll: function : TOpenSSL_C_INT; cdecl = Load_RAND_poll;
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
function Load_RAND_set_rand_method(const meth: PRAND_METHOD): TOpenSSL_C_INT; cdecl;
begin
  RAND_set_rand_method := LoadLibCryptoFunction('RAND_set_rand_method');
  if not assigned(RAND_set_rand_method) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('RAND_set_rand_method');
  Result := RAND_set_rand_method(meth);
end;

function Load_RAND_get_rand_method: PRAND_METHOD; cdecl;
begin
  RAND_get_rand_method := LoadLibCryptoFunction('RAND_get_rand_method');
  if not assigned(RAND_get_rand_method) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('RAND_get_rand_method');
  Result := RAND_get_rand_method();
end;

function Load_RAND_set_rand_engine(engine: PENGINE): TOpenSSL_C_INT; cdecl;
begin
  RAND_set_rand_engine := LoadLibCryptoFunction('RAND_set_rand_engine');
  if not assigned(RAND_set_rand_engine) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('RAND_set_rand_engine');
  Result := RAND_set_rand_engine(engine);
end;

function Load_RAND_OpenSSL: PRAND_METHOD; cdecl;
begin
  RAND_OpenSSL := LoadLibCryptoFunction('RAND_OpenSSL');
  if not assigned(RAND_OpenSSL) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('RAND_OpenSSL');
  Result := RAND_OpenSSL();
end;

function Load_RAND_bytes(buf: PByte; num: TOpenSSL_C_INT): TOpenSSL_C_INT; cdecl;
begin
  RAND_bytes := LoadLibCryptoFunction('RAND_bytes');
  if not assigned(RAND_bytes) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('RAND_bytes');
  Result := RAND_bytes(buf,num);
end;

function Load_RAND_priv_bytes(buf: PByte; num: TOpenSSL_C_INT): TOpenSSL_C_INT; cdecl;
begin
  RAND_priv_bytes := LoadLibCryptoFunction('RAND_priv_bytes');
  if not assigned(RAND_priv_bytes) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('RAND_priv_bytes');
  Result := RAND_priv_bytes(buf,num);
end;

procedure Load_RAND_seed(const buf: Pointer; num: TOpenSSL_C_INT); cdecl;
begin
  RAND_seed := LoadLibCryptoFunction('RAND_seed');
  if not assigned(RAND_seed) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('RAND_seed');
  RAND_seed(buf,num);
end;

procedure Load_RAND_keep_random_devices_open(keep: TOpenSSL_C_INT); cdecl;
begin
  RAND_keep_random_devices_open := LoadLibCryptoFunction('RAND_keep_random_devices_open');
  if not assigned(RAND_keep_random_devices_open) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('RAND_keep_random_devices_open');
  RAND_keep_random_devices_open(keep);
end;

procedure Load_RAND_add(const buf: Pointer; num: TOpenSSL_C_INT; randomness: TOpenSSL_C_DOUBLE); cdecl;
begin
  RAND_add := LoadLibCryptoFunction('RAND_add');
  if not assigned(RAND_add) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('RAND_add');
  RAND_add(buf,num,randomness);
end;

function Load_RAND_load_file(const file_: PAnsiChar; max_bytes: TOpenSSL_C_LONG): TOpenSSL_C_INT; cdecl;
begin
  RAND_load_file := LoadLibCryptoFunction('RAND_load_file');
  if not assigned(RAND_load_file) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('RAND_load_file');
  Result := RAND_load_file(file_,max_bytes);
end;

function Load_RAND_write_file(const file_: PAnsiChar): TOpenSSL_C_INT; cdecl;
begin
  RAND_write_file := LoadLibCryptoFunction('RAND_write_file');
  if not assigned(RAND_write_file) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('RAND_write_file');
  Result := RAND_write_file(file_);
end;

function Load_RAND_status: TOpenSSL_C_INT; cdecl;
begin
  RAND_status := LoadLibCryptoFunction('RAND_status');
  if not assigned(RAND_status) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('RAND_status');
  Result := RAND_status();
end;

function Load_RAND_query_egd_bytes(const path: PAnsiChar; buf: PByte; bytes: TOpenSSL_C_INT): TOpenSSL_C_INT; cdecl;
begin
  RAND_query_egd_bytes := LoadLibCryptoFunction('RAND_query_egd_bytes');
  if not assigned(RAND_query_egd_bytes) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('RAND_query_egd_bytes');
  Result := RAND_query_egd_bytes(path,buf,bytes);
end;

function Load_RAND_egd(const path: PAnsiChar): TOpenSSL_C_INT; cdecl;
begin
  RAND_egd := LoadLibCryptoFunction('RAND_egd');
  if not assigned(RAND_egd) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('RAND_egd');
  Result := RAND_egd(path);
end;

function Load_RAND_egd_bytes(const path: PAnsiChar; bytes: TOpenSSL_C_INT): TOpenSSL_C_INT; cdecl;
begin
  RAND_egd_bytes := LoadLibCryptoFunction('RAND_egd_bytes');
  if not assigned(RAND_egd_bytes) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('RAND_egd_bytes');
  Result := RAND_egd_bytes(path,bytes);
end;

function Load_RAND_poll: TOpenSSL_C_INT; cdecl;
begin
  RAND_poll := LoadLibCryptoFunction('RAND_poll');
  if not assigned(RAND_poll) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('RAND_poll');
  Result := RAND_poll();
end;


procedure UnLoad;
begin
  RAND_set_rand_method := Load_RAND_set_rand_method;
  RAND_get_rand_method := Load_RAND_get_rand_method;
  RAND_set_rand_engine := Load_RAND_set_rand_engine;
  RAND_OpenSSL := Load_RAND_OpenSSL;
  RAND_bytes := Load_RAND_bytes;
  RAND_priv_bytes := Load_RAND_priv_bytes;
  RAND_seed := Load_RAND_seed;
  RAND_keep_random_devices_open := Load_RAND_keep_random_devices_open;
  RAND_add := Load_RAND_add;
  RAND_load_file := Load_RAND_load_file;
  RAND_write_file := Load_RAND_write_file;
  RAND_status := Load_RAND_status;
  RAND_query_egd_bytes := Load_RAND_query_egd_bytes;
  RAND_egd := Load_RAND_egd;
  RAND_egd_bytes := Load_RAND_egd_bytes;
  RAND_poll := Load_RAND_poll;
end;
{$ENDIF}

initialization

{$IFNDEF OPENSSL_STATIC_LINK_MODEL}
Register_SSLUnloader(@Unload);
{$ENDIF}
finalization


end.
