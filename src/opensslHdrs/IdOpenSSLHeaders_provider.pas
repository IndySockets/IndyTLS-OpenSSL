(* This unit was generated from the source file provider.h2pas 
It should not be modified directly. All changes should be made to provider.h2pas
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


unit IdOpenSSLHeaders_provider;


interface

{
  Automatically converted by H2Pas 1.0.0 from provider.h
  The following command line parameters were used:
    provider.h
}

uses
  IdSSLOpenSSLAPI,
  IdOpenSSLHeaders_ossl_typ,
  IdOpenSSLHeaders_core;

{$IFDEF FPC}
{$PACKRECORDS C}
{$ENDIF}

type
    POSSL_ALGORITHM  = ^OSSL_ALGORITHM;
    POSSL_CALLBACK  = ^OSSL_CALLBACK;
    POSSL_DISPATCH  = ^OSSL_DISPATCH;
    POSSL_PARAM  = ^OSSL_PARAM;
    POSSL_PROVIDER  = pointer;
    POSSL_provider_init_fn  = ^OSSL_provider_init_fn;

    TDo_AllCallback = function (provider:POSSL_PROVIDER; cbdata:pointer):TOpenSSL_C_LONG; cdecl;

  {
   * Copyright 2019-2023 The OpenSSL Project Authors. All Rights Reserved.
   *
   * Licensed under the Apache License 2.0 (the "License").  You may not use
   * this file except in compliance with the License.  You can obtain a copy
   * in the file LICENSE in the source distribution or at
   * https://www.openssl.org/source/license.html
    }
  { Set and Get a library context search path  }
    
{ The EXTERNALSYM directive is ignored by FPC, however, it is used by Delphi as follows: 

The EXTERNALSYM directive prevents the specified Delphi symbol from appearing in header 
files generated for C++. }

{$EXTERNALSYM OSSL_PROVIDER_set_default_search_path}
{$EXTERNALSYM OSSL_PROVIDER_load}
{$EXTERNALSYM OSSL_PROVIDER_try_load}
{$EXTERNALSYM OSSL_PROVIDER_unload}
{$EXTERNALSYM OSSL_PROVIDER_available}
{$EXTERNALSYM OSSL_PROVIDER_do_all}
{$EXTERNALSYM OSSL_PROVIDER_gettable_params}
{$EXTERNALSYM OSSL_PROVIDER_get_params}
{$EXTERNALSYM OSSL_PROVIDER_self_test}
{$EXTERNALSYM OSSL_PROVIDER_get_capabilities}
{$EXTERNALSYM OSSL_PROVIDER_query_operation}
{$EXTERNALSYM OSSL_PROVIDER_unquery_operation}
{$EXTERNALSYM OSSL_PROVIDER_get0_provider_ctx}
{$EXTERNALSYM OSSL_PROVIDER_get0_dispatch}
{$EXTERNALSYM OSSL_PROVIDER_add_builtin}
{$EXTERNALSYM OSSL_PROVIDER_get0_name}
{$IFDEF OPENSSL_3_2_ORLATER}
{$EXTERNALSYM OSSL_PROVIDER_get0_default_search_path}
{$EXTERNALSYM OSSL_PROVIDER_try_load_ex}
{$EXTERNALSYM OSSL_PROVIDER_load_ex}
{$ENDIF}

{$IFDEF OPENSSL_STATIC_LINK_MODEL}
function OSSL_PROVIDER_set_default_search_path(ctx: POSSL_LIB_CTX; path: PAnsiChar): TOpenSSL_C_INT; cdecl; external CLibCrypto;
function OSSL_PROVIDER_load(_para1:POSSL_LIB_CTX; name: PAnsiChar): POSSL_PROVIDER; cdecl; external CLibCrypto;
function OSSL_PROVIDER_try_load(_para1:POSSL_LIB_CTX; name: PAnsiChar; retain_fallbacks: TOpenSSL_C_LONG): POSSL_PROVIDER; cdecl; external CLibCrypto;
function OSSL_PROVIDER_unload(prov:POSSL_PROVIDER): TOpenSSL_C_LONG; cdecl; external CLibCrypto;
function OSSL_PROVIDER_available(_para1:POSSL_LIB_CTX; name:PAnsiChar): TOpenSSL_C_LONG; cdecl; external CLibCrypto;
function OSSL_PROVIDER_do_all(ctx:POSSL_LIB_CTX; cb:TDo_AllCallback; cbdata:pointer): TOpenSSL_C_LONG; cdecl; external CLibCrypto;
function OSSL_PROVIDER_gettable_params(prov:POSSL_PROVIDER): POSSL_PARAM; cdecl; external CLibCrypto;
function OSSL_PROVIDER_get_params(prov:POSSL_PROVIDER; params:POSSL_PARAM): TOpenSSL_C_LONG; cdecl; external CLibCrypto;
function OSSL_PROVIDER_self_test(prov:POSSL_PROVIDER): TOpenSSL_C_LONG; cdecl; external CLibCrypto;
function OSSL_PROVIDER_get_capabilities(prov:POSSL_PROVIDER; capability:PAnsiChar; cb:POSSL_CALLBACK; arg:pointer): TOpenSSL_C_LONG; cdecl; external CLibCrypto;
function OSSL_PROVIDER_query_operation(prov:POSSL_PROVIDER; operation_id:TOpenSSL_C_LONG; no_cache:POpenSSL_C_LONG): POSSL_ALGORITHM; cdecl; external CLibCrypto;
procedure OSSL_PROVIDER_unquery_operation(prov:POSSL_PROVIDER; operation_id:TOpenSSL_C_LONG; algs:POSSL_ALGORITHM); cdecl; external CLibCrypto;
function OSSL_PROVIDER_get0_provider_ctx(prov:POSSL_PROVIDER): pointer; cdecl; external CLibCrypto;
function OSSL_PROVIDER_get0_dispatch(prov:POSSL_PROVIDER): POSSL_DISPATCH; cdecl; external CLibCrypto;
function OSSL_PROVIDER_add_builtin(_para1:POSSL_LIB_CTX; name:PAnsiChar; init_fn:POSSL_provider_init_fn): TOpenSSL_C_LONG; cdecl; external CLibCrypto;
function OSSL_PROVIDER_get0_name(prov:POSSL_PROVIDER): PAnsiChar; cdecl; external CLibCrypto;
{$IFDEF OPENSSL_3_2_ORLATER}
{$IFDEF OPENSSL_3_2_ORLATER}
    
function OSSL_PROVIDER_get0_default_search_path(libctx: POSSL_LIB_CTX): PAnsiChar; cdecl; {introduced 3.2.0 } external CLibCrypto;
function OSSL_PROVIDER_try_load_ex(_para1:POSSL_LIB_CTX; name: PAnsiChar; params:POSSL_PARAM; retain_fallbacks:TOpenSSL_C_LONG): POSSL_PROVIDER; cdecl; {introduced 3.2.0 } external CLibCrypto;
function OSSL_PROVIDER_load_ex(_para1:POSSL_LIB_CTX; name: PAnsiChar; params: POSSL_PARAM): POSSL_PROVIDER; cdecl; {introduced 3.2.0 } external CLibCrypto;
{$ENDIF}
{$ENDIF}



{$ELSE}

{Declare external function initialisers - should not be called directly}

function Load_OSSL_PROVIDER_set_default_search_path(ctx: POSSL_LIB_CTX; path: PAnsiChar): TOpenSSL_C_INT; cdecl;
function Load_OSSL_PROVIDER_load(_para1:POSSL_LIB_CTX; name: PAnsiChar): POSSL_PROVIDER; cdecl;
function Load_OSSL_PROVIDER_try_load(_para1:POSSL_LIB_CTX; name: PAnsiChar; retain_fallbacks: TOpenSSL_C_LONG): POSSL_PROVIDER; cdecl;
function Load_OSSL_PROVIDER_unload(prov:POSSL_PROVIDER): TOpenSSL_C_LONG; cdecl;
function Load_OSSL_PROVIDER_available(_para1:POSSL_LIB_CTX; name:PAnsiChar): TOpenSSL_C_LONG; cdecl;
function Load_OSSL_PROVIDER_do_all(ctx:POSSL_LIB_CTX; cb:TDo_AllCallback; cbdata:pointer): TOpenSSL_C_LONG; cdecl;
function Load_OSSL_PROVIDER_gettable_params(prov:POSSL_PROVIDER): POSSL_PARAM; cdecl;
function Load_OSSL_PROVIDER_get_params(prov:POSSL_PROVIDER; params:POSSL_PARAM): TOpenSSL_C_LONG; cdecl;
function Load_OSSL_PROVIDER_self_test(prov:POSSL_PROVIDER): TOpenSSL_C_LONG; cdecl;
function Load_OSSL_PROVIDER_get_capabilities(prov:POSSL_PROVIDER; capability:PAnsiChar; cb:POSSL_CALLBACK; arg:pointer): TOpenSSL_C_LONG; cdecl;
function Load_OSSL_PROVIDER_query_operation(prov:POSSL_PROVIDER; operation_id:TOpenSSL_C_LONG; no_cache:POpenSSL_C_LONG): POSSL_ALGORITHM; cdecl;
procedure Load_OSSL_PROVIDER_unquery_operation(prov:POSSL_PROVIDER; operation_id:TOpenSSL_C_LONG; algs:POSSL_ALGORITHM); cdecl;
function Load_OSSL_PROVIDER_get0_provider_ctx(prov:POSSL_PROVIDER): pointer; cdecl;
function Load_OSSL_PROVIDER_get0_dispatch(prov:POSSL_PROVIDER): POSSL_DISPATCH; cdecl;
function Load_OSSL_PROVIDER_add_builtin(_para1:POSSL_LIB_CTX; name:PAnsiChar; init_fn:POSSL_provider_init_fn): TOpenSSL_C_LONG; cdecl;
function Load_OSSL_PROVIDER_get0_name(prov:POSSL_PROVIDER): PAnsiChar; cdecl;
{$IFDEF OPENSSL_3_2_ORLATER}
function Load_OSSL_PROVIDER_get0_default_search_path(libctx: POSSL_LIB_CTX): PAnsiChar; cdecl;
function Load_OSSL_PROVIDER_try_load_ex(_para1:POSSL_LIB_CTX; name: PAnsiChar; params:POSSL_PARAM; retain_fallbacks:TOpenSSL_C_LONG): POSSL_PROVIDER; cdecl;
function Load_OSSL_PROVIDER_load_ex(_para1:POSSL_LIB_CTX; name: PAnsiChar; params: POSSL_PARAM): POSSL_PROVIDER; cdecl;
{$ENDIF}

var
  OSSL_PROVIDER_set_default_search_path: function (ctx: POSSL_LIB_CTX; path: PAnsiChar): TOpenSSL_C_INT; cdecl = Load_OSSL_PROVIDER_set_default_search_path;
  OSSL_PROVIDER_load: function (_para1:POSSL_LIB_CTX; name: PAnsiChar): POSSL_PROVIDER; cdecl = Load_OSSL_PROVIDER_load;
  OSSL_PROVIDER_try_load: function (_para1:POSSL_LIB_CTX; name: PAnsiChar; retain_fallbacks: TOpenSSL_C_LONG): POSSL_PROVIDER; cdecl = Load_OSSL_PROVIDER_try_load;
  OSSL_PROVIDER_unload: function (prov:POSSL_PROVIDER): TOpenSSL_C_LONG; cdecl = Load_OSSL_PROVIDER_unload;
  OSSL_PROVIDER_available: function (_para1:POSSL_LIB_CTX; name:PAnsiChar): TOpenSSL_C_LONG; cdecl = Load_OSSL_PROVIDER_available;
  OSSL_PROVIDER_do_all: function (ctx:POSSL_LIB_CTX; cb:TDo_AllCallback; cbdata:pointer): TOpenSSL_C_LONG; cdecl = Load_OSSL_PROVIDER_do_all;
  OSSL_PROVIDER_gettable_params: function (prov:POSSL_PROVIDER): POSSL_PARAM; cdecl = Load_OSSL_PROVIDER_gettable_params;
  OSSL_PROVIDER_get_params: function (prov:POSSL_PROVIDER; params:POSSL_PARAM): TOpenSSL_C_LONG; cdecl = Load_OSSL_PROVIDER_get_params;
  OSSL_PROVIDER_self_test: function (prov:POSSL_PROVIDER): TOpenSSL_C_LONG; cdecl = Load_OSSL_PROVIDER_self_test;
  OSSL_PROVIDER_get_capabilities: function (prov:POSSL_PROVIDER; capability:PAnsiChar; cb:POSSL_CALLBACK; arg:pointer): TOpenSSL_C_LONG; cdecl = Load_OSSL_PROVIDER_get_capabilities;
  OSSL_PROVIDER_query_operation: function (prov:POSSL_PROVIDER; operation_id:TOpenSSL_C_LONG; no_cache:POpenSSL_C_LONG): POSSL_ALGORITHM; cdecl = Load_OSSL_PROVIDER_query_operation;
  OSSL_PROVIDER_unquery_operation: procedure (prov:POSSL_PROVIDER; operation_id:TOpenSSL_C_LONG; algs:POSSL_ALGORITHM); cdecl = Load_OSSL_PROVIDER_unquery_operation;
  OSSL_PROVIDER_get0_provider_ctx: function (prov:POSSL_PROVIDER): pointer; cdecl = Load_OSSL_PROVIDER_get0_provider_ctx;
  OSSL_PROVIDER_get0_dispatch: function (prov:POSSL_PROVIDER): POSSL_DISPATCH; cdecl = Load_OSSL_PROVIDER_get0_dispatch;
  OSSL_PROVIDER_add_builtin: function (_para1:POSSL_LIB_CTX; name:PAnsiChar; init_fn:POSSL_provider_init_fn): TOpenSSL_C_LONG; cdecl = Load_OSSL_PROVIDER_add_builtin;
  OSSL_PROVIDER_get0_name: function (prov:POSSL_PROVIDER): PAnsiChar; cdecl = Load_OSSL_PROVIDER_get0_name;
{$IFDEF OPENSSL_3_2_ORLATER}
{$IFDEF OPENSSL_3_2_ORLATER}
    
  OSSL_PROVIDER_get0_default_search_path: function (libctx: POSSL_LIB_CTX): PAnsiChar; cdecl = Load_OSSL_PROVIDER_get0_default_search_path; {introduced 3.2.0 }
  OSSL_PROVIDER_try_load_ex: function (_para1:POSSL_LIB_CTX; name: PAnsiChar; params:POSSL_PARAM; retain_fallbacks:TOpenSSL_C_LONG): POSSL_PROVIDER; cdecl = Load_OSSL_PROVIDER_try_load_ex; {introduced 3.2.0 }
  OSSL_PROVIDER_load_ex: function (_para1:POSSL_LIB_CTX; name: PAnsiChar; params: POSSL_PARAM): POSSL_PROVIDER; cdecl = Load_OSSL_PROVIDER_load_ex; {introduced 3.2.0 }
{$ENDIF}
{$ENDIF}


{$ENDIF}
const
  OSSL_PROVIDER_set_default_search_path_introduced = ((((((byte(3) shl 8) or byte(0)) shl 8) or byte(0)) shl 8) or byte(0)) shl 4; {introduced 3.0.0}
  OSSL_PROVIDER_load_introduced = ((((((byte(3) shl 8) or byte(0)) shl 8) or byte(0)) shl 8) or byte(0)) shl 4; {introduced 3.0.0}
  OSSL_PROVIDER_try_load_introduced = ((((((byte(3) shl 8) or byte(0)) shl 8) or byte(0)) shl 8) or byte(0)) shl 4; {introduced 3.0.0}
  OSSL_PROVIDER_unload_introduced = ((((((byte(3) shl 8) or byte(0)) shl 8) or byte(0)) shl 8) or byte(0)) shl 4; {introduced 3.0.0}
  OSSL_PROVIDER_available_introduced = ((((((byte(3) shl 8) or byte(0)) shl 8) or byte(0)) shl 8) or byte(0)) shl 4; {introduced 3.0.0}
  OSSL_PROVIDER_do_all_introduced = ((((((byte(3) shl 8) or byte(0)) shl 8) or byte(0)) shl 8) or byte(0)) shl 4; {introduced 3.0.0}
  OSSL_PROVIDER_gettable_params_introduced = ((((((byte(3) shl 8) or byte(0)) shl 8) or byte(0)) shl 8) or byte(0)) shl 4; {introduced 3.0.0}
  OSSL_PROVIDER_get_params_introduced = ((((((byte(3) shl 8) or byte(0)) shl 8) or byte(0)) shl 8) or byte(0)) shl 4; {introduced 3.0.0}
  OSSL_PROVIDER_self_test_introduced = ((((((byte(3) shl 8) or byte(0)) shl 8) or byte(0)) shl 8) or byte(0)) shl 4; {introduced 3.0.0}
  OSSL_PROVIDER_get_capabilities_introduced = ((((((byte(3) shl 8) or byte(0)) shl 8) or byte(0)) shl 8) or byte(0)) shl 4; {introduced 3.0.0}
  OSSL_PROVIDER_query_operation_introduced = ((((((byte(3) shl 8) or byte(0)) shl 8) or byte(0)) shl 8) or byte(0)) shl 4; {introduced 3.0.0}
  OSSL_PROVIDER_unquery_operation_introduced = ((((((byte(3) shl 8) or byte(0)) shl 8) or byte(0)) shl 8) or byte(0)) shl 4; {introduced 3.0.0}
  OSSL_PROVIDER_get0_provider_ctx_introduced = ((((((byte(3) shl 8) or byte(0)) shl 8) or byte(0)) shl 8) or byte(0)) shl 4; {introduced 3.0.0}
  OSSL_PROVIDER_get0_dispatch_introduced = ((((((byte(3) shl 8) or byte(0)) shl 8) or byte(0)) shl 8) or byte(0)) shl 4; {introduced 3.0.0}
  OSSL_PROVIDER_add_builtin_introduced = ((((((byte(3) shl 8) or byte(0)) shl 8) or byte(0)) shl 8) or byte(0)) shl 4; {introduced 3.0.0}
  OSSL_PROVIDER_get0_name_introduced = ((((((byte(3) shl 8) or byte(0)) shl 8) or byte(0)) shl 8) or byte(0)) shl 4; {introduced 3.0.0}
  OSSL_PROVIDER_get0_default_search_path_introduced = ((((((byte(3) shl 8) or byte(2)) shl 8) or byte(0)) shl 8) or byte(0)) shl 4; {introduced 3.2.0}
  OSSL_PROVIDER_try_load_ex_introduced = ((((((byte(3) shl 8) or byte(2)) shl 8) or byte(0)) shl 8) or byte(0)) shl 4; {introduced 3.2.0}
  OSSL_PROVIDER_load_ex_introduced = ((((((byte(3) shl 8) or byte(2)) shl 8) or byte(0)) shl 8) or byte(0)) shl 4; {introduced 3.2.0}


implementation


uses Classes,
     IdSSLOpenSSLExceptionHandlers,
     IdSSLOpenSSLResourceStrings;

{$IFNDEF OPENSSL_STATIC_LINK_MODEL}
{$IFNDEF OPENSSL_NO_LEGACY_SUPPORT}
{$IFDEF OPENSSL_3_2_ORLATER}
{$ENDIF}
{$ENDIF} { End of OPENSSL_NO_LEGACY_SUPPORT}
{$ENDIF}
{$IFNDEF OPENSSL_STATIC_LINK_MODEL}
{$IFNDEF OPENSSL_NO_LEGACY_SUPPORT}
{$ENDIF} { End of OPENSSL_NO_LEGACY_SUPPORT}
function Load_OSSL_PROVIDER_set_default_search_path(ctx: POSSL_LIB_CTX; path: PAnsiChar): TOpenSSL_C_INT; cdecl;
begin
  OSSL_PROVIDER_set_default_search_path := LoadLibCryptoFunction('OSSL_PROVIDER_set_default_search_path');
  if not assigned(OSSL_PROVIDER_set_default_search_path) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('OSSL_PROVIDER_set_default_search_path');
  Result := OSSL_PROVIDER_set_default_search_path(ctx,path);
end;

function Load_OSSL_PROVIDER_load(_para1:POSSL_LIB_CTX; name: PAnsiChar): POSSL_PROVIDER; cdecl;
begin
  OSSL_PROVIDER_load := LoadLibCryptoFunction('OSSL_PROVIDER_load');
  if not assigned(OSSL_PROVIDER_load) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('OSSL_PROVIDER_load');
  Result := OSSL_PROVIDER_load(_para1,name);
end;

function Load_OSSL_PROVIDER_try_load(_para1:POSSL_LIB_CTX; name: PAnsiChar; retain_fallbacks: TOpenSSL_C_LONG): POSSL_PROVIDER; cdecl;
begin
  OSSL_PROVIDER_try_load := LoadLibCryptoFunction('OSSL_PROVIDER_try_load');
  if not assigned(OSSL_PROVIDER_try_load) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('OSSL_PROVIDER_try_load');
  Result := OSSL_PROVIDER_try_load(_para1,name,retain_fallbacks);
end;

function Load_OSSL_PROVIDER_unload(prov:POSSL_PROVIDER): TOpenSSL_C_LONG; cdecl;
begin
  OSSL_PROVIDER_unload := LoadLibCryptoFunction('OSSL_PROVIDER_unload');
  if not assigned(OSSL_PROVIDER_unload) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('OSSL_PROVIDER_unload');
  Result := OSSL_PROVIDER_unload(prov);
end;

function Load_OSSL_PROVIDER_available(_para1:POSSL_LIB_CTX; name:PAnsiChar): TOpenSSL_C_LONG; cdecl;
begin
  OSSL_PROVIDER_available := LoadLibCryptoFunction('OSSL_PROVIDER_available');
  if not assigned(OSSL_PROVIDER_available) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('OSSL_PROVIDER_available');
  Result := OSSL_PROVIDER_available(_para1,name);
end;

function Load_OSSL_PROVIDER_do_all(ctx:POSSL_LIB_CTX; cb:TDo_AllCallback; cbdata:pointer): TOpenSSL_C_LONG; cdecl;
begin
  OSSL_PROVIDER_do_all := LoadLibCryptoFunction('OSSL_PROVIDER_do_all');
  if not assigned(OSSL_PROVIDER_do_all) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('OSSL_PROVIDER_do_all');
  Result := OSSL_PROVIDER_do_all(ctx,cb,cbdata);
end;

function Load_OSSL_PROVIDER_gettable_params(prov:POSSL_PROVIDER): POSSL_PARAM; cdecl;
begin
  OSSL_PROVIDER_gettable_params := LoadLibCryptoFunction('OSSL_PROVIDER_gettable_params');
  if not assigned(OSSL_PROVIDER_gettable_params) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('OSSL_PROVIDER_gettable_params');
  Result := OSSL_PROVIDER_gettable_params(prov);
end;

function Load_OSSL_PROVIDER_get_params(prov:POSSL_PROVIDER; params:POSSL_PARAM): TOpenSSL_C_LONG; cdecl;
begin
  OSSL_PROVIDER_get_params := LoadLibCryptoFunction('OSSL_PROVIDER_get_params');
  if not assigned(OSSL_PROVIDER_get_params) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('OSSL_PROVIDER_get_params');
  Result := OSSL_PROVIDER_get_params(prov,params);
end;

function Load_OSSL_PROVIDER_self_test(prov:POSSL_PROVIDER): TOpenSSL_C_LONG; cdecl;
begin
  OSSL_PROVIDER_self_test := LoadLibCryptoFunction('OSSL_PROVIDER_self_test');
  if not assigned(OSSL_PROVIDER_self_test) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('OSSL_PROVIDER_self_test');
  Result := OSSL_PROVIDER_self_test(prov);
end;

function Load_OSSL_PROVIDER_get_capabilities(prov:POSSL_PROVIDER; capability:PAnsiChar; cb:POSSL_CALLBACK; arg:pointer): TOpenSSL_C_LONG; cdecl;
begin
  OSSL_PROVIDER_get_capabilities := LoadLibCryptoFunction('OSSL_PROVIDER_get_capabilities');
  if not assigned(OSSL_PROVIDER_get_capabilities) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('OSSL_PROVIDER_get_capabilities');
  Result := OSSL_PROVIDER_get_capabilities(prov,capability,cb,arg);
end;

function Load_OSSL_PROVIDER_query_operation(prov:POSSL_PROVIDER; operation_id:TOpenSSL_C_LONG; no_cache:POpenSSL_C_LONG): POSSL_ALGORITHM; cdecl;
begin
  OSSL_PROVIDER_query_operation := LoadLibCryptoFunction('OSSL_PROVIDER_query_operation');
  if not assigned(OSSL_PROVIDER_query_operation) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('OSSL_PROVIDER_query_operation');
  Result := OSSL_PROVIDER_query_operation(prov,operation_id,no_cache);
end;

procedure Load_OSSL_PROVIDER_unquery_operation(prov:POSSL_PROVIDER; operation_id:TOpenSSL_C_LONG; algs:POSSL_ALGORITHM); cdecl;
begin
  OSSL_PROVIDER_unquery_operation := LoadLibCryptoFunction('OSSL_PROVIDER_unquery_operation');
  if not assigned(OSSL_PROVIDER_unquery_operation) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('OSSL_PROVIDER_unquery_operation');
  OSSL_PROVIDER_unquery_operation(prov,operation_id,algs);
end;

function Load_OSSL_PROVIDER_get0_provider_ctx(prov:POSSL_PROVIDER): pointer; cdecl;
begin
  OSSL_PROVIDER_get0_provider_ctx := LoadLibCryptoFunction('OSSL_PROVIDER_get0_provider_ctx');
  if not assigned(OSSL_PROVIDER_get0_provider_ctx) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('OSSL_PROVIDER_get0_provider_ctx');
  Result := OSSL_PROVIDER_get0_provider_ctx(prov);
end;

function Load_OSSL_PROVIDER_get0_dispatch(prov:POSSL_PROVIDER): POSSL_DISPATCH; cdecl;
begin
  OSSL_PROVIDER_get0_dispatch := LoadLibCryptoFunction('OSSL_PROVIDER_get0_dispatch');
  if not assigned(OSSL_PROVIDER_get0_dispatch) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('OSSL_PROVIDER_get0_dispatch');
  Result := OSSL_PROVIDER_get0_dispatch(prov);
end;

function Load_OSSL_PROVIDER_add_builtin(_para1:POSSL_LIB_CTX; name:PAnsiChar; init_fn:POSSL_provider_init_fn): TOpenSSL_C_LONG; cdecl;
begin
  OSSL_PROVIDER_add_builtin := LoadLibCryptoFunction('OSSL_PROVIDER_add_builtin');
  if not assigned(OSSL_PROVIDER_add_builtin) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('OSSL_PROVIDER_add_builtin');
  Result := OSSL_PROVIDER_add_builtin(_para1,name,init_fn);
end;

function Load_OSSL_PROVIDER_get0_name(prov:POSSL_PROVIDER): PAnsiChar; cdecl;
begin
  OSSL_PROVIDER_get0_name := LoadLibCryptoFunction('OSSL_PROVIDER_get0_name');
  if not assigned(OSSL_PROVIDER_get0_name) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('OSSL_PROVIDER_get0_name');
  Result := OSSL_PROVIDER_get0_name(prov);
end;

{$IFDEF OPENSSL_3_2_ORLATER}
function Load_OSSL_PROVIDER_get0_default_search_path(libctx: POSSL_LIB_CTX): PAnsiChar; cdecl;
begin
  OSSL_PROVIDER_get0_default_search_path := LoadLibCryptoFunction('OSSL_PROVIDER_get0_default_search_path');
  if not assigned(OSSL_PROVIDER_get0_default_search_path) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('OSSL_PROVIDER_get0_default_search_path');
  Result := OSSL_PROVIDER_get0_default_search_path(libctx);
end;

function Load_OSSL_PROVIDER_try_load_ex(_para1:POSSL_LIB_CTX; name: PAnsiChar; params:POSSL_PARAM; retain_fallbacks:TOpenSSL_C_LONG): POSSL_PROVIDER; cdecl;
begin
  OSSL_PROVIDER_try_load_ex := LoadLibCryptoFunction('OSSL_PROVIDER_try_load_ex');
  if not assigned(OSSL_PROVIDER_try_load_ex) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('OSSL_PROVIDER_try_load_ex');
  Result := OSSL_PROVIDER_try_load_ex(_para1,name,params,retain_fallbacks);
end;

function Load_OSSL_PROVIDER_load_ex(_para1:POSSL_LIB_CTX; name: PAnsiChar; params: POSSL_PARAM): POSSL_PROVIDER; cdecl;
begin
  OSSL_PROVIDER_load_ex := LoadLibCryptoFunction('OSSL_PROVIDER_load_ex');
  if not assigned(OSSL_PROVIDER_load_ex) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('OSSL_PROVIDER_load_ex');
  Result := OSSL_PROVIDER_load_ex(_para1,name,params);
end;

{$ENDIF}

{$WARN  NO_RETVAL OFF}
{$IFDEF OPENSSL_3_2_ORLATER}
{$ENDIF}
{$WARN  NO_RETVAL ON}

procedure UnLoad;
begin
  OSSL_PROVIDER_set_default_search_path := Load_OSSL_PROVIDER_set_default_search_path;
  OSSL_PROVIDER_load := Load_OSSL_PROVIDER_load;
  OSSL_PROVIDER_try_load := Load_OSSL_PROVIDER_try_load;
  OSSL_PROVIDER_unload := Load_OSSL_PROVIDER_unload;
  OSSL_PROVIDER_available := Load_OSSL_PROVIDER_available;
  OSSL_PROVIDER_do_all := Load_OSSL_PROVIDER_do_all;
  OSSL_PROVIDER_gettable_params := Load_OSSL_PROVIDER_gettable_params;
  OSSL_PROVIDER_get_params := Load_OSSL_PROVIDER_get_params;
  OSSL_PROVIDER_self_test := Load_OSSL_PROVIDER_self_test;
  OSSL_PROVIDER_get_capabilities := Load_OSSL_PROVIDER_get_capabilities;
  OSSL_PROVIDER_query_operation := Load_OSSL_PROVIDER_query_operation;
  OSSL_PROVIDER_unquery_operation := Load_OSSL_PROVIDER_unquery_operation;
  OSSL_PROVIDER_get0_provider_ctx := Load_OSSL_PROVIDER_get0_provider_ctx;
  OSSL_PROVIDER_get0_dispatch := Load_OSSL_PROVIDER_get0_dispatch;
  OSSL_PROVIDER_add_builtin := Load_OSSL_PROVIDER_add_builtin;
  OSSL_PROVIDER_get0_name := Load_OSSL_PROVIDER_get0_name;
{$IFDEF OPENSSL_3_2_ORLATER}
  OSSL_PROVIDER_get0_default_search_path := Load_OSSL_PROVIDER_get0_default_search_path;
  OSSL_PROVIDER_try_load_ex := Load_OSSL_PROVIDER_try_load_ex;
  OSSL_PROVIDER_load_ex := Load_OSSL_PROVIDER_load_ex;
{$ENDIF}
end;
{$ENDIF}

initialization

{$IFNDEF OPENSSL_STATIC_LINK_MODEL}
Register_SSLUnloader(@Unload);
{$ENDIF}
finalization


end.
