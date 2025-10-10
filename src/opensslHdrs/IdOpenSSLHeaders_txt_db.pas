(* This unit was generated from the source file txt_db.h2pas 
It should not be modified directly. All changes should be made to txt_db.h2pas
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


unit IdOpenSSLHeaders_txt_db;


interface

// Headers for OpenSSL 1.1.1
// txt_db.h


uses
  IdSSLOpenSSLAPI,
  IdOpenSSLHeaders_safestack,
  IdOpenSSLHeaders_ossl_typ;

const
  DB_ERROR_OK = 0;
  DB_ERROR_MALLOC = 1;
  DB_ERROR_INDEX_CLASH = 2;
  DB_ERROR_INDEX_OUT_OF_RANGE = 3;
  DB_ERROR_NO_INDEX = 4;
  DB_ERROR_INSERT_INDEX_CLASH = 5;
  DB_ERROR_WRONG_NUM_FIELDS = 6;

type
// DEFINE_SPECIAL_STACK_OF(OPENSSL_PSTRING, OPENSSL_STRING)

  qual_func =  function (v1: POPENSSL_STRING): TOpenSSL_C_INT;
  txt_db_st = record
    num_fields: TOpenSSL_C_INT;
    data: Pointer; // STACK_OF(OPENSSL_PSTRING) *
    index: Pointer; // LHASH_OF(OPENSSL_STRING) **
    qual: qual_func;
    error: TOpenSSL_C_LONG;
    arg1: TOpenSSL_C_LONG;
    arg2: TOpenSSL_C_LONG;
    arg_row: POPENSSL_STRING;
  end;
  TXT_DB = txt_db_st;
  PTXT_DB = ^TXT_DB;

  TXT_DB_create_index_qual = function(v1: POPENSSL_STRING): TOpenSSL_C_INT;

  
{ The EXTERNALSYM directive is ignored by FPC, however, it is used by Delphi as follows: 

The EXTERNALSYM directive prevents the specified Delphi symbol from appearing in header 
files generated for C++. }

{$EXTERNALSYM TXT_DB_read}
{$EXTERNALSYM TXT_DB_write}
{$EXTERNALSYM TXT_DB_free}
{$EXTERNALSYM TXT_DB_get_by_index}
{$EXTERNALSYM TXT_DB_insert}

{$IFDEF OPENSSL_STATIC_LINK_MODEL}
function TXT_DB_read(in_: PBIO; num: TOpenSSL_C_INT): PTXT_DB; cdecl; external CLibCrypto;
function TXT_DB_write(out_: PBIO; db: PTXT_DB): TOpenSSL_C_LONG; cdecl; external CLibCrypto;
procedure TXT_DB_free(db: PTXT_DB); cdecl; external CLibCrypto;
function TXT_DB_get_by_index(db: PTXT_DB; idx: TOpenSSL_C_INT; value: POPENSSL_STRING): POPENSSL_STRING; cdecl; external CLibCrypto;
function TXT_DB_insert(db: PTXT_DB; value: POPENSSL_STRING): TOpenSSL_C_INT; cdecl; external CLibCrypto;

{$ELSE}

{Declare external function initialisers - should not be called directly}

function Load_TXT_DB_read(in_: PBIO; num: TOpenSSL_C_INT): PTXT_DB; cdecl;
function Load_TXT_DB_write(out_: PBIO; db: PTXT_DB): TOpenSSL_C_LONG; cdecl;
procedure Load_TXT_DB_free(db: PTXT_DB); cdecl;
function Load_TXT_DB_get_by_index(db: PTXT_DB; idx: TOpenSSL_C_INT; value: POPENSSL_STRING): POPENSSL_STRING; cdecl;
function Load_TXT_DB_insert(db: PTXT_DB; value: POPENSSL_STRING): TOpenSSL_C_INT; cdecl;

var
  TXT_DB_read: function (in_: PBIO; num: TOpenSSL_C_INT): PTXT_DB; cdecl = Load_TXT_DB_read;
  TXT_DB_write: function (out_: PBIO; db: PTXT_DB): TOpenSSL_C_LONG; cdecl = Load_TXT_DB_write;
  TXT_DB_free: procedure (db: PTXT_DB); cdecl = Load_TXT_DB_free;
  TXT_DB_get_by_index: function (db: PTXT_DB; idx: TOpenSSL_C_INT; value: POPENSSL_STRING): POPENSSL_STRING; cdecl = Load_TXT_DB_get_by_index;
  TXT_DB_insert: function (db: PTXT_DB; value: POPENSSL_STRING): TOpenSSL_C_INT; cdecl = Load_TXT_DB_insert;
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
function Load_TXT_DB_read(in_: PBIO; num: TOpenSSL_C_INT): PTXT_DB; cdecl;
begin
  TXT_DB_read := LoadLibCryptoFunction('TXT_DB_read');
  if not assigned(TXT_DB_read) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('TXT_DB_read');
  Result := TXT_DB_read(in_,num);
end;

function Load_TXT_DB_write(out_: PBIO; db: PTXT_DB): TOpenSSL_C_LONG; cdecl;
begin
  TXT_DB_write := LoadLibCryptoFunction('TXT_DB_write');
  if not assigned(TXT_DB_write) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('TXT_DB_write');
  Result := TXT_DB_write(out_,db);
end;

procedure Load_TXT_DB_free(db: PTXT_DB); cdecl;
begin
  TXT_DB_free := LoadLibCryptoFunction('TXT_DB_free');
  if not assigned(TXT_DB_free) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('TXT_DB_free');
  TXT_DB_free(db);
end;

function Load_TXT_DB_get_by_index(db: PTXT_DB; idx: TOpenSSL_C_INT; value: POPENSSL_STRING): POPENSSL_STRING; cdecl;
begin
  TXT_DB_get_by_index := LoadLibCryptoFunction('TXT_DB_get_by_index');
  if not assigned(TXT_DB_get_by_index) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('TXT_DB_get_by_index');
  Result := TXT_DB_get_by_index(db,idx,value);
end;

function Load_TXT_DB_insert(db: PTXT_DB; value: POPENSSL_STRING): TOpenSSL_C_INT; cdecl;
begin
  TXT_DB_insert := LoadLibCryptoFunction('TXT_DB_insert');
  if not assigned(TXT_DB_insert) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('TXT_DB_insert');
  Result := TXT_DB_insert(db,value);
end;


procedure UnLoad;
begin
  TXT_DB_read := Load_TXT_DB_read;
  TXT_DB_write := Load_TXT_DB_write;
  TXT_DB_free := Load_TXT_DB_free;
  TXT_DB_get_by_index := Load_TXT_DB_get_by_index;
  TXT_DB_insert := Load_TXT_DB_insert;
end;
{$ENDIF}

initialization

{$IFNDEF OPENSSL_STATIC_LINK_MODEL}
Register_SSLUnloader(@Unload);
{$ENDIF}
finalization


end.
