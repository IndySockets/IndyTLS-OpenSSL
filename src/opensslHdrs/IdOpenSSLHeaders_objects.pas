(* This unit was generated from the source file objects.h2pas 
It should not be modified directly. All changes should be made to objects.h2pas
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


unit IdOpenSSLHeaders_objects;


interface

// Headers for OpenSSL 1.1.1
// objects.h


uses
  IdSSLOpenSSLAPI,
  IdOpenSSLHeaders_ossl_typ;

type
  obj_name_st = record
    type_: TOpenSSL_C_INT;
    alias: TOpenSSL_C_INT;
    name: PAnsiChar;
    data: PAnsiChar;
  end;
  OBJ_NAME = obj_name_st;
  POBJ_NAME = ^OBJ_NAME;

//# define         OBJ_create_and_add_object(a,b,c) OBJ_create(a,b,c)

  
{ The EXTERNALSYM directive is ignored by FPC, however, it is used by Delphi as follows: 

The EXTERNALSYM directive prevents the specified Delphi symbol from appearing in header 
files generated for C++. }

{$EXTERNALSYM OBJ_NAME_init}
{$EXTERNALSYM OBJ_NAME_get}
{$EXTERNALSYM OBJ_NAME_add}
{$EXTERNALSYM OBJ_NAME_remove}
{$EXTERNALSYM OBJ_NAME_cleanup}
{$EXTERNALSYM OBJ_dup}
{$EXTERNALSYM OBJ_nid2obj}
{$EXTERNALSYM OBJ_nid2ln}
{$EXTERNALSYM OBJ_nid2sn}
{$EXTERNALSYM OBJ_obj2nid}
{$EXTERNALSYM OBJ_txt2obj}
{$EXTERNALSYM OBJ_obj2txt}
{$EXTERNALSYM OBJ_txt2nid}
{$EXTERNALSYM OBJ_ln2nid}
{$EXTERNALSYM OBJ_sn2nid}
{$EXTERNALSYM OBJ_cmp}
{$EXTERNALSYM OBJ_new_nid}
{$EXTERNALSYM OBJ_add_object}
{$EXTERNALSYM OBJ_create}
{$EXTERNALSYM OBJ_create_objects}
{$EXTERNALSYM OBJ_length}
{$EXTERNALSYM OBJ_get0_data}
{$EXTERNALSYM OBJ_find_sigid_algs}
{$EXTERNALSYM OBJ_find_sigid_by_algs}
{$EXTERNALSYM OBJ_add_sigid}
{$EXTERNALSYM OBJ_sigid_free}

{$IFDEF OPENSSL_STATIC_LINK_MODEL}
function OBJ_NAME_init: TOpenSSL_C_INT; cdecl; external CLibCrypto;
function OBJ_NAME_get(const name: PAnsiChar; type_: TOpenSSL_C_INT): PAnsiChar; cdecl; external CLibCrypto;
function OBJ_NAME_add(const name: PAnsiChar; type_: TOpenSSL_C_INT; const data: PAnsiChar): TOpenSSL_C_INT; cdecl; external CLibCrypto;
function OBJ_NAME_remove(const name: PAnsiChar; type_: TOpenSSL_C_INT): TOpenSSL_C_INT; cdecl; external CLibCrypto;
procedure OBJ_NAME_cleanup(type_: TOpenSSL_C_INT); cdecl; external CLibCrypto;
function OBJ_dup(const o: PASN1_OBJECT): PASN1_OBJECT; cdecl; external CLibCrypto;
function OBJ_nid2obj(n: TOpenSSL_C_INT): PASN1_OBJECT; cdecl; external CLibCrypto;
function OBJ_nid2ln(n: TOpenSSL_C_INT): PAnsiChar; cdecl; external CLibCrypto;
function OBJ_nid2sn(n: TOpenSSL_C_INT): PAnsiChar; cdecl; external CLibCrypto;
function OBJ_obj2nid(const o: PASN1_OBJECT): TOpenSSL_C_INT; cdecl; external CLibCrypto;
function OBJ_txt2obj(const s: PAnsiChar; no_name: TOpenSSL_C_INT): PASN1_OBJECT; cdecl; external CLibCrypto;
function OBJ_obj2txt(buf: PAnsiChar; buf_len: TOpenSSL_C_INT; const a: PASN1_OBJECT; no_name: TOpenSSL_C_INT): TOpenSSL_C_INT; cdecl; external CLibCrypto;
function OBJ_txt2nid(const s: PAnsiChar): TOpenSSL_C_INT; cdecl; external CLibCrypto;
function OBJ_ln2nid(const s: PAnsiChar): TOpenSSL_C_INT; cdecl; external CLibCrypto;
function OBJ_sn2nid(const s: PAnsiChar): TOpenSSL_C_INT; cdecl; external CLibCrypto;
function OBJ_cmp(const a: PASN1_OBJECT; const b: PASN1_OBJECT): TOpenSSL_C_INT; cdecl; external CLibCrypto;
function OBJ_new_nid(num: TOpenSSL_C_INT): TOpenSSL_C_INT; cdecl; external CLibCrypto;
function OBJ_add_object(const obj: PASN1_OBJECT): TOpenSSL_C_INT; cdecl; external CLibCrypto;
function OBJ_create(const oid: PAnsiChar; const sn: PAnsiChar; const ln: PAnsiChar): TOpenSSL_C_INT; cdecl; external CLibCrypto;
function OBJ_create_objects(in_: PBIO): TOpenSSL_C_INT; cdecl; external CLibCrypto;
function OBJ_length(const obj: PASN1_OBJECT): TOpenSSL_C_SIZET; cdecl; external CLibCrypto;
function OBJ_get0_data(const obj: PASN1_OBJECT): PByte; cdecl; external CLibCrypto;
function OBJ_find_sigid_algs(signid: TOpenSSL_C_INT; pdig_nid: POpenSSL_C_INT; ppkey_nid: POpenSSL_C_INT): TOpenSSL_C_INT; cdecl; external CLibCrypto;
function OBJ_find_sigid_by_algs(psignid: POpenSSL_C_INT; dig_nid: TOpenSSL_C_INT; pkey_nid: TOpenSSL_C_INT): TOpenSSL_C_INT; cdecl; external CLibCrypto;
function OBJ_add_sigid(signid: TOpenSSL_C_INT; dig_id: TOpenSSL_C_INT; pkey_id: TOpenSSL_C_INT): TOpenSSL_C_INT; cdecl; external CLibCrypto;
procedure OBJ_sigid_free; cdecl; external CLibCrypto;

{$ELSE}

{Declare external function initialisers - should not be called directly}

function Load_OBJ_NAME_init: TOpenSSL_C_INT; cdecl;
function Load_OBJ_NAME_get(const name: PAnsiChar; type_: TOpenSSL_C_INT): PAnsiChar; cdecl;
function Load_OBJ_NAME_add(const name: PAnsiChar; type_: TOpenSSL_C_INT; const data: PAnsiChar): TOpenSSL_C_INT; cdecl;
function Load_OBJ_NAME_remove(const name: PAnsiChar; type_: TOpenSSL_C_INT): TOpenSSL_C_INT; cdecl;
procedure Load_OBJ_NAME_cleanup(type_: TOpenSSL_C_INT); cdecl;
function Load_OBJ_dup(const o: PASN1_OBJECT): PASN1_OBJECT; cdecl;
function Load_OBJ_nid2obj(n: TOpenSSL_C_INT): PASN1_OBJECT; cdecl;
function Load_OBJ_nid2ln(n: TOpenSSL_C_INT): PAnsiChar; cdecl;
function Load_OBJ_nid2sn(n: TOpenSSL_C_INT): PAnsiChar; cdecl;
function Load_OBJ_obj2nid(const o: PASN1_OBJECT): TOpenSSL_C_INT; cdecl;
function Load_OBJ_txt2obj(const s: PAnsiChar; no_name: TOpenSSL_C_INT): PASN1_OBJECT; cdecl;
function Load_OBJ_obj2txt(buf: PAnsiChar; buf_len: TOpenSSL_C_INT; const a: PASN1_OBJECT; no_name: TOpenSSL_C_INT): TOpenSSL_C_INT; cdecl;
function Load_OBJ_txt2nid(const s: PAnsiChar): TOpenSSL_C_INT; cdecl;
function Load_OBJ_ln2nid(const s: PAnsiChar): TOpenSSL_C_INT; cdecl;
function Load_OBJ_sn2nid(const s: PAnsiChar): TOpenSSL_C_INT; cdecl;
function Load_OBJ_cmp(const a: PASN1_OBJECT; const b: PASN1_OBJECT): TOpenSSL_C_INT; cdecl;
function Load_OBJ_new_nid(num: TOpenSSL_C_INT): TOpenSSL_C_INT; cdecl;
function Load_OBJ_add_object(const obj: PASN1_OBJECT): TOpenSSL_C_INT; cdecl;
function Load_OBJ_create(const oid: PAnsiChar; const sn: PAnsiChar; const ln: PAnsiChar): TOpenSSL_C_INT; cdecl;
function Load_OBJ_create_objects(in_: PBIO): TOpenSSL_C_INT; cdecl;
function Load_OBJ_length(const obj: PASN1_OBJECT): TOpenSSL_C_SIZET; cdecl;
function Load_OBJ_get0_data(const obj: PASN1_OBJECT): PByte; cdecl;
function Load_OBJ_find_sigid_algs(signid: TOpenSSL_C_INT; pdig_nid: POpenSSL_C_INT; ppkey_nid: POpenSSL_C_INT): TOpenSSL_C_INT; cdecl;
function Load_OBJ_find_sigid_by_algs(psignid: POpenSSL_C_INT; dig_nid: TOpenSSL_C_INT; pkey_nid: TOpenSSL_C_INT): TOpenSSL_C_INT; cdecl;
function Load_OBJ_add_sigid(signid: TOpenSSL_C_INT; dig_id: TOpenSSL_C_INT; pkey_id: TOpenSSL_C_INT): TOpenSSL_C_INT; cdecl;
procedure Load_OBJ_sigid_free; cdecl;

var
  OBJ_NAME_init: function : TOpenSSL_C_INT; cdecl = Load_OBJ_NAME_init;
  OBJ_NAME_get: function (const name: PAnsiChar; type_: TOpenSSL_C_INT): PAnsiChar; cdecl = Load_OBJ_NAME_get;
  OBJ_NAME_add: function (const name: PAnsiChar; type_: TOpenSSL_C_INT; const data: PAnsiChar): TOpenSSL_C_INT; cdecl = Load_OBJ_NAME_add;
  OBJ_NAME_remove: function (const name: PAnsiChar; type_: TOpenSSL_C_INT): TOpenSSL_C_INT; cdecl = Load_OBJ_NAME_remove;
  OBJ_NAME_cleanup: procedure (type_: TOpenSSL_C_INT); cdecl = Load_OBJ_NAME_cleanup;
  OBJ_dup: function (const o: PASN1_OBJECT): PASN1_OBJECT; cdecl = Load_OBJ_dup;
  OBJ_nid2obj: function (n: TOpenSSL_C_INT): PASN1_OBJECT; cdecl = Load_OBJ_nid2obj;
  OBJ_nid2ln: function (n: TOpenSSL_C_INT): PAnsiChar; cdecl = Load_OBJ_nid2ln;
  OBJ_nid2sn: function (n: TOpenSSL_C_INT): PAnsiChar; cdecl = Load_OBJ_nid2sn;
  OBJ_obj2nid: function (const o: PASN1_OBJECT): TOpenSSL_C_INT; cdecl = Load_OBJ_obj2nid;
  OBJ_txt2obj: function (const s: PAnsiChar; no_name: TOpenSSL_C_INT): PASN1_OBJECT; cdecl = Load_OBJ_txt2obj;
  OBJ_obj2txt: function (buf: PAnsiChar; buf_len: TOpenSSL_C_INT; const a: PASN1_OBJECT; no_name: TOpenSSL_C_INT): TOpenSSL_C_INT; cdecl = Load_OBJ_obj2txt;
  OBJ_txt2nid: function (const s: PAnsiChar): TOpenSSL_C_INT; cdecl = Load_OBJ_txt2nid;
  OBJ_ln2nid: function (const s: PAnsiChar): TOpenSSL_C_INT; cdecl = Load_OBJ_ln2nid;
  OBJ_sn2nid: function (const s: PAnsiChar): TOpenSSL_C_INT; cdecl = Load_OBJ_sn2nid;
  OBJ_cmp: function (const a: PASN1_OBJECT; const b: PASN1_OBJECT): TOpenSSL_C_INT; cdecl = Load_OBJ_cmp;
  OBJ_new_nid: function (num: TOpenSSL_C_INT): TOpenSSL_C_INT; cdecl = Load_OBJ_new_nid;
  OBJ_add_object: function (const obj: PASN1_OBJECT): TOpenSSL_C_INT; cdecl = Load_OBJ_add_object;
  OBJ_create: function (const oid: PAnsiChar; const sn: PAnsiChar; const ln: PAnsiChar): TOpenSSL_C_INT; cdecl = Load_OBJ_create;
  OBJ_create_objects: function (in_: PBIO): TOpenSSL_C_INT; cdecl = Load_OBJ_create_objects;
  OBJ_length: function (const obj: PASN1_OBJECT): TOpenSSL_C_SIZET; cdecl = Load_OBJ_length;
  OBJ_get0_data: function (const obj: PASN1_OBJECT): PByte; cdecl = Load_OBJ_get0_data;
  OBJ_find_sigid_algs: function (signid: TOpenSSL_C_INT; pdig_nid: POpenSSL_C_INT; ppkey_nid: POpenSSL_C_INT): TOpenSSL_C_INT; cdecl = Load_OBJ_find_sigid_algs;
  OBJ_find_sigid_by_algs: function (psignid: POpenSSL_C_INT; dig_nid: TOpenSSL_C_INT; pkey_nid: TOpenSSL_C_INT): TOpenSSL_C_INT; cdecl = Load_OBJ_find_sigid_by_algs;
  OBJ_add_sigid: function (signid: TOpenSSL_C_INT; dig_id: TOpenSSL_C_INT; pkey_id: TOpenSSL_C_INT): TOpenSSL_C_INT; cdecl = Load_OBJ_add_sigid;
  OBJ_sigid_free: procedure ; cdecl = Load_OBJ_sigid_free;
{$ENDIF}
const
  OBJ_length_introduced = ((((((byte(1) shl 8) or byte(1)) shl 8) or byte(0)) shl 8) or byte(0)) shl 4; {introduced 1.1.0}
  OBJ_get0_data_introduced = ((((((byte(1) shl 8) or byte(1)) shl 8) or byte(0)) shl 8) or byte(0)) shl 4; {introduced 1.1.0}


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
function Load_OBJ_NAME_init: TOpenSSL_C_INT; cdecl;
begin
  OBJ_NAME_init := LoadLibCryptoFunction('OBJ_NAME_init');
  if not assigned(OBJ_NAME_init) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('OBJ_NAME_init');
  Result := OBJ_NAME_init();
end;

function Load_OBJ_NAME_get(const name: PAnsiChar; type_: TOpenSSL_C_INT): PAnsiChar; cdecl;
begin
  OBJ_NAME_get := LoadLibCryptoFunction('OBJ_NAME_get');
  if not assigned(OBJ_NAME_get) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('OBJ_NAME_get');
  Result := OBJ_NAME_get(name,type_);
end;

function Load_OBJ_NAME_add(const name: PAnsiChar; type_: TOpenSSL_C_INT; const data: PAnsiChar): TOpenSSL_C_INT; cdecl;
begin
  OBJ_NAME_add := LoadLibCryptoFunction('OBJ_NAME_add');
  if not assigned(OBJ_NAME_add) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('OBJ_NAME_add');
  Result := OBJ_NAME_add(name,type_,data);
end;

function Load_OBJ_NAME_remove(const name: PAnsiChar; type_: TOpenSSL_C_INT): TOpenSSL_C_INT; cdecl;
begin
  OBJ_NAME_remove := LoadLibCryptoFunction('OBJ_NAME_remove');
  if not assigned(OBJ_NAME_remove) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('OBJ_NAME_remove');
  Result := OBJ_NAME_remove(name,type_);
end;

procedure Load_OBJ_NAME_cleanup(type_: TOpenSSL_C_INT); cdecl;
begin
  OBJ_NAME_cleanup := LoadLibCryptoFunction('OBJ_NAME_cleanup');
  if not assigned(OBJ_NAME_cleanup) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('OBJ_NAME_cleanup');
  OBJ_NAME_cleanup(type_);
end;

function Load_OBJ_dup(const o: PASN1_OBJECT): PASN1_OBJECT; cdecl;
begin
  OBJ_dup := LoadLibCryptoFunction('OBJ_dup');
  if not assigned(OBJ_dup) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('OBJ_dup');
  Result := OBJ_dup(o);
end;

function Load_OBJ_nid2obj(n: TOpenSSL_C_INT): PASN1_OBJECT; cdecl;
begin
  OBJ_nid2obj := LoadLibCryptoFunction('OBJ_nid2obj');
  if not assigned(OBJ_nid2obj) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('OBJ_nid2obj');
  Result := OBJ_nid2obj(n);
end;

function Load_OBJ_nid2ln(n: TOpenSSL_C_INT): PAnsiChar; cdecl;
begin
  OBJ_nid2ln := LoadLibCryptoFunction('OBJ_nid2ln');
  if not assigned(OBJ_nid2ln) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('OBJ_nid2ln');
  Result := OBJ_nid2ln(n);
end;

function Load_OBJ_nid2sn(n: TOpenSSL_C_INT): PAnsiChar; cdecl;
begin
  OBJ_nid2sn := LoadLibCryptoFunction('OBJ_nid2sn');
  if not assigned(OBJ_nid2sn) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('OBJ_nid2sn');
  Result := OBJ_nid2sn(n);
end;

function Load_OBJ_obj2nid(const o: PASN1_OBJECT): TOpenSSL_C_INT; cdecl;
begin
  OBJ_obj2nid := LoadLibCryptoFunction('OBJ_obj2nid');
  if not assigned(OBJ_obj2nid) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('OBJ_obj2nid');
  Result := OBJ_obj2nid(o);
end;

function Load_OBJ_txt2obj(const s: PAnsiChar; no_name: TOpenSSL_C_INT): PASN1_OBJECT; cdecl;
begin
  OBJ_txt2obj := LoadLibCryptoFunction('OBJ_txt2obj');
  if not assigned(OBJ_txt2obj) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('OBJ_txt2obj');
  Result := OBJ_txt2obj(s,no_name);
end;

function Load_OBJ_obj2txt(buf: PAnsiChar; buf_len: TOpenSSL_C_INT; const a: PASN1_OBJECT; no_name: TOpenSSL_C_INT): TOpenSSL_C_INT; cdecl;
begin
  OBJ_obj2txt := LoadLibCryptoFunction('OBJ_obj2txt');
  if not assigned(OBJ_obj2txt) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('OBJ_obj2txt');
  Result := OBJ_obj2txt(buf,buf_len,a,no_name);
end;

function Load_OBJ_txt2nid(const s: PAnsiChar): TOpenSSL_C_INT; cdecl;
begin
  OBJ_txt2nid := LoadLibCryptoFunction('OBJ_txt2nid');
  if not assigned(OBJ_txt2nid) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('OBJ_txt2nid');
  Result := OBJ_txt2nid(s);
end;

function Load_OBJ_ln2nid(const s: PAnsiChar): TOpenSSL_C_INT; cdecl;
begin
  OBJ_ln2nid := LoadLibCryptoFunction('OBJ_ln2nid');
  if not assigned(OBJ_ln2nid) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('OBJ_ln2nid');
  Result := OBJ_ln2nid(s);
end;

function Load_OBJ_sn2nid(const s: PAnsiChar): TOpenSSL_C_INT; cdecl;
begin
  OBJ_sn2nid := LoadLibCryptoFunction('OBJ_sn2nid');
  if not assigned(OBJ_sn2nid) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('OBJ_sn2nid');
  Result := OBJ_sn2nid(s);
end;

function Load_OBJ_cmp(const a: PASN1_OBJECT; const b: PASN1_OBJECT): TOpenSSL_C_INT; cdecl;
begin
  OBJ_cmp := LoadLibCryptoFunction('OBJ_cmp');
  if not assigned(OBJ_cmp) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('OBJ_cmp');
  Result := OBJ_cmp(a,b);
end;

function Load_OBJ_new_nid(num: TOpenSSL_C_INT): TOpenSSL_C_INT; cdecl;
begin
  OBJ_new_nid := LoadLibCryptoFunction('OBJ_new_nid');
  if not assigned(OBJ_new_nid) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('OBJ_new_nid');
  Result := OBJ_new_nid(num);
end;

function Load_OBJ_add_object(const obj: PASN1_OBJECT): TOpenSSL_C_INT; cdecl;
begin
  OBJ_add_object := LoadLibCryptoFunction('OBJ_add_object');
  if not assigned(OBJ_add_object) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('OBJ_add_object');
  Result := OBJ_add_object(obj);
end;

function Load_OBJ_create(const oid: PAnsiChar; const sn: PAnsiChar; const ln: PAnsiChar): TOpenSSL_C_INT; cdecl;
begin
  OBJ_create := LoadLibCryptoFunction('OBJ_create');
  if not assigned(OBJ_create) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('OBJ_create');
  Result := OBJ_create(oid,sn,ln);
end;

function Load_OBJ_create_objects(in_: PBIO): TOpenSSL_C_INT; cdecl;
begin
  OBJ_create_objects := LoadLibCryptoFunction('OBJ_create_objects');
  if not assigned(OBJ_create_objects) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('OBJ_create_objects');
  Result := OBJ_create_objects(in_);
end;

function Load_OBJ_length(const obj: PASN1_OBJECT): TOpenSSL_C_SIZET; cdecl;
begin
  OBJ_length := LoadLibCryptoFunction('OBJ_length');
  if not assigned(OBJ_length) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('OBJ_length');
  Result := OBJ_length(obj);
end;

function Load_OBJ_get0_data(const obj: PASN1_OBJECT): PByte; cdecl;
begin
  OBJ_get0_data := LoadLibCryptoFunction('OBJ_get0_data');
  if not assigned(OBJ_get0_data) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('OBJ_get0_data');
  Result := OBJ_get0_data(obj);
end;

function Load_OBJ_find_sigid_algs(signid: TOpenSSL_C_INT; pdig_nid: POpenSSL_C_INT; ppkey_nid: POpenSSL_C_INT): TOpenSSL_C_INT; cdecl;
begin
  OBJ_find_sigid_algs := LoadLibCryptoFunction('OBJ_find_sigid_algs');
  if not assigned(OBJ_find_sigid_algs) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('OBJ_find_sigid_algs');
  Result := OBJ_find_sigid_algs(signid,pdig_nid,ppkey_nid);
end;

function Load_OBJ_find_sigid_by_algs(psignid: POpenSSL_C_INT; dig_nid: TOpenSSL_C_INT; pkey_nid: TOpenSSL_C_INT): TOpenSSL_C_INT; cdecl;
begin
  OBJ_find_sigid_by_algs := LoadLibCryptoFunction('OBJ_find_sigid_by_algs');
  if not assigned(OBJ_find_sigid_by_algs) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('OBJ_find_sigid_by_algs');
  Result := OBJ_find_sigid_by_algs(psignid,dig_nid,pkey_nid);
end;

function Load_OBJ_add_sigid(signid: TOpenSSL_C_INT; dig_id: TOpenSSL_C_INT; pkey_id: TOpenSSL_C_INT): TOpenSSL_C_INT; cdecl;
begin
  OBJ_add_sigid := LoadLibCryptoFunction('OBJ_add_sigid');
  if not assigned(OBJ_add_sigid) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('OBJ_add_sigid');
  Result := OBJ_add_sigid(signid,dig_id,pkey_id);
end;

procedure Load_OBJ_sigid_free; cdecl;
begin
  OBJ_sigid_free := LoadLibCryptoFunction('OBJ_sigid_free');
  if not assigned(OBJ_sigid_free) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('OBJ_sigid_free');
  OBJ_sigid_free();
end;


procedure UnLoad;
begin
  OBJ_NAME_init := Load_OBJ_NAME_init;
  OBJ_NAME_get := Load_OBJ_NAME_get;
  OBJ_NAME_add := Load_OBJ_NAME_add;
  OBJ_NAME_remove := Load_OBJ_NAME_remove;
  OBJ_NAME_cleanup := Load_OBJ_NAME_cleanup;
  OBJ_dup := Load_OBJ_dup;
  OBJ_nid2obj := Load_OBJ_nid2obj;
  OBJ_nid2ln := Load_OBJ_nid2ln;
  OBJ_nid2sn := Load_OBJ_nid2sn;
  OBJ_obj2nid := Load_OBJ_obj2nid;
  OBJ_txt2obj := Load_OBJ_txt2obj;
  OBJ_obj2txt := Load_OBJ_obj2txt;
  OBJ_txt2nid := Load_OBJ_txt2nid;
  OBJ_ln2nid := Load_OBJ_ln2nid;
  OBJ_sn2nid := Load_OBJ_sn2nid;
  OBJ_cmp := Load_OBJ_cmp;
  OBJ_new_nid := Load_OBJ_new_nid;
  OBJ_add_object := Load_OBJ_add_object;
  OBJ_create := Load_OBJ_create;
  OBJ_create_objects := Load_OBJ_create_objects;
  OBJ_length := Load_OBJ_length;
  OBJ_get0_data := Load_OBJ_get0_data;
  OBJ_find_sigid_algs := Load_OBJ_find_sigid_algs;
  OBJ_find_sigid_by_algs := Load_OBJ_find_sigid_by_algs;
  OBJ_add_sigid := Load_OBJ_add_sigid;
  OBJ_sigid_free := Load_OBJ_sigid_free;
end;
{$ENDIF}

initialization

{$IFNDEF OPENSSL_STATIC_LINK_MODEL}
Register_SSLUnloader(@Unload);
{$ENDIF}
finalization


end.
