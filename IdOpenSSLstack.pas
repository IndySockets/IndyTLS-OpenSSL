unit IdOpenSSLstack;

interface

uses
  IdOpenSSLopensslconf,
  IdOpenSSLossl_typ,
  IdCTypes;

{
  Automatically converted by H2Pas 1.0.0 from openssl-1.1.0l/include/openssl/stack.h
  The following command line parameters were used:
  -p
  -P
  -t
  -T
  -C
  openssl-1.1.0l/include/openssl/stack.h
}

Type
  TOPENSSL_sk_compfunc = function(para1: pointer; para2: pointer)
    : TIdC_INT; cdecl;
  TOPENSSL_sk_freefunc = procedure(para1: pointer); cdecl;

  POPENSSL_sk_copyfunc = ^TOPENSSL_sk_compfunc;
  POPENSSL_STACK = pointer;
{$IFDEF FPC}
{$PACKRECORDS C}
{$ENDIF}
  {
    * Copyright 1995-2016 The OpenSSL Project Authors. All Rights Reserved.
    *
    * Licensed under the OpenSSL license (the "License").  You may not use
    * this file except in compliance with the License.  You can obtain a copy
    * in the file LICENSE in the source distribution or at
    * https://www.openssl.org/source/license.html
  }
  { C++ extern C conditionnal removed }

type
  TOPENSSL_sk_copyfunc = function(para1: pointer): pointer; cdecl;
  func = procedure(para1: pointer);

type
  LPN_OPENSSL_sk_num = function(para1: POPENSSL_STACK): TIdC_INT cdecl;
  LPN_OPENSSL_sk_value = function(para1: POPENSSL_STACK; para2: TIdC_INT)
    : pointer cdecl;
  LPN_OPENSSL_sk_set = function(st: POPENSSL_STACK; i: TIdC_INT; data: pointer)
    : pointer cdecl;
  LPN_OPENSSL_sk_new = function(cmp: TOPENSSL_sk_compfunc)
    : POPENSSL_STACK cdecl;
  LPN_OPENSSL_sk_new_null = function: POPENSSL_STACK cdecl;
  LPN_OPENSSL_sk_free = procedure(para1: POPENSSL_STACK)cdecl;
  LPN_OPENSSL_sk_pop_free = procedure(st: POPENSSL_STACK)cdecl;

  LPN_OPENSSL_sk_deep_copy = function(para1: POPENSSL_STACK;
    c: TOPENSSL_sk_copyfunc; f: TOPENSSL_sk_freefunc): POPENSSL_STACK cdecl;
  LPN_OPENSSL_sk_insert = function(sk: POPENSSL_STACK; data: pointer;
    where: TIdC_INT): TIdC_INT cdecl;
  LPN_OPENSSL_sk_delete = function(st: POPENSSL_STACK; loc: TIdC_INT)
    : pointer cdecl;
  LPN_OPENSSL_sk_delete_ptr = function(st: POPENSSL_STACK; p: pointer)
    : pointer cdecl;
  LPN_OPENSSL_sk_find = function(st: POPENSSL_STACK; data: pointer)
    : TIdC_INT cdecl;
  LPN_OPENSSL_sk_find_ex = function(st: POPENSSL_STACK; data: pointer)
    : TIdC_INT cdecl;
  LPN_OPENSSL_sk_push = function(st: POPENSSL_STACK; data: pointer)
    : TIdC_INT cdecl;
  LPN_OPENSSL_sk_unshift = function(st: POPENSSL_STACK; data: pointer)
    : TIdC_INT cdecl;
  LPN_OPENSSL_sk_shift = function(st: POPENSSL_STACK): pointer cdecl;
  LPN_OPENSSL_sk_pop = function(st: POPENSSL_STACK): pointer cdecl;
  LPN_OPENSSL_sk_zero = procedure(st: POPENSSL_STACK)cdecl;
  LPN_OPENSSL_sk_set_cmp_func = function(sk: POPENSSL_STACK;
    cmp: TOPENSSL_sk_compfunc): TOPENSSL_sk_compfunc cdecl;
  LPN_OPENSSL_sk_dup = function(st: POPENSSL_STACK): POPENSSL_STACK cdecl;
  LPN_OPENSSL_sk_sort = procedure(st: POPENSSL_STACK)cdecl;
  LPN_OPENSSL_sk_is_sorted = function(st: POPENSSL_STACK): TIdC_INT cdecl;

var
  OPENSSL_sk_num: LPN_OPENSSL_sk_num;
  OPENSSL_sk_value: LPN_OPENSSL_sk_value;
  OPENSSL_sk_set: LPN_OPENSSL_sk_set;
  OPENSSL_sk_new: LPN_OPENSSL_sk_new;
  OPENSSL_sk_new_null: LPN_OPENSSL_sk_new_null;
  OPENSSL_sk_free: LPN_OPENSSL_sk_free;
  OPENSSL_sk_pop_free: LPN_OPENSSL_sk_pop_free;

  OPENSSL_sk_deep_copy: LPN_OPENSSL_sk_deep_copy;
  OPENSSL_sk_insert: LPN_OPENSSL_sk_insert;
  OPENSSL_sk_delete: LPN_OPENSSL_sk_delete;
  OPENSSL_sk_delete_ptr: LPN_OPENSSL_sk_delete_ptr;
  OPENSSL_sk_find: LPN_OPENSSL_sk_find;
  OPENSSL_sk_find_ex: LPN_OPENSSL_sk_find_ex;
  OPENSSL_sk_push: LPN_OPENSSL_sk_push;
  OPENSSL_sk_unshift: LPN_OPENSSL_sk_unshift;
  OPENSSL_sk_shift: LPN_OPENSSL_sk_shift;
  OPENSSL_sk_pop: LPN_OPENSSL_sk_pop;
  OPENSSL_sk_zero: LPN_OPENSSL_sk_zero;
  OPENSSL_sk_set_cmp_func: LPN_OPENSSL_sk_set_cmp_func;
  OPENSSL_sk_dup: LPN_OPENSSL_sk_dup;
  OPENSSL_sk_sort: LPN_OPENSSL_sk_sort;
  OPENSSL_sk_is_sorted: LPN_OPENSSL_sk_is_sorted;

implementation

uses SysUtils;

function stub_OPENSSL_sk_num(para1: POPENSSL_STACK): TIdC_INT cdecl;
begin
  OPENSSL_sk_num := CryptoFixupStub('OPENSSL_sk_num'); { Do not Localize }
  Result := OPENSSL_sk_num(para1);
end;

function stub_OPENSSL_sk_value(para1: POPENSSL_STACK; para2: TIdC_INT)
  : pointer cdecl;
begin
  OPENSSL_sk_value := CryptoFixupStub('OPENSSL_sk_value'); { Do not Localize }
  Result := OPENSSL_sk_value(para1, para2);
end;

function stub_OPENSSL_sk_set(st: POPENSSL_STACK; i: TIdC_INT; data: pointer)
  : pointer cdecl;
begin
  OPENSSL_sk_set := CryptoFixupStub('OPENSSL_sk_set'); { Do not Localize }
  Result := OPENSSL_sk_set(st, i, data);
end;

function stub_OPENSSL_sk_new(cmp: TOPENSSL_sk_compfunc): POPENSSL_STACK cdecl;
begin
  OPENSSL_sk_new := CryptoFixupStub('OPENSSL_sk_new'); { Do not Localize }
  Result := OPENSSL_sk_new(cmp);
end;

function stub_OPENSSL_sk_new_null: POPENSSL_STACK cdecl; { Do not Localize }
begin
  OPENSSL_sk_new_null := CryptoFixupStub('OPENSSL_sk_new_null');
  { Do not Localize }
  Result := OPENSSL_sk_new_null;
end;

procedure stub_OPENSSL_sk_free(para1: POPENSSL_STACK)cdecl;
begin
  OPENSSL_sk_free := CryptoFixupStub('OPENSSL_sk_free'); { Do not Localize }
  OPENSSL_sk_free(para1);
end;

procedure stub_OPENSSL_sk_pop_free(st: POPENSSL_STACK)cdecl;
begin
  OPENSSL_sk_pop_free := CryptoFixupStub('OPENSSL_sk_pop_free');
  { Do not Localize }
  OPENSSL_sk_pop_free(st);
end;

function stub_OPENSSL_sk_deep_copy(para1: POPENSSL_STACK;
  c: TOPENSSL_sk_copyfunc; f: TOPENSSL_sk_freefunc): POPENSSL_STACK cdecl;
begin
  OPENSSL_sk_deep_copy := CryptoFixupStub('OPENSSL_sk_deep_copy');
  { Do not Localize }
  Result := OPENSSL_sk_deep_copy(para1, c, f);
end;

function stub_OPENSSL_sk_insert(sk: POPENSSL_STACK; data: pointer;
  where: TIdC_INT): TIdC_INT cdecl;
begin
  OPENSSL_sk_insert := CryptoFixupStub('OPENSSL_sk_insert'); { Do not Localize }
  Result := OPENSSL_sk_insert(sk, data, where);
end;

function stub_OPENSSL_sk_delete(st: POPENSSL_STACK; loc: TIdC_INT)
  : pointer cdecl;
begin
  OPENSSL_sk_delete := CryptoFixupStub('OPENSSL_sk_delete'); { Do not Localize }
  Result := OPENSSL_sk_delete(st, loc);
end;

function stub_OPENSSL_sk_delete_ptr(st: POPENSSL_STACK; p: pointer)
  : pointer cdecl;
begin
  OPENSSL_sk_delete_ptr := CryptoFixupStub('OPENSSL_sk_delete_ptr');
  { Do not Localize }
  Result := OPENSSL_sk_delete_ptr(st, p);
end;

function stub_OPENSSL_sk_find(st: POPENSSL_STACK; data: pointer)
  : TIdC_INT cdecl;
begin
  OPENSSL_sk_find := CryptoFixupStub('OPENSSL_sk_find'); { Do not Localize }
  Result := OPENSSL_sk_find(st, data);
end;

function stub_OPENSSL_sk_find_ex(st: POPENSSL_STACK; data: pointer)
  : TIdC_INT cdecl;
begin
  OPENSSL_sk_find_ex := CryptoFixupStub('OPENSSL_sk_find_ex');
  { Do not Localize }
  Result := OPENSSL_sk_find_ex(st, data);
end;

function stub_OPENSSL_sk_push(st: POPENSSL_STACK; data: pointer)
  : TIdC_INT cdecl;
begin
  OPENSSL_sk_push := CryptoFixupStub('OPENSSL_sk_push'); { Do not Localize }
  Result := OPENSSL_sk_push(st, data);
end;

function stub_OPENSSL_sk_unshift(st: POPENSSL_STACK; data: pointer)
  : TIdC_INT cdecl;
begin
  OPENSSL_sk_unshift := CryptoFixupStub('OPENSSL_sk_unshift');
  { Do not Localize }
  Result := OPENSSL_sk_unshift(st, data);
end;

function stub_OPENSSL_sk_shift(st: POPENSSL_STACK): pointer cdecl;
begin
  OPENSSL_sk_shift := CryptoFixupStub('OPENSSL_sk_shift'); { Do not Localize }
  Result := OPENSSL_sk_shift(st);
end;

function stub_OPENSSL_sk_pop(st: POPENSSL_STACK): pointer cdecl;
begin
  OPENSSL_sk_pop := CryptoFixupStub('OPENSSL_sk_pop'); { Do not Localize }
  Result := OPENSSL_sk_pop(st);
end;

procedure stub_OPENSSL_sk_zero(st: POPENSSL_STACK)cdecl;
begin
  OPENSSL_sk_zero := CryptoFixupStub('OPENSSL_sk_zero'); { Do not Localize }
  OPENSSL_sk_zero(st);
end;

function stub_OPENSSL_sk_set_cmp_func(sk: POPENSSL_STACK;
  cmp: TOPENSSL_sk_compfunc): TOPENSSL_sk_compfunc cdecl;
begin
  OPENSSL_sk_set_cmp_func := CryptoFixupStub('OPENSSL_sk_set_cmp_func');
  { Do not Localize }
  Result := OPENSSL_sk_set_cmp_func(sk, cmp);
end;

function stub_OPENSSL_sk_dup(st: POPENSSL_STACK): POPENSSL_STACK cdecl;
begin
  OPENSSL_sk_dup := CryptoFixupStub('OPENSSL_sk_dup'); { Do not Localize }
  Result := OPENSSL_sk_dup(st);
end;

procedure stub_OPENSSL_sk_sort(st: POPENSSL_STACK)cdecl;
begin
  OPENSSL_sk_sort := CryptoFixupStub('OPENSSL_sk_sort'); { Do not Localize }
  OPENSSL_sk_sort(st);
end;

function stub_OPENSSL_sk_is_sorted(st: POPENSSL_STACK): TIdC_INT cdecl;
begin
  OPENSSL_sk_is_sorted := CryptoFixupStub('OPENSSL_sk_is_sorted');
  { Do not Localize }
  Result := OPENSSL_sk_is_sorted(st);
end;

procedure InitStubs;
begin
  OPENSSL_sk_num := @stub_OPENSSL_sk_num;
  OPENSSL_sk_value := @stub_OPENSSL_sk_value;
  OPENSSL_sk_set := @stub_OPENSSL_sk_set;
  OPENSSL_sk_new := @stub_OPENSSL_sk_new;
  OPENSSL_sk_new_null := @stub_OPENSSL_sk_new_null;
  OPENSSL_sk_free := @stub_OPENSSL_sk_free;
  OPENSSL_sk_pop_free := @stub_OPENSSL_sk_pop_free;
  OPENSSL_sk_deep_copy := @stub_OPENSSL_sk_deep_copy;
  OPENSSL_sk_insert := @stub_OPENSSL_sk_insert;
  OPENSSL_sk_delete := @stub_OPENSSL_sk_delete;
  OPENSSL_sk_delete_ptr := @stub_OPENSSL_sk_delete_ptr;
  OPENSSL_sk_find := @stub_OPENSSL_sk_find;
  OPENSSL_sk_find_ex := @stub_OPENSSL_sk_find_ex;
  OPENSSL_sk_push := @stub_OPENSSL_sk_push;
  OPENSSL_sk_unshift := @stub_OPENSSL_sk_unshift;
  OPENSSL_sk_shift := @stub_OPENSSL_sk_shift;
  OPENSSL_sk_pop := @stub_OPENSSL_sk_pop;
  OPENSSL_sk_zero := @stub_OPENSSL_sk_zero;
  OPENSSL_sk_set_cmp_func := @stub_OPENSSL_sk_set_cmp_func;
  OPENSSL_sk_dup := @stub_OPENSSL_sk_dup;
  OPENSSL_sk_sort := @stub_OPENSSL_sk_sort;
  OPENSSL_sk_is_sorted := @OPENSSL_sk_is_sorted;
end;

initialization

  InitStubs;

end.
