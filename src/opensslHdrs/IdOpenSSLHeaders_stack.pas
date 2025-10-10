(* This unit was generated from the source file stack.h2pas 
It should not be modified directly. All changes should be made to stack.h2pas
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

unit IdOpenSSLHeaders_stack;


interface

uses
    IdSSLOpenSSLAPI;


{
  Automatically converted by H2Pas 1.0.0 from stack.h
  The following command line parameters were used:
  -p
  -t
    stack.h
}

 {
   * Copyright 1995-2017 The OpenSSL Project Authors. All Rights Reserved.
   *
   * Licensed under the OpenSSL license (the "License").  You may not use
   * this file except in compliance with the License.  You can obtain a copy
   * in the file LICENSE in the source distribution or at
   * https://www.openssl.org/source/license.html
    }

  
type
  POPENSSL_STACK  = pointer;

  TOPENSSL_sk_compfunc = function (_para1:pointer; _para2:pointer):longint;cdecl;
  TOPENSSL_sk_freefunc = procedure (_para1:pointer);cdecl;
  TOPENSSL_sk_copyfunc = function (_para1:pointer):pointer;cdecl;

  
{ The EXTERNALSYM directive is ignored by FPC, however, it is used by Delphi as follows: 

The EXTERNALSYM directive prevents the specified Delphi symbol from appearing in header 
files generated for C++. }

{$EXTERNALSYM OPENSSL_sk_num}
{$EXTERNALSYM OPENSSL_sk_value}
{$EXTERNALSYM OPENSSL_sk_set}
{$EXTERNALSYM OPENSSL_sk_new}
{$EXTERNALSYM OPENSSL_sk_new_null}
{$EXTERNALSYM OPENSSL_sk_new_reserve}
{$EXTERNALSYM OPENSSL_sk_reserve}
{$EXTERNALSYM OPENSSL_sk_free}
{$EXTERNALSYM OPENSSL_sk_pop_free}
{$EXTERNALSYM OPENSSL_sk_deep_copy}
{$EXTERNALSYM OPENSSL_sk_insert}
{$EXTERNALSYM OPENSSL_sk_delete}
{$EXTERNALSYM OPENSSL_sk_delete_ptr}
{$EXTERNALSYM OPENSSL_sk_find}
{$EXTERNALSYM OPENSSL_sk_find_ex}
{$EXTERNALSYM OPENSSL_sk_push}
{$EXTERNALSYM OPENSSL_sk_unshift}
{$EXTERNALSYM OPENSSL_sk_shift}
{$EXTERNALSYM OPENSSL_sk_pop}
{$EXTERNALSYM OPENSSL_sk_zero}
{$EXTERNALSYM OPENSSL_sk_set_cmp_func}
{$EXTERNALSYM OPENSSL_sk_dup}
{$EXTERNALSYM OPENSSL_sk_sort}
{$EXTERNALSYM OPENSSL_sk_is_sorted}

{$IFDEF OPENSSL_STATIC_LINK_MODEL}
function OPENSSL_sk_num(_para1:POPENSSL_STACK): longint; cdecl; external CLibCrypto;
function OPENSSL_sk_value(_para1:POPENSSL_STACK; _para2:longint): pointer; cdecl; external CLibCrypto;
function OPENSSL_sk_set(st:POPENSSL_STACK; i:longint; data:pointer): pointer; cdecl; external CLibCrypto;
function OPENSSL_sk_new(cmp:TOPENSSL_sk_compfunc): POPENSSL_STACK; cdecl; external CLibCrypto;
function OPENSSL_sk_new_null: POPENSSL_STACK; cdecl; external CLibCrypto;
function OPENSSL_sk_new_reserve(c:TOPENSSL_sk_compfunc; n:longint): POPENSSL_STACK; cdecl; external CLibCrypto;
function OPENSSL_sk_reserve(st:POPENSSL_STACK; n:longint): longint; cdecl; external CLibCrypto;
procedure OPENSSL_sk_free(_para1:POPENSSL_STACK); cdecl; external CLibCrypto;
procedure OPENSSL_sk_pop_free(st:POPENSSL_STACK; func:TOPENSSL_sk_freefunc); cdecl; external CLibCrypto;
function OPENSSL_sk_deep_copy(_para1:POPENSSL_STACK; c:TOPENSSL_sk_copyfunc; f:TOPENSSL_sk_freefunc): POPENSSL_STACK; cdecl; external CLibCrypto;
function OPENSSL_sk_insert(sk:POPENSSL_STACK; data:pointer; where:longint): longint; cdecl; external CLibCrypto;
function OPENSSL_sk_delete(st:POPENSSL_STACK; loc:longint): pointer; cdecl; external CLibCrypto;
function OPENSSL_sk_delete_ptr(st:POPENSSL_STACK; p:pointer): pointer; cdecl; external CLibCrypto;
function OPENSSL_sk_find(st:POPENSSL_STACK; data:pointer): longint; cdecl; external CLibCrypto;
function OPENSSL_sk_find_ex(st:POPENSSL_STACK; data:pointer): longint; cdecl; external CLibCrypto;
function OPENSSL_sk_push(st:POPENSSL_STACK; data:pointer): longint; cdecl; external CLibCrypto;
function OPENSSL_sk_unshift(st:POPENSSL_STACK; data:pointer): longint; cdecl; external CLibCrypto;
function OPENSSL_sk_shift(st:POPENSSL_STACK): pointer; cdecl; external CLibCrypto;
function OPENSSL_sk_pop(st:POPENSSL_STACK): pointer; cdecl; external CLibCrypto;
procedure OPENSSL_sk_zero(st:POPENSSL_STACK); cdecl; external CLibCrypto;
function OPENSSL_sk_set_cmp_func(sk:POPENSSL_STACK; cmp:TOPENSSL_sk_compfunc): TOPENSSL_sk_compfunc; cdecl; external CLibCrypto;
function OPENSSL_sk_dup(st:POPENSSL_STACK): POPENSSL_STACK; cdecl; external CLibCrypto;
procedure OPENSSL_sk_sort(st:POPENSSL_STACK); cdecl; external CLibCrypto;
function OPENSSL_sk_is_sorted(st:POPENSSL_STACK): longint; cdecl; external CLibCrypto;

{$ELSE}

{Declare external function initialisers - should not be called directly}

function Load_OPENSSL_sk_num(_para1:POPENSSL_STACK): longint; cdecl;
function Load_OPENSSL_sk_value(_para1:POPENSSL_STACK; _para2:longint): pointer; cdecl;
function Load_OPENSSL_sk_set(st:POPENSSL_STACK; i:longint; data:pointer): pointer; cdecl;
function Load_OPENSSL_sk_new(cmp:TOPENSSL_sk_compfunc): POPENSSL_STACK; cdecl;
function Load_OPENSSL_sk_new_null: POPENSSL_STACK; cdecl;
function Load_OPENSSL_sk_new_reserve(c:TOPENSSL_sk_compfunc; n:longint): POPENSSL_STACK; cdecl;
function Load_OPENSSL_sk_reserve(st:POPENSSL_STACK; n:longint): longint; cdecl;
procedure Load_OPENSSL_sk_free(_para1:POPENSSL_STACK); cdecl;
procedure Load_OPENSSL_sk_pop_free(st:POPENSSL_STACK; func:TOPENSSL_sk_freefunc); cdecl;
function Load_OPENSSL_sk_deep_copy(_para1:POPENSSL_STACK; c:TOPENSSL_sk_copyfunc; f:TOPENSSL_sk_freefunc): POPENSSL_STACK; cdecl;
function Load_OPENSSL_sk_insert(sk:POPENSSL_STACK; data:pointer; where:longint): longint; cdecl;
function Load_OPENSSL_sk_delete(st:POPENSSL_STACK; loc:longint): pointer; cdecl;
function Load_OPENSSL_sk_delete_ptr(st:POPENSSL_STACK; p:pointer): pointer; cdecl;
function Load_OPENSSL_sk_find(st:POPENSSL_STACK; data:pointer): longint; cdecl;
function Load_OPENSSL_sk_find_ex(st:POPENSSL_STACK; data:pointer): longint; cdecl;
function Load_OPENSSL_sk_push(st:POPENSSL_STACK; data:pointer): longint; cdecl;
function Load_OPENSSL_sk_unshift(st:POPENSSL_STACK; data:pointer): longint; cdecl;
function Load_OPENSSL_sk_shift(st:POPENSSL_STACK): pointer; cdecl;
function Load_OPENSSL_sk_pop(st:POPENSSL_STACK): pointer; cdecl;
procedure Load_OPENSSL_sk_zero(st:POPENSSL_STACK); cdecl;
function Load_OPENSSL_sk_set_cmp_func(sk:POPENSSL_STACK; cmp:TOPENSSL_sk_compfunc): TOPENSSL_sk_compfunc; cdecl;
function Load_OPENSSL_sk_dup(st:POPENSSL_STACK): POPENSSL_STACK; cdecl;
procedure Load_OPENSSL_sk_sort(st:POPENSSL_STACK); cdecl;
function Load_OPENSSL_sk_is_sorted(st:POPENSSL_STACK): longint; cdecl;
{$IFNDEF OPENSSL_NO_LEGACY_SUPPORT}
function Load_sk_num(_para1:POPENSSL_STACK): longint; cdecl;
function Load_sk_value(_para1:POPENSSL_STACK; _para2:longint): pointer; cdecl;
function Load_sk_set(st:POPENSSL_STACK; i:longint; data:pointer): pointer; cdecl;
function Load_sk_new(cmp:TOPENSSL_sk_compfunc): POPENSSL_STACK; cdecl;
function Load_sk_new_null: POPENSSL_STACK; cdecl;
function Load_sk_new_reserve(c:TOPENSSL_sk_compfunc; n:longint): POPENSSL_STACK; cdecl;
function Load_sk_reserve(st:POPENSSL_STACK; n:longint): longint; cdecl;
procedure Load_sk_free(_para1:POPENSSL_STACK); cdecl;
procedure Load_sk_pop_free(st:POPENSSL_STACK; func:TOPENSSL_sk_freefunc); cdecl;
function Load_sk_deep_copy(_para1:POPENSSL_STACK; c:TOPENSSL_sk_copyfunc; f:TOPENSSL_sk_freefunc): POPENSSL_STACK; cdecl;
function Load_sk_insert(sk:POPENSSL_STACK; data:pointer; where:longint): longint; cdecl;
function Load_sk_delete(st:POPENSSL_STACK; loc:longint): pointer; cdecl;
function Load_sk_delete_ptr(st:POPENSSL_STACK; p:pointer): pointer; cdecl;
function Load_sk_find(st:POPENSSL_STACK; data:pointer): longint; cdecl;
function Load_sk_find_ex(st:POPENSSL_STACK; data:pointer): longint; cdecl;
function Load_sk_push(st:POPENSSL_STACK; data:pointer): longint; cdecl;
function Load_sk_unshift(st:POPENSSL_STACK; data:pointer): longint; cdecl;
function Load_sk_shift(st:POPENSSL_STACK): pointer; cdecl;
function Load_sk_pop(st:POPENSSL_STACK): pointer; cdecl;
procedure Load_sk_zero(st:POPENSSL_STACK); cdecl;
function Load_sk_set_cmp_func(sk:POPENSSL_STACK; cmp:TOPENSSL_sk_compfunc): TOPENSSL_sk_compfunc; cdecl;
function Load_sk_dup(st:POPENSSL_STACK): POPENSSL_STACK; cdecl;
procedure Load_sk_sort(st:POPENSSL_STACK); cdecl;
function Load_sk_is_sorted(st:POPENSSL_STACK): longint; cdecl;
{$ENDIF} //of OPENSSL_NO_LEGACY_SUPPORT

var
  OPENSSL_sk_num: function (_para1:POPENSSL_STACK): longint; cdecl = Load_OPENSSL_sk_num;
  OPENSSL_sk_value: function (_para1:POPENSSL_STACK; _para2:longint): pointer; cdecl = Load_OPENSSL_sk_value;
  OPENSSL_sk_set: function (st:POPENSSL_STACK; i:longint; data:pointer): pointer; cdecl = Load_OPENSSL_sk_set;
  OPENSSL_sk_new: function (cmp:TOPENSSL_sk_compfunc): POPENSSL_STACK; cdecl = Load_OPENSSL_sk_new;
  OPENSSL_sk_new_null: function : POPENSSL_STACK; cdecl = Load_OPENSSL_sk_new_null;
  OPENSSL_sk_new_reserve: function (c:TOPENSSL_sk_compfunc; n:longint): POPENSSL_STACK; cdecl = Load_OPENSSL_sk_new_reserve;
  OPENSSL_sk_reserve: function (st:POPENSSL_STACK; n:longint): longint; cdecl = Load_OPENSSL_sk_reserve;
  OPENSSL_sk_free: procedure (_para1:POPENSSL_STACK); cdecl = Load_OPENSSL_sk_free;
  OPENSSL_sk_pop_free: procedure (st:POPENSSL_STACK; func:TOPENSSL_sk_freefunc); cdecl = Load_OPENSSL_sk_pop_free;
  OPENSSL_sk_deep_copy: function (_para1:POPENSSL_STACK; c:TOPENSSL_sk_copyfunc; f:TOPENSSL_sk_freefunc): POPENSSL_STACK; cdecl = Load_OPENSSL_sk_deep_copy;
  OPENSSL_sk_insert: function (sk:POPENSSL_STACK; data:pointer; where:longint): longint; cdecl = Load_OPENSSL_sk_insert;
  OPENSSL_sk_delete: function (st:POPENSSL_STACK; loc:longint): pointer; cdecl = Load_OPENSSL_sk_delete;
  OPENSSL_sk_delete_ptr: function (st:POPENSSL_STACK; p:pointer): pointer; cdecl = Load_OPENSSL_sk_delete_ptr;
  OPENSSL_sk_find: function (st:POPENSSL_STACK; data:pointer): longint; cdecl = Load_OPENSSL_sk_find;
  OPENSSL_sk_find_ex: function (st:POPENSSL_STACK; data:pointer): longint; cdecl = Load_OPENSSL_sk_find_ex;
  OPENSSL_sk_push: function (st:POPENSSL_STACK; data:pointer): longint; cdecl = Load_OPENSSL_sk_push;
  OPENSSL_sk_unshift: function (st:POPENSSL_STACK; data:pointer): longint; cdecl = Load_OPENSSL_sk_unshift;
  OPENSSL_sk_shift: function (st:POPENSSL_STACK): pointer; cdecl = Load_OPENSSL_sk_shift;
  OPENSSL_sk_pop: function (st:POPENSSL_STACK): pointer; cdecl = Load_OPENSSL_sk_pop;
  OPENSSL_sk_zero: procedure (st:POPENSSL_STACK); cdecl = Load_OPENSSL_sk_zero;
  OPENSSL_sk_set_cmp_func: function (sk:POPENSSL_STACK; cmp:TOPENSSL_sk_compfunc): TOPENSSL_sk_compfunc; cdecl = Load_OPENSSL_sk_set_cmp_func;
  OPENSSL_sk_dup: function (st:POPENSSL_STACK): POPENSSL_STACK; cdecl = Load_OPENSSL_sk_dup;
  OPENSSL_sk_sort: procedure (st:POPENSSL_STACK); cdecl = Load_OPENSSL_sk_sort;
  OPENSSL_sk_is_sorted: function (st:POPENSSL_STACK): longint; cdecl = Load_OPENSSL_sk_is_sorted;
{$ENDIF}
const
  OPENSSL_sk_num_introduced = ((((((byte(1) shl 8) or byte(1)) shl 8) or byte(0)) shl 8) or byte(0)) shl 4; {introduced 1.1.0}
  OPENSSL_sk_value_introduced = ((((((byte(1) shl 8) or byte(1)) shl 8) or byte(0)) shl 8) or byte(0)) shl 4; {introduced 1.1.0}
  OPENSSL_sk_set_introduced = ((((((byte(1) shl 8) or byte(1)) shl 8) or byte(0)) shl 8) or byte(0)) shl 4; {introduced 1.1.0}
  OPENSSL_sk_new_introduced = ((((((byte(1) shl 8) or byte(1)) shl 8) or byte(0)) shl 8) or byte(0)) shl 4; {introduced 1.1.0}
  OPENSSL_sk_new_null_introduced = ((((((byte(1) shl 8) or byte(1)) shl 8) or byte(0)) shl 8) or byte(0)) shl 4; {introduced 1.1.0}
  OPENSSL_sk_new_reserve_introduced = ((((((byte(1) shl 8) or byte(1)) shl 8) or byte(0)) shl 8) or byte(0)) shl 4; {introduced 1.1.0}
  OPENSSL_sk_reserve_introduced = ((((((byte(1) shl 8) or byte(1)) shl 8) or byte(0)) shl 8) or byte(0)) shl 4; {introduced 1.1.0}
  OPENSSL_sk_free_introduced = ((((((byte(1) shl 8) or byte(1)) shl 8) or byte(0)) shl 8) or byte(0)) shl 4; {introduced 1.1.0}
  OPENSSL_sk_pop_free_introduced = ((((((byte(1) shl 8) or byte(1)) shl 8) or byte(0)) shl 8) or byte(0)) shl 4; {introduced 1.1.0}
  OPENSSL_sk_deep_copy_introduced = ((((((byte(1) shl 8) or byte(1)) shl 8) or byte(0)) shl 8) or byte(0)) shl 4; {introduced 1.1.0}
  OPENSSL_sk_insert_introduced = ((((((byte(1) shl 8) or byte(1)) shl 8) or byte(0)) shl 8) or byte(0)) shl 4; {introduced 1.1.0}
  OPENSSL_sk_delete_introduced = ((((((byte(1) shl 8) or byte(1)) shl 8) or byte(0)) shl 8) or byte(0)) shl 4; {introduced 1.1.0}
  OPENSSL_sk_delete_ptr_introduced = ((((((byte(1) shl 8) or byte(1)) shl 8) or byte(0)) shl 8) or byte(0)) shl 4; {introduced 1.1.0}
  OPENSSL_sk_find_introduced = ((((((byte(1) shl 8) or byte(1)) shl 8) or byte(0)) shl 8) or byte(0)) shl 4; {introduced 1.1.0}
  OPENSSL_sk_find_ex_introduced = ((((((byte(1) shl 8) or byte(1)) shl 8) or byte(0)) shl 8) or byte(0)) shl 4; {introduced 1.1.0}
  OPENSSL_sk_push_introduced = ((((((byte(1) shl 8) or byte(1)) shl 8) or byte(0)) shl 8) or byte(0)) shl 4; {introduced 1.1.0}
  OPENSSL_sk_unshift_introduced = ((((((byte(1) shl 8) or byte(1)) shl 8) or byte(0)) shl 8) or byte(0)) shl 4; {introduced 1.1.0}
  OPENSSL_sk_shift_introduced = ((((((byte(1) shl 8) or byte(1)) shl 8) or byte(0)) shl 8) or byte(0)) shl 4; {introduced 1.1.0}
  OPENSSL_sk_pop_introduced = ((((((byte(1) shl 8) or byte(1)) shl 8) or byte(0)) shl 8) or byte(0)) shl 4; {introduced 1.1.0}
  OPENSSL_sk_zero_introduced = ((((((byte(1) shl 8) or byte(1)) shl 8) or byte(0)) shl 8) or byte(0)) shl 4; {introduced 1.1.0}
  OPENSSL_sk_set_cmp_func_introduced = ((((((byte(1) shl 8) or byte(1)) shl 8) or byte(0)) shl 8) or byte(0)) shl 4; {introduced 1.1.0}
  OPENSSL_sk_dup_introduced = ((((((byte(1) shl 8) or byte(1)) shl 8) or byte(0)) shl 8) or byte(0)) shl 4; {introduced 1.1.0}
  OPENSSL_sk_sort_introduced = ((((((byte(1) shl 8) or byte(1)) shl 8) or byte(0)) shl 8) or byte(0)) shl 4; {introduced 1.1.0}
  OPENSSL_sk_is_sorted_introduced = ((((((byte(1) shl 8) or byte(1)) shl 8) or byte(0)) shl 8) or byte(0)) shl 4; {introduced 1.1.0}
  sk_num_removed = ((((((byte(1) shl 8) or byte(1)) shl 8) or byte(0)) shl 8) or byte(0)) shl 4; {removed 1.1.0}
  sk_value_removed = ((((((byte(1) shl 8) or byte(1)) shl 8) or byte(0)) shl 8) or byte(0)) shl 4; {removed 1.1.0}
  sk_set_removed = ((((((byte(1) shl 8) or byte(1)) shl 8) or byte(0)) shl 8) or byte(0)) shl 4; {removed 1.1.0}
  sk_new_removed = ((((((byte(1) shl 8) or byte(1)) shl 8) or byte(0)) shl 8) or byte(0)) shl 4; {removed 1.1.0}
  sk_new_null_removed = ((((((byte(1) shl 8) or byte(1)) shl 8) or byte(0)) shl 8) or byte(0)) shl 4; {removed 1.1.0}
  sk_new_reserve_removed = ((((((byte(1) shl 8) or byte(0)) shl 8) or byte(0)) shl 8) or byte(0)) shl 4; {removed 1.0.0}
  sk_reserve_removed = ((((((byte(1) shl 8) or byte(0)) shl 8) or byte(0)) shl 8) or byte(0)) shl 4; {removed 1.0.0}
  sk_free_removed = ((((((byte(1) shl 8) or byte(1)) shl 8) or byte(0)) shl 8) or byte(0)) shl 4; {removed 1.1.0}
  sk_pop_free_removed = ((((((byte(1) shl 8) or byte(1)) shl 8) or byte(0)) shl 8) or byte(0)) shl 4; {removed 1.1.0}
  sk_deep_copy_removed = ((((((byte(1) shl 8) or byte(1)) shl 8) or byte(0)) shl 8) or byte(0)) shl 4; {removed 1.1.0}
  sk_insert_removed = ((((((byte(1) shl 8) or byte(1)) shl 8) or byte(0)) shl 8) or byte(0)) shl 4; {removed 1.1.0}
  sk_delete_removed = ((((((byte(1) shl 8) or byte(1)) shl 8) or byte(0)) shl 8) or byte(0)) shl 4; {removed 1.1.0}
  sk_delete_ptr_removed = ((((((byte(1) shl 8) or byte(1)) shl 8) or byte(0)) shl 8) or byte(0)) shl 4; {removed 1.1.0}
  sk_find_removed = ((((((byte(1) shl 8) or byte(1)) shl 8) or byte(0)) shl 8) or byte(0)) shl 4; {removed 1.1.0}
  sk_find_ex_removed = ((((((byte(1) shl 8) or byte(1)) shl 8) or byte(0)) shl 8) or byte(0)) shl 4; {removed 1.1.0}
  sk_push_removed = ((((((byte(1) shl 8) or byte(1)) shl 8) or byte(0)) shl 8) or byte(0)) shl 4; {removed 1.1.0}
  sk_unshift_removed = ((((((byte(1) shl 8) or byte(1)) shl 8) or byte(0)) shl 8) or byte(0)) shl 4; {removed 1.1.0}
  sk_shift_removed = ((((((byte(1) shl 8) or byte(1)) shl 8) or byte(0)) shl 8) or byte(0)) shl 4; {removed 1.1.0}
  sk_pop_removed = ((((((byte(1) shl 8) or byte(1)) shl 8) or byte(0)) shl 8) or byte(0)) shl 4; {removed 1.1.0}
  sk_zero_removed = ((((((byte(1) shl 8) or byte(1)) shl 8) or byte(0)) shl 8) or byte(0)) shl 4; {removed 1.1.0}
  sk_set_cmp_func_removed = ((((((byte(1) shl 8) or byte(1)) shl 8) or byte(0)) shl 8) or byte(0)) shl 4; {removed 1.1.0}
  sk_dup_removed = ((((((byte(1) shl 8) or byte(1)) shl 8) or byte(0)) shl 8) or byte(0)) shl 4; {removed 1.1.0}
  sk_sort_removed = ((((((byte(1) shl 8) or byte(1)) shl 8) or byte(0)) shl 8) or byte(0)) shl 4; {removed 1.1.0}
  sk_is_sorted_removed = ((((((byte(1) shl 8) or byte(1)) shl 8) or byte(0)) shl 8) or byte(0)) shl 4; {removed 1.1.0}


implementation


uses Classes,
     IdSSLOpenSSLExceptionHandlers,
     IdSSLOpenSSLResourceStrings;

{$IFNDEF OPENSSL_STATIC_LINK_MODEL}
{$IFNDEF OPENSSL_NO_LEGACY_SUPPORT}
var
  sk_num: function (_para1:POPENSSL_STACK): longint; cdecl = Load_sk_num; {removed 1.1.0}
  sk_value: function (_para1:POPENSSL_STACK; _para2:longint): pointer; cdecl = Load_sk_value; {removed 1.1.0}
  sk_set: function (st:POPENSSL_STACK; i:longint; data:pointer): pointer; cdecl = Load_sk_set; {removed 1.1.0}
  sk_new: function (cmp:TOPENSSL_sk_compfunc): POPENSSL_STACK; cdecl = Load_sk_new; {removed 1.1.0}
  sk_new_null: function : POPENSSL_STACK; cdecl = Load_sk_new_null; {removed 1.1.0}
  sk_new_reserve: function (c:TOPENSSL_sk_compfunc; n:longint): POPENSSL_STACK; cdecl = Load_sk_new_reserve; {removed 1.0.0}
  sk_reserve: function (st:POPENSSL_STACK; n:longint): longint; cdecl = Load_sk_reserve; {removed 1.0.0}
  sk_free: procedure (_para1:POPENSSL_STACK); cdecl = Load_sk_free; {removed 1.1.0}
  sk_pop_free: procedure (st:POPENSSL_STACK; func:TOPENSSL_sk_freefunc); cdecl = Load_sk_pop_free; {removed 1.1.0}
  sk_deep_copy: function (_para1:POPENSSL_STACK; c:TOPENSSL_sk_copyfunc; f:TOPENSSL_sk_freefunc): POPENSSL_STACK; cdecl = Load_sk_deep_copy; {removed 1.1.0}
  sk_insert: function (sk:POPENSSL_STACK; data:pointer; where:longint): longint; cdecl = Load_sk_insert; {removed 1.1.0}
  sk_delete: function (st:POPENSSL_STACK; loc:longint): pointer; cdecl = Load_sk_delete; {removed 1.1.0}
  sk_delete_ptr: function (st:POPENSSL_STACK; p:pointer): pointer; cdecl = Load_sk_delete_ptr; {removed 1.1.0}
  sk_find: function (st:POPENSSL_STACK; data:pointer): longint; cdecl = Load_sk_find; {removed 1.1.0}
  sk_find_ex: function (st:POPENSSL_STACK; data:pointer): longint; cdecl = Load_sk_find_ex; {removed 1.1.0}
  sk_push: function (st:POPENSSL_STACK; data:pointer): longint; cdecl = Load_sk_push; {removed 1.1.0}
  sk_unshift: function (st:POPENSSL_STACK; data:pointer): longint; cdecl = Load_sk_unshift; {removed 1.1.0}
  sk_shift: function (st:POPENSSL_STACK): pointer; cdecl = Load_sk_shift; {removed 1.1.0}
  sk_pop: function (st:POPENSSL_STACK): pointer; cdecl = Load_sk_pop; {removed 1.1.0}
  sk_zero: procedure (st:POPENSSL_STACK); cdecl = Load_sk_zero; {removed 1.1.0}
  sk_set_cmp_func: function (sk:POPENSSL_STACK; cmp:TOPENSSL_sk_compfunc): TOPENSSL_sk_compfunc; cdecl = Load_sk_set_cmp_func; {removed 1.1.0}
  sk_dup: function (st:POPENSSL_STACK): POPENSSL_STACK; cdecl = Load_sk_dup; {removed 1.1.0}
  sk_sort: procedure (st:POPENSSL_STACK); cdecl = Load_sk_sort; {removed 1.1.0}
  sk_is_sorted: function (st:POPENSSL_STACK): longint; cdecl = Load_sk_is_sorted; {removed 1.1.0}
{$ENDIF} { End of OPENSSL_NO_LEGACY_SUPPORT}
{$ENDIF}
{$IFNDEF OPENSSL_STATIC_LINK_MODEL}
{$IFNDEF OPENSSL_NO_LEGACY_SUPPORT}
function COMPAT_OPENSSL_sk_num(_para1:POPENSSL_STACK): longint; cdecl;

begin
  Result := sk_num(_para1);
end;



function COMPAT_OPENSSL_sk_value(_para1:POPENSSL_STACK; _para2:longint): pointer; cdecl;

begin
  Result := sk_value(_para1,_para2);
end;



function COMPAT_OPENSSL_sk_set(st:POPENSSL_STACK; i:longint; data:pointer): pointer; cdecl;

begin
  Result := sk_set(st,i,data);
end;



function COMPAT_OPENSSL_sk_new(cmp:TOPENSSL_sk_compfunc): POPENSSL_STACK; cdecl;

begin
  Result := sk_new(cmp);
end;



function COMPAT_OPENSSL_sk_new_null: POPENSSL_STACK; cdecl;

begin
  Result := sk_new_null;
end;



function COMPAT_OPENSSL_sk_new_reserve(c:TOPENSSL_sk_compfunc; n:longint): POPENSSL_STACK; cdecl;

begin
  Result := sk_new_reserve(c,n);
end;



function COMPAT_OPENSSL_sk_reserve(st:POPENSSL_STACK; n:longint): longint; cdecl;

begin
  Result := sk_reserve(st,n);
end;



procedure COMPAT_OPENSSL_sk_free(_para1:POPENSSL_STACK); cdecl;

begin
  sk_free(_para1);
end;



procedure COMPAT_OPENSSL_sk_pop_free(st:POPENSSL_STACK; func:TOPENSSL_sk_freefunc); cdecl;

begin
  sk_pop_free(st, func);
end;



function COMPAT_OPENSSL_sk_deep_copy(_para1:POPENSSL_STACK; c:TOPENSSL_sk_copyfunc; f:TOPENSSL_sk_freefunc): POPENSSL_STACK; cdecl;

begin
  Result := sk_deep_copy(_para1,c,f);
end;



function COMPAT_OPENSSL_sk_insert(sk:POPENSSL_STACK; data:pointer; where:longint): longint; cdecl;

begin
  Result := sk_insert(sk,data,where);
end;



function COMPAT_OPENSSL_sk_delete(st:POPENSSL_STACK; loc:longint): pointer; cdecl;

begin
  Result := sk_delete(st,loc);
end;



function COMPAT_OPENSSL_sk_delete_ptr(st:POPENSSL_STACK; p:pointer): pointer; cdecl;

begin
  Result := sk_delete_ptr(st,p);
end;



function COMPAT_OPENSSL_sk_find(st:POPENSSL_STACK; data:pointer): longint; cdecl;

begin
  Result := sk_find(st,data);
end;



function COMPAT_OPENSSL_sk_find_ex(st:POPENSSL_STACK; data:pointer): longint; cdecl;

begin
  Result := sk_find_ex(st,data);
end;



function COMPAT_OPENSSL_sk_push(st:POPENSSL_STACK; data:pointer): longint; cdecl;

begin
  Result := sk_push(st,data);
end;



function COMPAT_OPENSSL_sk_unshift(st:POPENSSL_STACK; data:pointer): longint; cdecl;

begin
  Result := sk_unshift(st,data);
end;



function COMPAT_OPENSSL_sk_shift(st:POPENSSL_STACK): pointer; cdecl;

begin
  Result := sk_shift(st);
end;



function COMPAT_OPENSSL_sk_pop(st:POPENSSL_STACK): pointer; cdecl;

begin
  Result := sk_pop(st);
end;



procedure COMPAT_OPENSSL_sk_zero(st:POPENSSL_STACK); cdecl;

begin
  OPENSSL_sk_zero(st);
end;



function COMPAT_OPENSSL_sk_set_cmp_func(sk:POPENSSL_STACK; cmp:TOPENSSL_sk_compfunc): TOPENSSL_sk_compfunc; cdecl;

begin
  Result := sk_set_cmp_func(sk,cmp);
end;



function COMPAT_OPENSSL_sk_dup(st:POPENSSL_STACK): POPENSSL_STACK; cdecl;

begin
  Result := sk_dup(st);
end;



procedure COMPAT_OPENSSL_sk_sort(st:POPENSSL_STACK); cdecl;

begin
  OPENSSL_sk_sort(st);
end;



function COMPAT_OPENSSL_sk_is_sorted(st:POPENSSL_STACK): longint; cdecl;

begin
  Result := sk_is_sorted(st);
end;






{$ENDIF} { End of OPENSSL_NO_LEGACY_SUPPORT}
function Load_OPENSSL_sk_num(_para1:POPENSSL_STACK): longint; cdecl;
begin
  OPENSSL_sk_num := LoadLibCryptoFunction('OPENSSL_sk_num');
  if not assigned(OPENSSL_sk_num) then
{$IFNDEF OPENSSL_NO_LEGACY_SUPPORT}
    OPENSSL_sk_num := @COMPAT_OPENSSL_sk_num;
{$ELSE}
    EOpenSSLAPIFunctionNotPresent.RaiseException('OPENSSL_sk_num');
{$ENDIF} { End of OPENSSL_NO_LEGACY_SUPPORT}
  Result := OPENSSL_sk_num(_para1);
end;

function Load_OPENSSL_sk_value(_para1:POPENSSL_STACK; _para2:longint): pointer; cdecl;
begin
  OPENSSL_sk_value := LoadLibCryptoFunction('OPENSSL_sk_value');
  if not assigned(OPENSSL_sk_value) then
{$IFNDEF OPENSSL_NO_LEGACY_SUPPORT}
    OPENSSL_sk_value := @COMPAT_OPENSSL_sk_value;
{$ELSE}
    EOpenSSLAPIFunctionNotPresent.RaiseException('OPENSSL_sk_value');
{$ENDIF} { End of OPENSSL_NO_LEGACY_SUPPORT}
  Result := OPENSSL_sk_value(_para1,_para2);
end;

function Load_OPENSSL_sk_set(st:POPENSSL_STACK; i:longint; data:pointer): pointer; cdecl;
begin
  OPENSSL_sk_set := LoadLibCryptoFunction('OPENSSL_sk_set');
  if not assigned(OPENSSL_sk_set) then
{$IFNDEF OPENSSL_NO_LEGACY_SUPPORT}
    OPENSSL_sk_set := @COMPAT_OPENSSL_sk_set;
{$ELSE}
    EOpenSSLAPIFunctionNotPresent.RaiseException('OPENSSL_sk_set');
{$ENDIF} { End of OPENSSL_NO_LEGACY_SUPPORT}
  Result := OPENSSL_sk_set(st,i,data);
end;

function Load_OPENSSL_sk_new(cmp:TOPENSSL_sk_compfunc): POPENSSL_STACK; cdecl;
begin
  OPENSSL_sk_new := LoadLibCryptoFunction('OPENSSL_sk_new');
  if not assigned(OPENSSL_sk_new) then
{$IFNDEF OPENSSL_NO_LEGACY_SUPPORT}
    OPENSSL_sk_new := @COMPAT_OPENSSL_sk_new;
{$ELSE}
    EOpenSSLAPIFunctionNotPresent.RaiseException('OPENSSL_sk_new');
{$ENDIF} { End of OPENSSL_NO_LEGACY_SUPPORT}
  Result := OPENSSL_sk_new(cmp);
end;

function Load_OPENSSL_sk_new_null: POPENSSL_STACK; cdecl;
begin
  OPENSSL_sk_new_null := LoadLibCryptoFunction('OPENSSL_sk_new_null');
  if not assigned(OPENSSL_sk_new_null) then
{$IFNDEF OPENSSL_NO_LEGACY_SUPPORT}
    OPENSSL_sk_new_null := @COMPAT_OPENSSL_sk_new_null;
{$ELSE}
    EOpenSSLAPIFunctionNotPresent.RaiseException('OPENSSL_sk_new_null');
{$ENDIF} { End of OPENSSL_NO_LEGACY_SUPPORT}
  Result := OPENSSL_sk_new_null();
end;

function Load_OPENSSL_sk_new_reserve(c:TOPENSSL_sk_compfunc; n:longint): POPENSSL_STACK; cdecl;
begin
  OPENSSL_sk_new_reserve := LoadLibCryptoFunction('OPENSSL_sk_new_reserve');
  if not assigned(OPENSSL_sk_new_reserve) then
{$IFNDEF OPENSSL_NO_LEGACY_SUPPORT}
    OPENSSL_sk_new_reserve := @COMPAT_OPENSSL_sk_new_reserve;
{$ELSE}
    EOpenSSLAPIFunctionNotPresent.RaiseException('OPENSSL_sk_new_reserve');
{$ENDIF} { End of OPENSSL_NO_LEGACY_SUPPORT}
  Result := OPENSSL_sk_new_reserve(c,n);
end;

function Load_OPENSSL_sk_reserve(st:POPENSSL_STACK; n:longint): longint; cdecl;
begin
  OPENSSL_sk_reserve := LoadLibCryptoFunction('OPENSSL_sk_reserve');
  if not assigned(OPENSSL_sk_reserve) then
{$IFNDEF OPENSSL_NO_LEGACY_SUPPORT}
    OPENSSL_sk_reserve := @COMPAT_OPENSSL_sk_reserve;
{$ELSE}
    EOpenSSLAPIFunctionNotPresent.RaiseException('OPENSSL_sk_reserve');
{$ENDIF} { End of OPENSSL_NO_LEGACY_SUPPORT}
  Result := OPENSSL_sk_reserve(st,n);
end;

procedure Load_OPENSSL_sk_free(_para1:POPENSSL_STACK); cdecl;
begin
  OPENSSL_sk_free := LoadLibCryptoFunction('OPENSSL_sk_free');
  if not assigned(OPENSSL_sk_free) then
{$IFNDEF OPENSSL_NO_LEGACY_SUPPORT}
    OPENSSL_sk_free := @COMPAT_OPENSSL_sk_free;
{$ELSE}
    EOpenSSLAPIFunctionNotPresent.RaiseException('OPENSSL_sk_free');
{$ENDIF} { End of OPENSSL_NO_LEGACY_SUPPORT}
  OPENSSL_sk_free(_para1);
end;

procedure Load_OPENSSL_sk_pop_free(st:POPENSSL_STACK; func:TOPENSSL_sk_freefunc); cdecl;
begin
  OPENSSL_sk_pop_free := LoadLibCryptoFunction('OPENSSL_sk_pop_free');
  if not assigned(OPENSSL_sk_pop_free) then
{$IFNDEF OPENSSL_NO_LEGACY_SUPPORT}
    OPENSSL_sk_pop_free := @COMPAT_OPENSSL_sk_pop_free;
{$ELSE}
    EOpenSSLAPIFunctionNotPresent.RaiseException('OPENSSL_sk_pop_free');
{$ENDIF} { End of OPENSSL_NO_LEGACY_SUPPORT}
  OPENSSL_sk_pop_free(st,func);
end;

function Load_OPENSSL_sk_deep_copy(_para1:POPENSSL_STACK; c:TOPENSSL_sk_copyfunc; f:TOPENSSL_sk_freefunc): POPENSSL_STACK; cdecl;
begin
  OPENSSL_sk_deep_copy := LoadLibCryptoFunction('OPENSSL_sk_deep_copy');
  if not assigned(OPENSSL_sk_deep_copy) then
{$IFNDEF OPENSSL_NO_LEGACY_SUPPORT}
    OPENSSL_sk_deep_copy := @COMPAT_OPENSSL_sk_deep_copy;
{$ELSE}
    EOpenSSLAPIFunctionNotPresent.RaiseException('OPENSSL_sk_deep_copy');
{$ENDIF} { End of OPENSSL_NO_LEGACY_SUPPORT}
  Result := OPENSSL_sk_deep_copy(_para1,c,f);
end;

function Load_OPENSSL_sk_insert(sk:POPENSSL_STACK; data:pointer; where:longint): longint; cdecl;
begin
  OPENSSL_sk_insert := LoadLibCryptoFunction('OPENSSL_sk_insert');
  if not assigned(OPENSSL_sk_insert) then
{$IFNDEF OPENSSL_NO_LEGACY_SUPPORT}
    OPENSSL_sk_insert := @COMPAT_OPENSSL_sk_insert;
{$ELSE}
    EOpenSSLAPIFunctionNotPresent.RaiseException('OPENSSL_sk_insert');
{$ENDIF} { End of OPENSSL_NO_LEGACY_SUPPORT}
  Result := OPENSSL_sk_insert(sk,data,where);
end;

function Load_OPENSSL_sk_delete(st:POPENSSL_STACK; loc:longint): pointer; cdecl;
begin
  OPENSSL_sk_delete := LoadLibCryptoFunction('OPENSSL_sk_delete');
  if not assigned(OPENSSL_sk_delete) then
{$IFNDEF OPENSSL_NO_LEGACY_SUPPORT}
    OPENSSL_sk_delete := @COMPAT_OPENSSL_sk_delete;
{$ELSE}
    EOpenSSLAPIFunctionNotPresent.RaiseException('OPENSSL_sk_delete');
{$ENDIF} { End of OPENSSL_NO_LEGACY_SUPPORT}
  Result := OPENSSL_sk_delete(st,loc);
end;

function Load_OPENSSL_sk_delete_ptr(st:POPENSSL_STACK; p:pointer): pointer; cdecl;
begin
  OPENSSL_sk_delete_ptr := LoadLibCryptoFunction('OPENSSL_sk_delete_ptr');
  if not assigned(OPENSSL_sk_delete_ptr) then
{$IFNDEF OPENSSL_NO_LEGACY_SUPPORT}
    OPENSSL_sk_delete_ptr := @COMPAT_OPENSSL_sk_delete_ptr;
{$ELSE}
    EOpenSSLAPIFunctionNotPresent.RaiseException('OPENSSL_sk_delete_ptr');
{$ENDIF} { End of OPENSSL_NO_LEGACY_SUPPORT}
  Result := OPENSSL_sk_delete_ptr(st,p);
end;

function Load_OPENSSL_sk_find(st:POPENSSL_STACK; data:pointer): longint; cdecl;
begin
  OPENSSL_sk_find := LoadLibCryptoFunction('OPENSSL_sk_find');
  if not assigned(OPENSSL_sk_find) then
{$IFNDEF OPENSSL_NO_LEGACY_SUPPORT}
    OPENSSL_sk_find := @COMPAT_OPENSSL_sk_find;
{$ELSE}
    EOpenSSLAPIFunctionNotPresent.RaiseException('OPENSSL_sk_find');
{$ENDIF} { End of OPENSSL_NO_LEGACY_SUPPORT}
  Result := OPENSSL_sk_find(st,data);
end;

function Load_OPENSSL_sk_find_ex(st:POPENSSL_STACK; data:pointer): longint; cdecl;
begin
  OPENSSL_sk_find_ex := LoadLibCryptoFunction('OPENSSL_sk_find_ex');
  if not assigned(OPENSSL_sk_find_ex) then
{$IFNDEF OPENSSL_NO_LEGACY_SUPPORT}
    OPENSSL_sk_find_ex := @COMPAT_OPENSSL_sk_find_ex;
{$ELSE}
    EOpenSSLAPIFunctionNotPresent.RaiseException('OPENSSL_sk_find_ex');
{$ENDIF} { End of OPENSSL_NO_LEGACY_SUPPORT}
  Result := OPENSSL_sk_find_ex(st,data);
end;

function Load_OPENSSL_sk_push(st:POPENSSL_STACK; data:pointer): longint; cdecl;
begin
  OPENSSL_sk_push := LoadLibCryptoFunction('OPENSSL_sk_push');
  if not assigned(OPENSSL_sk_push) then
{$IFNDEF OPENSSL_NO_LEGACY_SUPPORT}
    OPENSSL_sk_push := @COMPAT_OPENSSL_sk_push;
{$ELSE}
    EOpenSSLAPIFunctionNotPresent.RaiseException('OPENSSL_sk_push');
{$ENDIF} { End of OPENSSL_NO_LEGACY_SUPPORT}
  Result := OPENSSL_sk_push(st,data);
end;

function Load_OPENSSL_sk_unshift(st:POPENSSL_STACK; data:pointer): longint; cdecl;
begin
  OPENSSL_sk_unshift := LoadLibCryptoFunction('OPENSSL_sk_unshift');
  if not assigned(OPENSSL_sk_unshift) then
{$IFNDEF OPENSSL_NO_LEGACY_SUPPORT}
    OPENSSL_sk_unshift := @COMPAT_OPENSSL_sk_unshift;
{$ELSE}
    EOpenSSLAPIFunctionNotPresent.RaiseException('OPENSSL_sk_unshift');
{$ENDIF} { End of OPENSSL_NO_LEGACY_SUPPORT}
  Result := OPENSSL_sk_unshift(st,data);
end;

function Load_OPENSSL_sk_shift(st:POPENSSL_STACK): pointer; cdecl;
begin
  OPENSSL_sk_shift := LoadLibCryptoFunction('OPENSSL_sk_shift');
  if not assigned(OPENSSL_sk_shift) then
{$IFNDEF OPENSSL_NO_LEGACY_SUPPORT}
    OPENSSL_sk_shift := @COMPAT_OPENSSL_sk_shift;
{$ELSE}
    EOpenSSLAPIFunctionNotPresent.RaiseException('OPENSSL_sk_shift');
{$ENDIF} { End of OPENSSL_NO_LEGACY_SUPPORT}
  Result := OPENSSL_sk_shift(st);
end;

function Load_OPENSSL_sk_pop(st:POPENSSL_STACK): pointer; cdecl;
begin
  OPENSSL_sk_pop := LoadLibCryptoFunction('OPENSSL_sk_pop');
  if not assigned(OPENSSL_sk_pop) then
{$IFNDEF OPENSSL_NO_LEGACY_SUPPORT}
    OPENSSL_sk_pop := @COMPAT_OPENSSL_sk_pop;
{$ELSE}
    EOpenSSLAPIFunctionNotPresent.RaiseException('OPENSSL_sk_pop');
{$ENDIF} { End of OPENSSL_NO_LEGACY_SUPPORT}
  Result := OPENSSL_sk_pop(st);
end;

procedure Load_OPENSSL_sk_zero(st:POPENSSL_STACK); cdecl;
begin
  OPENSSL_sk_zero := LoadLibCryptoFunction('OPENSSL_sk_zero');
  if not assigned(OPENSSL_sk_zero) then
{$IFNDEF OPENSSL_NO_LEGACY_SUPPORT}
    OPENSSL_sk_zero := @COMPAT_OPENSSL_sk_zero;
{$ELSE}
    EOpenSSLAPIFunctionNotPresent.RaiseException('OPENSSL_sk_zero');
{$ENDIF} { End of OPENSSL_NO_LEGACY_SUPPORT}
  OPENSSL_sk_zero(st);
end;

function Load_OPENSSL_sk_set_cmp_func(sk:POPENSSL_STACK; cmp:TOPENSSL_sk_compfunc): TOPENSSL_sk_compfunc; cdecl;
begin
  OPENSSL_sk_set_cmp_func := LoadLibCryptoFunction('OPENSSL_sk_set_cmp_func');
  if not assigned(OPENSSL_sk_set_cmp_func) then
{$IFNDEF OPENSSL_NO_LEGACY_SUPPORT}
    OPENSSL_sk_set_cmp_func := @COMPAT_OPENSSL_sk_set_cmp_func;
{$ELSE}
    EOpenSSLAPIFunctionNotPresent.RaiseException('OPENSSL_sk_set_cmp_func');
{$ENDIF} { End of OPENSSL_NO_LEGACY_SUPPORT}
  Result := OPENSSL_sk_set_cmp_func(sk,cmp);
end;

function Load_OPENSSL_sk_dup(st:POPENSSL_STACK): POPENSSL_STACK; cdecl;
begin
  OPENSSL_sk_dup := LoadLibCryptoFunction('OPENSSL_sk_dup');
  if not assigned(OPENSSL_sk_dup) then
{$IFNDEF OPENSSL_NO_LEGACY_SUPPORT}
    OPENSSL_sk_dup := @COMPAT_OPENSSL_sk_dup;
{$ELSE}
    EOpenSSLAPIFunctionNotPresent.RaiseException('OPENSSL_sk_dup');
{$ENDIF} { End of OPENSSL_NO_LEGACY_SUPPORT}
  Result := OPENSSL_sk_dup(st);
end;

procedure Load_OPENSSL_sk_sort(st:POPENSSL_STACK); cdecl;
begin
  OPENSSL_sk_sort := LoadLibCryptoFunction('OPENSSL_sk_sort');
  if not assigned(OPENSSL_sk_sort) then
{$IFNDEF OPENSSL_NO_LEGACY_SUPPORT}
    OPENSSL_sk_sort := @COMPAT_OPENSSL_sk_sort;
{$ELSE}
    EOpenSSLAPIFunctionNotPresent.RaiseException('OPENSSL_sk_sort');
{$ENDIF} { End of OPENSSL_NO_LEGACY_SUPPORT}
  OPENSSL_sk_sort(st);
end;

function Load_OPENSSL_sk_is_sorted(st:POPENSSL_STACK): longint; cdecl;
begin
  OPENSSL_sk_is_sorted := LoadLibCryptoFunction('OPENSSL_sk_is_sorted');
  if not assigned(OPENSSL_sk_is_sorted) then
{$IFNDEF OPENSSL_NO_LEGACY_SUPPORT}
    OPENSSL_sk_is_sorted := @COMPAT_OPENSSL_sk_is_sorted;
{$ELSE}
    EOpenSSLAPIFunctionNotPresent.RaiseException('OPENSSL_sk_is_sorted');
{$ENDIF} { End of OPENSSL_NO_LEGACY_SUPPORT}
  Result := OPENSSL_sk_is_sorted(st);
end;

{$IFNDEF OPENSSL_NO_LEGACY_SUPPORT}
function Load_sk_num(_para1:POPENSSL_STACK): longint; cdecl;
begin
  sk_num := LoadLibCryptoFunction('sk_num');
  if not assigned(sk_num) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('sk_num');
  Result := sk_num(_para1);
end;

function Load_sk_value(_para1:POPENSSL_STACK; _para2:longint): pointer; cdecl;
begin
  sk_value := LoadLibCryptoFunction('sk_value');
  if not assigned(sk_value) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('sk_value');
  Result := sk_value(_para1,_para2);
end;

function Load_sk_set(st:POPENSSL_STACK; i:longint; data:pointer): pointer; cdecl;
begin
  sk_set := LoadLibCryptoFunction('sk_set');
  if not assigned(sk_set) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('sk_set');
  Result := sk_set(st,i,data);
end;

function Load_sk_new(cmp:TOPENSSL_sk_compfunc): POPENSSL_STACK; cdecl;
begin
  sk_new := LoadLibCryptoFunction('sk_new');
  if not assigned(sk_new) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('sk_new');
  Result := sk_new(cmp);
end;

function Load_sk_new_null: POPENSSL_STACK; cdecl;
begin
  sk_new_null := LoadLibCryptoFunction('sk_new_null');
  if not assigned(sk_new_null) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('sk_new_null');
  Result := sk_new_null();
end;

function Load_sk_new_reserve(c:TOPENSSL_sk_compfunc; n:longint): POPENSSL_STACK; cdecl;
begin
  sk_new_reserve := LoadLibCryptoFunction('sk_new_reserve');
  if not assigned(sk_new_reserve) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('sk_new_reserve');
  Result := sk_new_reserve(c,n);
end;

function Load_sk_reserve(st:POPENSSL_STACK; n:longint): longint; cdecl;
begin
  sk_reserve := LoadLibCryptoFunction('sk_reserve');
  if not assigned(sk_reserve) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('sk_reserve');
  Result := sk_reserve(st,n);
end;

procedure Load_sk_free(_para1:POPENSSL_STACK); cdecl;
begin
  sk_free := LoadLibCryptoFunction('sk_free');
  if not assigned(sk_free) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('sk_free');
  sk_free(_para1);
end;

procedure Load_sk_pop_free(st:POPENSSL_STACK; func:TOPENSSL_sk_freefunc); cdecl;
begin
  sk_pop_free := LoadLibCryptoFunction('sk_pop_free');
  if not assigned(sk_pop_free) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('sk_pop_free');
  sk_pop_free(st,func);
end;

function Load_sk_deep_copy(_para1:POPENSSL_STACK; c:TOPENSSL_sk_copyfunc; f:TOPENSSL_sk_freefunc): POPENSSL_STACK; cdecl;
begin
  sk_deep_copy := LoadLibCryptoFunction('sk_deep_copy');
  if not assigned(sk_deep_copy) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('sk_deep_copy');
  Result := sk_deep_copy(_para1,c,f);
end;

function Load_sk_insert(sk:POPENSSL_STACK; data:pointer; where:longint): longint; cdecl;
begin
  sk_insert := LoadLibCryptoFunction('sk_insert');
  if not assigned(sk_insert) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('sk_insert');
  Result := sk_insert(sk,data,where);
end;

function Load_sk_delete(st:POPENSSL_STACK; loc:longint): pointer; cdecl;
begin
  sk_delete := LoadLibCryptoFunction('sk_delete');
  if not assigned(sk_delete) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('sk_delete');
  Result := sk_delete(st,loc);
end;

function Load_sk_delete_ptr(st:POPENSSL_STACK; p:pointer): pointer; cdecl;
begin
  sk_delete_ptr := LoadLibCryptoFunction('sk_delete_ptr');
  if not assigned(sk_delete_ptr) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('sk_delete_ptr');
  Result := sk_delete_ptr(st,p);
end;

function Load_sk_find(st:POPENSSL_STACK; data:pointer): longint; cdecl;
begin
  sk_find := LoadLibCryptoFunction('sk_find');
  if not assigned(sk_find) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('sk_find');
  Result := sk_find(st,data);
end;

function Load_sk_find_ex(st:POPENSSL_STACK; data:pointer): longint; cdecl;
begin
  sk_find_ex := LoadLibCryptoFunction('sk_find_ex');
  if not assigned(sk_find_ex) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('sk_find_ex');
  Result := sk_find_ex(st,data);
end;

function Load_sk_push(st:POPENSSL_STACK; data:pointer): longint; cdecl;
begin
  sk_push := LoadLibCryptoFunction('sk_push');
  if not assigned(sk_push) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('sk_push');
  Result := sk_push(st,data);
end;

function Load_sk_unshift(st:POPENSSL_STACK; data:pointer): longint; cdecl;
begin
  sk_unshift := LoadLibCryptoFunction('sk_unshift');
  if not assigned(sk_unshift) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('sk_unshift');
  Result := sk_unshift(st,data);
end;

function Load_sk_shift(st:POPENSSL_STACK): pointer; cdecl;
begin
  sk_shift := LoadLibCryptoFunction('sk_shift');
  if not assigned(sk_shift) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('sk_shift');
  Result := sk_shift(st);
end;

function Load_sk_pop(st:POPENSSL_STACK): pointer; cdecl;
begin
  sk_pop := LoadLibCryptoFunction('sk_pop');
  if not assigned(sk_pop) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('sk_pop');
  Result := sk_pop(st);
end;

procedure Load_sk_zero(st:POPENSSL_STACK); cdecl;
begin
  sk_zero := LoadLibCryptoFunction('sk_zero');
  if not assigned(sk_zero) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('sk_zero');
  sk_zero(st);
end;

function Load_sk_set_cmp_func(sk:POPENSSL_STACK; cmp:TOPENSSL_sk_compfunc): TOPENSSL_sk_compfunc; cdecl;
begin
  sk_set_cmp_func := LoadLibCryptoFunction('sk_set_cmp_func');
  if not assigned(sk_set_cmp_func) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('sk_set_cmp_func');
  Result := sk_set_cmp_func(sk,cmp);
end;

function Load_sk_dup(st:POPENSSL_STACK): POPENSSL_STACK; cdecl;
begin
  sk_dup := LoadLibCryptoFunction('sk_dup');
  if not assigned(sk_dup) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('sk_dup');
  Result := sk_dup(st);
end;

procedure Load_sk_sort(st:POPENSSL_STACK); cdecl;
begin
  sk_sort := LoadLibCryptoFunction('sk_sort');
  if not assigned(sk_sort) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('sk_sort');
  sk_sort(st);
end;

function Load_sk_is_sorted(st:POPENSSL_STACK): longint; cdecl;
begin
  sk_is_sorted := LoadLibCryptoFunction('sk_is_sorted');
  if not assigned(sk_is_sorted) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('sk_is_sorted');
  Result := sk_is_sorted(st);
end;

{$ENDIF} //of OPENSSL_NO_LEGACY_SUPPORT

procedure UnLoad;
begin
  OPENSSL_sk_num := Load_OPENSSL_sk_num;
  OPENSSL_sk_value := Load_OPENSSL_sk_value;
  OPENSSL_sk_set := Load_OPENSSL_sk_set;
  OPENSSL_sk_new := Load_OPENSSL_sk_new;
  OPENSSL_sk_new_null := Load_OPENSSL_sk_new_null;
  OPENSSL_sk_new_reserve := Load_OPENSSL_sk_new_reserve;
  OPENSSL_sk_reserve := Load_OPENSSL_sk_reserve;
  OPENSSL_sk_free := Load_OPENSSL_sk_free;
  OPENSSL_sk_pop_free := Load_OPENSSL_sk_pop_free;
  OPENSSL_sk_deep_copy := Load_OPENSSL_sk_deep_copy;
  OPENSSL_sk_insert := Load_OPENSSL_sk_insert;
  OPENSSL_sk_delete := Load_OPENSSL_sk_delete;
  OPENSSL_sk_delete_ptr := Load_OPENSSL_sk_delete_ptr;
  OPENSSL_sk_find := Load_OPENSSL_sk_find;
  OPENSSL_sk_find_ex := Load_OPENSSL_sk_find_ex;
  OPENSSL_sk_push := Load_OPENSSL_sk_push;
  OPENSSL_sk_unshift := Load_OPENSSL_sk_unshift;
  OPENSSL_sk_shift := Load_OPENSSL_sk_shift;
  OPENSSL_sk_pop := Load_OPENSSL_sk_pop;
  OPENSSL_sk_zero := Load_OPENSSL_sk_zero;
  OPENSSL_sk_set_cmp_func := Load_OPENSSL_sk_set_cmp_func;
  OPENSSL_sk_dup := Load_OPENSSL_sk_dup;
  OPENSSL_sk_sort := Load_OPENSSL_sk_sort;
  OPENSSL_sk_is_sorted := Load_OPENSSL_sk_is_sorted;
{$IFNDEF OPENSSL_NO_LEGACY_SUPPORT}
  sk_num := Load_sk_num;
  sk_value := Load_sk_value;
  sk_set := Load_sk_set;
  sk_new := Load_sk_new;
  sk_new_null := Load_sk_new_null;
  sk_new_reserve := Load_sk_new_reserve;
  sk_reserve := Load_sk_reserve;
  sk_free := Load_sk_free;
  sk_pop_free := Load_sk_pop_free;
  sk_deep_copy := Load_sk_deep_copy;
  sk_insert := Load_sk_insert;
  sk_delete := Load_sk_delete;
  sk_delete_ptr := Load_sk_delete_ptr;
  sk_find := Load_sk_find;
  sk_find_ex := Load_sk_find_ex;
  sk_push := Load_sk_push;
  sk_unshift := Load_sk_unshift;
  sk_shift := Load_sk_shift;
  sk_pop := Load_sk_pop;
  sk_zero := Load_sk_zero;
  sk_set_cmp_func := Load_sk_set_cmp_func;
  sk_dup := Load_sk_dup;
  sk_sort := Load_sk_sort;
  sk_is_sorted := Load_sk_is_sorted;
{$ENDIF} //of OPENSSL_NO_LEGACY_SUPPORT
end;
{$ENDIF}

initialization

{$IFNDEF OPENSSL_STATIC_LINK_MODEL}
Register_SSLUnloader(@Unload);
{$ENDIF}
finalization


end.
