  (* This unit was generated using the script genOpenSSLHdrs.sh from the source file IdOpenSSLHeaders_stack.h2pas
     It should not be modified directly. All changes should be made to IdOpenSSLHeaders_stack.h2pas
     and this file regenerated. IdOpenSSLHeaders_stack.h2pas is distributed with the full Indy
     Distribution.
   *)
   
{$i IdCompilerDefines.inc} 
{$i IdSSLOpenSSLDefines.inc} 
{$IFNDEF USE_OPENSSL}
  { error Should not compile if USE_OPENSSL is not defined!!!}
{$ENDIF}
{******************************************************************************}
{                                                                              }
{            Indy (Internet Direct) - Internet Protocols Simplified            }
{                                                                              }
{            https://www.indyproject.org/                                      }
{            https://gitter.im/IndySockets/Indy                                }
{                                                                              }
{******************************************************************************}
{                                                                              }
{  This file is part of the Indy (Internet Direct) project, and is offered     }
{  under the dual-licensing agreement described on the Indy website.           }
{  (https://www.indyproject.org/license/)                                      }
{                                                                              }
{  Copyright:                                                                  }
{   (c) 1993-2020, Chad Z. Hower and the Indy Pit Crew. All rights reserved.   }
{                                                                              }
{******************************************************************************}
{                                                                              }
{                                                                              }
{******************************************************************************}
unit IdOpenSSLHeaders_stack;

interface

uses
    IdCTypes,
    IdGlobal,
    IdSSLOpenSSLConsts;


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
	  
  {$EXTERNALSYM OPENSSL_sk_num} {introduced 1.1.0}
  {$EXTERNALSYM OPENSSL_sk_value} {introduced 1.1.0}
  {$EXTERNALSYM OPENSSL_sk_set} {introduced 1.1.0}
  {$EXTERNALSYM OPENSSL_sk_new} {introduced 1.1.0}
  {$EXTERNALSYM OPENSSL_sk_new_null} {introduced 1.1.0}
  {$EXTERNALSYM OPENSSL_sk_new_reserve} {introduced 1.1.0}
  {$EXTERNALSYM OPENSSL_sk_reserve} {introduced 1.1.0}
  {$EXTERNALSYM OPENSSL_sk_free} {introduced 1.1.0}
  {$EXTERNALSYM OPENSSL_sk_pop_free} {introduced 1.1.0}
  {$EXTERNALSYM OPENSSL_sk_deep_copy} {introduced 1.1.0}
  {$EXTERNALSYM OPENSSL_sk_insert} {introduced 1.1.0}
  {$EXTERNALSYM OPENSSL_sk_delete} {introduced 1.1.0}
  {$EXTERNALSYM OPENSSL_sk_delete_ptr} {introduced 1.1.0}
  {$EXTERNALSYM OPENSSL_sk_find} {introduced 1.1.0}
  {$EXTERNALSYM OPENSSL_sk_find_ex} {introduced 1.1.0}
  {$EXTERNALSYM OPENSSL_sk_push} {introduced 1.1.0}
  {$EXTERNALSYM OPENSSL_sk_unshift} {introduced 1.1.0}
  {$EXTERNALSYM OPENSSL_sk_shift} {introduced 1.1.0}
  {$EXTERNALSYM OPENSSL_sk_pop} {introduced 1.1.0}
  {$EXTERNALSYM OPENSSL_sk_zero} {introduced 1.1.0}
  {$EXTERNALSYM OPENSSL_sk_set_cmp_func} {introduced 1.1.0}
  {$EXTERNALSYM OPENSSL_sk_dup} {introduced 1.1.0}
  {$EXTERNALSYM OPENSSL_sk_sort} {introduced 1.1.0}
  {$EXTERNALSYM OPENSSL_sk_is_sorted} {introduced 1.1.0}

{$IFNDEF OPENSSL_STATIC_LINK_MODEL}
var
  {$EXTERNALSYM sk_num} {removed 1.1.0}
  {$EXTERNALSYM sk_value} {removed 1.1.0}
  {$EXTERNALSYM sk_set} {removed 1.1.0}
  {$EXTERNALSYM sk_new} {removed 1.1.0}
  {$EXTERNALSYM sk_new_null} {removed 1.1.0}
  {$EXTERNALSYM sk_new_reserve} {removed 1.0.0}
  {$EXTERNALSYM sk_reserve} {removed 1.0.0}
  {$EXTERNALSYM sk_free} {removed 1.1.0}
  {$EXTERNALSYM sk_pop_free} {removed 1.1.0}
  {$EXTERNALSYM sk_deep_copy} {removed 1.1.0}
  {$EXTERNALSYM sk_insert} {removed 1.1.0}
  {$EXTERNALSYM sk_delete} {removed 1.1.0}
  {$EXTERNALSYM sk_delete_ptr} {removed 1.1.0}
  {$EXTERNALSYM sk_find} {removed 1.1.0}
  {$EXTERNALSYM sk_find_ex} {removed 1.1.0}
  {$EXTERNALSYM sk_push} {removed 1.1.0}
  {$EXTERNALSYM sk_unshift} {removed 1.1.0}
  {$EXTERNALSYM sk_shift} {removed 1.1.0}
  {$EXTERNALSYM sk_pop} {removed 1.1.0}
  {$EXTERNALSYM sk_zero} {removed 1.1.0}
  {$EXTERNALSYM sk_set_cmp_func} {removed 1.1.0}
  {$EXTERNALSYM sk_dup} {removed 1.1.0}
  {$EXTERNALSYM sk_sort} {removed 1.1.0}
  {$EXTERNALSYM sk_is_sorted} {removed 1.1.0}
  OPENSSL_sk_num: function (_para1:POPENSSL_STACK):longint; cdecl = nil; {introduced 1.1.0}
  OPENSSL_sk_value: function (_para1:POPENSSL_STACK; _para2:longint):pointer; cdecl = nil; {introduced 1.1.0}
  OPENSSL_sk_set: function (st:POPENSSL_STACK; i:longint; data:pointer):pointer; cdecl = nil; {introduced 1.1.0}
  OPENSSL_sk_new: function (cmp:TOPENSSL_sk_compfunc):POPENSSL_STACK; cdecl = nil; {introduced 1.1.0}
  OPENSSL_sk_new_null: function :POPENSSL_STACK; cdecl = nil; {introduced 1.1.0}
  OPENSSL_sk_new_reserve: function (c:TOPENSSL_sk_compfunc; n:longint):POPENSSL_STACK; cdecl = nil; {introduced 1.1.0}
  OPENSSL_sk_reserve: function (st:POPENSSL_STACK; n:longint):longint; cdecl = nil; {introduced 1.1.0}
  OPENSSL_sk_free: procedure (_para1:POPENSSL_STACK); cdecl = nil; {introduced 1.1.0}
  OPENSSL_sk_pop_free: procedure (st:POPENSSL_STACK; func:TOPENSSL_sk_freefunc); cdecl = nil; {introduced 1.1.0}
  OPENSSL_sk_deep_copy: function (_para1:POPENSSL_STACK; c:TOPENSSL_sk_copyfunc; f:TOPENSSL_sk_freefunc):POPENSSL_STACK; cdecl = nil; {introduced 1.1.0}
  OPENSSL_sk_insert: function (sk:POPENSSL_STACK; data:pointer; where:longint):longint; cdecl = nil; {introduced 1.1.0}
  OPENSSL_sk_delete: function (st:POPENSSL_STACK; loc:longint):pointer; cdecl = nil; {introduced 1.1.0}
  OPENSSL_sk_delete_ptr: function (st:POPENSSL_STACK; p:pointer):pointer; cdecl = nil; {introduced 1.1.0}
  OPENSSL_sk_find: function (st:POPENSSL_STACK; data:pointer):longint; cdecl = nil; {introduced 1.1.0}
  OPENSSL_sk_find_ex: function (st:POPENSSL_STACK; data:pointer):longint; cdecl = nil; {introduced 1.1.0}
  OPENSSL_sk_push: function (st:POPENSSL_STACK; data:pointer):longint; cdecl = nil; {introduced 1.1.0}
  OPENSSL_sk_unshift: function (st:POPENSSL_STACK; data:pointer):longint; cdecl = nil; {introduced 1.1.0}
  OPENSSL_sk_shift: function (st:POPENSSL_STACK):pointer; cdecl = nil; {introduced 1.1.0}
  OPENSSL_sk_pop: function (st:POPENSSL_STACK):pointer; cdecl = nil; {introduced 1.1.0}
  OPENSSL_sk_zero: procedure (st:POPENSSL_STACK); cdecl = nil; {introduced 1.1.0}
  OPENSSL_sk_set_cmp_func: function (sk:POPENSSL_STACK; cmp:TOPENSSL_sk_compfunc):TOPENSSL_sk_compfunc; cdecl = nil; {introduced 1.1.0}
  OPENSSL_sk_dup: function (st:POPENSSL_STACK):POPENSSL_STACK; cdecl = nil; {introduced 1.1.0}
  OPENSSL_sk_sort: procedure (st:POPENSSL_STACK); cdecl = nil; {introduced 1.1.0}
  OPENSSL_sk_is_sorted: function (st:POPENSSL_STACK):longint; cdecl = nil; {introduced 1.1.0}

  sk_num: function (_para1:POPENSSL_STACK):longint; cdecl = nil; {removed 1.1.0}
  sk_value: function (_para1:POPENSSL_STACK; _para2:longint):pointer; cdecl = nil; {removed 1.1.0}
  sk_set: function (st:POPENSSL_STACK; i:longint; data:pointer):pointer; cdecl = nil; {removed 1.1.0}
  sk_new: function (cmp:TOPENSSL_sk_compfunc):POPENSSL_STACK; cdecl = nil; {removed 1.1.0}
  sk_new_null: function :POPENSSL_STACK; cdecl = nil; {removed 1.1.0}
  sk_new_reserve: function (c:TOPENSSL_sk_compfunc; n:longint):POPENSSL_STACK; cdecl = nil; {removed 1.0.0}
  sk_reserve: function (st:POPENSSL_STACK; n:longint):longint; cdecl = nil; {removed 1.0.0}
  sk_free: procedure (_para1:POPENSSL_STACK); cdecl = nil; {removed 1.1.0}
  sk_pop_free: procedure (st:POPENSSL_STACK; func:TOPENSSL_sk_freefunc); cdecl = nil; {removed 1.1.0}
  sk_deep_copy: function (_para1:POPENSSL_STACK; c:TOPENSSL_sk_copyfunc; f:TOPENSSL_sk_freefunc):POPENSSL_STACK; cdecl = nil; {removed 1.1.0}
  sk_insert: function (sk:POPENSSL_STACK; data:pointer; where:longint):longint; cdecl = nil; {removed 1.1.0}
  sk_delete: function (st:POPENSSL_STACK; loc:longint):pointer; cdecl = nil; {removed 1.1.0}
  sk_delete_ptr: function (st:POPENSSL_STACK; p:pointer):pointer; cdecl = nil; {removed 1.1.0}
  sk_find: function (st:POPENSSL_STACK; data:pointer):longint; cdecl = nil; {removed 1.1.0}
  sk_find_ex: function (st:POPENSSL_STACK; data:pointer):longint; cdecl = nil; {removed 1.1.0}
  sk_push: function (st:POPENSSL_STACK; data:pointer):longint; cdecl = nil; {removed 1.1.0}
  sk_unshift: function (st:POPENSSL_STACK; data:pointer):longint; cdecl = nil; {removed 1.1.0}
  sk_shift: function (st:POPENSSL_STACK):pointer; cdecl = nil; {removed 1.1.0}
  sk_pop: function (st:POPENSSL_STACK):pointer; cdecl = nil; {removed 1.1.0}
  sk_zero: procedure (st:POPENSSL_STACK); cdecl = nil; {removed 1.1.0}
  sk_set_cmp_func: function (sk:POPENSSL_STACK; cmp:TOPENSSL_sk_compfunc):TOPENSSL_sk_compfunc; cdecl = nil; {removed 1.1.0}
  sk_dup: function (st:POPENSSL_STACK):POPENSSL_STACK; cdecl = nil; {removed 1.1.0}
  sk_sort: procedure (st:POPENSSL_STACK); cdecl = nil; {removed 1.1.0}
  sk_is_sorted: function (st:POPENSSL_STACK):longint; cdecl = nil; {removed 1.1.0}

{$ELSE}
  function OPENSSL_sk_num(_para1:POPENSSL_STACK):longint cdecl; external CLibCrypto; {introduced 1.1.0}
  function OPENSSL_sk_value(_para1:POPENSSL_STACK; _para2:longint):pointer cdecl; external CLibCrypto; {introduced 1.1.0}
  function OPENSSL_sk_set(st:POPENSSL_STACK; i:longint; data:pointer):pointer cdecl; external CLibCrypto; {introduced 1.1.0}
  function OPENSSL_sk_new(cmp:TOPENSSL_sk_compfunc):POPENSSL_STACK cdecl; external CLibCrypto; {introduced 1.1.0}
  function OPENSSL_sk_new_null:POPENSSL_STACK cdecl; external CLibCrypto; {introduced 1.1.0}
  function OPENSSL_sk_new_reserve(c:TOPENSSL_sk_compfunc; n:longint):POPENSSL_STACK cdecl; external CLibCrypto; {introduced 1.1.0}
  function OPENSSL_sk_reserve(st:POPENSSL_STACK; n:longint):longint cdecl; external CLibCrypto; {introduced 1.1.0}
  procedure OPENSSL_sk_free(_para1:POPENSSL_STACK) cdecl; external CLibCrypto; {introduced 1.1.0}
  procedure OPENSSL_sk_pop_free(st:POPENSSL_STACK; func:TOPENSSL_sk_freefunc) cdecl; external CLibCrypto; {introduced 1.1.0}
  function OPENSSL_sk_deep_copy(_para1:POPENSSL_STACK; c:TOPENSSL_sk_copyfunc; f:TOPENSSL_sk_freefunc):POPENSSL_STACK cdecl; external CLibCrypto; {introduced 1.1.0}
  function OPENSSL_sk_insert(sk:POPENSSL_STACK; data:pointer; where:longint):longint cdecl; external CLibCrypto; {introduced 1.1.0}
  function OPENSSL_sk_delete(st:POPENSSL_STACK; loc:longint):pointer cdecl; external CLibCrypto; {introduced 1.1.0}
  function OPENSSL_sk_delete_ptr(st:POPENSSL_STACK; p:pointer):pointer cdecl; external CLibCrypto; {introduced 1.1.0}
  function OPENSSL_sk_find(st:POPENSSL_STACK; data:pointer):longint cdecl; external CLibCrypto; {introduced 1.1.0}
  function OPENSSL_sk_find_ex(st:POPENSSL_STACK; data:pointer):longint cdecl; external CLibCrypto; {introduced 1.1.0}
  function OPENSSL_sk_push(st:POPENSSL_STACK; data:pointer):longint cdecl; external CLibCrypto; {introduced 1.1.0}
  function OPENSSL_sk_unshift(st:POPENSSL_STACK; data:pointer):longint cdecl; external CLibCrypto; {introduced 1.1.0}
  function OPENSSL_sk_shift(st:POPENSSL_STACK):pointer cdecl; external CLibCrypto; {introduced 1.1.0}
  function OPENSSL_sk_pop(st:POPENSSL_STACK):pointer cdecl; external CLibCrypto; {introduced 1.1.0}
  procedure OPENSSL_sk_zero(st:POPENSSL_STACK) cdecl; external CLibCrypto; {introduced 1.1.0}
  function OPENSSL_sk_set_cmp_func(sk:POPENSSL_STACK; cmp:TOPENSSL_sk_compfunc):TOPENSSL_sk_compfunc cdecl; external CLibCrypto; {introduced 1.1.0}
  function OPENSSL_sk_dup(st:POPENSSL_STACK):POPENSSL_STACK cdecl; external CLibCrypto; {introduced 1.1.0}
  procedure OPENSSL_sk_sort(st:POPENSSL_STACK) cdecl; external CLibCrypto; {introduced 1.1.0}
  function OPENSSL_sk_is_sorted(st:POPENSSL_STACK):longint cdecl; external CLibCrypto; {introduced 1.1.0}


  function sk_num(_para1:POPENSSL_STACK):longint; {removed 1.1.0}
  function sk_value(_para1:POPENSSL_STACK; _para2:longint):pointer; {removed 1.1.0}
  function sk_set(st:POPENSSL_STACK; i:longint; data:pointer):pointer; {removed 1.1.0}
  function sk_new(cmp:TOPENSSL_sk_compfunc):POPENSSL_STACK; {removed 1.1.0}
  function sk_new_null:POPENSSL_STACK; {removed 1.1.0}
  function sk_new_reserve(c:TOPENSSL_sk_compfunc; n:longint):POPENSSL_STACK; {removed 1.0.0}
  function sk_reserve(st:POPENSSL_STACK; n:longint):longint; {removed 1.0.0}
  procedure sk_free(_para1:POPENSSL_STACK); {removed 1.1.0}
  procedure sk_pop_free(st:POPENSSL_STACK; func:TOPENSSL_sk_freefunc); {removed 1.1.0}
  function sk_deep_copy(_para1:POPENSSL_STACK; c:TOPENSSL_sk_copyfunc; f:TOPENSSL_sk_freefunc):POPENSSL_STACK; {removed 1.1.0}
  function sk_insert(sk:POPENSSL_STACK; data:pointer; where:longint):longint; {removed 1.1.0}
  function sk_delete(st:POPENSSL_STACK; loc:longint):pointer; {removed 1.1.0}
  function sk_delete_ptr(st:POPENSSL_STACK; p:pointer):pointer; {removed 1.1.0}
  function sk_find(st:POPENSSL_STACK; data:pointer):longint; {removed 1.1.0}
  function sk_find_ex(st:POPENSSL_STACK; data:pointer):longint; {removed 1.1.0}
  function sk_push(st:POPENSSL_STACK; data:pointer):longint; {removed 1.1.0}
  function sk_unshift(st:POPENSSL_STACK; data:pointer):longint; {removed 1.1.0}
  function sk_shift(st:POPENSSL_STACK):pointer; {removed 1.1.0}
  function sk_pop(st:POPENSSL_STACK):pointer; {removed 1.1.0}
  procedure sk_zero(st:POPENSSL_STACK); {removed 1.1.0}
  function sk_set_cmp_func(sk:POPENSSL_STACK; cmp:TOPENSSL_sk_compfunc):TOPENSSL_sk_compfunc; {removed 1.1.0}
  function sk_dup(st:POPENSSL_STACK):POPENSSL_STACK; {removed 1.1.0}
  procedure sk_sort(st:POPENSSL_STACK); {removed 1.1.0}
  function sk_is_sorted(st:POPENSSL_STACK):longint; {removed 1.1.0}
{$ENDIF}

implementation

  uses
    classes, 
    IdSSLOpenSSLExceptionHandlers, 
    IdResourceStringsOpenSSL
  {$IFNDEF OPENSSL_STATIC_LINK_MODEL}
    ,IdSSLOpenSSLLoader
  {$ENDIF};
  
const
  OPENSSL_sk_num_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);
  OPENSSL_sk_value_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);
  OPENSSL_sk_set_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);
  OPENSSL_sk_new_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);
  OPENSSL_sk_new_null_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);
  OPENSSL_sk_new_reserve_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);
  OPENSSL_sk_reserve_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);
  OPENSSL_sk_free_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);
  OPENSSL_sk_pop_free_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);
  OPENSSL_sk_deep_copy_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);
  OPENSSL_sk_insert_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);
  OPENSSL_sk_delete_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);
  OPENSSL_sk_delete_ptr_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);
  OPENSSL_sk_find_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);
  OPENSSL_sk_find_ex_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);
  OPENSSL_sk_push_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);
  OPENSSL_sk_unshift_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);
  OPENSSL_sk_shift_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);
  OPENSSL_sk_pop_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);
  OPENSSL_sk_zero_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);
  OPENSSL_sk_set_cmp_func_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);
  OPENSSL_sk_dup_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);
  OPENSSL_sk_sort_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);
  OPENSSL_sk_is_sorted_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);
  sk_num_removed = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);
  sk_value_removed = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);
  sk_set_removed = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);
  sk_new_removed = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);
  sk_new_null_removed = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);
  sk_new_reserve_removed = (byte(1) shl 8 or byte(0)) shl 8 or byte(0);
  sk_reserve_removed = (byte(1) shl 8 or byte(0)) shl 8 or byte(0);
  sk_free_removed = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);
  sk_pop_free_removed = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);
  sk_deep_copy_removed = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);
  sk_insert_removed = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);
  sk_delete_removed = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);
  sk_delete_ptr_removed = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);
  sk_find_removed = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);
  sk_find_ex_removed = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);
  sk_push_removed = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);
  sk_unshift_removed = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);
  sk_shift_removed = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);
  sk_pop_removed = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);
  sk_zero_removed = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);
  sk_set_cmp_func_removed = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);
  sk_dup_removed = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);
  sk_sort_removed = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);
  sk_is_sorted_removed = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);

{$IFNDEF OPENSSL_STATIC_LINK_MODEL}
const
  OPENSSL_sk_num_procname = 'OPENSSL_sk_num'; {introduced 1.1.0}
  OPENSSL_sk_value_procname = 'OPENSSL_sk_value'; {introduced 1.1.0}
  OPENSSL_sk_set_procname = 'OPENSSL_sk_set'; {introduced 1.1.0}
  OPENSSL_sk_new_procname = 'OPENSSL_sk_new'; {introduced 1.1.0}
  OPENSSL_sk_new_null_procname = 'OPENSSL_sk_new_null'; {introduced 1.1.0}
  OPENSSL_sk_new_reserve_procname = 'OPENSSL_sk_new_reserve'; {introduced 1.1.0}
  OPENSSL_sk_reserve_procname = 'OPENSSL_sk_reserve'; {introduced 1.1.0}
  OPENSSL_sk_free_procname = 'OPENSSL_sk_free'; {introduced 1.1.0}
  OPENSSL_sk_pop_free_procname = 'OPENSSL_sk_pop_free'; {introduced 1.1.0}
  OPENSSL_sk_deep_copy_procname = 'OPENSSL_sk_deep_copy'; {introduced 1.1.0}
  OPENSSL_sk_insert_procname = 'OPENSSL_sk_insert'; {introduced 1.1.0}
  OPENSSL_sk_delete_procname = 'OPENSSL_sk_delete'; {introduced 1.1.0}
  OPENSSL_sk_delete_ptr_procname = 'OPENSSL_sk_delete_ptr'; {introduced 1.1.0}
  OPENSSL_sk_find_procname = 'OPENSSL_sk_find'; {introduced 1.1.0}
  OPENSSL_sk_find_ex_procname = 'OPENSSL_sk_find_ex'; {introduced 1.1.0}
  OPENSSL_sk_push_procname = 'OPENSSL_sk_push'; {introduced 1.1.0}
  OPENSSL_sk_unshift_procname = 'OPENSSL_sk_unshift'; {introduced 1.1.0}
  OPENSSL_sk_shift_procname = 'OPENSSL_sk_shift'; {introduced 1.1.0}
  OPENSSL_sk_pop_procname = 'OPENSSL_sk_pop'; {introduced 1.1.0}
  OPENSSL_sk_zero_procname = 'OPENSSL_sk_zero'; {introduced 1.1.0}
  OPENSSL_sk_set_cmp_func_procname = 'OPENSSL_sk_set_cmp_func'; {introduced 1.1.0}
  OPENSSL_sk_dup_procname = 'OPENSSL_sk_dup'; {introduced 1.1.0}
  OPENSSL_sk_sort_procname = 'OPENSSL_sk_sort'; {introduced 1.1.0}
  OPENSSL_sk_is_sorted_procname = 'OPENSSL_sk_is_sorted'; {introduced 1.1.0}

  sk_num_procname = 'sk_num'; {removed 1.1.0}
  sk_value_procname = 'sk_value'; {removed 1.1.0}
  sk_set_procname = 'sk_set'; {removed 1.1.0}
  sk_new_procname = 'sk_new'; {removed 1.1.0}
  sk_new_null_procname = 'sk_new_null'; {removed 1.1.0}
  sk_new_reserve_procname = 'sk_new_reserve'; {removed 1.0.0}
  sk_reserve_procname = 'sk_reserve'; {removed 1.0.0}
  sk_free_procname = 'sk_free'; {removed 1.1.0}
  sk_pop_free_procname = 'sk_pop_free'; {removed 1.1.0}
  sk_deep_copy_procname = 'sk_deep_copy'; {removed 1.1.0}
  sk_insert_procname = 'sk_insert'; {removed 1.1.0}
  sk_delete_procname = 'sk_delete'; {removed 1.1.0}
  sk_delete_ptr_procname = 'sk_delete_ptr'; {removed 1.1.0}
  sk_find_procname = 'sk_find'; {removed 1.1.0}
  sk_find_ex_procname = 'sk_find_ex'; {removed 1.1.0}
  sk_push_procname = 'sk_push'; {removed 1.1.0}
  sk_unshift_procname = 'sk_unshift'; {removed 1.1.0}
  sk_shift_procname = 'sk_shift'; {removed 1.1.0}
  sk_pop_procname = 'sk_pop'; {removed 1.1.0}
  sk_zero_procname = 'sk_zero'; {removed 1.1.0}
  sk_set_cmp_func_procname = 'sk_set_cmp_func'; {removed 1.1.0}
  sk_dup_procname = 'sk_dup'; {removed 1.1.0}
  sk_sort_procname = 'sk_sort'; {removed 1.1.0}
  sk_is_sorted_procname = 'sk_is_sorted'; {removed 1.1.0}


function  _sk_num(_para1:POPENSSL_STACK):longint; cdecl;
begin
  Result := OPENSSL_sk_num(_para1);
end;

function  _sk_value(_para1:POPENSSL_STACK; _para2:longint):pointer; cdecl;
begin
  Result := OPENSSL_sk_value(_para1,_para2);
end;

function  _sk_set(st:POPENSSL_STACK; i:longint; data:pointer):pointer; cdecl;
begin
  Result := OPENSSL_sk_set(st,i,data);
end;

function  _sk_new(cmp:TOPENSSL_sk_compfunc):POPENSSL_STACK; cdecl;
begin
  Result := OPENSSL_sk_new(cmp);
end;

function  _sk_new_null:POPENSSL_STACK; cdecl;
begin
  Result := OPENSSL_sk_new_null;
end;

function  _sk_new_reserve(c:TOPENSSL_sk_compfunc; n:longint):POPENSSL_STACK; cdecl;
begin
  Result := OPENSSL_sk_new_reserve(c,n);
end;

function  _sk_reserve(st:POPENSSL_STACK; n:longint):longint; cdecl;
begin
  Result := OPENSSL_sk_reserve(st,n);
end;

procedure  _sk_free(_para1:POPENSSL_STACK); cdecl;
begin
  OPENSSL_sk_free(_para1);
end;

procedure  _sk_pop_free(st:POPENSSL_STACK; func:TOPENSSL_sk_freefunc); cdecl;
begin
  OPENSSL_sk_pop_free(st, func);
end;

function  _sk_deep_copy(_para1:POPENSSL_STACK; c:TOPENSSL_sk_copyfunc; f:TOPENSSL_sk_freefunc):POPENSSL_STACK; cdecl;
begin
  Result := OPENSSL_sk_deep_copy(_para1,c,f);
end;

function  _sk_insert(sk:POPENSSL_STACK; data:pointer; where:longint):longint; cdecl;
begin
  Result := OPENSSL_sk_insert(sk,data,where);
end;

function  _sk_delete(st:POPENSSL_STACK; loc:longint):pointer; cdecl;
begin
  Result := OPENSSL_sk_delete(st,loc);
end;

function  _sk_delete_ptr(st:POPENSSL_STACK; p:pointer):pointer; cdecl;
begin
  Result := OPENSSL_sk_delete_ptr(st,p);
end;

function  _sk_find(st:POPENSSL_STACK; data:pointer):longint; cdecl;
begin
  Result := OPENSSL_sk_find(st,data);
end;

function  _sk_find_ex(st:POPENSSL_STACK; data:pointer):longint; cdecl;
begin
  Result := OPENSSL_sk_find_ex(st,data);
end;

function  _sk_push(st:POPENSSL_STACK; data:pointer):longint; cdecl;
begin
  Result := OPENSSL_sk_push(st,data);
end;

function  _sk_unshift(st:POPENSSL_STACK; data:pointer):longint; cdecl;
begin
  Result := OPENSSL_sk_unshift(st,data);
end;

function  _sk_shift(st:POPENSSL_STACK):pointer; cdecl;
begin
  Result := OPENSSL_sk_shift(st);
end;

function  _sk_pop(st:POPENSSL_STACK):pointer; cdecl;
begin
  Result := OPENSSL_sk_pop(st);
end;

procedure  _sk_zero(st:POPENSSL_STACK); cdecl;
begin
  OPENSSL_sk_zero(st);
end;

function  _sk_set_cmp_func(sk:POPENSSL_STACK; cmp:TOPENSSL_sk_compfunc):TOPENSSL_sk_compfunc; cdecl;
begin
  Result := OPENSSL_sk_set_cmp_func(sk,cmp);
end;

function  _sk_dup(st:POPENSSL_STACK):POPENSSL_STACK; cdecl;
begin
  Result := OPENSSL_sk_dup(st);
end;

procedure  _sk_sort(st:POPENSSL_STACK); cdecl;
begin
  OPENSSL_sk_sort(st);
end;

function  _sk_is_sorted(st:POPENSSL_STACK):longint; cdecl;
begin
  Result := OPENSSL_sk_is_sorted(st);
end;



{$WARN  NO_RETVAL OFF}
function  ERR_OPENSSL_sk_num(_para1:POPENSSL_STACK):longint; 
begin
  EIdAPIFunctionNotPresent.RaiseException(OPENSSL_sk_num_procname);
end;

 {introduced 1.1.0}
function  ERR_OPENSSL_sk_value(_para1:POPENSSL_STACK; _para2:longint):pointer; 
begin
  EIdAPIFunctionNotPresent.RaiseException(OPENSSL_sk_value_procname);
end;

 {introduced 1.1.0}
function  ERR_OPENSSL_sk_set(st:POPENSSL_STACK; i:longint; data:pointer):pointer; 
begin
  EIdAPIFunctionNotPresent.RaiseException(OPENSSL_sk_set_procname);
end;

 {introduced 1.1.0}
function  ERR_OPENSSL_sk_new(cmp:TOPENSSL_sk_compfunc):POPENSSL_STACK; 
begin
  EIdAPIFunctionNotPresent.RaiseException(OPENSSL_sk_new_procname);
end;

 {introduced 1.1.0}
function  ERR_OPENSSL_sk_new_null:POPENSSL_STACK; 
begin
  EIdAPIFunctionNotPresent.RaiseException(OPENSSL_sk_new_null_procname);
end;

 {introduced 1.1.0}
function  ERR_OPENSSL_sk_new_reserve(c:TOPENSSL_sk_compfunc; n:longint):POPENSSL_STACK; 
begin
  EIdAPIFunctionNotPresent.RaiseException(OPENSSL_sk_new_reserve_procname);
end;

 {introduced 1.1.0}
function  ERR_OPENSSL_sk_reserve(st:POPENSSL_STACK; n:longint):longint; 
begin
  EIdAPIFunctionNotPresent.RaiseException(OPENSSL_sk_reserve_procname);
end;

 {introduced 1.1.0}
procedure  ERR_OPENSSL_sk_free(_para1:POPENSSL_STACK); 
begin
  EIdAPIFunctionNotPresent.RaiseException(OPENSSL_sk_free_procname);
end;

 {introduced 1.1.0}
procedure  ERR_OPENSSL_sk_pop_free(st:POPENSSL_STACK; func:TOPENSSL_sk_freefunc); 
begin
  EIdAPIFunctionNotPresent.RaiseException(OPENSSL_sk_pop_free_procname);
end;

 {introduced 1.1.0}
function  ERR_OPENSSL_sk_deep_copy(_para1:POPENSSL_STACK; c:TOPENSSL_sk_copyfunc; f:TOPENSSL_sk_freefunc):POPENSSL_STACK; 
begin
  EIdAPIFunctionNotPresent.RaiseException(OPENSSL_sk_deep_copy_procname);
end;

 {introduced 1.1.0}
function  ERR_OPENSSL_sk_insert(sk:POPENSSL_STACK; data:pointer; where:longint):longint; 
begin
  EIdAPIFunctionNotPresent.RaiseException(OPENSSL_sk_insert_procname);
end;

 {introduced 1.1.0}
function  ERR_OPENSSL_sk_delete(st:POPENSSL_STACK; loc:longint):pointer; 
begin
  EIdAPIFunctionNotPresent.RaiseException(OPENSSL_sk_delete_procname);
end;

 {introduced 1.1.0}
function  ERR_OPENSSL_sk_delete_ptr(st:POPENSSL_STACK; p:pointer):pointer; 
begin
  EIdAPIFunctionNotPresent.RaiseException(OPENSSL_sk_delete_ptr_procname);
end;

 {introduced 1.1.0}
function  ERR_OPENSSL_sk_find(st:POPENSSL_STACK; data:pointer):longint; 
begin
  EIdAPIFunctionNotPresent.RaiseException(OPENSSL_sk_find_procname);
end;

 {introduced 1.1.0}
function  ERR_OPENSSL_sk_find_ex(st:POPENSSL_STACK; data:pointer):longint; 
begin
  EIdAPIFunctionNotPresent.RaiseException(OPENSSL_sk_find_ex_procname);
end;

 {introduced 1.1.0}
function  ERR_OPENSSL_sk_push(st:POPENSSL_STACK; data:pointer):longint; 
begin
  EIdAPIFunctionNotPresent.RaiseException(OPENSSL_sk_push_procname);
end;

 {introduced 1.1.0}
function  ERR_OPENSSL_sk_unshift(st:POPENSSL_STACK; data:pointer):longint; 
begin
  EIdAPIFunctionNotPresent.RaiseException(OPENSSL_sk_unshift_procname);
end;

 {introduced 1.1.0}
function  ERR_OPENSSL_sk_shift(st:POPENSSL_STACK):pointer; 
begin
  EIdAPIFunctionNotPresent.RaiseException(OPENSSL_sk_shift_procname);
end;

 {introduced 1.1.0}
function  ERR_OPENSSL_sk_pop(st:POPENSSL_STACK):pointer; 
begin
  EIdAPIFunctionNotPresent.RaiseException(OPENSSL_sk_pop_procname);
end;

 {introduced 1.1.0}
procedure  ERR_OPENSSL_sk_zero(st:POPENSSL_STACK); 
begin
  EIdAPIFunctionNotPresent.RaiseException(OPENSSL_sk_zero_procname);
end;

 {introduced 1.1.0}
function  ERR_OPENSSL_sk_set_cmp_func(sk:POPENSSL_STACK; cmp:TOPENSSL_sk_compfunc):TOPENSSL_sk_compfunc; 
begin
  EIdAPIFunctionNotPresent.RaiseException(OPENSSL_sk_set_cmp_func_procname);
end;

 {introduced 1.1.0}
function  ERR_OPENSSL_sk_dup(st:POPENSSL_STACK):POPENSSL_STACK; 
begin
  EIdAPIFunctionNotPresent.RaiseException(OPENSSL_sk_dup_procname);
end;

 {introduced 1.1.0}
procedure  ERR_OPENSSL_sk_sort(st:POPENSSL_STACK); 
begin
  EIdAPIFunctionNotPresent.RaiseException(OPENSSL_sk_sort_procname);
end;

 {introduced 1.1.0}
function  ERR_OPENSSL_sk_is_sorted(st:POPENSSL_STACK):longint; 
begin
  EIdAPIFunctionNotPresent.RaiseException(OPENSSL_sk_is_sorted_procname);
end;

 {introduced 1.1.0}

function  ERR_sk_num(_para1:POPENSSL_STACK):longint; 
begin
  EIdAPIFunctionNotPresent.RaiseException(sk_num_procname);
end;

 
function  ERR_sk_value(_para1:POPENSSL_STACK; _para2:longint):pointer; 
begin
  EIdAPIFunctionNotPresent.RaiseException(sk_value_procname);
end;

 
function  ERR_sk_set(st:POPENSSL_STACK; i:longint; data:pointer):pointer; 
begin
  EIdAPIFunctionNotPresent.RaiseException(sk_set_procname);
end;

 
function  ERR_sk_new(cmp:TOPENSSL_sk_compfunc):POPENSSL_STACK; 
begin
  EIdAPIFunctionNotPresent.RaiseException(sk_new_procname);
end;

 
function  ERR_sk_new_null:POPENSSL_STACK; 
begin
  EIdAPIFunctionNotPresent.RaiseException(sk_new_null_procname);
end;

 
function  ERR_sk_new_reserve(c:TOPENSSL_sk_compfunc; n:longint):POPENSSL_STACK; 
begin
  EIdAPIFunctionNotPresent.RaiseException(sk_new_reserve_procname);
end;

 
function  ERR_sk_reserve(st:POPENSSL_STACK; n:longint):longint; 
begin
  EIdAPIFunctionNotPresent.RaiseException(sk_reserve_procname);
end;

 
procedure  ERR_sk_free(_para1:POPENSSL_STACK); 
begin
  EIdAPIFunctionNotPresent.RaiseException(sk_free_procname);
end;

 
procedure  ERR_sk_pop_free(st:POPENSSL_STACK; func:TOPENSSL_sk_freefunc); 
begin
  EIdAPIFunctionNotPresent.RaiseException(sk_pop_free_procname);
end;

 
function  ERR_sk_deep_copy(_para1:POPENSSL_STACK; c:TOPENSSL_sk_copyfunc; f:TOPENSSL_sk_freefunc):POPENSSL_STACK; 
begin
  EIdAPIFunctionNotPresent.RaiseException(sk_deep_copy_procname);
end;

 
function  ERR_sk_insert(sk:POPENSSL_STACK; data:pointer; where:longint):longint; 
begin
  EIdAPIFunctionNotPresent.RaiseException(sk_insert_procname);
end;

 
function  ERR_sk_delete(st:POPENSSL_STACK; loc:longint):pointer; 
begin
  EIdAPIFunctionNotPresent.RaiseException(sk_delete_procname);
end;

 
function  ERR_sk_delete_ptr(st:POPENSSL_STACK; p:pointer):pointer; 
begin
  EIdAPIFunctionNotPresent.RaiseException(sk_delete_ptr_procname);
end;

 
function  ERR_sk_find(st:POPENSSL_STACK; data:pointer):longint; 
begin
  EIdAPIFunctionNotPresent.RaiseException(sk_find_procname);
end;

 
function  ERR_sk_find_ex(st:POPENSSL_STACK; data:pointer):longint; 
begin
  EIdAPIFunctionNotPresent.RaiseException(sk_find_ex_procname);
end;

 
function  ERR_sk_push(st:POPENSSL_STACK; data:pointer):longint; 
begin
  EIdAPIFunctionNotPresent.RaiseException(sk_push_procname);
end;

 
function  ERR_sk_unshift(st:POPENSSL_STACK; data:pointer):longint; 
begin
  EIdAPIFunctionNotPresent.RaiseException(sk_unshift_procname);
end;

 
function  ERR_sk_shift(st:POPENSSL_STACK):pointer; 
begin
  EIdAPIFunctionNotPresent.RaiseException(sk_shift_procname);
end;

 
function  ERR_sk_pop(st:POPENSSL_STACK):pointer; 
begin
  EIdAPIFunctionNotPresent.RaiseException(sk_pop_procname);
end;

 
procedure  ERR_sk_zero(st:POPENSSL_STACK); 
begin
  EIdAPIFunctionNotPresent.RaiseException(sk_zero_procname);
end;

 
function  ERR_sk_set_cmp_func(sk:POPENSSL_STACK; cmp:TOPENSSL_sk_compfunc):TOPENSSL_sk_compfunc; 
begin
  EIdAPIFunctionNotPresent.RaiseException(sk_set_cmp_func_procname);
end;

 
function  ERR_sk_dup(st:POPENSSL_STACK):POPENSSL_STACK; 
begin
  EIdAPIFunctionNotPresent.RaiseException(sk_dup_procname);
end;

 
procedure  ERR_sk_sort(st:POPENSSL_STACK); 
begin
  EIdAPIFunctionNotPresent.RaiseException(sk_sort_procname);
end;

 
function  ERR_sk_is_sorted(st:POPENSSL_STACK):longint; 
begin
  EIdAPIFunctionNotPresent.RaiseException(sk_is_sorted_procname);
end;

 

{$WARN  NO_RETVAL ON}

procedure Load(const ADllHandle: TIdLibHandle; LibVersion: TIdC_UINT; const AFailed: TStringList);

var FuncLoadError: boolean;

begin
  OPENSSL_sk_num := LoadLibFunction(ADllHandle, OPENSSL_sk_num_procname);
  FuncLoadError := not assigned(OPENSSL_sk_num);
  if FuncLoadError then
  begin
    {$if not defined(OPENSSL_sk_num_allownil)}
    OPENSSL_sk_num := @ERR_OPENSSL_sk_num;
    {$ifend}
    {$if declared(OPENSSL_sk_num_introduced)}
    if LibVersion < OPENSSL_sk_num_introduced then
    begin
      {$if declared(FC_OPENSSL_sk_num)}
      OPENSSL_sk_num := @FC_OPENSSL_sk_num;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(OPENSSL_sk_num_removed)}
    if OPENSSL_sk_num_removed <= LibVersion then
    begin
      {$if declared(_OPENSSL_sk_num)}
      OPENSSL_sk_num := @_OPENSSL_sk_num;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(OPENSSL_sk_num_allownil)}
    if FuncLoadError then
      AFailed.Add('OPENSSL_sk_num');
    {$ifend}
  end;

 {introduced 1.1.0}
  OPENSSL_sk_value := LoadLibFunction(ADllHandle, OPENSSL_sk_value_procname);
  FuncLoadError := not assigned(OPENSSL_sk_value);
  if FuncLoadError then
  begin
    {$if not defined(OPENSSL_sk_value_allownil)}
    OPENSSL_sk_value := @ERR_OPENSSL_sk_value;
    {$ifend}
    {$if declared(OPENSSL_sk_value_introduced)}
    if LibVersion < OPENSSL_sk_value_introduced then
    begin
      {$if declared(FC_OPENSSL_sk_value)}
      OPENSSL_sk_value := @FC_OPENSSL_sk_value;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(OPENSSL_sk_value_removed)}
    if OPENSSL_sk_value_removed <= LibVersion then
    begin
      {$if declared(_OPENSSL_sk_value)}
      OPENSSL_sk_value := @_OPENSSL_sk_value;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(OPENSSL_sk_value_allownil)}
    if FuncLoadError then
      AFailed.Add('OPENSSL_sk_value');
    {$ifend}
  end;

 {introduced 1.1.0}
  OPENSSL_sk_set := LoadLibFunction(ADllHandle, OPENSSL_sk_set_procname);
  FuncLoadError := not assigned(OPENSSL_sk_set);
  if FuncLoadError then
  begin
    {$if not defined(OPENSSL_sk_set_allownil)}
    OPENSSL_sk_set := @ERR_OPENSSL_sk_set;
    {$ifend}
    {$if declared(OPENSSL_sk_set_introduced)}
    if LibVersion < OPENSSL_sk_set_introduced then
    begin
      {$if declared(FC_OPENSSL_sk_set)}
      OPENSSL_sk_set := @FC_OPENSSL_sk_set;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(OPENSSL_sk_set_removed)}
    if OPENSSL_sk_set_removed <= LibVersion then
    begin
      {$if declared(_OPENSSL_sk_set)}
      OPENSSL_sk_set := @_OPENSSL_sk_set;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(OPENSSL_sk_set_allownil)}
    if FuncLoadError then
      AFailed.Add('OPENSSL_sk_set');
    {$ifend}
  end;

 {introduced 1.1.0}
  OPENSSL_sk_new := LoadLibFunction(ADllHandle, OPENSSL_sk_new_procname);
  FuncLoadError := not assigned(OPENSSL_sk_new);
  if FuncLoadError then
  begin
    {$if not defined(OPENSSL_sk_new_allownil)}
    OPENSSL_sk_new := @ERR_OPENSSL_sk_new;
    {$ifend}
    {$if declared(OPENSSL_sk_new_introduced)}
    if LibVersion < OPENSSL_sk_new_introduced then
    begin
      {$if declared(FC_OPENSSL_sk_new)}
      OPENSSL_sk_new := @FC_OPENSSL_sk_new;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(OPENSSL_sk_new_removed)}
    if OPENSSL_sk_new_removed <= LibVersion then
    begin
      {$if declared(_OPENSSL_sk_new)}
      OPENSSL_sk_new := @_OPENSSL_sk_new;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(OPENSSL_sk_new_allownil)}
    if FuncLoadError then
      AFailed.Add('OPENSSL_sk_new');
    {$ifend}
  end;

 {introduced 1.1.0}
  OPENSSL_sk_new_null := LoadLibFunction(ADllHandle, OPENSSL_sk_new_null_procname);
  FuncLoadError := not assigned(OPENSSL_sk_new_null);
  if FuncLoadError then
  begin
    {$if not defined(OPENSSL_sk_new_null_allownil)}
    OPENSSL_sk_new_null := @ERR_OPENSSL_sk_new_null;
    {$ifend}
    {$if declared(OPENSSL_sk_new_null_introduced)}
    if LibVersion < OPENSSL_sk_new_null_introduced then
    begin
      {$if declared(FC_OPENSSL_sk_new_null)}
      OPENSSL_sk_new_null := @FC_OPENSSL_sk_new_null;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(OPENSSL_sk_new_null_removed)}
    if OPENSSL_sk_new_null_removed <= LibVersion then
    begin
      {$if declared(_OPENSSL_sk_new_null)}
      OPENSSL_sk_new_null := @_OPENSSL_sk_new_null;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(OPENSSL_sk_new_null_allownil)}
    if FuncLoadError then
      AFailed.Add('OPENSSL_sk_new_null');
    {$ifend}
  end;

 {introduced 1.1.0}
  OPENSSL_sk_new_reserve := LoadLibFunction(ADllHandle, OPENSSL_sk_new_reserve_procname);
  FuncLoadError := not assigned(OPENSSL_sk_new_reserve);
  if FuncLoadError then
  begin
    {$if not defined(OPENSSL_sk_new_reserve_allownil)}
    OPENSSL_sk_new_reserve := @ERR_OPENSSL_sk_new_reserve;
    {$ifend}
    {$if declared(OPENSSL_sk_new_reserve_introduced)}
    if LibVersion < OPENSSL_sk_new_reserve_introduced then
    begin
      {$if declared(FC_OPENSSL_sk_new_reserve)}
      OPENSSL_sk_new_reserve := @FC_OPENSSL_sk_new_reserve;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(OPENSSL_sk_new_reserve_removed)}
    if OPENSSL_sk_new_reserve_removed <= LibVersion then
    begin
      {$if declared(_OPENSSL_sk_new_reserve)}
      OPENSSL_sk_new_reserve := @_OPENSSL_sk_new_reserve;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(OPENSSL_sk_new_reserve_allownil)}
    if FuncLoadError then
      AFailed.Add('OPENSSL_sk_new_reserve');
    {$ifend}
  end;

 {introduced 1.1.0}
  OPENSSL_sk_reserve := LoadLibFunction(ADllHandle, OPENSSL_sk_reserve_procname);
  FuncLoadError := not assigned(OPENSSL_sk_reserve);
  if FuncLoadError then
  begin
    {$if not defined(OPENSSL_sk_reserve_allownil)}
    OPENSSL_sk_reserve := @ERR_OPENSSL_sk_reserve;
    {$ifend}
    {$if declared(OPENSSL_sk_reserve_introduced)}
    if LibVersion < OPENSSL_sk_reserve_introduced then
    begin
      {$if declared(FC_OPENSSL_sk_reserve)}
      OPENSSL_sk_reserve := @FC_OPENSSL_sk_reserve;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(OPENSSL_sk_reserve_removed)}
    if OPENSSL_sk_reserve_removed <= LibVersion then
    begin
      {$if declared(_OPENSSL_sk_reserve)}
      OPENSSL_sk_reserve := @_OPENSSL_sk_reserve;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(OPENSSL_sk_reserve_allownil)}
    if FuncLoadError then
      AFailed.Add('OPENSSL_sk_reserve');
    {$ifend}
  end;

 {introduced 1.1.0}
  OPENSSL_sk_free := LoadLibFunction(ADllHandle, OPENSSL_sk_free_procname);
  FuncLoadError := not assigned(OPENSSL_sk_free);
  if FuncLoadError then
  begin
    {$if not defined(OPENSSL_sk_free_allownil)}
    OPENSSL_sk_free := @ERR_OPENSSL_sk_free;
    {$ifend}
    {$if declared(OPENSSL_sk_free_introduced)}
    if LibVersion < OPENSSL_sk_free_introduced then
    begin
      {$if declared(FC_OPENSSL_sk_free)}
      OPENSSL_sk_free := @FC_OPENSSL_sk_free;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(OPENSSL_sk_free_removed)}
    if OPENSSL_sk_free_removed <= LibVersion then
    begin
      {$if declared(_OPENSSL_sk_free)}
      OPENSSL_sk_free := @_OPENSSL_sk_free;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(OPENSSL_sk_free_allownil)}
    if FuncLoadError then
      AFailed.Add('OPENSSL_sk_free');
    {$ifend}
  end;

 {introduced 1.1.0}
  OPENSSL_sk_pop_free := LoadLibFunction(ADllHandle, OPENSSL_sk_pop_free_procname);
  FuncLoadError := not assigned(OPENSSL_sk_pop_free);
  if FuncLoadError then
  begin
    {$if not defined(OPENSSL_sk_pop_free_allownil)}
    OPENSSL_sk_pop_free := @ERR_OPENSSL_sk_pop_free;
    {$ifend}
    {$if declared(OPENSSL_sk_pop_free_introduced)}
    if LibVersion < OPENSSL_sk_pop_free_introduced then
    begin
      {$if declared(FC_OPENSSL_sk_pop_free)}
      OPENSSL_sk_pop_free := @FC_OPENSSL_sk_pop_free;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(OPENSSL_sk_pop_free_removed)}
    if OPENSSL_sk_pop_free_removed <= LibVersion then
    begin
      {$if declared(_OPENSSL_sk_pop_free)}
      OPENSSL_sk_pop_free := @_OPENSSL_sk_pop_free;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(OPENSSL_sk_pop_free_allownil)}
    if FuncLoadError then
      AFailed.Add('OPENSSL_sk_pop_free');
    {$ifend}
  end;

 {introduced 1.1.0}
  OPENSSL_sk_deep_copy := LoadLibFunction(ADllHandle, OPENSSL_sk_deep_copy_procname);
  FuncLoadError := not assigned(OPENSSL_sk_deep_copy);
  if FuncLoadError then
  begin
    {$if not defined(OPENSSL_sk_deep_copy_allownil)}
    OPENSSL_sk_deep_copy := @ERR_OPENSSL_sk_deep_copy;
    {$ifend}
    {$if declared(OPENSSL_sk_deep_copy_introduced)}
    if LibVersion < OPENSSL_sk_deep_copy_introduced then
    begin
      {$if declared(FC_OPENSSL_sk_deep_copy)}
      OPENSSL_sk_deep_copy := @FC_OPENSSL_sk_deep_copy;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(OPENSSL_sk_deep_copy_removed)}
    if OPENSSL_sk_deep_copy_removed <= LibVersion then
    begin
      {$if declared(_OPENSSL_sk_deep_copy)}
      OPENSSL_sk_deep_copy := @_OPENSSL_sk_deep_copy;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(OPENSSL_sk_deep_copy_allownil)}
    if FuncLoadError then
      AFailed.Add('OPENSSL_sk_deep_copy');
    {$ifend}
  end;

 {introduced 1.1.0}
  OPENSSL_sk_insert := LoadLibFunction(ADllHandle, OPENSSL_sk_insert_procname);
  FuncLoadError := not assigned(OPENSSL_sk_insert);
  if FuncLoadError then
  begin
    {$if not defined(OPENSSL_sk_insert_allownil)}
    OPENSSL_sk_insert := @ERR_OPENSSL_sk_insert;
    {$ifend}
    {$if declared(OPENSSL_sk_insert_introduced)}
    if LibVersion < OPENSSL_sk_insert_introduced then
    begin
      {$if declared(FC_OPENSSL_sk_insert)}
      OPENSSL_sk_insert := @FC_OPENSSL_sk_insert;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(OPENSSL_sk_insert_removed)}
    if OPENSSL_sk_insert_removed <= LibVersion then
    begin
      {$if declared(_OPENSSL_sk_insert)}
      OPENSSL_sk_insert := @_OPENSSL_sk_insert;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(OPENSSL_sk_insert_allownil)}
    if FuncLoadError then
      AFailed.Add('OPENSSL_sk_insert');
    {$ifend}
  end;

 {introduced 1.1.0}
  OPENSSL_sk_delete := LoadLibFunction(ADllHandle, OPENSSL_sk_delete_procname);
  FuncLoadError := not assigned(OPENSSL_sk_delete);
  if FuncLoadError then
  begin
    {$if not defined(OPENSSL_sk_delete_allownil)}
    OPENSSL_sk_delete := @ERR_OPENSSL_sk_delete;
    {$ifend}
    {$if declared(OPENSSL_sk_delete_introduced)}
    if LibVersion < OPENSSL_sk_delete_introduced then
    begin
      {$if declared(FC_OPENSSL_sk_delete)}
      OPENSSL_sk_delete := @FC_OPENSSL_sk_delete;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(OPENSSL_sk_delete_removed)}
    if OPENSSL_sk_delete_removed <= LibVersion then
    begin
      {$if declared(_OPENSSL_sk_delete)}
      OPENSSL_sk_delete := @_OPENSSL_sk_delete;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(OPENSSL_sk_delete_allownil)}
    if FuncLoadError then
      AFailed.Add('OPENSSL_sk_delete');
    {$ifend}
  end;

 {introduced 1.1.0}
  OPENSSL_sk_delete_ptr := LoadLibFunction(ADllHandle, OPENSSL_sk_delete_ptr_procname);
  FuncLoadError := not assigned(OPENSSL_sk_delete_ptr);
  if FuncLoadError then
  begin
    {$if not defined(OPENSSL_sk_delete_ptr_allownil)}
    OPENSSL_sk_delete_ptr := @ERR_OPENSSL_sk_delete_ptr;
    {$ifend}
    {$if declared(OPENSSL_sk_delete_ptr_introduced)}
    if LibVersion < OPENSSL_sk_delete_ptr_introduced then
    begin
      {$if declared(FC_OPENSSL_sk_delete_ptr)}
      OPENSSL_sk_delete_ptr := @FC_OPENSSL_sk_delete_ptr;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(OPENSSL_sk_delete_ptr_removed)}
    if OPENSSL_sk_delete_ptr_removed <= LibVersion then
    begin
      {$if declared(_OPENSSL_sk_delete_ptr)}
      OPENSSL_sk_delete_ptr := @_OPENSSL_sk_delete_ptr;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(OPENSSL_sk_delete_ptr_allownil)}
    if FuncLoadError then
      AFailed.Add('OPENSSL_sk_delete_ptr');
    {$ifend}
  end;

 {introduced 1.1.0}
  OPENSSL_sk_find := LoadLibFunction(ADllHandle, OPENSSL_sk_find_procname);
  FuncLoadError := not assigned(OPENSSL_sk_find);
  if FuncLoadError then
  begin
    {$if not defined(OPENSSL_sk_find_allownil)}
    OPENSSL_sk_find := @ERR_OPENSSL_sk_find;
    {$ifend}
    {$if declared(OPENSSL_sk_find_introduced)}
    if LibVersion < OPENSSL_sk_find_introduced then
    begin
      {$if declared(FC_OPENSSL_sk_find)}
      OPENSSL_sk_find := @FC_OPENSSL_sk_find;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(OPENSSL_sk_find_removed)}
    if OPENSSL_sk_find_removed <= LibVersion then
    begin
      {$if declared(_OPENSSL_sk_find)}
      OPENSSL_sk_find := @_OPENSSL_sk_find;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(OPENSSL_sk_find_allownil)}
    if FuncLoadError then
      AFailed.Add('OPENSSL_sk_find');
    {$ifend}
  end;

 {introduced 1.1.0}
  OPENSSL_sk_find_ex := LoadLibFunction(ADllHandle, OPENSSL_sk_find_ex_procname);
  FuncLoadError := not assigned(OPENSSL_sk_find_ex);
  if FuncLoadError then
  begin
    {$if not defined(OPENSSL_sk_find_ex_allownil)}
    OPENSSL_sk_find_ex := @ERR_OPENSSL_sk_find_ex;
    {$ifend}
    {$if declared(OPENSSL_sk_find_ex_introduced)}
    if LibVersion < OPENSSL_sk_find_ex_introduced then
    begin
      {$if declared(FC_OPENSSL_sk_find_ex)}
      OPENSSL_sk_find_ex := @FC_OPENSSL_sk_find_ex;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(OPENSSL_sk_find_ex_removed)}
    if OPENSSL_sk_find_ex_removed <= LibVersion then
    begin
      {$if declared(_OPENSSL_sk_find_ex)}
      OPENSSL_sk_find_ex := @_OPENSSL_sk_find_ex;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(OPENSSL_sk_find_ex_allownil)}
    if FuncLoadError then
      AFailed.Add('OPENSSL_sk_find_ex');
    {$ifend}
  end;

 {introduced 1.1.0}
  OPENSSL_sk_push := LoadLibFunction(ADllHandle, OPENSSL_sk_push_procname);
  FuncLoadError := not assigned(OPENSSL_sk_push);
  if FuncLoadError then
  begin
    {$if not defined(OPENSSL_sk_push_allownil)}
    OPENSSL_sk_push := @ERR_OPENSSL_sk_push;
    {$ifend}
    {$if declared(OPENSSL_sk_push_introduced)}
    if LibVersion < OPENSSL_sk_push_introduced then
    begin
      {$if declared(FC_OPENSSL_sk_push)}
      OPENSSL_sk_push := @FC_OPENSSL_sk_push;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(OPENSSL_sk_push_removed)}
    if OPENSSL_sk_push_removed <= LibVersion then
    begin
      {$if declared(_OPENSSL_sk_push)}
      OPENSSL_sk_push := @_OPENSSL_sk_push;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(OPENSSL_sk_push_allownil)}
    if FuncLoadError then
      AFailed.Add('OPENSSL_sk_push');
    {$ifend}
  end;

 {introduced 1.1.0}
  OPENSSL_sk_unshift := LoadLibFunction(ADllHandle, OPENSSL_sk_unshift_procname);
  FuncLoadError := not assigned(OPENSSL_sk_unshift);
  if FuncLoadError then
  begin
    {$if not defined(OPENSSL_sk_unshift_allownil)}
    OPENSSL_sk_unshift := @ERR_OPENSSL_sk_unshift;
    {$ifend}
    {$if declared(OPENSSL_sk_unshift_introduced)}
    if LibVersion < OPENSSL_sk_unshift_introduced then
    begin
      {$if declared(FC_OPENSSL_sk_unshift)}
      OPENSSL_sk_unshift := @FC_OPENSSL_sk_unshift;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(OPENSSL_sk_unshift_removed)}
    if OPENSSL_sk_unshift_removed <= LibVersion then
    begin
      {$if declared(_OPENSSL_sk_unshift)}
      OPENSSL_sk_unshift := @_OPENSSL_sk_unshift;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(OPENSSL_sk_unshift_allownil)}
    if FuncLoadError then
      AFailed.Add('OPENSSL_sk_unshift');
    {$ifend}
  end;

 {introduced 1.1.0}
  OPENSSL_sk_shift := LoadLibFunction(ADllHandle, OPENSSL_sk_shift_procname);
  FuncLoadError := not assigned(OPENSSL_sk_shift);
  if FuncLoadError then
  begin
    {$if not defined(OPENSSL_sk_shift_allownil)}
    OPENSSL_sk_shift := @ERR_OPENSSL_sk_shift;
    {$ifend}
    {$if declared(OPENSSL_sk_shift_introduced)}
    if LibVersion < OPENSSL_sk_shift_introduced then
    begin
      {$if declared(FC_OPENSSL_sk_shift)}
      OPENSSL_sk_shift := @FC_OPENSSL_sk_shift;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(OPENSSL_sk_shift_removed)}
    if OPENSSL_sk_shift_removed <= LibVersion then
    begin
      {$if declared(_OPENSSL_sk_shift)}
      OPENSSL_sk_shift := @_OPENSSL_sk_shift;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(OPENSSL_sk_shift_allownil)}
    if FuncLoadError then
      AFailed.Add('OPENSSL_sk_shift');
    {$ifend}
  end;

 {introduced 1.1.0}
  OPENSSL_sk_pop := LoadLibFunction(ADllHandle, OPENSSL_sk_pop_procname);
  FuncLoadError := not assigned(OPENSSL_sk_pop);
  if FuncLoadError then
  begin
    {$if not defined(OPENSSL_sk_pop_allownil)}
    OPENSSL_sk_pop := @ERR_OPENSSL_sk_pop;
    {$ifend}
    {$if declared(OPENSSL_sk_pop_introduced)}
    if LibVersion < OPENSSL_sk_pop_introduced then
    begin
      {$if declared(FC_OPENSSL_sk_pop)}
      OPENSSL_sk_pop := @FC_OPENSSL_sk_pop;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(OPENSSL_sk_pop_removed)}
    if OPENSSL_sk_pop_removed <= LibVersion then
    begin
      {$if declared(_OPENSSL_sk_pop)}
      OPENSSL_sk_pop := @_OPENSSL_sk_pop;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(OPENSSL_sk_pop_allownil)}
    if FuncLoadError then
      AFailed.Add('OPENSSL_sk_pop');
    {$ifend}
  end;

 {introduced 1.1.0}
  OPENSSL_sk_zero := LoadLibFunction(ADllHandle, OPENSSL_sk_zero_procname);
  FuncLoadError := not assigned(OPENSSL_sk_zero);
  if FuncLoadError then
  begin
    {$if not defined(OPENSSL_sk_zero_allownil)}
    OPENSSL_sk_zero := @ERR_OPENSSL_sk_zero;
    {$ifend}
    {$if declared(OPENSSL_sk_zero_introduced)}
    if LibVersion < OPENSSL_sk_zero_introduced then
    begin
      {$if declared(FC_OPENSSL_sk_zero)}
      OPENSSL_sk_zero := @FC_OPENSSL_sk_zero;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(OPENSSL_sk_zero_removed)}
    if OPENSSL_sk_zero_removed <= LibVersion then
    begin
      {$if declared(_OPENSSL_sk_zero)}
      OPENSSL_sk_zero := @_OPENSSL_sk_zero;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(OPENSSL_sk_zero_allownil)}
    if FuncLoadError then
      AFailed.Add('OPENSSL_sk_zero');
    {$ifend}
  end;

 {introduced 1.1.0}
  OPENSSL_sk_set_cmp_func := LoadLibFunction(ADllHandle, OPENSSL_sk_set_cmp_func_procname);
  FuncLoadError := not assigned(OPENSSL_sk_set_cmp_func);
  if FuncLoadError then
  begin
    {$if not defined(OPENSSL_sk_set_cmp_func_allownil)}
    OPENSSL_sk_set_cmp_func := @ERR_OPENSSL_sk_set_cmp_func;
    {$ifend}
    {$if declared(OPENSSL_sk_set_cmp_func_introduced)}
    if LibVersion < OPENSSL_sk_set_cmp_func_introduced then
    begin
      {$if declared(FC_OPENSSL_sk_set_cmp_func)}
      OPENSSL_sk_set_cmp_func := @FC_OPENSSL_sk_set_cmp_func;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(OPENSSL_sk_set_cmp_func_removed)}
    if OPENSSL_sk_set_cmp_func_removed <= LibVersion then
    begin
      {$if declared(_OPENSSL_sk_set_cmp_func)}
      OPENSSL_sk_set_cmp_func := @_OPENSSL_sk_set_cmp_func;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(OPENSSL_sk_set_cmp_func_allownil)}
    if FuncLoadError then
      AFailed.Add('OPENSSL_sk_set_cmp_func');
    {$ifend}
  end;

 {introduced 1.1.0}
  OPENSSL_sk_dup := LoadLibFunction(ADllHandle, OPENSSL_sk_dup_procname);
  FuncLoadError := not assigned(OPENSSL_sk_dup);
  if FuncLoadError then
  begin
    {$if not defined(OPENSSL_sk_dup_allownil)}
    OPENSSL_sk_dup := @ERR_OPENSSL_sk_dup;
    {$ifend}
    {$if declared(OPENSSL_sk_dup_introduced)}
    if LibVersion < OPENSSL_sk_dup_introduced then
    begin
      {$if declared(FC_OPENSSL_sk_dup)}
      OPENSSL_sk_dup := @FC_OPENSSL_sk_dup;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(OPENSSL_sk_dup_removed)}
    if OPENSSL_sk_dup_removed <= LibVersion then
    begin
      {$if declared(_OPENSSL_sk_dup)}
      OPENSSL_sk_dup := @_OPENSSL_sk_dup;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(OPENSSL_sk_dup_allownil)}
    if FuncLoadError then
      AFailed.Add('OPENSSL_sk_dup');
    {$ifend}
  end;

 {introduced 1.1.0}
  OPENSSL_sk_sort := LoadLibFunction(ADllHandle, OPENSSL_sk_sort_procname);
  FuncLoadError := not assigned(OPENSSL_sk_sort);
  if FuncLoadError then
  begin
    {$if not defined(OPENSSL_sk_sort_allownil)}
    OPENSSL_sk_sort := @ERR_OPENSSL_sk_sort;
    {$ifend}
    {$if declared(OPENSSL_sk_sort_introduced)}
    if LibVersion < OPENSSL_sk_sort_introduced then
    begin
      {$if declared(FC_OPENSSL_sk_sort)}
      OPENSSL_sk_sort := @FC_OPENSSL_sk_sort;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(OPENSSL_sk_sort_removed)}
    if OPENSSL_sk_sort_removed <= LibVersion then
    begin
      {$if declared(_OPENSSL_sk_sort)}
      OPENSSL_sk_sort := @_OPENSSL_sk_sort;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(OPENSSL_sk_sort_allownil)}
    if FuncLoadError then
      AFailed.Add('OPENSSL_sk_sort');
    {$ifend}
  end;

 {introduced 1.1.0}
  OPENSSL_sk_is_sorted := LoadLibFunction(ADllHandle, OPENSSL_sk_is_sorted_procname);
  FuncLoadError := not assigned(OPENSSL_sk_is_sorted);
  if FuncLoadError then
  begin
    {$if not defined(OPENSSL_sk_is_sorted_allownil)}
    OPENSSL_sk_is_sorted := @ERR_OPENSSL_sk_is_sorted;
    {$ifend}
    {$if declared(OPENSSL_sk_is_sorted_introduced)}
    if LibVersion < OPENSSL_sk_is_sorted_introduced then
    begin
      {$if declared(FC_OPENSSL_sk_is_sorted)}
      OPENSSL_sk_is_sorted := @FC_OPENSSL_sk_is_sorted;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(OPENSSL_sk_is_sorted_removed)}
    if OPENSSL_sk_is_sorted_removed <= LibVersion then
    begin
      {$if declared(_OPENSSL_sk_is_sorted)}
      OPENSSL_sk_is_sorted := @_OPENSSL_sk_is_sorted;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(OPENSSL_sk_is_sorted_allownil)}
    if FuncLoadError then
      AFailed.Add('OPENSSL_sk_is_sorted');
    {$ifend}
  end;

 {introduced 1.1.0}
  sk_num := LoadLibFunction(ADllHandle, sk_num_procname);
  FuncLoadError := not assigned(sk_num);
  if FuncLoadError then
  begin
    {$if not defined(sk_num_allownil)}
    sk_num := @ERR_sk_num;
    {$ifend}
    {$if declared(sk_num_introduced)}
    if LibVersion < sk_num_introduced then
    begin
      {$if declared(FC_sk_num)}
      sk_num := @FC_sk_num;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(sk_num_removed)}
    if sk_num_removed <= LibVersion then
    begin
      {$if declared(_sk_num)}
      sk_num := @_sk_num;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(sk_num_allownil)}
    if FuncLoadError then
      AFailed.Add('sk_num');
    {$ifend}
  end;

 
  sk_value := LoadLibFunction(ADllHandle, sk_value_procname);
  FuncLoadError := not assigned(sk_value);
  if FuncLoadError then
  begin
    {$if not defined(sk_value_allownil)}
    sk_value := @ERR_sk_value;
    {$ifend}
    {$if declared(sk_value_introduced)}
    if LibVersion < sk_value_introduced then
    begin
      {$if declared(FC_sk_value)}
      sk_value := @FC_sk_value;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(sk_value_removed)}
    if sk_value_removed <= LibVersion then
    begin
      {$if declared(_sk_value)}
      sk_value := @_sk_value;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(sk_value_allownil)}
    if FuncLoadError then
      AFailed.Add('sk_value');
    {$ifend}
  end;

 
  sk_set := LoadLibFunction(ADllHandle, sk_set_procname);
  FuncLoadError := not assigned(sk_set);
  if FuncLoadError then
  begin
    {$if not defined(sk_set_allownil)}
    sk_set := @ERR_sk_set;
    {$ifend}
    {$if declared(sk_set_introduced)}
    if LibVersion < sk_set_introduced then
    begin
      {$if declared(FC_sk_set)}
      sk_set := @FC_sk_set;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(sk_set_removed)}
    if sk_set_removed <= LibVersion then
    begin
      {$if declared(_sk_set)}
      sk_set := @_sk_set;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(sk_set_allownil)}
    if FuncLoadError then
      AFailed.Add('sk_set');
    {$ifend}
  end;

 
  sk_new := LoadLibFunction(ADllHandle, sk_new_procname);
  FuncLoadError := not assigned(sk_new);
  if FuncLoadError then
  begin
    {$if not defined(sk_new_allownil)}
    sk_new := @ERR_sk_new;
    {$ifend}
    {$if declared(sk_new_introduced)}
    if LibVersion < sk_new_introduced then
    begin
      {$if declared(FC_sk_new)}
      sk_new := @FC_sk_new;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(sk_new_removed)}
    if sk_new_removed <= LibVersion then
    begin
      {$if declared(_sk_new)}
      sk_new := @_sk_new;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(sk_new_allownil)}
    if FuncLoadError then
      AFailed.Add('sk_new');
    {$ifend}
  end;

 
  sk_new_null := LoadLibFunction(ADllHandle, sk_new_null_procname);
  FuncLoadError := not assigned(sk_new_null);
  if FuncLoadError then
  begin
    {$if not defined(sk_new_null_allownil)}
    sk_new_null := @ERR_sk_new_null;
    {$ifend}
    {$if declared(sk_new_null_introduced)}
    if LibVersion < sk_new_null_introduced then
    begin
      {$if declared(FC_sk_new_null)}
      sk_new_null := @FC_sk_new_null;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(sk_new_null_removed)}
    if sk_new_null_removed <= LibVersion then
    begin
      {$if declared(_sk_new_null)}
      sk_new_null := @_sk_new_null;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(sk_new_null_allownil)}
    if FuncLoadError then
      AFailed.Add('sk_new_null');
    {$ifend}
  end;

 
  sk_new_reserve := LoadLibFunction(ADllHandle, sk_new_reserve_procname);
  FuncLoadError := not assigned(sk_new_reserve);
  if FuncLoadError then
  begin
    {$if not defined(sk_new_reserve_allownil)}
    sk_new_reserve := @ERR_sk_new_reserve;
    {$ifend}
    {$if declared(sk_new_reserve_introduced)}
    if LibVersion < sk_new_reserve_introduced then
    begin
      {$if declared(FC_sk_new_reserve)}
      sk_new_reserve := @FC_sk_new_reserve;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(sk_new_reserve_removed)}
    if sk_new_reserve_removed <= LibVersion then
    begin
      {$if declared(_sk_new_reserve)}
      sk_new_reserve := @_sk_new_reserve;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(sk_new_reserve_allownil)}
    if FuncLoadError then
      AFailed.Add('sk_new_reserve');
    {$ifend}
  end;

 
  sk_reserve := LoadLibFunction(ADllHandle, sk_reserve_procname);
  FuncLoadError := not assigned(sk_reserve);
  if FuncLoadError then
  begin
    {$if not defined(sk_reserve_allownil)}
    sk_reserve := @ERR_sk_reserve;
    {$ifend}
    {$if declared(sk_reserve_introduced)}
    if LibVersion < sk_reserve_introduced then
    begin
      {$if declared(FC_sk_reserve)}
      sk_reserve := @FC_sk_reserve;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(sk_reserve_removed)}
    if sk_reserve_removed <= LibVersion then
    begin
      {$if declared(_sk_reserve)}
      sk_reserve := @_sk_reserve;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(sk_reserve_allownil)}
    if FuncLoadError then
      AFailed.Add('sk_reserve');
    {$ifend}
  end;

 
  sk_free := LoadLibFunction(ADllHandle, sk_free_procname);
  FuncLoadError := not assigned(sk_free);
  if FuncLoadError then
  begin
    {$if not defined(sk_free_allownil)}
    sk_free := @ERR_sk_free;
    {$ifend}
    {$if declared(sk_free_introduced)}
    if LibVersion < sk_free_introduced then
    begin
      {$if declared(FC_sk_free)}
      sk_free := @FC_sk_free;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(sk_free_removed)}
    if sk_free_removed <= LibVersion then
    begin
      {$if declared(_sk_free)}
      sk_free := @_sk_free;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(sk_free_allownil)}
    if FuncLoadError then
      AFailed.Add('sk_free');
    {$ifend}
  end;

 
  sk_pop_free := LoadLibFunction(ADllHandle, sk_pop_free_procname);
  FuncLoadError := not assigned(sk_pop_free);
  if FuncLoadError then
  begin
    {$if not defined(sk_pop_free_allownil)}
    sk_pop_free := @ERR_sk_pop_free;
    {$ifend}
    {$if declared(sk_pop_free_introduced)}
    if LibVersion < sk_pop_free_introduced then
    begin
      {$if declared(FC_sk_pop_free)}
      sk_pop_free := @FC_sk_pop_free;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(sk_pop_free_removed)}
    if sk_pop_free_removed <= LibVersion then
    begin
      {$if declared(_sk_pop_free)}
      sk_pop_free := @_sk_pop_free;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(sk_pop_free_allownil)}
    if FuncLoadError then
      AFailed.Add('sk_pop_free');
    {$ifend}
  end;

 
  sk_deep_copy := LoadLibFunction(ADllHandle, sk_deep_copy_procname);
  FuncLoadError := not assigned(sk_deep_copy);
  if FuncLoadError then
  begin
    {$if not defined(sk_deep_copy_allownil)}
    sk_deep_copy := @ERR_sk_deep_copy;
    {$ifend}
    {$if declared(sk_deep_copy_introduced)}
    if LibVersion < sk_deep_copy_introduced then
    begin
      {$if declared(FC_sk_deep_copy)}
      sk_deep_copy := @FC_sk_deep_copy;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(sk_deep_copy_removed)}
    if sk_deep_copy_removed <= LibVersion then
    begin
      {$if declared(_sk_deep_copy)}
      sk_deep_copy := @_sk_deep_copy;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(sk_deep_copy_allownil)}
    if FuncLoadError then
      AFailed.Add('sk_deep_copy');
    {$ifend}
  end;

 
  sk_insert := LoadLibFunction(ADllHandle, sk_insert_procname);
  FuncLoadError := not assigned(sk_insert);
  if FuncLoadError then
  begin
    {$if not defined(sk_insert_allownil)}
    sk_insert := @ERR_sk_insert;
    {$ifend}
    {$if declared(sk_insert_introduced)}
    if LibVersion < sk_insert_introduced then
    begin
      {$if declared(FC_sk_insert)}
      sk_insert := @FC_sk_insert;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(sk_insert_removed)}
    if sk_insert_removed <= LibVersion then
    begin
      {$if declared(_sk_insert)}
      sk_insert := @_sk_insert;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(sk_insert_allownil)}
    if FuncLoadError then
      AFailed.Add('sk_insert');
    {$ifend}
  end;

 
  sk_delete := LoadLibFunction(ADllHandle, sk_delete_procname);
  FuncLoadError := not assigned(sk_delete);
  if FuncLoadError then
  begin
    {$if not defined(sk_delete_allownil)}
    sk_delete := @ERR_sk_delete;
    {$ifend}
    {$if declared(sk_delete_introduced)}
    if LibVersion < sk_delete_introduced then
    begin
      {$if declared(FC_sk_delete)}
      sk_delete := @FC_sk_delete;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(sk_delete_removed)}
    if sk_delete_removed <= LibVersion then
    begin
      {$if declared(_sk_delete)}
      sk_delete := @_sk_delete;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(sk_delete_allownil)}
    if FuncLoadError then
      AFailed.Add('sk_delete');
    {$ifend}
  end;

 
  sk_delete_ptr := LoadLibFunction(ADllHandle, sk_delete_ptr_procname);
  FuncLoadError := not assigned(sk_delete_ptr);
  if FuncLoadError then
  begin
    {$if not defined(sk_delete_ptr_allownil)}
    sk_delete_ptr := @ERR_sk_delete_ptr;
    {$ifend}
    {$if declared(sk_delete_ptr_introduced)}
    if LibVersion < sk_delete_ptr_introduced then
    begin
      {$if declared(FC_sk_delete_ptr)}
      sk_delete_ptr := @FC_sk_delete_ptr;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(sk_delete_ptr_removed)}
    if sk_delete_ptr_removed <= LibVersion then
    begin
      {$if declared(_sk_delete_ptr)}
      sk_delete_ptr := @_sk_delete_ptr;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(sk_delete_ptr_allownil)}
    if FuncLoadError then
      AFailed.Add('sk_delete_ptr');
    {$ifend}
  end;

 
  sk_find := LoadLibFunction(ADllHandle, sk_find_procname);
  FuncLoadError := not assigned(sk_find);
  if FuncLoadError then
  begin
    {$if not defined(sk_find_allownil)}
    sk_find := @ERR_sk_find;
    {$ifend}
    {$if declared(sk_find_introduced)}
    if LibVersion < sk_find_introduced then
    begin
      {$if declared(FC_sk_find)}
      sk_find := @FC_sk_find;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(sk_find_removed)}
    if sk_find_removed <= LibVersion then
    begin
      {$if declared(_sk_find)}
      sk_find := @_sk_find;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(sk_find_allownil)}
    if FuncLoadError then
      AFailed.Add('sk_find');
    {$ifend}
  end;

 
  sk_find_ex := LoadLibFunction(ADllHandle, sk_find_ex_procname);
  FuncLoadError := not assigned(sk_find_ex);
  if FuncLoadError then
  begin
    {$if not defined(sk_find_ex_allownil)}
    sk_find_ex := @ERR_sk_find_ex;
    {$ifend}
    {$if declared(sk_find_ex_introduced)}
    if LibVersion < sk_find_ex_introduced then
    begin
      {$if declared(FC_sk_find_ex)}
      sk_find_ex := @FC_sk_find_ex;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(sk_find_ex_removed)}
    if sk_find_ex_removed <= LibVersion then
    begin
      {$if declared(_sk_find_ex)}
      sk_find_ex := @_sk_find_ex;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(sk_find_ex_allownil)}
    if FuncLoadError then
      AFailed.Add('sk_find_ex');
    {$ifend}
  end;

 
  sk_push := LoadLibFunction(ADllHandle, sk_push_procname);
  FuncLoadError := not assigned(sk_push);
  if FuncLoadError then
  begin
    {$if not defined(sk_push_allownil)}
    sk_push := @ERR_sk_push;
    {$ifend}
    {$if declared(sk_push_introduced)}
    if LibVersion < sk_push_introduced then
    begin
      {$if declared(FC_sk_push)}
      sk_push := @FC_sk_push;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(sk_push_removed)}
    if sk_push_removed <= LibVersion then
    begin
      {$if declared(_sk_push)}
      sk_push := @_sk_push;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(sk_push_allownil)}
    if FuncLoadError then
      AFailed.Add('sk_push');
    {$ifend}
  end;

 
  sk_unshift := LoadLibFunction(ADllHandle, sk_unshift_procname);
  FuncLoadError := not assigned(sk_unshift);
  if FuncLoadError then
  begin
    {$if not defined(sk_unshift_allownil)}
    sk_unshift := @ERR_sk_unshift;
    {$ifend}
    {$if declared(sk_unshift_introduced)}
    if LibVersion < sk_unshift_introduced then
    begin
      {$if declared(FC_sk_unshift)}
      sk_unshift := @FC_sk_unshift;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(sk_unshift_removed)}
    if sk_unshift_removed <= LibVersion then
    begin
      {$if declared(_sk_unshift)}
      sk_unshift := @_sk_unshift;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(sk_unshift_allownil)}
    if FuncLoadError then
      AFailed.Add('sk_unshift');
    {$ifend}
  end;

 
  sk_shift := LoadLibFunction(ADllHandle, sk_shift_procname);
  FuncLoadError := not assigned(sk_shift);
  if FuncLoadError then
  begin
    {$if not defined(sk_shift_allownil)}
    sk_shift := @ERR_sk_shift;
    {$ifend}
    {$if declared(sk_shift_introduced)}
    if LibVersion < sk_shift_introduced then
    begin
      {$if declared(FC_sk_shift)}
      sk_shift := @FC_sk_shift;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(sk_shift_removed)}
    if sk_shift_removed <= LibVersion then
    begin
      {$if declared(_sk_shift)}
      sk_shift := @_sk_shift;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(sk_shift_allownil)}
    if FuncLoadError then
      AFailed.Add('sk_shift');
    {$ifend}
  end;

 
  sk_pop := LoadLibFunction(ADllHandle, sk_pop_procname);
  FuncLoadError := not assigned(sk_pop);
  if FuncLoadError then
  begin
    {$if not defined(sk_pop_allownil)}
    sk_pop := @ERR_sk_pop;
    {$ifend}
    {$if declared(sk_pop_introduced)}
    if LibVersion < sk_pop_introduced then
    begin
      {$if declared(FC_sk_pop)}
      sk_pop := @FC_sk_pop;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(sk_pop_removed)}
    if sk_pop_removed <= LibVersion then
    begin
      {$if declared(_sk_pop)}
      sk_pop := @_sk_pop;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(sk_pop_allownil)}
    if FuncLoadError then
      AFailed.Add('sk_pop');
    {$ifend}
  end;

 
  sk_zero := LoadLibFunction(ADllHandle, sk_zero_procname);
  FuncLoadError := not assigned(sk_zero);
  if FuncLoadError then
  begin
    {$if not defined(sk_zero_allownil)}
    sk_zero := @ERR_sk_zero;
    {$ifend}
    {$if declared(sk_zero_introduced)}
    if LibVersion < sk_zero_introduced then
    begin
      {$if declared(FC_sk_zero)}
      sk_zero := @FC_sk_zero;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(sk_zero_removed)}
    if sk_zero_removed <= LibVersion then
    begin
      {$if declared(_sk_zero)}
      sk_zero := @_sk_zero;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(sk_zero_allownil)}
    if FuncLoadError then
      AFailed.Add('sk_zero');
    {$ifend}
  end;

 
  sk_set_cmp_func := LoadLibFunction(ADllHandle, sk_set_cmp_func_procname);
  FuncLoadError := not assigned(sk_set_cmp_func);
  if FuncLoadError then
  begin
    {$if not defined(sk_set_cmp_func_allownil)}
    sk_set_cmp_func := @ERR_sk_set_cmp_func;
    {$ifend}
    {$if declared(sk_set_cmp_func_introduced)}
    if LibVersion < sk_set_cmp_func_introduced then
    begin
      {$if declared(FC_sk_set_cmp_func)}
      sk_set_cmp_func := @FC_sk_set_cmp_func;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(sk_set_cmp_func_removed)}
    if sk_set_cmp_func_removed <= LibVersion then
    begin
      {$if declared(_sk_set_cmp_func)}
      sk_set_cmp_func := @_sk_set_cmp_func;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(sk_set_cmp_func_allownil)}
    if FuncLoadError then
      AFailed.Add('sk_set_cmp_func');
    {$ifend}
  end;

 
  sk_dup := LoadLibFunction(ADllHandle, sk_dup_procname);
  FuncLoadError := not assigned(sk_dup);
  if FuncLoadError then
  begin
    {$if not defined(sk_dup_allownil)}
    sk_dup := @ERR_sk_dup;
    {$ifend}
    {$if declared(sk_dup_introduced)}
    if LibVersion < sk_dup_introduced then
    begin
      {$if declared(FC_sk_dup)}
      sk_dup := @FC_sk_dup;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(sk_dup_removed)}
    if sk_dup_removed <= LibVersion then
    begin
      {$if declared(_sk_dup)}
      sk_dup := @_sk_dup;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(sk_dup_allownil)}
    if FuncLoadError then
      AFailed.Add('sk_dup');
    {$ifend}
  end;

 
  sk_sort := LoadLibFunction(ADllHandle, sk_sort_procname);
  FuncLoadError := not assigned(sk_sort);
  if FuncLoadError then
  begin
    {$if not defined(sk_sort_allownil)}
    sk_sort := @ERR_sk_sort;
    {$ifend}
    {$if declared(sk_sort_introduced)}
    if LibVersion < sk_sort_introduced then
    begin
      {$if declared(FC_sk_sort)}
      sk_sort := @FC_sk_sort;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(sk_sort_removed)}
    if sk_sort_removed <= LibVersion then
    begin
      {$if declared(_sk_sort)}
      sk_sort := @_sk_sort;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(sk_sort_allownil)}
    if FuncLoadError then
      AFailed.Add('sk_sort');
    {$ifend}
  end;

 
  sk_is_sorted := LoadLibFunction(ADllHandle, sk_is_sorted_procname);
  FuncLoadError := not assigned(sk_is_sorted);
  if FuncLoadError then
  begin
    {$if not defined(sk_is_sorted_allownil)}
    sk_is_sorted := @ERR_sk_is_sorted;
    {$ifend}
    {$if declared(sk_is_sorted_introduced)}
    if LibVersion < sk_is_sorted_introduced then
    begin
      {$if declared(FC_sk_is_sorted)}
      sk_is_sorted := @FC_sk_is_sorted;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(sk_is_sorted_removed)}
    if sk_is_sorted_removed <= LibVersion then
    begin
      {$if declared(_sk_is_sorted)}
      sk_is_sorted := @_sk_is_sorted;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(sk_is_sorted_allownil)}
    if FuncLoadError then
      AFailed.Add('sk_is_sorted');
    {$ifend}
  end;

 
end;

procedure Unload;
begin
  OPENSSL_sk_num := nil; {introduced 1.1.0}
  OPENSSL_sk_value := nil; {introduced 1.1.0}
  OPENSSL_sk_set := nil; {introduced 1.1.0}
  OPENSSL_sk_new := nil; {introduced 1.1.0}
  OPENSSL_sk_new_null := nil; {introduced 1.1.0}
  OPENSSL_sk_new_reserve := nil; {introduced 1.1.0}
  OPENSSL_sk_reserve := nil; {introduced 1.1.0}
  OPENSSL_sk_free := nil; {introduced 1.1.0}
  OPENSSL_sk_pop_free := nil; {introduced 1.1.0}
  OPENSSL_sk_deep_copy := nil; {introduced 1.1.0}
  OPENSSL_sk_insert := nil; {introduced 1.1.0}
  OPENSSL_sk_delete := nil; {introduced 1.1.0}
  OPENSSL_sk_delete_ptr := nil; {introduced 1.1.0}
  OPENSSL_sk_find := nil; {introduced 1.1.0}
  OPENSSL_sk_find_ex := nil; {introduced 1.1.0}
  OPENSSL_sk_push := nil; {introduced 1.1.0}
  OPENSSL_sk_unshift := nil; {introduced 1.1.0}
  OPENSSL_sk_shift := nil; {introduced 1.1.0}
  OPENSSL_sk_pop := nil; {introduced 1.1.0}
  OPENSSL_sk_zero := nil; {introduced 1.1.0}
  OPENSSL_sk_set_cmp_func := nil; {introduced 1.1.0}
  OPENSSL_sk_dup := nil; {introduced 1.1.0}
  OPENSSL_sk_sort := nil; {introduced 1.1.0}
  OPENSSL_sk_is_sorted := nil; {introduced 1.1.0}
  sk_num := nil; {removed 1.1.0}
  sk_value := nil; {removed 1.1.0}
  sk_set := nil; {removed 1.1.0}
  sk_new := nil; {removed 1.1.0}
  sk_new_null := nil; {removed 1.1.0}
  sk_new_reserve := nil; {removed 1.0.0}
  sk_reserve := nil; {removed 1.0.0}
  sk_free := nil; {removed 1.1.0}
  sk_pop_free := nil; {removed 1.1.0}
  sk_deep_copy := nil; {removed 1.1.0}
  sk_insert := nil; {removed 1.1.0}
  sk_delete := nil; {removed 1.1.0}
  sk_delete_ptr := nil; {removed 1.1.0}
  sk_find := nil; {removed 1.1.0}
  sk_find_ex := nil; {removed 1.1.0}
  sk_push := nil; {removed 1.1.0}
  sk_unshift := nil; {removed 1.1.0}
  sk_shift := nil; {removed 1.1.0}
  sk_pop := nil; {removed 1.1.0}
  sk_zero := nil; {removed 1.1.0}
  sk_set_cmp_func := nil; {removed 1.1.0}
  sk_dup := nil; {removed 1.1.0}
  sk_sort := nil; {removed 1.1.0}
  sk_is_sorted := nil; {removed 1.1.0}
end;
{$ELSE}
function sk_num(_para1:POPENSSL_STACK):longint;
begin
  Result := OPENSSL_sk_num(_para1);
end;

function sk_value(_para1:POPENSSL_STACK; _para2:longint):pointer;
begin
  Result := OPENSSL_sk_value(_para1,_para2);
end;

function sk_set(st:POPENSSL_STACK; i:longint; data:pointer):pointer;
begin
  Result := OPENSSL_sk_set(st,i,data);
end;

function sk_new(cmp:TOPENSSL_sk_compfunc):POPENSSL_STACK;
begin
  Result := OPENSSL_sk_new(cmp);
end;

function sk_new_null:POPENSSL_STACK;
begin
  Result := OPENSSL_sk_new_null;
end;

function sk_new_reserve(c:TOPENSSL_sk_compfunc; n:longint):POPENSSL_STACK;
begin
  Result := OPENSSL_sk_new_reserve(c,n);
end;

function sk_reserve(st:POPENSSL_STACK; n:longint):longint;
begin
  Result := OPENSSL_sk_reserve(st,n);
end;

procedure sk_free(_para1:POPENSSL_STACK);
begin
  OPENSSL_sk_free(_para1);
end;

procedure sk_pop_free(st:POPENSSL_STACK; func:TOPENSSL_sk_freefunc);
begin
  OPENSSL_sk_pop_free(st, func);
end;

function sk_deep_copy(_para1:POPENSSL_STACK; c:TOPENSSL_sk_copyfunc; f:TOPENSSL_sk_freefunc):POPENSSL_STACK;
begin
  Result := OPENSSL_sk_deep_copy(_para1,c,f);
end;

function sk_insert(sk:POPENSSL_STACK; data:pointer; where:longint):longint;
begin
  Result := OPENSSL_sk_insert(sk,data,where);
end;

function sk_delete(st:POPENSSL_STACK; loc:longint):pointer;
begin
  Result := OPENSSL_sk_delete(st,loc);
end;

function sk_delete_ptr(st:POPENSSL_STACK; p:pointer):pointer;
begin
  Result := OPENSSL_sk_delete_ptr(st,p);
end;

function sk_find(st:POPENSSL_STACK; data:pointer):longint;
begin
  Result := OPENSSL_sk_find(st,data);
end;

function sk_find_ex(st:POPENSSL_STACK; data:pointer):longint;
begin
  Result := OPENSSL_sk_find_ex(st,data);
end;

function sk_push(st:POPENSSL_STACK; data:pointer):longint;
begin
  Result := OPENSSL_sk_push(st,data);
end;

function sk_unshift(st:POPENSSL_STACK; data:pointer):longint;
begin
  Result := OPENSSL_sk_unshift(st,data);
end;

function sk_shift(st:POPENSSL_STACK):pointer;
begin
  Result := OPENSSL_sk_shift(st);
end;

function sk_pop(st:POPENSSL_STACK):pointer;
begin
  Result := OPENSSL_sk_pop(st);
end;

procedure sk_zero(st:POPENSSL_STACK);
begin
  OPENSSL_sk_zero(st);
end;

function sk_set_cmp_func(sk:POPENSSL_STACK; cmp:TOPENSSL_sk_compfunc):TOPENSSL_sk_compfunc;
begin
  Result := OPENSSL_sk_set_cmp_func(sk,cmp);
end;

function sk_dup(st:POPENSSL_STACK):POPENSSL_STACK;
begin
  Result := OPENSSL_sk_dup(st);
end;

procedure sk_sort(st:POPENSSL_STACK);
begin
  OPENSSL_sk_sort(st);
end;

function sk_is_sorted(st:POPENSSL_STACK):longint;
begin
  Result := OPENSSL_sk_is_sorted(st);
end;



{$ENDIF}

{$IFNDEF OPENSSL_STATIC_LINK_MODEL}
initialization
  Register_SSLLoader(@Load,'LibCrypto');
  Register_SSLUnloader(@Unload);
{$ENDIF}
end.
