(* This unit was generated from the source file safestack.h2pas 
It should not be modified directly. All changes should be made to safestack.h2pas
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

unit IdOpenSSLHeaders_safestack;


interface

uses
  IdSSLOpenSSLAPI,
  IdOpenSSLHeaders_stack;

type
  POPENSSL_STRING = PAnsiChar;

  PSTACK_OF_OPENSSL_STRING = pointer;
  sk_OPENSSL_STRING_compfunc = function(a: PPAnsiChar; b: PPAnsiChar): TOpenSSL_C_INT;
  sk_OPENSSL_STRING_freefunc = procedure(a: PAnsiChar);
  sk_OPENSSL_STRING_copyfunc = function(a: PAnsiChar): PAnsiChar;


function sk_OPENSSL_STRING_num(sk: PSTACK_OF_OPENSSL_STRING): TOpenSSL_C_INT;

function sk_OPENSSL_STRING_value(sk: PSTACK_OF_OPENSSL_STRING; idx: TOpenSSL_C_INT): PAnsiChar;
function sk_OPENSSL_STRING_new(compare: sk_OPENSSL_STRING_compfunc): PSTACK_OF_OPENSSL_STRING;
function sk_OPENSSL_STRING_new_null: PSTACK_OF_OPENSSL_STRING;
procedure sk_OPENSSL_STRING_free(sk: PSTACK_OF_OPENSSL_STRING);
procedure sk_OPENSSL_STRING_zero(sk: PSTACK_OF_OPENSSL_STRING);
function sk_OPENSSL_STRING_delete(sk: PSTACK_OF_OPENSSL_STRING; i: TOpenSSL_C_INT)
  : PAnsiChar;
function sk_OPENSSL_STRING_delete_ptr(sk: PSTACK_OF_OPENSSL_STRING;
  ptr: PAnsiChar): PAnsiChar;
function sk_OPENSSL_STRING_push(sk: PSTACK_OF_OPENSSL_STRING; ptr: PAnsiChar)
  : TOpenSSL_C_INT;
function sk_OPENSSL_STRING_unshift(sk: PSTACK_OF_OPENSSL_STRING; ptr: PAnsiChar)
  : TOpenSSL_C_INT;
function sk_OPENSSL_STRING_pop(sk: PSTACK_OF_OPENSSL_STRING): PAnsiChar;
function sk_OPENSSL_STRING_shift(sk: PSTACK_OF_OPENSSL_STRING): PAnsiChar;
procedure sk_OPENSSL_STRING_pop_free(sk: PSTACK_OF_OPENSSL_STRING;
  freefunc: sk_OPENSSL_STRING_freefunc);
function sk_OPENSSL_STRING_insert(sk: PSTACK_OF_OPENSSL_STRING; ptr: PAnsiChar;
  idx: TOpenSSL_C_INT): TOpenSSL_C_INT;
function sk_OPENSSL_STRING_set(sk: PSTACK_OF_OPENSSL_STRING; idx: TOpenSSL_C_INT;
  ptr: PAnsiChar): PAnsiChar;
function sk_OPENSSL_STRING_find(sk: PSTACK_OF_OPENSSL_STRING; ptr: PAnsiChar)
  : TOpenSSL_C_INT;
function sk_OPENSSL_STRING_find_ex(sk: PSTACK_OF_OPENSSL_STRING; ptr: PAnsiChar)
  : TOpenSSL_C_INT;
procedure sk_OPENSSL_STRING_sort(sk: PSTACK_OF_OPENSSL_STRING);
function sk_OPENSSL_STRING_is_sorted(sk: PSTACK_OF_OPENSSL_STRING): TOpenSSL_C_INT;
function sk_OPENSSL_STRING_dup(sk: PSTACK_OF_OPENSSL_STRING): PSTACK_OF_OPENSSL_STRING;
function sk_OPENSSL_STRING_deep_copy(sk: PSTACK_OF_OPENSSL_STRING;
  copyfunc: sk_OPENSSL_STRING_copyfunc; freefunc: sk_OPENSSL_STRING_freefunc)
  : PSTACK_OF_OPENSSL_STRING;
function sk_OPENSSL_STRING_set_cmp_func(sk: PSTACK_OF_OPENSSL_STRING;
  compare: sk_OPENSSL_STRING_compfunc): sk_OPENSSL_STRING_compfunc;




{ The EXTERNALSYM directive is ignored by FPC, however, it is used by Delphi as follows: 

The EXTERNALSYM directive prevents the specified Delphi symbol from appearing in header 
files generated for C++. }


{$IFDEF OPENSSL_STATIC_LINK_MODEL}

{$ELSE}

{$ENDIF}

implementation

uses Classes,
     IdSSLOpenSSLExceptionHandlers,
     IdSSLOpenSSLResourceStrings;


function sk_OPENSSL_STRING_num(sk: PSTACK_OF_OPENSSL_STRING): TOpenSSL_C_INT;
begin
  Result := OPENSSL_sk_num(POPENSSL_STACK(sk));
end;

function sk_OPENSSL_STRING_value(sk: PSTACK_OF_OPENSSL_STRING; idx: TOpenSSL_C_INT)
  : PAnsiChar;
begin
  Result := PAnsiChar(OPENSSL_sk_value(POPENSSL_STACK(sk), idx));
end;

function sk_OPENSSL_STRING_new(compare: sk_OPENSSL_STRING_compfunc)
  : PSTACK_OF_OPENSSL_STRING;
begin
  Result := PSTACK_OF_OPENSSL_STRING
    (OPENSSL_sk_new(TOPENSSL_sk_compfunc(compare)));
end;

function sk_OPENSSL_STRING_new_null: PSTACK_OF_OPENSSL_STRING;
begin
  Result := PSTACK_OF_OPENSSL_STRING(OPENSSL_sk_new_null);
end;

procedure sk_OPENSSL_STRING_free(sk: PSTACK_OF_OPENSSL_STRING);
begin
  OPENSSL_sk_free(POPENSSL_STACK(sk));
end;

procedure sk_OPENSSL_STRING_zero(sk: PSTACK_OF_OPENSSL_STRING);
begin
  OPENSSL_sk_zero(POPENSSL_STACK(sk));
end;
function sk_OPENSSL_STRING_delete(sk: PSTACK_OF_OPENSSL_STRING; i: TOpenSSL_C_INT)
  : PAnsiChar;
begin
  Result := PAnsiChar(OPENSSL_sk_delete(POPENSSL_STACK(sk), i));
end;

function sk_OPENSSL_STRING_delete_ptr(sk: PSTACK_OF_OPENSSL_STRING;
  ptr: PAnsiChar): PAnsiChar;
begin
  Result := PAnsiChar(OPENSSL_sk_delete_ptr(POPENSSL_STACK(sk), pointer(ptr)));
end;

function sk_OPENSSL_STRING_push(sk: PSTACK_OF_OPENSSL_STRING; ptr: PAnsiChar)
  : TOpenSSL_C_INT;
begin
  Result := OPENSSL_sk_push(POPENSSL_STACK(sk), pointer(ptr));
end;

function sk_OPENSSL_STRING_unshift(sk: PSTACK_OF_OPENSSL_STRING; ptr: PAnsiChar)
  : TOpenSSL_C_INT;
begin
  Result := OPENSSL_sk_unshift(POPENSSL_STACK(sk), pointer(ptr));
end;

function sk_OPENSSL_STRING_pop(sk: PSTACK_OF_OPENSSL_STRING): PAnsiChar;
begin
  Result := PAnsiChar(OPENSSL_sk_pop(POPENSSL_STACK(sk)));
end;

function sk_OPENSSL_STRING_shift(sk: PSTACK_OF_OPENSSL_STRING): PAnsiChar;
begin
  Result := PAnsiChar(OPENSSL_sk_shift(POPENSSL_STACK(sk)));
end;

procedure sk_OPENSSL_STRING_pop_free(sk: PSTACK_OF_OPENSSL_STRING;
  freefunc: sk_OPENSSL_STRING_freefunc);
begin
  OPENSSL_sk_pop_free(POPENSSL_STACK(sk), TOPENSSL_sk_freefunc(freefunc));
end;

function sk_OPENSSL_STRING_insert(sk: PSTACK_OF_OPENSSL_STRING; ptr: PAnsiChar;
  idx: TOpenSSL_C_INT): TOpenSSL_C_INT;
begin
  Result := OPENSSL_sk_insert(POPENSSL_STACK(sk), pointer(ptr), idx);
end;

function sk_OPENSSL_STRING_set(sk: PSTACK_OF_OPENSSL_STRING; idx: TOpenSSL_C_INT;
  ptr: PAnsiChar): PAnsiChar;
begin
  Result := PAnsiChar(OPENSSL_sk_set(POPENSSL_STACK(sk), idx, pointer(ptr)));
end;

function sk_OPENSSL_STRING_find(sk: PSTACK_OF_OPENSSL_STRING; ptr: PAnsiChar)
  : TOpenSSL_C_INT;
begin
  Result := OPENSSL_sk_find(POPENSSL_STACK(sk), pointer(ptr));
end;

function sk_OPENSSL_STRING_find_ex(sk: PSTACK_OF_OPENSSL_STRING; ptr: PAnsiChar)
  : TOpenSSL_C_INT;
begin
  Result := OPENSSL_sk_find_ex(POPENSSL_STACK(sk), pointer(ptr));
end;

procedure sk_OPENSSL_STRING_sort(sk: PSTACK_OF_OPENSSL_STRING);
begin
  OPENSSL_sk_sort(POPENSSL_STACK(sk));
end;

function sk_OPENSSL_STRING_is_sorted(sk: PSTACK_OF_OPENSSL_STRING): TOpenSSL_C_INT;
begin
  Result := OPENSSL_sk_is_sorted(POPENSSL_STACK(sk));
end;

function sk_OPENSSL_STRING_dup(sk: PSTACK_OF_OPENSSL_STRING)
  : PSTACK_OF_OPENSSL_STRING;
begin
  Result := PSTACK_OF_OPENSSL_STRING(OPENSSL_sk_dup(POPENSSL_STACK(sk)));
end;

function sk_OPENSSL_STRING_deep_copy(sk: PSTACK_OF_OPENSSL_STRING;
  copyfunc: sk_OPENSSL_STRING_copyfunc; freefunc: sk_OPENSSL_STRING_freefunc)
  : PSTACK_OF_OPENSSL_STRING;
begin
  Result := PSTACK_OF_OPENSSL_STRING(OPENSSL_sk_deep_copy(POPENSSL_STACK(sk),
    TOPENSSL_sk_copyfunc(copyfunc), TOPENSSL_sk_freefunc(freefunc)));
end;

function sk_OPENSSL_STRING_set_cmp_func(sk: PSTACK_OF_OPENSSL_STRING;
  compare: sk_OPENSSL_STRING_compfunc): sk_OPENSSL_STRING_compfunc;
begin
  Result := sk_OPENSSL_STRING_compfunc
    (OPENSSL_sk_set_cmp_func(POPENSSL_STACK(sk),
    TOPENSSL_sk_compfunc(compare)));
end;





{$IFNDEF OPENSSL_STATIC_LINK_MODEL}
{$IFNDEF OPENSSL_NO_LEGACY_SUPPORT}
{$ENDIF} { End of OPENSSL_NO_LEGACY_SUPPORT}
{$ENDIF}
{$IFNDEF OPENSSL_STATIC_LINK_MODEL}
{$IFNDEF OPENSSL_NO_LEGACY_SUPPORT}
{$ENDIF} { End of OPENSSL_NO_LEGACY_SUPPORT}
{$ENDIF}

initialization

{$IFNDEF OPENSSL_STATIC_LINK_MODEL}
{$ENDIF}
finalization


end.
