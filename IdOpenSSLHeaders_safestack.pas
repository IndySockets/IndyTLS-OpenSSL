unit IdOpenSSLHeaders_safestack;

{$i IdCompilerDefines.inc}
{$i IdSSLOpenSSLDefines.inc}

{ ****************************************************************************** }
{ }
{ Indy (Internet Direct) - Internet Protocols Simplified }
{ }
{ https://www.indyproject.org/ }
{ https://gitter.im/IndySockets/Indy }
{ }
{ ****************************************************************************** }
{ }
{ This file is part of the Indy (Internet Direct) project, and is offered }
{ under the dual-licensing agreement described on the Indy website. }
{ (https://www.indyproject.org/license/) }
{ }
{ Copyright: }
{ (c) 1993-2020, Chad Z. Hower and the Indy Pit Crew. All rights reserved. }
{ }
{ ****************************************************************************** }
{ }
{ }
{ ****************************************************************************** }
interface

uses
  IdCTypes,
  IdOpenSSLHeaders_stack;

type
  POPENSSL_STRING = PAnsiChar;

  PSTACK_OF_OPENSSL_STRING = pointer;
  sk_OPENSSL_STRING_compfunc = function(a: PPAnsiChar; b: PPAnsiChar): TIdC_INT;
  sk_OPENSSL_STRING_freefunc = procedure(a: PAnsiChar);
  sk_OPENSSL_STRING_copyfunc = function(a: PAnsiChar): PAnsiChar;

function sk_OPENSSL_STRING_num(sk: PSTACK_OF_OPENSSL_STRING): TIdC_INT;
{$IFDEF INLINE}inline; {$ENDIF}
function sk_OPENSSL_STRING_value(sk: PSTACK_OF_OPENSSL_STRING; idx: TIdC_INT)
  : PAnsiChar; {$IFDEF INLINE}inline; {$ENDIF}
function sk_OPENSSL_STRING_new(compare: sk_OPENSSL_STRING_compfunc)
  : PSTACK_OF_OPENSSL_STRING; {$IFDEF INLINE}inline; {$ENDIF}
function sk_OPENSSL_STRING_new_null: PSTACK_OF_OPENSSL_STRING;
{$IFDEF INLINE}inline; {$ENDIF}
procedure sk_OPENSSL_STRING_free(sk: PSTACK_OF_OPENSSL_STRING);
{$IFDEF INLINE}inline; {$ENDIF}
procedure sk_OPENSSL_STRING_zero(sk: PSTACK_OF_OPENSSL_STRING);
{$IFDEF INLINE}inline; {$ENDIF}
function sk_OPENSSL_STRING_delete(sk: PSTACK_OF_OPENSSL_STRING; i: TIdC_INT)
  : PAnsiChar; {$IFDEF INLINE}inline; {$ENDIF}
function sk_OPENSSL_STRING_delete_ptr(sk: PSTACK_OF_OPENSSL_STRING;
  ptr: PAnsiChar): PAnsiChar; {$IFDEF INLINE}inline; {$ENDIF}
function sk_OPENSSL_STRING_push(sk: PSTACK_OF_OPENSSL_STRING; ptr: PAnsiChar)
  : TIdC_INT; {$IFDEF INLINE}inline; {$ENDIF}
function sk_OPENSSL_STRING_unshift(sk: PSTACK_OF_OPENSSL_STRING; ptr: PAnsiChar)
  : TIdC_INT; {$IFDEF INLINE}inline; {$ENDIF}
function sk_OPENSSL_STRING_pop(sk: PSTACK_OF_OPENSSL_STRING): PAnsiChar;
{$IFDEF INLINE}inline; {$ENDIF}
function sk_OPENSSL_STRING_shift(sk: PSTACK_OF_OPENSSL_STRING): PAnsiChar;
{$IFDEF INLINE}inline; {$ENDIF}
procedure sk_OPENSSL_STRING_pop_free(sk: PSTACK_OF_OPENSSL_STRING;
  freefunc: sk_OPENSSL_STRING_freefunc); {$IFDEF INLINE}inline; {$ENDIF}
function sk_OPENSSL_STRING_insert(sk: PSTACK_OF_OPENSSL_STRING; ptr: PAnsiChar;
  idx: TIdC_INT): TIdC_INT; {$IFDEF INLINE}inline; {$ENDIF}
function sk_OPENSSL_STRING_set(sk: PSTACK_OF_OPENSSL_STRING; idx: TIdC_INT;
  ptr: PAnsiChar): PAnsiChar; {$IFDEF INLINE}inline; {$ENDIF}
function sk_OPENSSL_STRING_find(sk: PSTACK_OF_OPENSSL_STRING; ptr: PAnsiChar)
  : TIdC_INT; {$IFDEF INLINE}inline; {$ENDIF}
function sk_OPENSSL_STRING_find_ex(sk: PSTACK_OF_OPENSSL_STRING; ptr: PAnsiChar)
  : TIdC_INT; {$IFDEF INLINE}inline; {$ENDIF}
procedure sk_OPENSSL_STRING_sort(sk: PSTACK_OF_OPENSSL_STRING);
{$IFDEF INLINE}inline; {$ENDIF}
function sk_OPENSSL_STRING_is_sorted(sk: PSTACK_OF_OPENSSL_STRING): TIdC_INT;
{$IFDEF INLINE}inline; {$ENDIF}
function sk_OPENSSL_STRING_dup(sk: PSTACK_OF_OPENSSL_STRING)
  : PSTACK_OF_OPENSSL_STRING; {$IFDEF INLINE}inline; {$ENDIF}
function sk_OPENSSL_STRING_deep_copy(sk: PSTACK_OF_OPENSSL_STRING;
  copyfunc: sk_OPENSSL_STRING_copyfunc; freefunc: sk_OPENSSL_STRING_freefunc)
  : PSTACK_OF_OPENSSL_STRING;  {$IFDEF INLINE}inline;{$ENDIF}
function sk_OPENSSL_STRING_set_cmp_func(sk: PSTACK_OF_OPENSSL_STRING;
  compare: sk_OPENSSL_STRING_compfunc): sk_OPENSSL_STRING_compfunc;   {$IFDEF INLINE}inline;{$ENDIF}

implementation

function sk_OPENSSL_STRING_num(sk: PSTACK_OF_OPENSSL_STRING): TIdC_INT;
{$IFDEF INLINE}inline; {$ENDIF}
begin
  Result := OPENSSL_sk_num(POPENSSL_STACK(sk));
end;

function sk_OPENSSL_STRING_value(sk: PSTACK_OF_OPENSSL_STRING; idx: TIdC_INT)
  : PAnsiChar; {$IFDEF INLINE}inline; {$ENDIF}
begin
  Result := PAnsiChar(OPENSSL_sk_value(POPENSSL_STACK(sk), idx));
end;

function sk_OPENSSL_STRING_new(compare: sk_OPENSSL_STRING_compfunc)
  : PSTACK_OF_OPENSSL_STRING; {$IFDEF INLINE}inline; {$ENDIF}
begin
  Result := PSTACK_OF_OPENSSL_STRING
    (OPENSSL_sk_new(TOPENSSL_sk_compfunc(compare)));
end;

function sk_OPENSSL_STRING_new_null: PSTACK_OF_OPENSSL_STRING;
{$IFDEF INLINE}inline; {$ENDIF}
begin
  Result := PSTACK_OF_OPENSSL_STRING(OPENSSL_sk_new_null);
end;

procedure sk_OPENSSL_STRING_free(sk: PSTACK_OF_OPENSSL_STRING);
{$IFDEF INLINE}inline; {$ENDIF}
begin
  OPENSSL_sk_free(POPENSSL_STACK(sk));
end;

procedure sk_OPENSSL_STRING_zero(sk: PSTACK_OF_OPENSSL_STRING);
{$IFDEF INLINE}inline; {$ENDIF}
begin
  OPENSSL_sk_zero(POPENSSL_STACK(sk));
end;

function sk_OPENSSL_STRING_delete(sk: PSTACK_OF_OPENSSL_STRING; i: TIdC_INT)
  : PAnsiChar; {$IFDEF INLINE}inline; {$ENDIF}
begin
  Result := PAnsiChar(OPENSSL_sk_delete(POPENSSL_STACK(sk), i));
end;

function sk_OPENSSL_STRING_delete_ptr(sk: PSTACK_OF_OPENSSL_STRING;
  ptr: PAnsiChar): PAnsiChar; {$IFDEF INLINE}inline; {$ENDIF}
begin
  Result := PAnsiChar(OPENSSL_sk_delete_ptr(POPENSSL_STACK(sk), pointer(ptr)));
end;

function sk_OPENSSL_STRING_push(sk: PSTACK_OF_OPENSSL_STRING; ptr: PAnsiChar)
  : TIdC_INT; {$IFDEF INLINE}inline; {$ENDIF}
begin
  Result := OPENSSL_sk_push(POPENSSL_STACK(sk), pointer(ptr));
end;

function sk_OPENSSL_STRING_unshift(sk: PSTACK_OF_OPENSSL_STRING; ptr: PAnsiChar)
  : TIdC_INT; {$IFDEF INLINE}inline; {$ENDIF}
begin
  Result := OPENSSL_sk_unshift(POPENSSL_STACK(sk), pointer(ptr));
end;

function sk_OPENSSL_STRING_pop(sk: PSTACK_OF_OPENSSL_STRING): PAnsiChar;
{$IFDEF INLINE}inline; {$ENDIF}
begin
  Result := PAnsiChar(OPENSSL_sk_pop(POPENSSL_STACK(sk)));
end;

function sk_OPENSSL_STRING_shift(sk: PSTACK_OF_OPENSSL_STRING): PAnsiChar;
{$IFDEF INLINE}inline; {$ENDIF}
begin
  Result := PAnsiChar(OPENSSL_sk_shift(POPENSSL_STACK(sk)));
end;

procedure sk_OPENSSL_STRING_pop_free(sk: PSTACK_OF_OPENSSL_STRING;
  freefunc: sk_OPENSSL_STRING_freefunc); {$IFDEF INLINE}inline; {$ENDIF}
begin
  OPENSSL_sk_pop_free(POPENSSL_STACK(sk), TOPENSSL_sk_freefunc(freefunc));
end;

function sk_OPENSSL_STRING_insert(sk: PSTACK_OF_OPENSSL_STRING; ptr: PAnsiChar;
  idx: TIdC_INT): TIdC_INT; {$IFDEF INLINE}inline; {$ENDIF}
begin
  Result := OPENSSL_sk_insert(POPENSSL_STACK(sk), pointer(ptr), idx);
end;

function sk_OPENSSL_STRING_set(sk: PSTACK_OF_OPENSSL_STRING; idx: TIdC_INT;
  ptr: PAnsiChar): PAnsiChar; {$IFDEF INLINE}inline; {$ENDIF}
begin
  Result := PAnsiChar(OPENSSL_sk_set(POPENSSL_STACK(sk), idx, pointer(ptr)));
end;

function sk_OPENSSL_STRING_find(sk: PSTACK_OF_OPENSSL_STRING; ptr: PAnsiChar)
  : TIdC_INT; {$IFDEF INLINE}inline; {$ENDIF}
begin
  Result := OPENSSL_sk_find(POPENSSL_STACK(sk), pointer(ptr));
end;

function sk_OPENSSL_STRING_find_ex(sk: PSTACK_OF_OPENSSL_STRING; ptr: PAnsiChar)
  : TIdC_INT; {$IFDEF INLINE}inline; {$ENDIF}
begin
  Result := OPENSSL_sk_find_ex(POPENSSL_STACK(sk), pointer(ptr));
end;

procedure sk_OPENSSL_STRING_sort(sk: PSTACK_OF_OPENSSL_STRING);
{$IFDEF INLINE}inline; {$ENDIF}
begin
  OPENSSL_sk_sort(POPENSSL_STACK(sk));
end;

function sk_OPENSSL_STRING_is_sorted(sk: PSTACK_OF_OPENSSL_STRING): TIdC_INT;
{$IFDEF INLINE}inline; {$ENDIF}
begin
  Result := OPENSSL_sk_is_sorted(POPENSSL_STACK(sk));
end;

function sk_OPENSSL_STRING_dup(sk: PSTACK_OF_OPENSSL_STRING)
  : PSTACK_OF_OPENSSL_STRING; {$IFDEF INLINE}inline; {$ENDIF}
begin
  Result := PSTACK_OF_OPENSSL_STRING(OPENSSL_sk_dup(POPENSSL_STACK(sk)));
end;

function sk_OPENSSL_STRING_deep_copy(sk: PSTACK_OF_OPENSSL_STRING;
  copyfunc: sk_OPENSSL_STRING_copyfunc; freefunc: sk_OPENSSL_STRING_freefunc)
  : PSTACK_OF_OPENSSL_STRING;  {$IFDEF INLINE}inline;{$ENDIF}
begin
  Result := PSTACK_OF_OPENSSL_STRING(OPENSSL_sk_deep_copy(POPENSSL_STACK(sk),
    TOPENSSL_sk_copyfunc(copyfunc), TOPENSSL_sk_freefunc(freefunc)));
end;

function sk_OPENSSL_STRING_set_cmp_func(sk: PSTACK_OF_OPENSSL_STRING;
  compare: sk_OPENSSL_STRING_compfunc): sk_OPENSSL_STRING_compfunc;   {$IFDEF INLINE}inline;{$ENDIF}
begin
  Result := sk_OPENSSL_STRING_compfunc
    (OPENSSL_sk_set_cmp_func(POPENSSL_STACK(sk),
    TOPENSSL_sk_compfunc(compare)));
end;

end.
