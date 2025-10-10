(* This unit was generated from the source file buffer.h2pas 
It should not be modified directly. All changes should be made to buffer.h2pas
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


unit IdOpenSSLHeaders_buffer;


interface

// Headers for OpenSSL 1.1.1
// buffer.h


uses
  IdSSLOpenSSLAPI,
  IdOpenSSLHeaders_ossl_typ;

const
  BUF_MEM_FLAG_SECURE = $01;

type
  buf_mem_st = record
    length: TOpenSSL_C_SIZET;
    data: PAnsiChar;
    max: TOpenSSL_C_SIZET;
    flags: TOpenSSL_C_ULONG;
  end;

  
{ The EXTERNALSYM directive is ignored by FPC, however, it is used by Delphi as follows: 

The EXTERNALSYM directive prevents the specified Delphi symbol from appearing in header 
files generated for C++. }

{$EXTERNALSYM BUF_MEM_new}
{$EXTERNALSYM BUF_MEM_new_ex}
{$EXTERNALSYM BUF_MEM_free}
{$EXTERNALSYM BUF_MEM_grow}
{$EXTERNALSYM BUF_MEM_grow_clean}
{$EXTERNALSYM BUF_reverse}

{$IFDEF OPENSSL_STATIC_LINK_MODEL}
function BUF_MEM_new: PBUF_MEM; cdecl; external CLibCrypto;
function BUF_MEM_new_ex(flags: TOpenSSL_C_ULONG): PBUF_MEM; cdecl; external CLibCrypto;
procedure BUF_MEM_free(a: PBUF_MEM); cdecl; external CLibCrypto;
function BUF_MEM_grow(str: PBUF_MEM; len: TOpenSSL_C_SIZET): TOpenSSL_C_SIZET; cdecl; external CLibCrypto;
function BUF_MEM_grow_clean(str: PBUF_MEM; len: TOpenSSL_C_SIZET): TOpenSSL_C_SIZET; cdecl; external CLibCrypto;
procedure BUF_reverse(out_: PByte; const in_: PByte; siz: TOpenSSL_C_SIZET); cdecl; external CLibCrypto;

{$ELSE}

{Declare external function initialisers - should not be called directly}

function Load_BUF_MEM_new: PBUF_MEM; cdecl;
function Load_BUF_MEM_new_ex(flags: TOpenSSL_C_ULONG): PBUF_MEM; cdecl;
procedure Load_BUF_MEM_free(a: PBUF_MEM); cdecl;
function Load_BUF_MEM_grow(str: PBUF_MEM; len: TOpenSSL_C_SIZET): TOpenSSL_C_SIZET; cdecl;
function Load_BUF_MEM_grow_clean(str: PBUF_MEM; len: TOpenSSL_C_SIZET): TOpenSSL_C_SIZET; cdecl;
procedure Load_BUF_reverse(out_: PByte; const in_: PByte; siz: TOpenSSL_C_SIZET); cdecl;

var
  BUF_MEM_new: function : PBUF_MEM; cdecl = Load_BUF_MEM_new;
  BUF_MEM_new_ex: function (flags: TOpenSSL_C_ULONG): PBUF_MEM; cdecl = Load_BUF_MEM_new_ex;
  BUF_MEM_free: procedure (a: PBUF_MEM); cdecl = Load_BUF_MEM_free;
  BUF_MEM_grow: function (str: PBUF_MEM; len: TOpenSSL_C_SIZET): TOpenSSL_C_SIZET; cdecl = Load_BUF_MEM_grow;
  BUF_MEM_grow_clean: function (str: PBUF_MEM; len: TOpenSSL_C_SIZET): TOpenSSL_C_SIZET; cdecl = Load_BUF_MEM_grow_clean;
  BUF_reverse: procedure (out_: PByte; const in_: PByte; siz: TOpenSSL_C_SIZET); cdecl = Load_BUF_reverse;
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
function Load_BUF_MEM_new: PBUF_MEM; cdecl;
begin
  BUF_MEM_new := LoadLibCryptoFunction('BUF_MEM_new');
  if not assigned(BUF_MEM_new) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('BUF_MEM_new');
  Result := BUF_MEM_new();
end;

function Load_BUF_MEM_new_ex(flags: TOpenSSL_C_ULONG): PBUF_MEM; cdecl;
begin
  BUF_MEM_new_ex := LoadLibCryptoFunction('BUF_MEM_new_ex');
  if not assigned(BUF_MEM_new_ex) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('BUF_MEM_new_ex');
  Result := BUF_MEM_new_ex(flags);
end;

procedure Load_BUF_MEM_free(a: PBUF_MEM); cdecl;
begin
  BUF_MEM_free := LoadLibCryptoFunction('BUF_MEM_free');
  if not assigned(BUF_MEM_free) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('BUF_MEM_free');
  BUF_MEM_free(a);
end;

function Load_BUF_MEM_grow(str: PBUF_MEM; len: TOpenSSL_C_SIZET): TOpenSSL_C_SIZET; cdecl;
begin
  BUF_MEM_grow := LoadLibCryptoFunction('BUF_MEM_grow');
  if not assigned(BUF_MEM_grow) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('BUF_MEM_grow');
  Result := BUF_MEM_grow(str,len);
end;

function Load_BUF_MEM_grow_clean(str: PBUF_MEM; len: TOpenSSL_C_SIZET): TOpenSSL_C_SIZET; cdecl;
begin
  BUF_MEM_grow_clean := LoadLibCryptoFunction('BUF_MEM_grow_clean');
  if not assigned(BUF_MEM_grow_clean) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('BUF_MEM_grow_clean');
  Result := BUF_MEM_grow_clean(str,len);
end;

procedure Load_BUF_reverse(out_: PByte; const in_: PByte; siz: TOpenSSL_C_SIZET); cdecl;
begin
  BUF_reverse := LoadLibCryptoFunction('BUF_reverse');
  if not assigned(BUF_reverse) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('BUF_reverse');
  BUF_reverse(out_,in_,siz);
end;


procedure UnLoad;
begin
  BUF_MEM_new := Load_BUF_MEM_new;
  BUF_MEM_new_ex := Load_BUF_MEM_new_ex;
  BUF_MEM_free := Load_BUF_MEM_free;
  BUF_MEM_grow := Load_BUF_MEM_grow;
  BUF_MEM_grow_clean := Load_BUF_MEM_grow_clean;
  BUF_reverse := Load_BUF_reverse;
end;
{$ENDIF}

initialization

{$IFNDEF OPENSSL_STATIC_LINK_MODEL}
Register_SSLUnloader(@Unload);
{$ENDIF}
finalization


end.
