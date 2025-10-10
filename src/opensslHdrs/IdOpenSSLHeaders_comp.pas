(* This unit was generated from the source file comp.h2pas 
It should not be modified directly. All changes should be made to comp.h2pas
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


unit IdOpenSSLHeaders_comp;


interface

// Headers for OpenSSL 1.1.1
// comp.h


uses
  IdSSLOpenSSLAPI,
  IdOpenSSLHeaders_bio,
  IdOpenSSLHeaders_ossl_typ;

  
{ The EXTERNALSYM directive is ignored by FPC, however, it is used by Delphi as follows: 

The EXTERNALSYM directive prevents the specified Delphi symbol from appearing in header 
files generated for C++. }

{$EXTERNALSYM COMP_CTX_new}
{$EXTERNALSYM COMP_CTX_get_method}
{$EXTERNALSYM COMP_CTX_get_type}
{$EXTERNALSYM COMP_get_type}
{$EXTERNALSYM COMP_get_name}
{$EXTERNALSYM COMP_CTX_free}
{$EXTERNALSYM COMP_compress_block}
{$EXTERNALSYM COMP_expand_block}
{$EXTERNALSYM COMP_zlib}
{$EXTERNALSYM BIO_f_zlib}

{$IFDEF OPENSSL_STATIC_LINK_MODEL}
function COMP_CTX_new(meth: PCOMP_METHOD): PCOMP_CTX; cdecl; external CLibCrypto;
function COMP_CTX_get_method(const ctx: PCOMP_CTX): PCOMP_METHOD; cdecl; external CLibCrypto;
function COMP_CTX_get_type(const comp: PCOMP_CTX): TOpenSSL_C_INT; cdecl; external CLibCrypto;
function COMP_get_type(const meth: PCOMP_METHOD): TOpenSSL_C_INT; cdecl; external CLibCrypto;
function COMP_get_name(const meth: PCOMP_METHOD): PAnsiChar; cdecl; external CLibCrypto;
procedure COMP_CTX_free(ctx: PCOMP_CTX); cdecl; external CLibCrypto;
function COMP_compress_block(ctx: PCOMP_CTX; out_: PByte; olen: TOpenSSL_C_INT; in_: PByte; ilen: TOpenSSL_C_INT): TOpenSSL_C_INT; cdecl; external CLibCrypto;
function COMP_expand_block(ctx: PCOMP_CTX; out_: PByte; olen: TOpenSSL_C_INT; in_: PByte; ilen: TOpenSSL_C_INT): TOpenSSL_C_INT; cdecl; external CLibCrypto;
function COMP_zlib: PCOMP_METHOD; cdecl; external CLibCrypto;
function BIO_f_zlib: PBIO_METHOD; cdecl; external CLibCrypto;

{$ELSE}

{Declare external function initialisers - should not be called directly}

function Load_COMP_CTX_new(meth: PCOMP_METHOD): PCOMP_CTX; cdecl;
function Load_COMP_CTX_get_method(const ctx: PCOMP_CTX): PCOMP_METHOD; cdecl;
function Load_COMP_CTX_get_type(const comp: PCOMP_CTX): TOpenSSL_C_INT; cdecl;
function Load_COMP_get_type(const meth: PCOMP_METHOD): TOpenSSL_C_INT; cdecl;
function Load_COMP_get_name(const meth: PCOMP_METHOD): PAnsiChar; cdecl;
procedure Load_COMP_CTX_free(ctx: PCOMP_CTX); cdecl;
function Load_COMP_compress_block(ctx: PCOMP_CTX; out_: PByte; olen: TOpenSSL_C_INT; in_: PByte; ilen: TOpenSSL_C_INT): TOpenSSL_C_INT; cdecl;
function Load_COMP_expand_block(ctx: PCOMP_CTX; out_: PByte; olen: TOpenSSL_C_INT; in_: PByte; ilen: TOpenSSL_C_INT): TOpenSSL_C_INT; cdecl;
function Load_COMP_zlib: PCOMP_METHOD; cdecl;
function Load_BIO_f_zlib: PBIO_METHOD; cdecl;

var
  COMP_CTX_new: function (meth: PCOMP_METHOD): PCOMP_CTX; cdecl = Load_COMP_CTX_new;
  COMP_CTX_get_method: function (const ctx: PCOMP_CTX): PCOMP_METHOD; cdecl = Load_COMP_CTX_get_method;
  COMP_CTX_get_type: function (const comp: PCOMP_CTX): TOpenSSL_C_INT; cdecl = Load_COMP_CTX_get_type;
  COMP_get_type: function (const meth: PCOMP_METHOD): TOpenSSL_C_INT; cdecl = Load_COMP_get_type;
  COMP_get_name: function (const meth: PCOMP_METHOD): PAnsiChar; cdecl = Load_COMP_get_name;
  COMP_CTX_free: procedure (ctx: PCOMP_CTX); cdecl = Load_COMP_CTX_free;
  COMP_compress_block: function (ctx: PCOMP_CTX; out_: PByte; olen: TOpenSSL_C_INT; in_: PByte; ilen: TOpenSSL_C_INT): TOpenSSL_C_INT; cdecl = Load_COMP_compress_block;
  COMP_expand_block: function (ctx: PCOMP_CTX; out_: PByte; olen: TOpenSSL_C_INT; in_: PByte; ilen: TOpenSSL_C_INT): TOpenSSL_C_INT; cdecl = Load_COMP_expand_block;
  COMP_zlib: function : PCOMP_METHOD; cdecl = Load_COMP_zlib;
  BIO_f_zlib: function : PBIO_METHOD; cdecl = Load_BIO_f_zlib;
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
function Load_COMP_CTX_new(meth: PCOMP_METHOD): PCOMP_CTX; cdecl;
begin
  COMP_CTX_new := LoadLibCryptoFunction('COMP_CTX_new');
  if not assigned(COMP_CTX_new) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('COMP_CTX_new');
  Result := COMP_CTX_new(meth);
end;

function Load_COMP_CTX_get_method(const ctx: PCOMP_CTX): PCOMP_METHOD; cdecl;
begin
  COMP_CTX_get_method := LoadLibCryptoFunction('COMP_CTX_get_method');
  if not assigned(COMP_CTX_get_method) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('COMP_CTX_get_method');
  Result := COMP_CTX_get_method(ctx);
end;

function Load_COMP_CTX_get_type(const comp: PCOMP_CTX): TOpenSSL_C_INT; cdecl;
begin
  COMP_CTX_get_type := LoadLibCryptoFunction('COMP_CTX_get_type');
  if not assigned(COMP_CTX_get_type) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('COMP_CTX_get_type');
  Result := COMP_CTX_get_type(comp);
end;

function Load_COMP_get_type(const meth: PCOMP_METHOD): TOpenSSL_C_INT; cdecl;
begin
  COMP_get_type := LoadLibCryptoFunction('COMP_get_type');
  if not assigned(COMP_get_type) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('COMP_get_type');
  Result := COMP_get_type(meth);
end;

function Load_COMP_get_name(const meth: PCOMP_METHOD): PAnsiChar; cdecl;
begin
  COMP_get_name := LoadLibCryptoFunction('COMP_get_name');
  if not assigned(COMP_get_name) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('COMP_get_name');
  Result := COMP_get_name(meth);
end;

procedure Load_COMP_CTX_free(ctx: PCOMP_CTX); cdecl;
begin
  COMP_CTX_free := LoadLibCryptoFunction('COMP_CTX_free');
  if not assigned(COMP_CTX_free) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('COMP_CTX_free');
  COMP_CTX_free(ctx);
end;

function Load_COMP_compress_block(ctx: PCOMP_CTX; out_: PByte; olen: TOpenSSL_C_INT; in_: PByte; ilen: TOpenSSL_C_INT): TOpenSSL_C_INT; cdecl;
begin
  COMP_compress_block := LoadLibCryptoFunction('COMP_compress_block');
  if not assigned(COMP_compress_block) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('COMP_compress_block');
  Result := COMP_compress_block(ctx,out_,olen,in_,ilen);
end;

function Load_COMP_expand_block(ctx: PCOMP_CTX; out_: PByte; olen: TOpenSSL_C_INT; in_: PByte; ilen: TOpenSSL_C_INT): TOpenSSL_C_INT; cdecl;
begin
  COMP_expand_block := LoadLibCryptoFunction('COMP_expand_block');
  if not assigned(COMP_expand_block) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('COMP_expand_block');
  Result := COMP_expand_block(ctx,out_,olen,in_,ilen);
end;

function Load_COMP_zlib: PCOMP_METHOD; cdecl;
begin
  COMP_zlib := LoadLibCryptoFunction('COMP_zlib');
  if not assigned(COMP_zlib) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('COMP_zlib');
  Result := COMP_zlib();
end;

function Load_BIO_f_zlib: PBIO_METHOD; cdecl;
begin
  BIO_f_zlib := LoadLibCryptoFunction('BIO_f_zlib');
  if not assigned(BIO_f_zlib) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('BIO_f_zlib');
  Result := BIO_f_zlib();
end;


procedure UnLoad;
begin
  COMP_CTX_new := Load_COMP_CTX_new;
  COMP_CTX_get_method := Load_COMP_CTX_get_method;
  COMP_CTX_get_type := Load_COMP_CTX_get_type;
  COMP_get_type := Load_COMP_get_type;
  COMP_get_name := Load_COMP_get_name;
  COMP_CTX_free := Load_COMP_CTX_free;
  COMP_compress_block := Load_COMP_compress_block;
  COMP_expand_block := Load_COMP_expand_block;
  COMP_zlib := Load_COMP_zlib;
  BIO_f_zlib := Load_BIO_f_zlib;
end;
{$ENDIF}

initialization

{$IFNDEF OPENSSL_STATIC_LINK_MODEL}
Register_SSLUnloader(@Unload);
{$ENDIF}
finalization


end.
