(* This unit was generated from the source file cmac.h2pas 
It should not be modified directly. All changes should be made to cmac.h2pas
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


unit IdOpenSSLHeaders_cmac;


interface

// Headers for OpenSSL 1.1.1
// cmac.h


uses
  IdSSLOpenSSLAPI,
  IdOpenSSLHeaders_evp,
  IdOpenSSLHeaders_ossl_typ;

//* Opaque */

type
  CMAC_CTX_st = type Pointer;
  CMAC_CTX = CMAC_CTX_st;
  PCMAC_CTX = ^CMAC_CTX;

  
{ The EXTERNALSYM directive is ignored by FPC, however, it is used by Delphi as follows: 

The EXTERNALSYM directive prevents the specified Delphi symbol from appearing in header 
files generated for C++. }

{$EXTERNALSYM CMAC_CTX_new}
{$EXTERNALSYM CMAC_CTX_cleanup}
{$EXTERNALSYM CMAC_CTX_free}
{$EXTERNALSYM CMAC_CTX_get0_cipher_ctx}
{$EXTERNALSYM CMAC_CTX_copy}
{$EXTERNALSYM CMAC_Init}
{$EXTERNALSYM CMAC_Update}
{$EXTERNALSYM CMAC_Final}
{$EXTERNALSYM CMAC_resume}

{$IFDEF OPENSSL_STATIC_LINK_MODEL}
function CMAC_CTX_new: PCMAC_CTX; cdecl; external CLibCrypto;
procedure CMAC_CTX_cleanup(ctx: PCMAC_CTX); cdecl; external CLibCrypto;
procedure CMAC_CTX_free(ctx: PCMAC_CTX); cdecl; external CLibCrypto;
function CMAC_CTX_get0_cipher_ctx(ctx: PCMAC_CTX): PEVP_CIPHER_CTX; cdecl; external CLibCrypto;
function CMAC_CTX_copy(out_: PCMAC_CTX; const in_: PCMAC_CTX): TOpenSSL_C_INT; cdecl; external CLibCrypto;
function CMAC_Init(ctx: PCMAC_CTX; const key: Pointer; keylen: TOpenSSL_C_SIZET; const cipher: PEVP_Cipher; impl: PENGINe): TOpenSSL_C_INT; cdecl; external CLibCrypto;
function CMAC_Update(ctx: PCMAC_CTX; const data: Pointer; dlen: TOpenSSL_C_SIZET): TOpenSSL_C_INT; cdecl; external CLibCrypto;
function CMAC_Final(ctx: PCMAC_CTX; out_: PByte; poutlen: POpenSSL_C_SIZET): TOpenSSL_C_INT; cdecl; external CLibCrypto;
function CMAC_resume(ctx: PCMAC_CTX): TOpenSSL_C_INT; cdecl; external CLibCrypto;

{$ELSE}

{Declare external function initialisers - should not be called directly}

function Load_CMAC_CTX_new: PCMAC_CTX; cdecl;
procedure Load_CMAC_CTX_cleanup(ctx: PCMAC_CTX); cdecl;
procedure Load_CMAC_CTX_free(ctx: PCMAC_CTX); cdecl;
function Load_CMAC_CTX_get0_cipher_ctx(ctx: PCMAC_CTX): PEVP_CIPHER_CTX; cdecl;
function Load_CMAC_CTX_copy(out_: PCMAC_CTX; const in_: PCMAC_CTX): TOpenSSL_C_INT; cdecl;
function Load_CMAC_Init(ctx: PCMAC_CTX; const key: Pointer; keylen: TOpenSSL_C_SIZET; const cipher: PEVP_Cipher; impl: PENGINe): TOpenSSL_C_INT; cdecl;
function Load_CMAC_Update(ctx: PCMAC_CTX; const data: Pointer; dlen: TOpenSSL_C_SIZET): TOpenSSL_C_INT; cdecl;
function Load_CMAC_Final(ctx: PCMAC_CTX; out_: PByte; poutlen: POpenSSL_C_SIZET): TOpenSSL_C_INT; cdecl;
function Load_CMAC_resume(ctx: PCMAC_CTX): TOpenSSL_C_INT; cdecl;

var
  CMAC_CTX_new: function : PCMAC_CTX; cdecl = Load_CMAC_CTX_new;
  CMAC_CTX_cleanup: procedure (ctx: PCMAC_CTX); cdecl = Load_CMAC_CTX_cleanup;
  CMAC_CTX_free: procedure (ctx: PCMAC_CTX); cdecl = Load_CMAC_CTX_free;
  CMAC_CTX_get0_cipher_ctx: function (ctx: PCMAC_CTX): PEVP_CIPHER_CTX; cdecl = Load_CMAC_CTX_get0_cipher_ctx;
  CMAC_CTX_copy: function (out_: PCMAC_CTX; const in_: PCMAC_CTX): TOpenSSL_C_INT; cdecl = Load_CMAC_CTX_copy;
  CMAC_Init: function (ctx: PCMAC_CTX; const key: Pointer; keylen: TOpenSSL_C_SIZET; const cipher: PEVP_Cipher; impl: PENGINe): TOpenSSL_C_INT; cdecl = Load_CMAC_Init;
  CMAC_Update: function (ctx: PCMAC_CTX; const data: Pointer; dlen: TOpenSSL_C_SIZET): TOpenSSL_C_INT; cdecl = Load_CMAC_Update;
  CMAC_Final: function (ctx: PCMAC_CTX; out_: PByte; poutlen: POpenSSL_C_SIZET): TOpenSSL_C_INT; cdecl = Load_CMAC_Final;
  CMAC_resume: function (ctx: PCMAC_CTX): TOpenSSL_C_INT; cdecl = Load_CMAC_resume;
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
function Load_CMAC_CTX_new: PCMAC_CTX; cdecl;
begin
  CMAC_CTX_new := LoadLibCryptoFunction('CMAC_CTX_new');
  if not assigned(CMAC_CTX_new) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('CMAC_CTX_new');
  Result := CMAC_CTX_new();
end;

procedure Load_CMAC_CTX_cleanup(ctx: PCMAC_CTX); cdecl;
begin
  CMAC_CTX_cleanup := LoadLibCryptoFunction('CMAC_CTX_cleanup');
  if not assigned(CMAC_CTX_cleanup) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('CMAC_CTX_cleanup');
  CMAC_CTX_cleanup(ctx);
end;

procedure Load_CMAC_CTX_free(ctx: PCMAC_CTX); cdecl;
begin
  CMAC_CTX_free := LoadLibCryptoFunction('CMAC_CTX_free');
  if not assigned(CMAC_CTX_free) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('CMAC_CTX_free');
  CMAC_CTX_free(ctx);
end;

function Load_CMAC_CTX_get0_cipher_ctx(ctx: PCMAC_CTX): PEVP_CIPHER_CTX; cdecl;
begin
  CMAC_CTX_get0_cipher_ctx := LoadLibCryptoFunction('CMAC_CTX_get0_cipher_ctx');
  if not assigned(CMAC_CTX_get0_cipher_ctx) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('CMAC_CTX_get0_cipher_ctx');
  Result := CMAC_CTX_get0_cipher_ctx(ctx);
end;

function Load_CMAC_CTX_copy(out_: PCMAC_CTX; const in_: PCMAC_CTX): TOpenSSL_C_INT; cdecl;
begin
  CMAC_CTX_copy := LoadLibCryptoFunction('CMAC_CTX_copy');
  if not assigned(CMAC_CTX_copy) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('CMAC_CTX_copy');
  Result := CMAC_CTX_copy(out_,in_);
end;

function Load_CMAC_Init(ctx: PCMAC_CTX; const key: Pointer; keylen: TOpenSSL_C_SIZET; const cipher: PEVP_Cipher; impl: PENGINe): TOpenSSL_C_INT; cdecl;
begin
  CMAC_Init := LoadLibCryptoFunction('CMAC_Init');
  if not assigned(CMAC_Init) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('CMAC_Init');
  Result := CMAC_Init(ctx,key,keylen,cipher,impl);
end;

function Load_CMAC_Update(ctx: PCMAC_CTX; const data: Pointer; dlen: TOpenSSL_C_SIZET): TOpenSSL_C_INT; cdecl;
begin
  CMAC_Update := LoadLibCryptoFunction('CMAC_Update');
  if not assigned(CMAC_Update) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('CMAC_Update');
  Result := CMAC_Update(ctx,data,dlen);
end;

function Load_CMAC_Final(ctx: PCMAC_CTX; out_: PByte; poutlen: POpenSSL_C_SIZET): TOpenSSL_C_INT; cdecl;
begin
  CMAC_Final := LoadLibCryptoFunction('CMAC_Final');
  if not assigned(CMAC_Final) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('CMAC_Final');
  Result := CMAC_Final(ctx,out_,poutlen);
end;

function Load_CMAC_resume(ctx: PCMAC_CTX): TOpenSSL_C_INT; cdecl;
begin
  CMAC_resume := LoadLibCryptoFunction('CMAC_resume');
  if not assigned(CMAC_resume) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('CMAC_resume');
  Result := CMAC_resume(ctx);
end;


procedure UnLoad;
begin
  CMAC_CTX_new := Load_CMAC_CTX_new;
  CMAC_CTX_cleanup := Load_CMAC_CTX_cleanup;
  CMAC_CTX_free := Load_CMAC_CTX_free;
  CMAC_CTX_get0_cipher_ctx := Load_CMAC_CTX_get0_cipher_ctx;
  CMAC_CTX_copy := Load_CMAC_CTX_copy;
  CMAC_Init := Load_CMAC_Init;
  CMAC_Update := Load_CMAC_Update;
  CMAC_Final := Load_CMAC_Final;
  CMAC_resume := Load_CMAC_resume;
end;
{$ENDIF}

initialization

{$IFNDEF OPENSSL_STATIC_LINK_MODEL}
Register_SSLUnloader(@Unload);
{$ENDIF}
finalization


end.
