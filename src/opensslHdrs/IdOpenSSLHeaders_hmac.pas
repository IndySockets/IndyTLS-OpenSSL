(* This unit was generated from the source file hmac.h2pas 
It should not be modified directly. All changes should be made to hmac.h2pas
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


unit IdOpenSSLHeaders_hmac;


interface

// Headers for OpenSSL 1.1.1
// hmac.h


uses
  IdSSLOpenSSLAPI,
  IdOpenSSLHeaders_ossl_typ,
  IdOpenSSLHeaders_evp;

  
{ The EXTERNALSYM directive is ignored by FPC, however, it is used by Delphi as follows: 

The EXTERNALSYM directive prevents the specified Delphi symbol from appearing in header 
files generated for C++. }

{$EXTERNALSYM HMAC_size}
{$EXTERNALSYM HMAC_CTX_new}
{$EXTERNALSYM HMAC_CTX_reset}
{$EXTERNALSYM HMAC_CTX_free}
{$EXTERNALSYM HMAC_Init_ex}
{$EXTERNALSYM HMAC_Update}
{$EXTERNALSYM HMAC_Final}
{$EXTERNALSYM HMAC}
{$EXTERNALSYM HMAC_CTX_copy}
{$EXTERNALSYM HMAC_CTX_set_flags}
{$EXTERNALSYM HMAC_CTX_get_md}

{$IFDEF OPENSSL_STATIC_LINK_MODEL}
function HMAC_size(const e: PHMAC_CTX): TOpenSSL_C_SIZET; cdecl; external CLibCrypto;
function HMAC_CTX_new: PHMAC_CTX; cdecl; external CLibCrypto;
function HMAC_CTX_reset(ctx: PHMAC_CTX): TOpenSSL_C_INT; cdecl; external CLibCrypto;
procedure HMAC_CTX_free(ctx: PHMAC_CTX); cdecl; external CLibCrypto;
function HMAC_Init_ex(ctx: PHMAC_CTX; const key: Pointer; len: TOpenSSL_C_INT; const md: PEVP_MD; impl: PENGINE): TOpenSSL_C_INT; cdecl; external CLibCrypto;
function HMAC_Update(ctx: PHMAC_CTX; const data: PByte; len: TOpenSSL_C_SIZET): TOpenSSL_C_INT; cdecl; external CLibCrypto;
function HMAC_Final(ctx: PHMAC_CTX; md: PByte; len: PByte): TOpenSSL_C_INT; cdecl; external CLibCrypto;
function HMAC(const evp_md: PEVP_MD; const key: Pointer; key_len: TOpenSSL_C_INT; const d: PByte; n: TOpenSSL_C_SIZET; md: PByte; md_len: POpenSSL_C_INT): PByte; cdecl; external CLibCrypto;
function HMAC_CTX_copy(dctx: PHMAC_CTX; sctx: PHMAC_CTX): TOpenSSL_C_INT; cdecl; external CLibCrypto;
procedure HMAC_CTX_set_flags(ctx: PHMAC_CTX; flags: TOpenSSL_C_ULONG); cdecl; external CLibCrypto;
function HMAC_CTX_get_md(const ctx: PHMAC_CTX): PEVP_MD; cdecl; external CLibCrypto;

{$ELSE}

{Declare external function initialisers - should not be called directly}

{$IFNDEF OPENSSL_NO_LEGACY_SUPPORT}
procedure Load_HMAC_CTX_init(ctx : PHMAC_CTX); cdecl;
{$ENDIF} //of OPENSSL_NO_LEGACY_SUPPORT
function Load_HMAC_size(const e: PHMAC_CTX): TOpenSSL_C_SIZET; cdecl;
function Load_HMAC_CTX_new: PHMAC_CTX; cdecl;
function Load_HMAC_CTX_reset(ctx: PHMAC_CTX): TOpenSSL_C_INT; cdecl;
{$IFNDEF OPENSSL_NO_LEGACY_SUPPORT}
procedure Load_HMAC_CTX_cleanup(ctx : PHMAC_CTX); cdecl;
{$ENDIF} //of OPENSSL_NO_LEGACY_SUPPORT
procedure Load_HMAC_CTX_free(ctx: PHMAC_CTX); cdecl;
function Load_HMAC_Init_ex(ctx: PHMAC_CTX; const key: Pointer; len: TOpenSSL_C_INT; const md: PEVP_MD; impl: PENGINE): TOpenSSL_C_INT; cdecl;
function Load_HMAC_Update(ctx: PHMAC_CTX; const data: PByte; len: TOpenSSL_C_SIZET): TOpenSSL_C_INT; cdecl;
function Load_HMAC_Final(ctx: PHMAC_CTX; md: PByte; len: PByte): TOpenSSL_C_INT; cdecl;
function Load_HMAC(const evp_md: PEVP_MD; const key: Pointer; key_len: TOpenSSL_C_INT; const d: PByte; n: TOpenSSL_C_SIZET; md: PByte; md_len: POpenSSL_C_INT): PByte; cdecl;
function Load_HMAC_CTX_copy(dctx: PHMAC_CTX; sctx: PHMAC_CTX): TOpenSSL_C_INT; cdecl;
procedure Load_HMAC_CTX_set_flags(ctx: PHMAC_CTX; flags: TOpenSSL_C_ULONG); cdecl;
function Load_HMAC_CTX_get_md(const ctx: PHMAC_CTX): PEVP_MD; cdecl;

var
  HMAC_size: function (const e: PHMAC_CTX): TOpenSSL_C_SIZET; cdecl = Load_HMAC_size;
  HMAC_CTX_new: function : PHMAC_CTX; cdecl = Load_HMAC_CTX_new;
  HMAC_CTX_reset: function (ctx: PHMAC_CTX): TOpenSSL_C_INT; cdecl = Load_HMAC_CTX_reset;
  HMAC_CTX_free: procedure (ctx: PHMAC_CTX); cdecl = Load_HMAC_CTX_free;
  HMAC_Init_ex: function (ctx: PHMAC_CTX; const key: Pointer; len: TOpenSSL_C_INT; const md: PEVP_MD; impl: PENGINE): TOpenSSL_C_INT; cdecl = Load_HMAC_Init_ex;
  HMAC_Update: function (ctx: PHMAC_CTX; const data: PByte; len: TOpenSSL_C_SIZET): TOpenSSL_C_INT; cdecl = Load_HMAC_Update;
  HMAC_Final: function (ctx: PHMAC_CTX; md: PByte; len: PByte): TOpenSSL_C_INT; cdecl = Load_HMAC_Final;
  HMAC: function (const evp_md: PEVP_MD; const key: Pointer; key_len: TOpenSSL_C_INT; const d: PByte; n: TOpenSSL_C_SIZET; md: PByte; md_len: POpenSSL_C_INT): PByte; cdecl = Load_HMAC;
  HMAC_CTX_copy: function (dctx: PHMAC_CTX; sctx: PHMAC_CTX): TOpenSSL_C_INT; cdecl = Load_HMAC_CTX_copy;
  HMAC_CTX_set_flags: procedure (ctx: PHMAC_CTX; flags: TOpenSSL_C_ULONG); cdecl = Load_HMAC_CTX_set_flags;
  HMAC_CTX_get_md: function (const ctx: PHMAC_CTX): PEVP_MD; cdecl = Load_HMAC_CTX_get_md;
{$ENDIF}
const
  HMAC_CTX_init_removed = ((((((byte(1) shl 8) or byte(1)) shl 8) or byte(0)) shl 8) or byte(0)) shl 4; {removed 1.1.0}
  HMAC_size_introduced = ((((((byte(1) shl 8) or byte(1)) shl 8) or byte(0)) shl 8) or byte(0)) shl 4; {introduced 1.1.0}
  HMAC_CTX_new_introduced = ((((((byte(1) shl 8) or byte(1)) shl 8) or byte(0)) shl 8) or byte(0)) shl 4; {introduced 1.1.0}
  HMAC_CTX_reset_introduced = ((((((byte(1) shl 8) or byte(1)) shl 8) or byte(0)) shl 8) or byte(0)) shl 4; {introduced 1.1.0}
  HMAC_CTX_cleanup_removed = ((((((byte(1) shl 8) or byte(1)) shl 8) or byte(0)) shl 8) or byte(0)) shl 4; {removed 1.1.0}
  HMAC_CTX_free_introduced = ((((((byte(1) shl 8) or byte(1)) shl 8) or byte(0)) shl 8) or byte(0)) shl 4; {introduced 1.1.0}
  HMAC_CTX_get_md_introduced = ((((((byte(1) shl 8) or byte(1)) shl 8) or byte(0)) shl 8) or byte(0)) shl 4; {introduced 1.1.0}


implementation



uses Classes,
     IdSSLOpenSSLExceptionHandlers,
     IdSSLOpenSSLResourceStrings;

{$IFNDEF OPENSSL_STATIC_LINK_MODEL}
{$IFNDEF OPENSSL_NO_LEGACY_SUPPORT}
var
  HMAC_CTX_init: procedure (ctx : PHMAC_CTX); cdecl = Load_HMAC_CTX_init; {removed 1.1.0}
  HMAC_CTX_cleanup: procedure (ctx : PHMAC_CTX); cdecl = Load_HMAC_CTX_cleanup; {removed 1.1.0}
{$ENDIF} { End of OPENSSL_NO_LEGACY_SUPPORT}
{$ENDIF}
const
  HMAC_MAX_MD_CBLOCK = 128; {largest known is SHA512}

type
 _PHMAC_CTX = ^HMAC_CTX;
 HMAC_CTX = record
   md: EVP_MD;
   md_ctx: EVP_MD_CTX;
   i_ctx: EVP_MD_CTX;
   o_ctx: EVP_MD_CTX;
   key_length: TOpenSSL_C_UINT;
   key: array [0..HMAC_MAX_MD_CBLOCK] of char;
 end;



{$IFNDEF OPENSSL_STATIC_LINK_MODEL}
{$IFNDEF OPENSSL_NO_LEGACY_SUPPORT}
function COMPAT_HMAC_CTX_new: PHMAC_CTX; cdecl;

begin
  Result := AllocMem(SizeOf(HMAC_CTX));
  HMAC_CTX_init(Result);
end;



procedure COMPAT_HMAC_CTX_free(ctx: PHMAC_CTX); cdecl;

begin
  HMAC_CTX_cleanup(ctx);
  FreeMem(ctx,SizeOf(HMAC_CTX));
end;

(*
typedef struct hmac_ctx_st {
    const EVP_MD *md;
    EVP_MD_CTX md_ctx;
    EVP_MD_CTX i_ctx;
    EVP_MD_CTX o_ctx;
    unsigned int key_length;
    unsigned char key[HMAC_MAX_MD_CBLOCK];
} HMAC_CTX;
*)


function COMPAT_HMAC_size(const e: PHMAC_CTX): TOpenSSL_C_SIZET; cdecl;

var EVP_MD_size: function (const md: PEVP_MD): TOpenSSL_C_INT; cdecl;
begin
  EVP_MD_size := LoadLibCryptoFunction('EVP_MD_size');
  if not assigned(EVP_MD_size) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('EVP_MD_size');
  Result := EVP_MD_size(_PHMAC_CTX(e)^.md);
end;







{$ENDIF} { End of OPENSSL_NO_LEGACY_SUPPORT}
{$IFNDEF OPENSSL_NO_LEGACY_SUPPORT}
procedure Load_HMAC_CTX_init(ctx : PHMAC_CTX); cdecl;
begin
  HMAC_CTX_init := LoadLibCryptoFunction('HMAC_CTX_init');
  if not assigned(HMAC_CTX_init) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('HMAC_CTX_init');
  HMAC_CTX_init(ctx);
end;

{$ENDIF} //of OPENSSL_NO_LEGACY_SUPPORT
function Load_HMAC_size(const e: PHMAC_CTX): TOpenSSL_C_SIZET; cdecl;
begin
  HMAC_size := LoadLibCryptoFunction('HMAC_size');
  if not assigned(HMAC_size) then
{$IFNDEF OPENSSL_NO_LEGACY_SUPPORT}
    HMAC_size := @COMPAT_HMAC_size;
{$ELSE}
    EOpenSSLAPIFunctionNotPresent.RaiseException('HMAC_size');
{$ENDIF} { End of OPENSSL_NO_LEGACY_SUPPORT}
  Result := HMAC_size(e);
end;

function Load_HMAC_CTX_new: PHMAC_CTX; cdecl;
begin
  HMAC_CTX_new := LoadLibCryptoFunction('HMAC_CTX_new');
  if not assigned(HMAC_CTX_new) then
{$IFNDEF OPENSSL_NO_LEGACY_SUPPORT}
    HMAC_CTX_new := @COMPAT_HMAC_CTX_new;
{$ELSE}
    EOpenSSLAPIFunctionNotPresent.RaiseException('HMAC_CTX_new');
{$ENDIF} { End of OPENSSL_NO_LEGACY_SUPPORT}
  Result := HMAC_CTX_new();
end;

function Load_HMAC_CTX_reset(ctx: PHMAC_CTX): TOpenSSL_C_INT; cdecl;
begin
  HMAC_CTX_reset := LoadLibCryptoFunction('HMAC_CTX_reset');
  if not assigned(HMAC_CTX_reset) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('HMAC_CTX_reset');
  Result := HMAC_CTX_reset(ctx);
end;

{$IFNDEF OPENSSL_NO_LEGACY_SUPPORT}
procedure Load_HMAC_CTX_cleanup(ctx : PHMAC_CTX); cdecl;
begin
  HMAC_CTX_cleanup := LoadLibCryptoFunction('HMAC_CTX_cleanup');
  if not assigned(HMAC_CTX_cleanup) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('HMAC_CTX_cleanup');
  HMAC_CTX_cleanup(ctx);
end;

{$ENDIF} //of OPENSSL_NO_LEGACY_SUPPORT
procedure Load_HMAC_CTX_free(ctx: PHMAC_CTX); cdecl;
begin
  HMAC_CTX_free := LoadLibCryptoFunction('HMAC_CTX_free');
  if not assigned(HMAC_CTX_free) then
{$IFNDEF OPENSSL_NO_LEGACY_SUPPORT}
    HMAC_CTX_free := @COMPAT_HMAC_CTX_free;
{$ELSE}
    EOpenSSLAPIFunctionNotPresent.RaiseException('HMAC_CTX_free');
{$ENDIF} { End of OPENSSL_NO_LEGACY_SUPPORT}
  HMAC_CTX_free(ctx);
end;

function Load_HMAC_Init_ex(ctx: PHMAC_CTX; const key: Pointer; len: TOpenSSL_C_INT; const md: PEVP_MD; impl: PENGINE): TOpenSSL_C_INT; cdecl;
begin
  HMAC_Init_ex := LoadLibCryptoFunction('HMAC_Init_ex');
  if not assigned(HMAC_Init_ex) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('HMAC_Init_ex');
  Result := HMAC_Init_ex(ctx,key,len,md,impl);
end;

function Load_HMAC_Update(ctx: PHMAC_CTX; const data: PByte; len: TOpenSSL_C_SIZET): TOpenSSL_C_INT; cdecl;
begin
  HMAC_Update := LoadLibCryptoFunction('HMAC_Update');
  if not assigned(HMAC_Update) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('HMAC_Update');
  Result := HMAC_Update(ctx,data,len);
end;

function Load_HMAC_Final(ctx: PHMAC_CTX; md: PByte; len: PByte): TOpenSSL_C_INT; cdecl;
begin
  HMAC_Final := LoadLibCryptoFunction('HMAC_Final');
  if not assigned(HMAC_Final) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('HMAC_Final');
  Result := HMAC_Final(ctx,md,len);
end;

function Load_HMAC(const evp_md: PEVP_MD; const key: Pointer; key_len: TOpenSSL_C_INT; const d: PByte; n: TOpenSSL_C_SIZET; md: PByte; md_len: POpenSSL_C_INT): PByte; cdecl;
begin
  HMAC := LoadLibCryptoFunction('HMAC');
  if not assigned(HMAC) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('HMAC');
  Result := HMAC(evp_md,key,key_len,d,n,md,md_len);
end;

function Load_HMAC_CTX_copy(dctx: PHMAC_CTX; sctx: PHMAC_CTX): TOpenSSL_C_INT; cdecl;
begin
  HMAC_CTX_copy := LoadLibCryptoFunction('HMAC_CTX_copy');
  if not assigned(HMAC_CTX_copy) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('HMAC_CTX_copy');
  Result := HMAC_CTX_copy(dctx,sctx);
end;

procedure Load_HMAC_CTX_set_flags(ctx: PHMAC_CTX; flags: TOpenSSL_C_ULONG); cdecl;
begin
  HMAC_CTX_set_flags := LoadLibCryptoFunction('HMAC_CTX_set_flags');
  if not assigned(HMAC_CTX_set_flags) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('HMAC_CTX_set_flags');
  HMAC_CTX_set_flags(ctx,flags);
end;

function Load_HMAC_CTX_get_md(const ctx: PHMAC_CTX): PEVP_MD; cdecl;
begin
  HMAC_CTX_get_md := LoadLibCryptoFunction('HMAC_CTX_get_md');
  if not assigned(HMAC_CTX_get_md) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('HMAC_CTX_get_md');
  Result := HMAC_CTX_get_md(ctx);
end;


procedure UnLoad;
begin
{$IFNDEF OPENSSL_NO_LEGACY_SUPPORT}
  HMAC_CTX_init := Load_HMAC_CTX_init;
{$ENDIF} //of OPENSSL_NO_LEGACY_SUPPORT
  HMAC_size := Load_HMAC_size;
  HMAC_CTX_new := Load_HMAC_CTX_new;
  HMAC_CTX_reset := Load_HMAC_CTX_reset;
{$IFNDEF OPENSSL_NO_LEGACY_SUPPORT}
  HMAC_CTX_cleanup := Load_HMAC_CTX_cleanup;
{$ENDIF} //of OPENSSL_NO_LEGACY_SUPPORT
  HMAC_CTX_free := Load_HMAC_CTX_free;
  HMAC_Init_ex := Load_HMAC_Init_ex;
  HMAC_Update := Load_HMAC_Update;
  HMAC_Final := Load_HMAC_Final;
  HMAC := Load_HMAC;
  HMAC_CTX_copy := Load_HMAC_CTX_copy;
  HMAC_CTX_set_flags := Load_HMAC_CTX_set_flags;
  HMAC_CTX_get_md := Load_HMAC_CTX_get_md;
end;
{$ENDIF}

initialization

{$IFNDEF OPENSSL_STATIC_LINK_MODEL}
Register_SSLUnloader(@Unload);
{$ENDIF}
finalization


end.
