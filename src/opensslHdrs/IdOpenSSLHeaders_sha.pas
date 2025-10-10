(* This unit was generated from the source file sha.h2pas 
It should not be modified directly. All changes should be made to sha.h2pas
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


unit IdOpenSSLHeaders_sha;


interface

// Headers for OpenSSL 1.1.1
// sha.h


uses
  IdSSLOpenSSLAPI;

const
  SHA_LBLOCK = 16;
  SHA_CBLOCK = SHA_LBLOCK * 4;

  SHA_LAST_BLOCK = SHA_CBLOCK - 8;
  SHA_DIGEST_LENGTH = 20;

  SHA256_CBLOCK = SHA_LBLOCK * 4;

  SHA224_DIGEST_LENGTH = 28;
  SHA256_DIGEST_LENGTH = 32;
  SHA384_DIGEST_LENGTH = 48;
  SHA512_DIGEST_LENGTH = 64;

  SHA512_CBLOCK = SHA_LBLOCK * 8;

type
  SHA_LONG = TOpenSSL_C_UINT;

  SHAstate_sf = record
    h0, h1, h2, h3, h4: SHA_LONG;
    Nl, Nh: SHA_LONG;
    data: array[0 .. SHA_LAST_BLOCK - 1] of SHA_LONG;
    num: TOpenSSL_C_UINT;
  end;
  SHA_CTX = SHAstate_sf;
  PSHA_CTX = ^SHA_CTX;

  SHAstate256_sf = record
    h: array[0..7] of SHA_LONG;
    Nl, Nh: SHA_LONG;
    data: array[0 .. SHA_LAST_BLOCK - 1] of SHA_LONG;
    num, md_len: TOpenSSL_C_UINT;
  end;
  SHA256_CTX = SHAstate256_sf;
  PSHA256_CTX = ^SHA256_CTX;

  SHA_LONG64 = TOpenSSL_C_UINT64;

  SHA512state_st_u = record
    case Integer of
    0: (d: array[0 .. SHA_LBLOCK - 1] of SHA_LONG64);
    1: (p: array[0 .. SHA512_CBLOCK - 1] of Byte);
  end;

  SHA512state_st = record
    h: array[0..7] of SHA_LONG64;
    Nl, Nh: SHA_LONG64;
    u: SHA512state_st_u;
    num, md_len: TOpenSSL_C_UINT;
  end;
  SHA512_CTX = SHA512state_st;
  PSHA512_CTX = ^SHA512_CTX;

  
{ The EXTERNALSYM directive is ignored by FPC, however, it is used by Delphi as follows: 

The EXTERNALSYM directive prevents the specified Delphi symbol from appearing in header 
files generated for C++. }

{$EXTERNALSYM SHA1_Init}
{$EXTERNALSYM SHA1_Update}
{$EXTERNALSYM SHA1_Final}
{$EXTERNALSYM SHA1}
{$EXTERNALSYM SHA1_Transform}
{$EXTERNALSYM SHA224_Init}
{$EXTERNALSYM SHA224_Update}
{$EXTERNALSYM SHA224_Final}
{$EXTERNALSYM SHA224}
{$EXTERNALSYM SHA256_Init}
{$EXTERNALSYM SHA256_Update}
{$EXTERNALSYM SHA256_Final}
{$EXTERNALSYM SHA256}
{$EXTERNALSYM SHA256_Transform}
{$EXTERNALSYM SHA384_Init}
{$EXTERNALSYM SHA384_Update}
{$EXTERNALSYM SHA384_Final}
{$EXTERNALSYM SHA384}
{$EXTERNALSYM SHA512_Init}
{$EXTERNALSYM SHA512_Update}
{$EXTERNALSYM SHA512_Final}
{$EXTERNALSYM SHA512}
{$EXTERNALSYM SHA512_Transform}

{$IFDEF OPENSSL_STATIC_LINK_MODEL}
function SHA1_Init(c: PSHA_CTX): TOpenSSL_C_INT; cdecl; external CLibCrypto;
function SHA1_Update(c: PSHA_CTX; const data: Pointer; len: TOpenSSL_C_SIZET): TOpenSSL_C_INT; cdecl; external CLibCrypto;
function SHA1_Final(md: PByte; c: PSHA_CTX): TOpenSSL_C_INT; cdecl; external CLibCrypto;
function SHA1(const d: PByte; n: TOpenSSL_C_SIZET; md: PByte): PByte; cdecl; external CLibCrypto;
procedure SHA1_Transform(c: PSHA_CTX; const data: PByte); cdecl; external CLibCrypto;
function SHA224_Init(c: PSHA256_CTX): TOpenSSL_C_INT; cdecl; external CLibCrypto;
function SHA224_Update(c: PSHA256_CTX; const data: Pointer; len: TOpenSSL_C_SIZET): TOpenSSL_C_INT; cdecl; external CLibCrypto;
function SHA224_Final(md: PByte; c: PSHA256_CTX): TOpenSSL_C_INT; cdecl; external CLibCrypto;
function SHA224(const d: PByte; n: TOpenSSL_C_SIZET; md: PByte): PByte; cdecl; external CLibCrypto;
function SHA256_Init(c: PSHA256_CTX): TOpenSSL_C_INT; cdecl; external CLibCrypto;
function SHA256_Update(c: PSHA256_CTX; const data: Pointer; len: TOpenSSL_C_SIZET): TOpenSSL_C_INT; cdecl; external CLibCrypto;
function SHA256_Final(md: PByte; c: PSHA256_CTX): TOpenSSL_C_INT; cdecl; external CLibCrypto;
function SHA256(const d: PByte; n: TOpenSSL_C_SIZET; md: PByte): PByte; cdecl; external CLibCrypto;
procedure SHA256_Transform(c: PSHA256_CTX; const data: PByte); cdecl; external CLibCrypto;
function SHA384_Init(c: PSHA512_CTX): TOpenSSL_C_INT; cdecl; external CLibCrypto;
function SHA384_Update(c: PSHA512_CTX; const data: Pointer; len: TOpenSSL_C_SIZET): TOpenSSL_C_INT; cdecl; external CLibCrypto;
function SHA384_Final(md: PByte; c: PSHA512_CTX): TOpenSSL_C_INT; cdecl; external CLibCrypto;
function SHA384(const d: PByte; n: TOpenSSL_C_SIZET; md: PByte): PByte; cdecl; external CLibCrypto;
function SHA512_Init(c: PSHA512_CTX): TOpenSSL_C_INT; cdecl; external CLibCrypto;
function SHA512_Update(c: PSHA512_CTX; const data: Pointer; len: TOpenSSL_C_SIZET): TOpenSSL_C_INT; cdecl; external CLibCrypto;
function SHA512_Final(md: PByte; c: PSHA512_CTX): TOpenSSL_C_INT; cdecl; external CLibCrypto;
function SHA512(const d: PByte; n: TOpenSSL_C_SIZET; md: PByte): PByte; cdecl; external CLibCrypto;
procedure SHA512_Transform(c: PSHA512_CTX; const data: PByte); cdecl; external CLibCrypto;

{$ELSE}

{Declare external function initialisers - should not be called directly}

function Load_SHA1_Init(c: PSHA_CTX): TOpenSSL_C_INT; cdecl;
function Load_SHA1_Update(c: PSHA_CTX; const data: Pointer; len: TOpenSSL_C_SIZET): TOpenSSL_C_INT; cdecl;
function Load_SHA1_Final(md: PByte; c: PSHA_CTX): TOpenSSL_C_INT; cdecl;
function Load_SHA1(const d: PByte; n: TOpenSSL_C_SIZET; md: PByte): PByte; cdecl;
procedure Load_SHA1_Transform(c: PSHA_CTX; const data: PByte); cdecl;
function Load_SHA224_Init(c: PSHA256_CTX): TOpenSSL_C_INT; cdecl;
function Load_SHA224_Update(c: PSHA256_CTX; const data: Pointer; len: TOpenSSL_C_SIZET): TOpenSSL_C_INT; cdecl;
function Load_SHA224_Final(md: PByte; c: PSHA256_CTX): TOpenSSL_C_INT; cdecl;
function Load_SHA224(const d: PByte; n: TOpenSSL_C_SIZET; md: PByte): PByte; cdecl;
function Load_SHA256_Init(c: PSHA256_CTX): TOpenSSL_C_INT; cdecl;
function Load_SHA256_Update(c: PSHA256_CTX; const data: Pointer; len: TOpenSSL_C_SIZET): TOpenSSL_C_INT; cdecl;
function Load_SHA256_Final(md: PByte; c: PSHA256_CTX): TOpenSSL_C_INT; cdecl;
function Load_SHA256(const d: PByte; n: TOpenSSL_C_SIZET; md: PByte): PByte; cdecl;
procedure Load_SHA256_Transform(c: PSHA256_CTX; const data: PByte); cdecl;
function Load_SHA384_Init(c: PSHA512_CTX): TOpenSSL_C_INT; cdecl;
function Load_SHA384_Update(c: PSHA512_CTX; const data: Pointer; len: TOpenSSL_C_SIZET): TOpenSSL_C_INT; cdecl;
function Load_SHA384_Final(md: PByte; c: PSHA512_CTX): TOpenSSL_C_INT; cdecl;
function Load_SHA384(const d: PByte; n: TOpenSSL_C_SIZET; md: PByte): PByte; cdecl;
function Load_SHA512_Init(c: PSHA512_CTX): TOpenSSL_C_INT; cdecl;
function Load_SHA512_Update(c: PSHA512_CTX; const data: Pointer; len: TOpenSSL_C_SIZET): TOpenSSL_C_INT; cdecl;
function Load_SHA512_Final(md: PByte; c: PSHA512_CTX): TOpenSSL_C_INT; cdecl;
function Load_SHA512(const d: PByte; n: TOpenSSL_C_SIZET; md: PByte): PByte; cdecl;
procedure Load_SHA512_Transform(c: PSHA512_CTX; const data: PByte); cdecl;

var
  SHA1_Init: function (c: PSHA_CTX): TOpenSSL_C_INT; cdecl = Load_SHA1_Init;
  SHA1_Update: function (c: PSHA_CTX; const data: Pointer; len: TOpenSSL_C_SIZET): TOpenSSL_C_INT; cdecl = Load_SHA1_Update;
  SHA1_Final: function (md: PByte; c: PSHA_CTX): TOpenSSL_C_INT; cdecl = Load_SHA1_Final;
  SHA1: function (const d: PByte; n: TOpenSSL_C_SIZET; md: PByte): PByte; cdecl = Load_SHA1;
  SHA1_Transform: procedure (c: PSHA_CTX; const data: PByte); cdecl = Load_SHA1_Transform;
  SHA224_Init: function (c: PSHA256_CTX): TOpenSSL_C_INT; cdecl = Load_SHA224_Init;
  SHA224_Update: function (c: PSHA256_CTX; const data: Pointer; len: TOpenSSL_C_SIZET): TOpenSSL_C_INT; cdecl = Load_SHA224_Update;
  SHA224_Final: function (md: PByte; c: PSHA256_CTX): TOpenSSL_C_INT; cdecl = Load_SHA224_Final;
  SHA224: function (const d: PByte; n: TOpenSSL_C_SIZET; md: PByte): PByte; cdecl = Load_SHA224;
  SHA256_Init: function (c: PSHA256_CTX): TOpenSSL_C_INT; cdecl = Load_SHA256_Init;
  SHA256_Update: function (c: PSHA256_CTX; const data: Pointer; len: TOpenSSL_C_SIZET): TOpenSSL_C_INT; cdecl = Load_SHA256_Update;
  SHA256_Final: function (md: PByte; c: PSHA256_CTX): TOpenSSL_C_INT; cdecl = Load_SHA256_Final;
  SHA256: function (const d: PByte; n: TOpenSSL_C_SIZET; md: PByte): PByte; cdecl = Load_SHA256;
  SHA256_Transform: procedure (c: PSHA256_CTX; const data: PByte); cdecl = Load_SHA256_Transform;
  SHA384_Init: function (c: PSHA512_CTX): TOpenSSL_C_INT; cdecl = Load_SHA384_Init;
  SHA384_Update: function (c: PSHA512_CTX; const data: Pointer; len: TOpenSSL_C_SIZET): TOpenSSL_C_INT; cdecl = Load_SHA384_Update;
  SHA384_Final: function (md: PByte; c: PSHA512_CTX): TOpenSSL_C_INT; cdecl = Load_SHA384_Final;
  SHA384: function (const d: PByte; n: TOpenSSL_C_SIZET; md: PByte): PByte; cdecl = Load_SHA384;
  SHA512_Init: function (c: PSHA512_CTX): TOpenSSL_C_INT; cdecl = Load_SHA512_Init;
  SHA512_Update: function (c: PSHA512_CTX; const data: Pointer; len: TOpenSSL_C_SIZET): TOpenSSL_C_INT; cdecl = Load_SHA512_Update;
  SHA512_Final: function (md: PByte; c: PSHA512_CTX): TOpenSSL_C_INT; cdecl = Load_SHA512_Final;
  SHA512: function (const d: PByte; n: TOpenSSL_C_SIZET; md: PByte): PByte; cdecl = Load_SHA512;
  SHA512_Transform: procedure (c: PSHA512_CTX; const data: PByte); cdecl = Load_SHA512_Transform;
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
function Load_SHA1_Init(c: PSHA_CTX): TOpenSSL_C_INT; cdecl;
begin
  SHA1_Init := LoadLibCryptoFunction('SHA1_Init');
  if not assigned(SHA1_Init) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('SHA1_Init');
  Result := SHA1_Init(c);
end;

function Load_SHA1_Update(c: PSHA_CTX; const data: Pointer; len: TOpenSSL_C_SIZET): TOpenSSL_C_INT; cdecl;
begin
  SHA1_Update := LoadLibCryptoFunction('SHA1_Update');
  if not assigned(SHA1_Update) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('SHA1_Update');
  Result := SHA1_Update(c,data,len);
end;

function Load_SHA1_Final(md: PByte; c: PSHA_CTX): TOpenSSL_C_INT; cdecl;
begin
  SHA1_Final := LoadLibCryptoFunction('SHA1_Final');
  if not assigned(SHA1_Final) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('SHA1_Final');
  Result := SHA1_Final(md,c);
end;

function Load_SHA1(const d: PByte; n: TOpenSSL_C_SIZET; md: PByte): PByte; cdecl;
begin
  SHA1 := LoadLibCryptoFunction('SHA1');
  if not assigned(SHA1) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('SHA1');
  Result := SHA1(d,n,md);
end;

procedure Load_SHA1_Transform(c: PSHA_CTX; const data: PByte); cdecl;
begin
  SHA1_Transform := LoadLibCryptoFunction('SHA1_Transform');
  if not assigned(SHA1_Transform) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('SHA1_Transform');
  SHA1_Transform(c,data);
end;

function Load_SHA224_Init(c: PSHA256_CTX): TOpenSSL_C_INT; cdecl;
begin
  SHA224_Init := LoadLibCryptoFunction('SHA224_Init');
  if not assigned(SHA224_Init) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('SHA224_Init');
  Result := SHA224_Init(c);
end;

function Load_SHA224_Update(c: PSHA256_CTX; const data: Pointer; len: TOpenSSL_C_SIZET): TOpenSSL_C_INT; cdecl;
begin
  SHA224_Update := LoadLibCryptoFunction('SHA224_Update');
  if not assigned(SHA224_Update) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('SHA224_Update');
  Result := SHA224_Update(c,data,len);
end;

function Load_SHA224_Final(md: PByte; c: PSHA256_CTX): TOpenSSL_C_INT; cdecl;
begin
  SHA224_Final := LoadLibCryptoFunction('SHA224_Final');
  if not assigned(SHA224_Final) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('SHA224_Final');
  Result := SHA224_Final(md,c);
end;

function Load_SHA224(const d: PByte; n: TOpenSSL_C_SIZET; md: PByte): PByte; cdecl;
begin
  SHA224 := LoadLibCryptoFunction('SHA224');
  if not assigned(SHA224) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('SHA224');
  Result := SHA224(d,n,md);
end;

function Load_SHA256_Init(c: PSHA256_CTX): TOpenSSL_C_INT; cdecl;
begin
  SHA256_Init := LoadLibCryptoFunction('SHA256_Init');
  if not assigned(SHA256_Init) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('SHA256_Init');
  Result := SHA256_Init(c);
end;

function Load_SHA256_Update(c: PSHA256_CTX; const data: Pointer; len: TOpenSSL_C_SIZET): TOpenSSL_C_INT; cdecl;
begin
  SHA256_Update := LoadLibCryptoFunction('SHA256_Update');
  if not assigned(SHA256_Update) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('SHA256_Update');
  Result := SHA256_Update(c,data,len);
end;

function Load_SHA256_Final(md: PByte; c: PSHA256_CTX): TOpenSSL_C_INT; cdecl;
begin
  SHA256_Final := LoadLibCryptoFunction('SHA256_Final');
  if not assigned(SHA256_Final) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('SHA256_Final');
  Result := SHA256_Final(md,c);
end;

function Load_SHA256(const d: PByte; n: TOpenSSL_C_SIZET; md: PByte): PByte; cdecl;
begin
  SHA256 := LoadLibCryptoFunction('SHA256');
  if not assigned(SHA256) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('SHA256');
  Result := SHA256(d,n,md);
end;

procedure Load_SHA256_Transform(c: PSHA256_CTX; const data: PByte); cdecl;
begin
  SHA256_Transform := LoadLibCryptoFunction('SHA256_Transform');
  if not assigned(SHA256_Transform) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('SHA256_Transform');
  SHA256_Transform(c,data);
end;

function Load_SHA384_Init(c: PSHA512_CTX): TOpenSSL_C_INT; cdecl;
begin
  SHA384_Init := LoadLibCryptoFunction('SHA384_Init');
  if not assigned(SHA384_Init) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('SHA384_Init');
  Result := SHA384_Init(c);
end;

function Load_SHA384_Update(c: PSHA512_CTX; const data: Pointer; len: TOpenSSL_C_SIZET): TOpenSSL_C_INT; cdecl;
begin
  SHA384_Update := LoadLibCryptoFunction('SHA384_Update');
  if not assigned(SHA384_Update) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('SHA384_Update');
  Result := SHA384_Update(c,data,len);
end;

function Load_SHA384_Final(md: PByte; c: PSHA512_CTX): TOpenSSL_C_INT; cdecl;
begin
  SHA384_Final := LoadLibCryptoFunction('SHA384_Final');
  if not assigned(SHA384_Final) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('SHA384_Final');
  Result := SHA384_Final(md,c);
end;

function Load_SHA384(const d: PByte; n: TOpenSSL_C_SIZET; md: PByte): PByte; cdecl;
begin
  SHA384 := LoadLibCryptoFunction('SHA384');
  if not assigned(SHA384) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('SHA384');
  Result := SHA384(d,n,md);
end;

function Load_SHA512_Init(c: PSHA512_CTX): TOpenSSL_C_INT; cdecl;
begin
  SHA512_Init := LoadLibCryptoFunction('SHA512_Init');
  if not assigned(SHA512_Init) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('SHA512_Init');
  Result := SHA512_Init(c);
end;

function Load_SHA512_Update(c: PSHA512_CTX; const data: Pointer; len: TOpenSSL_C_SIZET): TOpenSSL_C_INT; cdecl;
begin
  SHA512_Update := LoadLibCryptoFunction('SHA512_Update');
  if not assigned(SHA512_Update) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('SHA512_Update');
  Result := SHA512_Update(c,data,len);
end;

function Load_SHA512_Final(md: PByte; c: PSHA512_CTX): TOpenSSL_C_INT; cdecl;
begin
  SHA512_Final := LoadLibCryptoFunction('SHA512_Final');
  if not assigned(SHA512_Final) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('SHA512_Final');
  Result := SHA512_Final(md,c);
end;

function Load_SHA512(const d: PByte; n: TOpenSSL_C_SIZET; md: PByte): PByte; cdecl;
begin
  SHA512 := LoadLibCryptoFunction('SHA512');
  if not assigned(SHA512) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('SHA512');
  Result := SHA512(d,n,md);
end;

procedure Load_SHA512_Transform(c: PSHA512_CTX; const data: PByte); cdecl;
begin
  SHA512_Transform := LoadLibCryptoFunction('SHA512_Transform');
  if not assigned(SHA512_Transform) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('SHA512_Transform');
  SHA512_Transform(c,data);
end;


procedure UnLoad;
begin
  SHA1_Init := Load_SHA1_Init;
  SHA1_Update := Load_SHA1_Update;
  SHA1_Final := Load_SHA1_Final;
  SHA1 := Load_SHA1;
  SHA1_Transform := Load_SHA1_Transform;
  SHA224_Init := Load_SHA224_Init;
  SHA224_Update := Load_SHA224_Update;
  SHA224_Final := Load_SHA224_Final;
  SHA224 := Load_SHA224;
  SHA256_Init := Load_SHA256_Init;
  SHA256_Update := Load_SHA256_Update;
  SHA256_Final := Load_SHA256_Final;
  SHA256 := Load_SHA256;
  SHA256_Transform := Load_SHA256_Transform;
  SHA384_Init := Load_SHA384_Init;
  SHA384_Update := Load_SHA384_Update;
  SHA384_Final := Load_SHA384_Final;
  SHA384 := Load_SHA384;
  SHA512_Init := Load_SHA512_Init;
  SHA512_Update := Load_SHA512_Update;
  SHA512_Final := Load_SHA512_Final;
  SHA512 := Load_SHA512;
  SHA512_Transform := Load_SHA512_Transform;
end;
{$ENDIF}

initialization

{$IFNDEF OPENSSL_STATIC_LINK_MODEL}
Register_SSLUnloader(@Unload);
{$ENDIF}
finalization


end.
