(* This unit was generated from the source file whrlpool.h2pas 
It should not be modified directly. All changes should be made to whrlpool.h2pas
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


unit IdOpenSSLHeaders_whrlpool;


interface

// Headers for OpenSSL 1.1.1
// whrlpool.h


uses
  IdSSLOpenSSLAPI;

const
  WHIRLPOOL_DIGEST_LENGTH = 512 div 8;
  WHIRLPOOL_BBLOCK = 512;
  WHIRLPOOL_COUNTER = 256 div 8;

type
  WHIRLPOOL_CTX_union = record
    case Byte of
      0: (c: array[0 .. WHIRLPOOL_DIGEST_LENGTH -1] of Byte);
      (* double q is here to ensure 64-bit alignment *)
      1: (q: array[0 .. (WHIRLPOOL_DIGEST_LENGTH div SizeOf(TOpenSSL_C_DOUBLE)) -1] of TOpenSSL_C_DOUBLE);
  end;
  WHIRLPOOL_CTX = record
    H: WHIRLPOOL_CTX_union;
    data: array[0 .. (WHIRLPOOL_BBLOCK div 8) -1] of Byte;
    bitoff: TOpenSSL_C_UINT;
    bitlen: array[0 .. (WHIRLPOOL_COUNTER div SizeOf(TOpenSSL_C_SIZET)) -1] of TOpenSSL_C_SIZET;
  end;
  PWHIRLPOOL_CTX = ^WHIRLPOOL_CTX;

  
{ The EXTERNALSYM directive is ignored by FPC, however, it is used by Delphi as follows: 

The EXTERNALSYM directive prevents the specified Delphi symbol from appearing in header 
files generated for C++. }

{$EXTERNALSYM WHIRLPOOL_Init}
{$EXTERNALSYM WHIRLPOOL_Update}
{$EXTERNALSYM WHIRLPOOL_BitUpdate}
{$EXTERNALSYM WHIRLPOOL_Final}
{$EXTERNALSYM WHIRLPOOL}

{$IFDEF OPENSSL_STATIC_LINK_MODEL}
function WHIRLPOOL_Init(c: PWHIRLPOOL_CTX): TOpenSSL_C_INT; cdecl; external CLibCrypto;
function WHIRLPOOL_Update(c: PWHIRLPOOL_CTX; inp: Pointer; bytes: TOpenSSL_C_SIZET): TOpenSSL_C_INT; cdecl; external CLibCrypto;
procedure WHIRLPOOL_BitUpdate(c: PWHIRLPOOL_CTX; inp: Pointer; bits: TOpenSSL_C_SIZET); cdecl; external CLibCrypto;
function WHIRLPOOL_Final(md: PByte; c: PWHIRLPOOL_CTX): TOpenSSL_C_INT; cdecl; external CLibCrypto;
function WHIRLPOOL(inp: Pointer; bytes: TOpenSSL_C_SIZET; md: PByte): PByte; cdecl; external CLibCrypto;

{$ELSE}

{Declare external function initialisers - should not be called directly}

function Load_WHIRLPOOL_Init(c: PWHIRLPOOL_CTX): TOpenSSL_C_INT; cdecl;
function Load_WHIRLPOOL_Update(c: PWHIRLPOOL_CTX; inp: Pointer; bytes: TOpenSSL_C_SIZET): TOpenSSL_C_INT; cdecl;
procedure Load_WHIRLPOOL_BitUpdate(c: PWHIRLPOOL_CTX; inp: Pointer; bits: TOpenSSL_C_SIZET); cdecl;
function Load_WHIRLPOOL_Final(md: PByte; c: PWHIRLPOOL_CTX): TOpenSSL_C_INT; cdecl;
function Load_WHIRLPOOL(inp: Pointer; bytes: TOpenSSL_C_SIZET; md: PByte): PByte; cdecl;

var
  WHIRLPOOL_Init: function (c: PWHIRLPOOL_CTX): TOpenSSL_C_INT; cdecl = Load_WHIRLPOOL_Init;
  WHIRLPOOL_Update: function (c: PWHIRLPOOL_CTX; inp: Pointer; bytes: TOpenSSL_C_SIZET): TOpenSSL_C_INT; cdecl = Load_WHIRLPOOL_Update;
  WHIRLPOOL_BitUpdate: procedure (c: PWHIRLPOOL_CTX; inp: Pointer; bits: TOpenSSL_C_SIZET); cdecl = Load_WHIRLPOOL_BitUpdate;
  WHIRLPOOL_Final: function (md: PByte; c: PWHIRLPOOL_CTX): TOpenSSL_C_INT; cdecl = Load_WHIRLPOOL_Final;
  WHIRLPOOL: function (inp: Pointer; bytes: TOpenSSL_C_SIZET; md: PByte): PByte; cdecl = Load_WHIRLPOOL;
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
function Load_WHIRLPOOL_Init(c: PWHIRLPOOL_CTX): TOpenSSL_C_INT; cdecl;
begin
  WHIRLPOOL_Init := LoadLibCryptoFunction('WHIRLPOOL_Init');
  if not assigned(WHIRLPOOL_Init) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('WHIRLPOOL_Init');
  Result := WHIRLPOOL_Init(c);
end;

function Load_WHIRLPOOL_Update(c: PWHIRLPOOL_CTX; inp: Pointer; bytes: TOpenSSL_C_SIZET): TOpenSSL_C_INT; cdecl;
begin
  WHIRLPOOL_Update := LoadLibCryptoFunction('WHIRLPOOL_Update');
  if not assigned(WHIRLPOOL_Update) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('WHIRLPOOL_Update');
  Result := WHIRLPOOL_Update(c,inp,bytes);
end;

procedure Load_WHIRLPOOL_BitUpdate(c: PWHIRLPOOL_CTX; inp: Pointer; bits: TOpenSSL_C_SIZET); cdecl;
begin
  WHIRLPOOL_BitUpdate := LoadLibCryptoFunction('WHIRLPOOL_BitUpdate');
  if not assigned(WHIRLPOOL_BitUpdate) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('WHIRLPOOL_BitUpdate');
  WHIRLPOOL_BitUpdate(c,inp,bits);
end;

function Load_WHIRLPOOL_Final(md: PByte; c: PWHIRLPOOL_CTX): TOpenSSL_C_INT; cdecl;
begin
  WHIRLPOOL_Final := LoadLibCryptoFunction('WHIRLPOOL_Final');
  if not assigned(WHIRLPOOL_Final) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('WHIRLPOOL_Final');
  Result := WHIRLPOOL_Final(md,c);
end;

function Load_WHIRLPOOL(inp: Pointer; bytes: TOpenSSL_C_SIZET; md: PByte): PByte; cdecl;
begin
  WHIRLPOOL := LoadLibCryptoFunction('WHIRLPOOL');
  if not assigned(WHIRLPOOL) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('WHIRLPOOL');
  Result := WHIRLPOOL(inp,bytes,md);
end;


procedure UnLoad;
begin
  WHIRLPOOL_Init := Load_WHIRLPOOL_Init;
  WHIRLPOOL_Update := Load_WHIRLPOOL_Update;
  WHIRLPOOL_BitUpdate := Load_WHIRLPOOL_BitUpdate;
  WHIRLPOOL_Final := Load_WHIRLPOOL_Final;
  WHIRLPOOL := Load_WHIRLPOOL;
end;
{$ENDIF}

initialization

{$IFNDEF OPENSSL_STATIC_LINK_MODEL}
Register_SSLUnloader(@Unload);
{$ENDIF}
finalization


end.
