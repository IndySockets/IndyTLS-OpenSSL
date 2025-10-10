(* This unit was generated from the source file blowfish.h2pas 
It should not be modified directly. All changes should be made to blowfish.h2pas
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


unit IdOpenSSLHeaders_blowfish;


interface

// Headers for OpenSSL 1.1.1
// blowfish.h


uses
  IdSSLOpenSSLAPI;

const
  // Added '_CONST' to avoid name clashes
  BF_ENCRYPT_CONST = 1;
  // Added '_CONST' to avoid name clashes
  BF_DECRYPT_CONST = 0;

  BF_ROUNDS = 16;
  BF_BLOCK  = 8;

type
  BF_LONG = TOpenSSL_C_UINT;
  PBF_LONG = ^BF_LONG;

  bf_key_st = record
    p: array[0 .. BF_ROUNDS + 2 - 1] of BF_LONG;
    s: array[0 .. 4 * 256 - 1] of BF_LONG;
  end;
  BF_KEY = bf_key_st;
  PBF_KEY = ^BF_KEY;

  
{ The EXTERNALSYM directive is ignored by FPC, however, it is used by Delphi as follows: 

The EXTERNALSYM directive prevents the specified Delphi symbol from appearing in header 
files generated for C++. }

{$EXTERNALSYM BF_set_key}
{$EXTERNALSYM BF_encrypt}
{$EXTERNALSYM BF_decrypt}
{$EXTERNALSYM BF_ecb_encrypt}
{$EXTERNALSYM BF_cbc_encrypt}
{$EXTERNALSYM BF_cfb64_encrypt}
{$EXTERNALSYM BF_ofb64_encrypt}
{$EXTERNALSYM BF_options}

{$IFDEF OPENSSL_STATIC_LINK_MODEL}
procedure BF_set_key(key: PBF_KEY; len: TOpenSSL_C_INT; const data: PByte); cdecl; external CLibCrypto;
procedure BF_encrypt(data: PBF_LONG; const key: PBF_KEY); cdecl; external CLibCrypto;
procedure BF_decrypt(data: PBF_LONG; const key: PBF_KEY); cdecl; external CLibCrypto;
procedure BF_ecb_encrypt(const in_: PByte; out_: PByte; key: PBF_KEY; enc: TOpenSSL_C_INT); cdecl; external CLibCrypto;
procedure BF_cbc_encrypt(const in_: PByte; out_: PByte; length: TOpenSSL_C_LONG; schedule: PBF_KEY; ivec: PByte; enc: TOpenSSL_C_INT); cdecl; external CLibCrypto;
procedure BF_cfb64_encrypt(const in_: PByte; out_: PByte; length: TOpenSSL_C_LONG; schedule: PBF_KEY; ivec: PByte; num: POpenSSL_C_INT; enc: TOpenSSL_C_INT); cdecl; external CLibCrypto;
procedure BF_ofb64_encrypt(const in_: PByte; out_: PByte; length: TOpenSSL_C_LONG; schedule: PBF_KEY; ivec: PByte; num: POpenSSL_C_INT); cdecl; external CLibCrypto;
function BF_options: PAnsiChar; cdecl; external CLibCrypto;

{$ELSE}

{Declare external function initialisers - should not be called directly}

procedure Load_BF_set_key(key: PBF_KEY; len: TOpenSSL_C_INT; const data: PByte); cdecl;
procedure Load_BF_encrypt(data: PBF_LONG; const key: PBF_KEY); cdecl;
procedure Load_BF_decrypt(data: PBF_LONG; const key: PBF_KEY); cdecl;
procedure Load_BF_ecb_encrypt(const in_: PByte; out_: PByte; key: PBF_KEY; enc: TOpenSSL_C_INT); cdecl;
procedure Load_BF_cbc_encrypt(const in_: PByte; out_: PByte; length: TOpenSSL_C_LONG; schedule: PBF_KEY; ivec: PByte; enc: TOpenSSL_C_INT); cdecl;
procedure Load_BF_cfb64_encrypt(const in_: PByte; out_: PByte; length: TOpenSSL_C_LONG; schedule: PBF_KEY; ivec: PByte; num: POpenSSL_C_INT; enc: TOpenSSL_C_INT); cdecl;
procedure Load_BF_ofb64_encrypt(const in_: PByte; out_: PByte; length: TOpenSSL_C_LONG; schedule: PBF_KEY; ivec: PByte; num: POpenSSL_C_INT); cdecl;
function Load_BF_options: PAnsiChar; cdecl;

var
  BF_set_key: procedure (key: PBF_KEY; len: TOpenSSL_C_INT; const data: PByte); cdecl = Load_BF_set_key;
  BF_encrypt: procedure (data: PBF_LONG; const key: PBF_KEY); cdecl = Load_BF_encrypt;
  BF_decrypt: procedure (data: PBF_LONG; const key: PBF_KEY); cdecl = Load_BF_decrypt;
  BF_ecb_encrypt: procedure (const in_: PByte; out_: PByte; key: PBF_KEY; enc: TOpenSSL_C_INT); cdecl = Load_BF_ecb_encrypt;
  BF_cbc_encrypt: procedure (const in_: PByte; out_: PByte; length: TOpenSSL_C_LONG; schedule: PBF_KEY; ivec: PByte; enc: TOpenSSL_C_INT); cdecl = Load_BF_cbc_encrypt;
  BF_cfb64_encrypt: procedure (const in_: PByte; out_: PByte; length: TOpenSSL_C_LONG; schedule: PBF_KEY; ivec: PByte; num: POpenSSL_C_INT; enc: TOpenSSL_C_INT); cdecl = Load_BF_cfb64_encrypt;
  BF_ofb64_encrypt: procedure (const in_: PByte; out_: PByte; length: TOpenSSL_C_LONG; schedule: PBF_KEY; ivec: PByte; num: POpenSSL_C_INT); cdecl = Load_BF_ofb64_encrypt;
  BF_options: function : PAnsiChar; cdecl = Load_BF_options;
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
procedure Load_BF_set_key(key: PBF_KEY; len: TOpenSSL_C_INT; const data: PByte); cdecl;
begin
  BF_set_key := LoadLibCryptoFunction('BF_set_key');
  if not assigned(BF_set_key) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('BF_set_key');
  BF_set_key(key,len,data);
end;

procedure Load_BF_encrypt(data: PBF_LONG; const key: PBF_KEY); cdecl;
begin
  BF_encrypt := LoadLibCryptoFunction('BF_encrypt');
  if not assigned(BF_encrypt) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('BF_encrypt');
  BF_encrypt(data,key);
end;

procedure Load_BF_decrypt(data: PBF_LONG; const key: PBF_KEY); cdecl;
begin
  BF_decrypt := LoadLibCryptoFunction('BF_decrypt');
  if not assigned(BF_decrypt) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('BF_decrypt');
  BF_decrypt(data,key);
end;

procedure Load_BF_ecb_encrypt(const in_: PByte; out_: PByte; key: PBF_KEY; enc: TOpenSSL_C_INT); cdecl;
begin
  BF_ecb_encrypt := LoadLibCryptoFunction('BF_ecb_encrypt');
  if not assigned(BF_ecb_encrypt) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('BF_ecb_encrypt');
  BF_ecb_encrypt(in_,out_,key,enc);
end;

procedure Load_BF_cbc_encrypt(const in_: PByte; out_: PByte; length: TOpenSSL_C_LONG; schedule: PBF_KEY; ivec: PByte; enc: TOpenSSL_C_INT); cdecl;
begin
  BF_cbc_encrypt := LoadLibCryptoFunction('BF_cbc_encrypt');
  if not assigned(BF_cbc_encrypt) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('BF_cbc_encrypt');
  BF_cbc_encrypt(in_,out_,length,schedule,ivec,enc);
end;

procedure Load_BF_cfb64_encrypt(const in_: PByte; out_: PByte; length: TOpenSSL_C_LONG; schedule: PBF_KEY; ivec: PByte; num: POpenSSL_C_INT; enc: TOpenSSL_C_INT); cdecl;
begin
  BF_cfb64_encrypt := LoadLibCryptoFunction('BF_cfb64_encrypt');
  if not assigned(BF_cfb64_encrypt) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('BF_cfb64_encrypt');
  BF_cfb64_encrypt(in_,out_,length,schedule,ivec,num,enc);
end;

procedure Load_BF_ofb64_encrypt(const in_: PByte; out_: PByte; length: TOpenSSL_C_LONG; schedule: PBF_KEY; ivec: PByte; num: POpenSSL_C_INT); cdecl;
begin
  BF_ofb64_encrypt := LoadLibCryptoFunction('BF_ofb64_encrypt');
  if not assigned(BF_ofb64_encrypt) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('BF_ofb64_encrypt');
  BF_ofb64_encrypt(in_,out_,length,schedule,ivec,num);
end;

function Load_BF_options: PAnsiChar; cdecl;
begin
  BF_options := LoadLibCryptoFunction('BF_options');
  if not assigned(BF_options) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('BF_options');
  Result := BF_options();
end;


procedure UnLoad;
begin
  BF_set_key := Load_BF_set_key;
  BF_encrypt := Load_BF_encrypt;
  BF_decrypt := Load_BF_decrypt;
  BF_ecb_encrypt := Load_BF_ecb_encrypt;
  BF_cbc_encrypt := Load_BF_cbc_encrypt;
  BF_cfb64_encrypt := Load_BF_cfb64_encrypt;
  BF_ofb64_encrypt := Load_BF_ofb64_encrypt;
  BF_options := Load_BF_options;
end;
{$ENDIF}

initialization

{$IFNDEF OPENSSL_STATIC_LINK_MODEL}
Register_SSLUnloader(@Unload);
{$ENDIF}
finalization


end.
